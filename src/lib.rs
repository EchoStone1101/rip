#![allow(dead_code)]
#![allow(unused)]

//! This library implements basic IPv4 protocol and enables routing of packets
//! based on *pre-assigned* IPs (DHCP is not yet implemented). It also provides
//! interface for sending and receiving IP packets for upper layer programs.
//! 
//! The routing algorithm is traditional Link State Algorithm. To be able to
//! route packets around the network, an instance of this library should be run
//! on each node, which after init() spawns daemon threads to handle the routing.
//! 
//! To keep things simple, this implementation uses minimum number of control 
//! messages. There is no separate ARP message (MAC addresses can be acquired
//! via the Neighbor Detection Protocol in LSA), and all LSA related messages require 
//! no ACK. Again, this library is built upon Rlink, which supports only stable
//! Ethernet link.

use rlink::{DeviceHandle, Direction, Device, PError, RlinkError, EtherType};
use timer::Timer;
use chrono::{Duration, Utc};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::sync::{mpsc, Mutex, Arc};
use std::fmt;
use std::collections::{HashMap};

pub mod ipv4;
pub mod link_state;
pub mod route;

pub use rlink::MacAddress;
pub use ipv4::ipv4::{Ipv4Packet, Ipv4Header, IpProtoType};
pub use link_state::link_state::{LinkStatePacket, LinkStateNode};
pub use route::route::{RoutingTable, RoutingRule, IPorMAC, RoutingRuleKey, RoutingRuleValue};

/// Errors in Rip library
#[derive(Debug)]
pub enum RipError {
    /// Packet parsed is invalid as IPv4 packet
    InvalidIpv4Packet,
    /// Packet parsed is invalid as ND packet
    InvalidNDPacket,
    /// Packet parsed is invalid as LSP
    InvalidLSP,
    /// LSP packet too large
    LSPTooLarge,
    /// IPv4 packet too large
    IPPacketTooLarge,
}

impl fmt::Display for RipError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use RipError::*;
        match *self {
            InvalidIpv4Packet => write!(f, "invalid IPv4 packet"),
            InvalidNDPacket => write!(f, "invalid ND packet"),
            InvalidLSP => write!(f, "invalid LSP"),
            LSPTooLarge => write!(f, "generating an oversized LSP"),
            IPPacketTooLarge => write!(f, "IPv4 packet too large"),
        }
    }
}

/// Packet format of Neighbor Detection Protocol, the protocol in Rip 
/// implementation for sniffing the network topology.
#[derive(Debug)]
struct NDPacket {
    /// Sender's IP address
    ip: Ipv4Addr,
    /// Sender's mac address
    mac: MacAddress,
    /// The IP of the device that received the packet.
    rx_ip: Ipv4Addr,
    timestamp: i64,
}

impl NDPacket {
    pub fn parse(data: &[u8], rx_ip: Ipv4Addr) -> Result<Self, RipError> {
        // ND packet is [ip_addr][mac_addr][timestamp]
        if data.len() < 4 + 6 + 8 {
            return Err(RipError::InvalidNDPacket);
        }
        Ok(NDPacket{
            ip: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
            mac: MacAddress::new(data[4..10].try_into().unwrap()),
            rx_ip,
            timestamp: i64::from_be_bytes(data[10..18].try_into().unwrap()),
        })
    }
}

/// Packets that are sent to the main thread for dispatching. The main purpose
/// of this enum is to unify NDPacket and Ipv4Packet, so that they are sent via
/// the same channel.
#[derive(Debug)]
enum RipPacket {
    NDP(NDPacket),
    IPv4(Ipv4Packet),
}

/// A library instance. Details are opaque outside this library.
pub struct RipCtl {
    /// The main dispatching thread
    main_thread: thread::JoinHandle<Result<(), mpsc::RecvError>>,
    /// Receiver of IP packets whose destination is a local IP (and not an LSP)
    rx: mpsc::Receiver<Ipv4Packet>,
    /// Sender of IP packets to the main thread
    tx: mpsc::Sender<RipPacket>,
    /// Handle for manually configuring the routing table
    rules: Arc<Mutex<Vec<RoutingRule>>>,
}


impl RipCtl {

    /// Default TTL for Rip packets.
    pub const RIP_TTL: u8 = 64;

    /// Initiate the Rip library. First the main dispatch thread is created, then 
    /// it spawns and manages worker threads, ND thread and LS thread.
    /// Note that this function should only be called once. 
    /// Set VETH_ONLY to make Rip library recognize only devices with name prefix "veth". This
    /// is for testing with the makeVNet scripts.
    pub fn init(veth_only: bool) -> RipCtl {

        // Channel for sending IPv4 packets to the user interface
        let (usr_tx, usr_rx) = mpsc::channel::<Ipv4Packet>();
        // Channel for sending packets to the main thread
        let (mt_tx, mt_rx) = mpsc::channel::<RipPacket>();

        // Initiate routing table. Keep a clone of the handle of rules, then move 
        // the table into the main thread.
        let mut routing_table = RoutingTable::init();
        let rules = routing_table.get_rules_writer();

        // Spawn the main dispatch thread
        let main_thread: thread::JoinHandle<Result<(), mpsc::RecvError>> = {
            let mt_tx = mt_tx.clone();
            let usr_tx = usr_tx.clone();
            thread::spawn(move || {
                
                // `routing_table` moved; it is further moved to the LS thread
                let mut routing_table = routing_table;
                let mut workers: Vec<WorkerThread> = Vec::new();
                let (ls_tx, ls_rx) = mpsc::channel();
    
                // Builds an LSP over time
                let lsp = 
                    Arc::new(Mutex::new(Option::<LinkStatePacket>::Some(LinkStatePacket::new(0u64))));
                // Accumulates ip2mac mapping from NDP, omitting ARP
                let mut neighbors_ip2mac = HashMap::new();
    
                // Register the timer thread.
                // * It periodically sends NDP with rx_ip=broadcast to the main thread
                //   which triggers scaling at the main thread. The NDP is also broadcast.
                // * Once countdown reaches 0, the received NDP is gathered as an LSP and 
                //   sent to LS thread for routing computation.
                 // Register timer for periodical ND
                let timer = timer::Timer::new();
                let countdown = Arc::new(Mutex::new(3));
                let _guard = {
                    let countdown = countdown.clone();
                    let mt_tx = mt_tx.clone();
                    let ls_tx = ls_tx.clone();
                    let lsp = lsp.clone();
    
                    timer.schedule_repeating(Duration::seconds(1), move || {
                        // ND triggered
                        mt_tx.send(RipPacket::NDP(NDPacket{
                            ip: Ipv4Addr::new(0x0u8, 0x0u8, 0x0u8, 0x0u8),
                            mac: MacAddress::new([0x0u8; 6]),
                            // rx_ip=unspecified, so that the main thread knows that this NDP
                            // is not from workers
                            rx_ip: Ipv4Addr::new(0x0u8, 0x0u8, 0x0u8, 0x0u8),
                            timestamp: 0,
                        }));
    
                        let mut mg = countdown.lock().unwrap();
                        *mg -= 1;
                        if *mg == 0 {
                            *mg = 4;
    
                            // LS triggered
                            let mut mg = lsp.lock().unwrap();
                            let lsp = mg.take().unwrap();
                            let nxt_version = lsp.version + 1;
                            mg.insert(LinkStatePacket::new(nxt_version));
                            drop(mg);
                            ls_tx.send(lsp);   
                        }
                    })
                };
    
                // Spawn the LS thread.
                // * It receives LSPs from ND thread and the main thread
                // * It manages the list of LSPs, which represents current node's vision
                //   of the network. LSPs may expire or be updated.
                // * It sends LSPs back to the main thread to be flooded
                // * Once the list of LSPs changes, it rebuilds the LS graph, and recomputes
                //   the routing table.
    
                // Initiate the routing table here, keep a clone of the reading handle,
                // and move the table into LS thread.
                
                let routing_table_handle = routing_table.get_table_reader();

                let ls_thread: thread::JoinHandle<Result<(), mpsc::RecvError>> = {
                    // Clone tx end of main thread, for flooding LSP back
                    let mt_tx = mt_tx.clone();               
                    thread::spawn(move || {
    
                        // The list of living LSNs
                        let mut lsn_list: Vec<LinkStateNode> = Vec::new();
                        // `routing_table` moved
                        let mut routing_table = routing_table;
                        loop {
                            let mut lsp = Some(ls_rx.recv()?);
        
                            // Update the list of LSPs
                            let mut update = false;
                            for idx in 0..lsn_list.len() {
                                if let Some(LinkStatePacket{version, id, ..}) = lsp {
                                    if lsn_list[idx].lsp.id == id {
                                        let lsp = lsp.take().unwrap();
                                        if lsn_list[idx].lsp.version < version {
                                            // Flood this LSP
                                            let ip_packet = lsp.as_ipv4_packet().unwrap();
                                            mt_tx.send(RipPacket::IPv4(ip_packet));
                                            lsn_list[idx].lsp = lsp;
                                            lsn_list[idx].birth = Utc::now().timestamp_micros();
                                            update = true;
                                        }
                                        break;
                                    }
                                } 
                            }
                            if let Some(lsp) = lsp {
                                // Flood this LSP
                                let ip_packet = lsp.as_ipv4_packet().unwrap();
                                mt_tx.send(RipPacket::IPv4(ip_packet));
    
                                lsn_list.push(LinkStateNode{
                                    lsp,
                                    birth: Utc::now().timestamp_micros(),
                                });
                                update = true;
                            }
                            let now = Utc::now().timestamp_micros();
                            lsn_list.retain(|lsn| {
                                if now - lsn.birth >= 10 * 1_000_000 {
                                    update = true;
                                    return false;
                                }
                                true
                            });
    
                            // print!("{esc}c", esc = 27 as char);
                            // for (idx, lsn) in lsn_list.iter().enumerate() {
                            //     println!("[{idx}]: {:?} (id: {}, version: {})", lsn.lsp.node, lsn.lsp.id, lsn.lsp.version);
                            // }
        
                            // If updated, flood this LSP, and rebuild the LSN graph
                            if (update) {
                                LinkStateNode::reroute(&mut lsn_list, &mut routing_table);
                            }

                        }
                        Ok(())
                    })
                };
    
                loop {
                    let packet = mt_rx.recv()?;
    
                    match packet {
                        RipPacket::NDP(ndp) => {
                            // An unspecified NDP, sent from the timer thread
                            // Scaling is triggered; then the NDP is broadcast
                            if ndp.rx_ip.is_unspecified() {
                                RipCtl::scale(veth_only, &mut workers, &mt_tx, &usr_tx, &ls_tx);
                                for worker in workers.iter_mut() {
                                    // Before sending the NDP, record timestamp.
                                    let now = Utc::now().timestamp_micros();
                                    worker.out_handle.send_packet([
                                            worker.ip.octets().as_ref(), 
                                            worker.out_handle.mac_address().bytes().as_ref(), 
                                            now.to_be_bytes().as_ref(),].concat(),
                                            EtherType::NDP, 
                                            &[0xffu8; 6],
                                            false);
                                    
                                }
                            }
                            // Otherwise, NDP sent from a worker. Build LSP.
                            else {
                                neighbors_ip2mac.insert(ndp.ip, ndp.mac);
    
                                let mut mg = lsp.lock().unwrap();
                                let mut lsp = mg.take().unwrap();
                                
                                let cost: u32 = ndp.timestamp as u32;
                                // FOR TESTING
                                // let cost = 1u32;
                                lsp.add(IpAddr::V4(ndp.rx_ip), IpAddr::V4(ndp.ip), cost);
                                mg.insert(lsp);
                            }
                        },
                        RipPacket::IPv4(mut ip_packet) => {
                            // IPv4 packets are equally routed.
    
                            if ip_packet.hdr.ttl == 0 {
                                continue;
                            }
                            else {
                                ip_packet.hdr.ttl -= 1;
                            }
    
                            // Broadcast
                            if ip_packet.hdr.dst_ip.is_broadcast() {
                                for WorkerThread{out_handle, ip, ..} in workers.iter_mut() {
                                    // Avoid flooding backwards
                                    if ip_packet.rx_ip.eq(ip) {
                                        continue;
                                    }
    
                                    let mut payload = ip_packet.hdr.to_bytes(ip);
                                    payload.extend_from_slice(ip_packet.data.as_slice());
     
                                    out_handle.send_packet(payload.as_slice(), 
                                                            EtherType::IPv4, &[0xffu8; 6], false);
                                }
                                continue;
                            }
    
                            // Route
                            // If `dst_ip` is just local IP, accept the packet and send to user.
                            if let Some(_) = workers.iter().find(|w| w.ip == ip_packet.hdr.dst_ip) {
                                usr_tx.send(ip_packet);
                                continue;
                            }

                            if let Some((via, recv)) = RoutingTable::route(
                                &routing_table_handle,
                                ip_packet.hdr.dst_ip,
                                None,
                            ) {
                                let via_worker = workers.iter_mut().find(|w| w.ip == via);
                                if matches!(via_worker, None) {
                                    // Workers can die after they report an NDP.
                                    continue;
                                }
                                let via_worker = via_worker.unwrap();
                                // print!("{esc}c", esc = 27 as char);

                                match recv {
                                    IPorMAC::IPv4(recv) => {
                                        if let Some(mac) = neighbors_ip2mac.get(&recv) {
                                            // println!("Dest IP {} is about to be routed via {}, to {}({})", 
                                            //     ip_packet.hdr.dst_ip, 
                                            //     via, 
                                            //     recv, 
                                            //     mac,
                                            // );
        
                                            let mut payload = ip_packet.hdr.to_bytes(&via);
                                            payload.append(&mut ip_packet.data);
                                            via_worker.out_handle.send_packet(
                                                payload.as_slice(), EtherType::IPv4, &mac.bytes(), false);
                                        }
                                    },
                                    IPorMAC::Mac(mac) => {
                                        // println!("Dest IP {} is about to be routed via {}, to {}", 
                                        //     ip_packet.hdr.dst_ip, 
                                        //     via, 
                                        //     mac,
                                        // );
        
                                        let mut payload = ip_packet.hdr.to_bytes(&via);
                                        payload.append(&mut ip_packet.data);
                                        via_worker.out_handle.send_packet(
                                            payload.as_slice(), EtherType::IPv4, &mac.bytes(), false);
                                    }
                                }
                            }
                            else {
                                // println!("Dest IP {} not in the routing table", ip_packet.hdr.dst_ip);
                            }
                            
                        },
                    }
                }
                Ok(())
            })
        };

        RipCtl {
            main_thread,
            rx: usr_rx,
            tx: mt_tx,
            rules,
        }
    }

    /// Send an IP packet to be routed.
    pub fn send_ipv4_packet(
        &mut self, 
        dst_ip: Ipv4Addr,
        data: &[u8]) -> Result<(), RipError> 
    {
        if data.len() + 20 > 65535 {
            return Err(RipError::IPPacketTooLarge);
        }
        self.tx.send(RipPacket::IPv4(
            Ipv4Packet {
                hdr: Ipv4Header {
                version: 4,
                hdr_len: 5,     // Default header length
                tos: 0,         // Default TOS
                tot_len: 20 + data.len() as u16,
                id: 0,          // Fragmenation not supported
                df: true,
                mf: false,
                frag_ofs: 0,
                ttl: RipCtl::RIP_TTL,
                proto: IpProtoType::TCP,
                checksum: 0,    // checksum ommited
                src_ip: Ipv4Addr::UNSPECIFIED,
                dst_ip,
                options: [0u8; 40],
            },
            rx_ip: Ipv4Addr::UNSPECIFIED,
            data: Vec::from(data),
        }));
        Ok(())
    }

    /// Receive an IP packet from all underlying devices.
    /// Blocks on waiting.
    pub fn next_ipv4_packet(&mut self) -> Ipv4Packet {
        self.rx.recv().unwrap()
    }

    /// Returns the routing table configuration handle. The routing rules
    /// are available as a vector of RoutingRule for arbitrary configuration.
    pub fn get_config_handle(&self) -> &Arc<Mutex<Vec<RoutingRule>>> {
        &self.rules
    }

    /// The scaling of worker threads. The devices are re-scanned to detect new ones/
    /// broken old ones. The worker thread list is adjusted accordingly, joining dead
    /// threads or spawning new workers.
    fn scale(
        veth_only: bool,
        workers: &mut Vec<WorkerThread>,
        // The following are tx ends that are possibly cloned and sent to new worker threads
        mt_tx: &mpsc::Sender<RipPacket>,
        usr_tx: &mpsc::Sender<Ipv4Packet>,
        ls_tx: &mpsc::Sender<LinkStatePacket>) 
    {
        // Worker threads terminate once any availablility issue occurs, i.e. if
        // the device cannot be opened, or is turned down after a while. The main
        // thread shall check and join dead workers.
        workers.retain_mut(|worker_thread| {
            let thread = worker_thread.thread.take().unwrap();
            let finished = thread.is_finished();
            if finished {
                thread.join();
            }
            else {
                worker_thread.thread.insert(thread);
            }
            !finished
        });

        // Re-scan devices
        let devices: Vec<Device> = Device::list().unwrap()
            .into_iter()
            .filter(|dev| {
                // We want only devices with IPv4 address
                !dev.addresses.is_empty() &&
                matches!(dev.addresses[0].addr, IpAddr::V4(_)) &&
                if veth_only {dev.name.starts_with("veth")} else {true}
            })
            .collect();
        
        // Spawn the worker threads from devices. If corresponding worker is still
        // running, skip it.
        for dev in devices.into_iter() {
            if let Some(_) = workers.iter().find(|worker| worker.ip == dev.addresses[0].addr) {
                continue;
            }

            let out_handle = DeviceHandle::new(&dev.name, 10, false);
            if matches!(out_handle, Err(_)) {
                continue;
            }
            let out_handle = out_handle.unwrap();

            if let IpAddr::V4(worker_ip) = dev.addresses[0].addr {
                if worker_ip.is_unspecified() || worker_ip.is_loopback() {
                    continue;
                }

                // Spawn the worker thread.
                // * It captures ingoing packets on the device; packets with mismatching mac
                //   addresses are discarded
                // * NDPs are sent to the main thread for information gathering
                // * LSPs are are recognized and sent to the LS thread
                // * The rest are normal IP packets. Those with matching IP are sent to user interface
                //   for reception; others are sent to the main thread to be routed.
                let thread = {
                    // Clone the tx ends
                    let mt_tx = mt_tx.clone();
                    let usr_tx = usr_tx.clone();
                    let ls_tx = ls_tx.clone();
                    thread::spawn(move || {
                        // Obtain the handle
                        let handle = DeviceHandle::new(&dev.name, 10, false);
                        if matches!(handle, Err(_)) {
                            return;
                        }
                        let mut handle = handle.unwrap();
                        // Important: as we use separate handles for sending and receiving
                        // packets, the receiving handle should only accept ingoing packets.
                        if matches!(handle.direction(Direction::In), Err(_)) {
                            return;
                        }
        
                        // Discard packets with wrong mac address
                        let mac_addr = handle.mac_address().clone();
                        handle.set_callback(Box::new(move |packet, dst_mac_addr| {
                            if dst_mac_addr.bytes() == [0xffu8; 6] || dst_mac_addr.eq(&mac_addr) {
                                Some(packet)
                            }
                            else {
                                None
                            }
                        }));
        
                        // Work
                        loop {
                            let packet = handle.next_packet();
                            if let Err(e) = &packet {
                                // Worker threads seem to report this; neglect it.
                                if matches!(e, PError::TimeoutExpired) {
                                    continue
                                }
                                println!("worker error: {}", e);
                            }
                            if let Some(packet) = packet.unwrap() {
                                if let Ok(parsed_packet) = packet.parse_eth(false) {
                                    
                                    // NDPs
                                    if matches!(parsed_packet.ethtype(), EtherType::NDP) {
                                        if let Ok(mut ndp) = NDPacket::parse(parsed_packet.data(), worker_ip) {
                                            // If the NDP is sent with broadcast mac address, echo back
                                            if [0xffu8; 6].eq(parsed_packet.dst_addr()) {
                                                let payload = [
                                                    worker_ip.octets().as_ref(),
                                                    handle.mac_address().bytes().as_ref(),
                                                    ndp.timestamp.to_be_bytes().as_ref(),].concat();
                                                handle.send_packet(
                                                    payload.as_slice(), 
                                                    EtherType::NDP, 
                                                    &(ndp.mac.bytes()),
                                                    false);
                                            }
                                            // Else, NDP is echoed from a neighbor; send to main thread 
                                            // for information gathering.
                                            else {
                                                let elapsed = Utc::now().timestamp_micros() - ndp.timestamp;
                                                let cost = if elapsed < 0 {0u32} else {elapsed as u32 / 2};
                                                ndp.timestamp = cost as i64;
                                                mt_tx.send(RipPacket::NDP(ndp));
                                            }
                                        }
                                        continue;
                                    }

                                    if !matches!(parsed_packet.ethtype(), EtherType::IPv4) {
                                        continue;
                                    }

                                    let ip_packet = 
                                        Ipv4Packet::parse(parsed_packet.data(), worker_ip);
                                    if matches!(ip_packet, Err(_)) {
                                        continue;
                                    }
                                    let ip_packet = ip_packet.unwrap();
                                    // Fragmented packets are dropped for now
                                    if ip_packet.hdr.mf || ip_packet.hdr.frag_ofs != 0 {
                                        continue;
                                    }

                                    // LSP to the LS thread
                                    if matches!(ip_packet.hdr.proto, IpProtoType::LSP) 
                                        && ip_packet.hdr.dst_ip.is_broadcast()
                                    {
                                        let payload_len = ip_packet.hdr.tot_len - ip_packet.hdr.hdr_len as u16*4;
                                        let lsp = 
                                            LinkStatePacket::parse(&ip_packet.data[..payload_len as usize], worker_ip);
                                        if matches!(lsp, Err(_)) {
                                            continue;
                                        }
                                        let lsp = lsp.unwrap();
                                        ls_tx.send(lsp);
                                        continue;
                                    }

                                    // Matched IP to the user
                                    if ip_packet.hdr.dst_ip.is_broadcast()
                                        || ip_packet.hdr.dst_ip == worker_ip 
                                    {
                                        usr_tx.send(ip_packet);
                                        continue;
                                    }

                                    // Mismatched IP to the main thread
                                    mt_tx.send(RipPacket::IPv4(ip_packet));
                                }
                            }
                        }
                    })
                };

                workers.push(WorkerThread{
                    ip: worker_ip,
                    out_handle,
                    thread: Some(thread),
                })
            }
        }
    }
}

/// A worker thread that captures packets on Devices.
struct WorkerThread {
    pub ip: Ipv4Addr,
    /// Handle for sending packets to the device
    pub out_handle: DeviceHandle,
    /// The running thread
    pub thread: Option<thread::JoinHandle<()>>,
}


