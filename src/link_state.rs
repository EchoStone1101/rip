#![allow(dead_code)]
#![allow(unused)]

pub mod link_state {

    use std::net::{IpAddr, Ipv4Addr};
    use crate::{RipError, Ipv4Packet, Ipv4Header, IpProtoType, RipCtl, RoutingTable, IPorMAC};
    use std::collections::{HashMap, BinaryHeap};
    use std::fmt;
    use std::convert::TryInto;


    /// A link, identified by IP of both ends
    #[derive(Debug, Eq, PartialEq, Hash)]
    pub struct Link {
        pub from: IpAddr,
        pub to: IpAddr,
    }

    /// A link-state packet
    pub struct LinkStatePacket {
        /// Node consists of multiple IPs
        pub node: Vec<IpAddr>,
        /// Edges are a set of weighted links
        pub edges: HashMap<Link, u32>,
        /// ID of the source of this LSP; the maximum of node IP is used
        pub id: u128,
        /// Sequence number to help with flooding
        pub version: u64,
        /// The IP of the device that received the packet. Unspecified value
        /// means the packet is locally built from the main thread.
        pub rx_ip: Ipv4Addr,
    }

    impl fmt::Display for LinkStatePacket {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}\n", self.node);
            for (link, cost) in &self.edges {
                write!(f, "{:?}({}), ", link, cost);
            }
            Ok(())
        }
    }

    impl LinkStatePacket {

        /// Returns an empty node
        pub fn new(version: u64) -> Self {
            LinkStatePacket {
                node: Vec::new(),
                edges: HashMap::new(),
                id: 0u128,
                version,
                rx_ip: Ipv4Addr::UNSPECIFIED,
            }
        }

        /// Adds a new weighted link to the node. Newer cost is adapted,
        /// if collision occurs.
        pub fn add(&mut self, from: IpAddr, to: IpAddr, cost: u32) {
            if !self.node.contains(&from) {
                self.node.push(from);
            }
            self.edges.insert(Link{from, to}, cost);
            
            match from {
                IpAddr::V4(ip) => {
                    let id =  u32::from_be_bytes(ip.octets()) as u128;
                    if id > self.id {
                        self.id = id;
                    }
                }
                IpAddr::V6(ip) => {
                    let id =  u128::from_be_bytes(ip.octets());
                    if id > self.id {
                        self.id = id;
                    }
                }
            }
        }

        /// Parse from an actual Link State packet received on wire.
        pub fn parse(data: &[u8], rx_ip: Ipv4Addr) -> Result<LinkStatePacket, RipError>{
            // An LSP buffer is formatted as:
            // ------------------------
            // version: 8   bytes
            // edges:   12  bytes (multiple)
            // (from, to, cost)
            // ------------------------

            if (data.len() < 8 || (data.len()-8) % 12 != 0) {
                return Err(RipError::InvalidLSP);
            }

            let version = u64::from_be_bytes(data[..8].try_into().unwrap());
            let mut lsp = LinkStatePacket::new(version);
            lsp.rx_ip = rx_ip;

            let mut cur: usize = 8;
            while cur < data.len() {
                let from = Ipv4Addr::new(data[cur], data[cur + 1], data[cur + 2], data[cur + 3]);
                let to = Ipv4Addr::new(data[cur + 4], data[cur + 5], data[cur + 6], data[cur + 7]);
                let cost = u32::from_be_bytes(data[cur+8..cur+12].try_into().unwrap());
                lsp.add(IpAddr::V4(from), IpAddr::V4(to), cost);
                cur += 12;
            }

            Ok(lsp)  
        }

        /// Format this LSP as IPv4 packet, for flooding.
        pub fn as_ipv4_packet(&self) -> Result<Ipv4Packet, RipError> {

            let mut data = Vec::with_capacity(8 + 12*self.edges.len());
            data.extend_from_slice(&self.version.to_be_bytes());
            for (Link{from, to}, cost) in self.edges.iter() {
                if let IpAddr::V4(from) = from {
                    data.extend_from_slice(&from.octets());
                }
                if let IpAddr::V4(to) = to {
                    data.extend_from_slice(&to.octets());
                }
                data.extend_from_slice(&cost.to_be_bytes());
            }
            if data.len() + 20 > 65535 {
                return Err(RipError::LSPTooLarge);
            }
            let tot_len = 20 + data.len() as u16;

            Ok(Ipv4Packet {
                hdr: Ipv4Header {
                    version: 4,
                    hdr_len: 5,     // Default header length
                    tos: 0,         // Default TOS
                    tot_len,
                    id: 0,          // Fragmenation not supported
                    df: true,
                    mf: false,
                    frag_ofs: 0,
                    ttl: RipCtl::RIP_TTL,
                    proto: IpProtoType::LSP,
                    checksum: 0,    // checksum ommited
                    src_ip: Ipv4Addr::UNSPECIFIED,
                    dst_ip: Ipv4Addr::BROADCAST,
                    options: [0u8; 40],
                },
                rx_ip: self.rx_ip,
                data,
            })
        }
    }


    /// Node version of an LSP. Besides the owned data of an LSP, LSN are further
    /// checked for expiration.
    pub struct LinkStateNode {
        /// Owned data of an LSP
        pub lsp: LinkStatePacket,
        /// Birth time of this LSN. LSNs will expire.
        /// This timestamp if retrieved via Utc::timestamp_micros().
        pub birth: i64,
    }

    /// Utility struct for Dijksta Algorithm
    struct HeapNode {
        cur_ip: IpAddr,
        pre_ip: IpAddr,
        dist: u32,
    }
    impl PartialEq for HeapNode {
        fn eq(&self, other: &HeapNode) -> bool {
            self.dist == other.dist
        }
    }
    impl Eq for HeapNode {}
    impl PartialOrd for HeapNode {
        fn partial_cmp(&self, other: &HeapNode) -> Option<std::cmp::Ordering> {
            self.dist.partial_cmp(&other.dist).and_then(|o| Some(o.reverse()))
        }
    }
    impl Ord for HeapNode {
        fn cmp(&self, other: &HeapNode) -> std::cmp::Ordering {
            self.dist.cmp(&other.dist).reverse()
        }
    }

    impl LinkStateNode {

        /// Rebuild the graph implied by the given nodes, their `neighbors` field
        /// reconfigured. Nodes should be unique in terms of no IP conflictions.
        /// Shortest routing paths are then calculated on the new graph, generating
        /// new routing rules. 
        pub fn reroute(nodes: &mut Vec<LinkStateNode>, routing_table: &mut RoutingTable) {

            assert!(!nodes.is_empty());

            // Rebuild the graph by mapping from IP to index in the list
            let mut root_idx = 0;
            let mut ip2idx = HashMap::<IpAddr, usize>::new();
            for (idx, node) in nodes.iter().enumerate() {
                for ip in node.lsp.node.iter() {
                    ip2idx.insert(*ip, idx);
                }
                if node.lsp.rx_ip.is_unspecified() {
                    root_idx = idx;
                }
            }
            
            // If root node is empty, skip
            if nodes[root_idx].lsp.node.is_empty() {
                return;
            }

            // Run Dijkstra for the shortest path
            let mut dist = vec![None; nodes.len()];
            // let mut dangling_ip_map: HashMap<IpAddr, (u32, IpAddr)> = HashMap::new();
            let mut how_to = HashMap::new();

            let mut queue = BinaryHeap::<HeapNode>::new();
            queue.push(HeapNode{
                cur_ip: *nodes[root_idx].lsp.node.first().unwrap(),
                pre_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dist: 0,
            });
            // IPs in the root node are routed to themselves
            for ip in nodes[root_idx].lsp.node.iter() {
                how_to.insert(*ip, (*ip, *ip));
            }

            while !queue.is_empty() {
                let HeapNode { cur_ip, pre_ip, dist: d} = queue.pop().unwrap();
                let &cur = ip2idx.get(&cur_ip).unwrap();

                if let Some(_) = dist[cur] {
                    continue;
                }

                if !pre_ip.is_unspecified() {
                    if *ip2idx.get(&pre_ip).unwrap() == root_idx {
                        // IPs in the direct neighbor are routed via `pre_ip`,
                        // received at `cur_ip`
                        for ip in nodes[cur].lsp.node.iter() {
                            how_to.insert(*ip, (pre_ip, cur_ip));
                        }
                    }
                    else {
                        // IPs in farther nodes have `pre_ip` recorded in `how_to`.
                        // They share the same (via, recv) setting with `pre_ip`.
                        let &(via, recv) = how_to.get(&pre_ip).unwrap();
                        for ip in nodes[cur].lsp.node.iter() {
                            how_to.insert(*ip, (via, recv));
                        }
                    }
                }
                dist[cur].insert(d);

                for (Link{from, to}, &cost) in nodes[cur].lsp.edges.iter() {
                    if let Some(&nxt) =  ip2idx.get(to) {
                        if matches!(dist[nxt], None) {
                            queue.push(HeapNode{
                                cur_ip: *to,
                                pre_ip: *from,
                                dist: u32::saturating_add(d, cost),
                            });
                        }
                    }
                }
            }

            // Show the calculated distances
            // print!("{esc}c", esc = 27 as char);
            // for (idx, d) in dist.iter().enumerate() {
            //     print!("{:?}: ", nodes[idx].lsp.node);
            //     println!("{:?}", dist[idx]);
            // }
                            
            for (ip, (via, recv)) in how_to.iter() {
                if let (IpAddr::V4(ip), IpAddr::V4(via), IpAddr::V4(recv)) = (ip, via, recv) {
                    routing_table.add_to_shadow_table(*ip, vec![(*via, IPorMAC::IPv4(*recv))]);
                }
            }

            // The routing table is flipped.
            routing_table.flip();

            // for (idx, d) in dist.iter().enumerate() {
            //     println!("dist[{}]: {}", idx, if let Some(d) = d {d.to_string()} else {String::from("unreachable")});
            // }
        }

    }

}