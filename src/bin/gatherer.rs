#![allow(dead_code)]
#![allow(unused)]

//! Multi-thread to gather packets from multiple devices.

use rlink::{DeviceHandle, EtherType, DevicePool, Packet};
use rip::{Ipv4Packet, IpProtoType};
use std::env;
use std::net::Ipv4Addr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: gatherer [dev name..]\n");
        return;
    }

    let pool = DevicePool::new(
        args[1..].iter().map(|s| s.clone()).collect(),
        50
    ).unwrap();


    loop {
        let packet = pool.select().unwrap();
        let parsed_packet = packet.parse_eth(false).unwrap();
        if matches!(parsed_packet.ethtype(), EtherType::IPv4) {
            if let Ok(ip_packet) = Ipv4Packet::parse(parsed_packet.data(), Ipv4Addr::UNSPECIFIED) {
                if !matches!(ip_packet.hdr.proto, IpProtoType::LSP) {
                    // We want only the IPv4 data packets
                    println!("{}", ip_packet);
                }
            }
        }
    }
}
