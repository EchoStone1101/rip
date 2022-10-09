#![allow(dead_code)]
#![allow(unused)]

//! Activate Rip library

use rip::{RipCtl, RoutingRule, RoutingRuleKey, RoutingRuleValue, IPorMAC, MacAddress};
use std::net::Ipv4Addr;
use std::io;
use std::env;

fn main() {
    let mut ctl = RipCtl::init(true);

    let mut args = env::args();
    args.next();
    match args.next() {
        None => {
            // let mut guard = ctl.get_config_handle().lock().unwrap();
            // guard.push(RoutingRule{
            //     key: RoutingRuleKey::new(Ipv4Addr::new(10, 100, 3, 0), 24),
            //     value: RoutingRuleValue{
            //         choices: vec![(Ipv4Addr::new(10,100,2,1), IPorMAC::Mac(MacAddress::new([0xff,0xff,0xff,0xff,0xff,0xff])))]
            //     }
            // });
            // drop(guard);
            
            loop {// Run Rip in the background
            }
        }, 
        Some(s) => {
            if s.eq("recv") {

                // Receive packets
                // let mut guard = ctl.get_config_handle().lock().unwrap();
                // guard.push(RoutingRule{
                //     key: RoutingRuleKey::new(Ipv4Addr::new(10,100,3,0), 24),
                //     value: RoutingRuleValue{
                //         choices: vec![(Ipv4Addr::new(10,100,3,1), IPorMAC::Mac(MacAddress::new([0xff,0xff,0xff,0xff,0xff,0xff])))]
                //     }
                // });
                // drop(guard);

                loop {
                    let packet = ctl.next_ipv4_packet();
                    println!("{}", packet);
                    let msg = String::from_utf8(packet.data).unwrap();
                    println!("{}", msg);
                }
            }
            if s.eq("send") {

                // let mut guard = ctl.get_config_handle().lock().unwrap();
                // guard.push(RoutingRule{
                //     key: RoutingRuleKey::new(Ipv4Addr::new(10, 100, 3, 0), 24),
                //     value: RoutingRuleValue{
                //         choices: vec![(Ipv4Addr::new(10,100,1,1), IPorMAC::Mac(MacAddress::new([0xff,0xff,0xff,0xff,0xff,0xff])))]
                //     }
                // });
                // drop(guard);

                // Send packets
                let data = "Across the Great Wall we can reach every corner in the world.".as_bytes();
                loop {
                    let mut line = String::new();
                    io::stdin().read_line(&mut line).unwrap();
                    let line = line.trim();

                    let bytes = line.split(".").map(|b| b.parse::<u8>().unwrap()).collect::<Vec<_>>();
                    if bytes.len() != 4 {
                        println!("invalid IP");
                        continue;
                    }

                    let dst_ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    ctl.send_ipv4_packet(dst_ip, data);
                }
            }
        }
    }
    
}