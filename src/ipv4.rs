#![allow(dead_code)]
#![allow(unused)]

pub mod ipv4 {

    use std::net::Ipv4Addr;
    use crate::RipError;
    use std::convert::TryInto;
    use std::fmt;

    /// IPv4 packet header format.
    #[derive(Debug)]
    pub struct Ipv4Header {
        pub version: u8,
        pub hdr_len: u8,
        pub tos: u8,
        pub tot_len: u16,
        pub id: u16,
        /// Don't fragment Bit
        pub df: bool,
        /// More fragment Bit
        pub mf: bool,
        pub frag_ofs: u16,
        pub ttl: u8,
        /// Type of protocol in the datagram
        pub proto: IpProtoType,
        pub checksum: u16,

        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        /// Extra header bytes
        pub options: [u8;40],
    }

    impl Ipv4Header {
        pub fn to_bytes(&self, src_ip: &Ipv4Addr) -> Vec<u8> {
            let src_ip_bytes = if self.src_ip.is_unspecified() {src_ip.octets()} else {self.src_ip.octets()};
            [
                &[(self.version << 4) | self.hdr_len],
                &[self.tos],
                self.tot_len.to_be_bytes().as_ref(),
                self.id.to_be_bytes().as_ref(),
                &[((self.df as u8) << 6) | ((self.mf as u8) << 5) | (((self.frag_ofs & 0xFF00)>>4) as u8)], 
                &[(self.frag_ofs & 0xFF) as u8],
                &[self.ttl],
                &[self.proto.into()],
                self.checksum.to_be_bytes().as_ref(),
                src_ip_bytes.as_ref(),
                self.dst_ip.octets().as_ref(),
                self.options[..(self.hdr_len as usize *4-20)].as_ref(),
            ].concat()
        }
    }

    impl fmt::Display for Ipv4Header {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "version: {}\thdr len: {}\n", self.version, self.hdr_len);
            write!(f, "total len: {}\n", self.tot_len);
            // Fragmentation related fields ommited
            write!(f, "ttl: {}\n", self.ttl);
            write!(f, "protocol: {}\n", self.proto);
            write!(f, "src IP: {}\ndst IP: {}\n", self.src_ip, self.dst_ip);
            // `option` omitted
            Ok(())
        }
    }

    /// An IPv4 packet.
    #[derive(Debug)]
    pub struct Ipv4Packet {
        pub hdr: Ipv4Header,
        pub data: Vec<u8>,
        /// The IP of the device that received the packet, useful in routing.
        pub rx_ip: Ipv4Addr,
    }

    impl fmt::Display for Ipv4Packet {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "============ Hdr ============\n");
            write!(f, "{}", self.hdr);
            write!(f, "received at {}\n", self.rx_ip);
            write!(f, "============ Data ===========\n");
            self.data[..self.hdr.tot_len as usize - self.hdr.hdr_len as usize*4]
                .iter()
                .enumerate()
                .for_each(|(idx, byte)| {
                    write!(f, "{:02X} ", *byte);
                    if idx % 12 == 5 {
                        write!(f, " ");
                    }
                    if idx % 12 == 11 {
                        write!(f, "\n");
                    }
                }
            );
            Ok(())
        }
    }

    impl Ipv4Packet {
        pub fn parse(packet: &[u8], rx_ip: Ipv4Addr) -> Result<Ipv4Packet, RipError> {
            // IPv4 packets have a mandatory 20 byte header.
            if packet.len() < 20 {
                return Err(RipError::InvalidIpv4Packet);
            }

            // Check if hdr_len is appropriate
            let hdr_len = packet[0] & 0xF;
            if hdr_len < 5 || hdr_len > 15 || hdr_len as usize * 4 > packet.len() {
                return Err(RipError::InvalidIpv4Packet);
            }

            // Check if tot_len is appropriate
            let tot_len = u16::from_be_bytes(packet[2..4].try_into().unwrap());
            if tot_len as usize > packet.len() {
                return Err(RipError::InvalidIpv4Packet);
            }

            // Checksum is NOT checked

            let mut options = [0u8; 40];
            let len = (hdr_len as usize)*4 - 20;
            options[..len].copy_from_slice(&packet[20..20+len]);
            // Valid IPv4 packet 
            Ok(Ipv4Packet {
                hdr: Ipv4Header {
                    version: (packet[0] & 0xF0) >> 4,
                    hdr_len,
                    tos: packet[1],
                    tot_len,
                    id: u16::from_be_bytes(packet[4..6].try_into().unwrap()),
                    df: (packet[6] & 0x40) != 0,
                    mf: (packet[6] & 0x20) != 0,
                    frag_ofs: ((packet[6] as u16 & 0x1F)<<8) + packet[7] as u16,
                    ttl: packet[8],
                    proto: packet[9].into(),
                    checksum: u16::from_be_bytes(packet[10..12].try_into().unwrap()),
                    src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
                    dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
                    options,
                },
                data: packet[(hdr_len as usize)*4..].to_vec(),
                rx_ip,

            })
        }
    }

    #[derive(Clone, Debug, Copy, PartialEq)]
    pub enum IpProtoType {
        ICMP,
        IGMP,
        TCP,
        UDP,
        DCCP,
        /// Link State Protocol, part of Rip implementation
        LSP,
        UNKNOWN(u8),
    }
    
    use super::ipv4::IpProtoType::*;
    impl std::fmt::Display for IpProtoType {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match *self {
                ICMP => write!(f, "Internet Control Message Protocol"),
                IGMP => write!(f, "Internet Group Management Protocol"),
                TCP => write!(f, "Transmission Control Protocol"),
                UDP => write!(f, "User Datagram Protocol"),
                DCCP => write!(f, "Datagram Congestion Control Protocol"),
                LSP => write!(f, "Rip Link State Protocol"),
                UNKNOWN(v) => write!(f, "Unknown Protocol ({})", v),
            }
        }
    }
    
    use std::convert::From;
    impl From<u8> for IpProtoType {
        fn from(value: u8) -> Self {
            match value {
                0x1 => ICMP,
                0x2 => IGMP,
                0x6 => TCP,
                0x11 => UDP,
                0x21 => DCCP,
                0xFE => LSP,
                _ => UNKNOWN(value),
            }
        }
    }

    impl From<IpProtoType> for u8 {
        fn from(ethtype: IpProtoType) -> Self {
            match ethtype {
                ICMP => 0x1,
                IGMP => 0x2,
                TCP => 0x6,
                UDP => 0x11,
                DCCP => 0x21,
                LSP => 0xFE,
                UNKNOWN(value) => value,
            }
        }
    }

}