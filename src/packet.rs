use dns_parser::{rdata, Packet as DnsPacket, RData};
use etherparse::{InternetSlice, SlicedPacket};
use std::{net::IpAddr, result::Result};

pub struct TrafficPacket {
    pub dest_addr: IpAddr,
    pub dns_data: Vec<(String, IpAddr)>,
}

impl TrafficPacket {
    /// Parse Dns response from transport layer payload
    fn parse_dns(payload: &[u8]) -> Vec<(String, IpAddr)> {
        let mut dns_data = vec![];
        if let Ok(packet) = DnsPacket::parse(payload) {
            for response in packet.answers {
                let hostname = response.name.to_string();
                if hostname == "." {
                    continue;
                }
                let hostname = hostname.trim_end_matches(".");
                match response.data {
                    RData::A(rdata::a::Record(ip)) => {
                        dns_data.push((hostname.into(), IpAddr::V4(ip)));
                    }
                    RData::AAAA(rdata::aaaa::Record(ip)) => {
                        dns_data.push((hostname.into(), IpAddr::V6(ip)));
                    }
                    _ => {}
                }
            }
        }
        dns_data
    }

    pub fn from(packet: &[u8]) -> Result<Self, String> {
        match SlicedPacket::from_ip(packet) {
            Ok(pkt) => {
                let dest_addr = match pkt.ip {
                    Some(InternetSlice::Ipv4(ip)) => IpAddr::V4(ip.destination_addr()),
                    Some(InternetSlice::Ipv6(ip, _)) => IpAddr::V6(ip.destination_addr()),
                    None => {
                        return Err("could not parse ip layer".into());
                    }
                };
                let dns_data = Self::parse_dns(pkt.payload);
                Ok(Self {
                    dest_addr,
                    dns_data,
                })
            }
            Err(msg) => {
                return Err(format!("failed to parse packet {}", msg));
            }
        }
    }
}
