use dns_parser::{rdata, Packet as DnsPacket, RData};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use glob::glob;
use std::{
    fs::{read_link, File},
    io::{BufRead, BufReader},
    net::IpAddr,
    result::Result,
};

#[derive(Debug)]
pub struct TrafficPacket {
    pub dest_addr: IpAddr,
    pub dest_port: u16,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub protocol: &'static str,
    pub dns_data: Vec<(String, IpAddr)>,
}

impl TrafficPacket {
    const FILE_DESCRIPTOR_GLOB: &'static str = "/proc/[0-9]*/fd/[0-9]*";

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

    fn get_ips_from_packet(pkt: &SlicedPacket) -> Result<(IpAddr, IpAddr), String> {
        match &pkt.ip {
            Some(InternetSlice::Ipv4(ip)) => Ok((
                IpAddr::V4(ip.source_addr()),
                IpAddr::V4(ip.destination_addr()),
            )),
            Some(InternetSlice::Ipv6(ip, _)) => Ok((
                IpAddr::V6(ip.source_addr()),
                IpAddr::V6(ip.destination_addr()),
            )),
            None => {
                return Err("could not parse ip layer".into());
            }
        }
    }

    fn get_ports_from_packet(pkt: &SlicedPacket) -> Result<(u16, u16, &'static str), String> {
        match &pkt.transport {
            Some(TransportSlice::Udp(udp)) => {
                Ok((udp.source_port(), udp.destination_port(), "udp"))
            }
            Some(TransportSlice::Tcp(tcp)) => {
                Ok((tcp.source_port(), tcp.destination_port(), "tcp"))
            }
            None => {
                return Err("could not parse transport layer".into());
            }
        }
    }

    pub fn from(packet: &[u8]) -> Result<Self, String> {
        match SlicedPacket::from_ip(packet) {
            Ok(pkt) => {
                let (src_addr, dest_addr) = Self::get_ips_from_packet(&pkt)?;
                let (src_port, dest_port, protocol) = Self::get_ports_from_packet(&pkt)?;
                let dns_data = Self::parse_dns(pkt.payload);
                Ok(Self {
                    dest_addr,
                    dest_port,
                    src_addr,
                    src_port,
                    protocol,
                    dns_data,
                })
            }
            Err(msg) => {
                return Err(format!("failed to parse packet {}", msg));
            }
        }
    }

    fn ip_to_string(ip: IpAddr) -> String {
        match &ip {
            IpAddr::V4(ipv4) => ipv4
                .octets()
                .iter()
                .rev()
                .fold(String::new(), |string, &oct| {
                    format!("{}{:02X?}", string, oct)
                }),
            IpAddr::V6(ipv6) => ipv6
                .octets()
                .chunks(4)
                .map(|a| a.iter().rev())
                .flatten()
                .fold(String::new(), |string, &oct| {
                    format!("{}{:02X?}", string, oct)
                }),
        }
    }

    fn to_proc_net_text(&self) -> String {
        format!(
            "{}:{:04X?} {}:{:04X?}",
            Self::ip_to_string(self.src_addr),
            self.src_port,
            Self::ip_to_string(self.dest_addr),
            self.dest_port,
        )
    }

    fn get_pid_of_inode(inode: &str) -> Option<u32> {
        let link_name = format!("socket:[{}]", inode);
        for entry in glob(Self::FILE_DESCRIPTOR_GLOB).ok()? {
            if let Ok(path) = entry {
                if let Ok(path_buf) = path.read_link() {
                    if path_buf.to_str()? == link_name.as_str() {
                        return path.iter().nth(2)?.to_str()?.parse().ok();
                    }
                }
            }
        }
        None
    }

    pub fn get_process_name(&self) -> Option<String> {
        let filename = if matches!(self.dest_addr, IpAddr::V6(_)) {
            format!("/proc/net/{}6", self.protocol)
        } else {
            format!("/proc/net/{}", self.protocol)
        };

        let proc_next_text = self.to_proc_net_text();
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);
        for io_line in reader.lines() {
            let line = io_line.unwrap();
            let content = line.trim_start().splitn(2, " ").last()?;
            if content.starts_with(&proc_next_text) {
                let inode = line.trim_start().split_whitespace().nth(9).unwrap();
                if let Some(pid) = Self::get_pid_of_inode(inode) {
                    return Some(if let Ok(path) = read_link(format!("/proc/{}/exe", pid)) {
                        if let Some(name) = path.to_str() {
                            name.to_string()
                        } else {
                            pid.to_string()
                        }
                    } else {
                        pid.to_string()
                    });
                }
            }
        }
        None
    }
}
