use dns_parser::{rdata, Packet as DnsPacket, RData};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use glob::glob;
use std::{
    fs::{read_link, File},
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    result::Result,
};

#[derive(Debug)]
pub struct TrafficPacket {
    pub dest_addr: SocketAddr,
    pub src_addr: SocketAddr,
    pub protocol: &'static str,
    pub dns_data: Vec<(String, IpAddr)>,
    pub pid: u32,
    pub exe: Option<String>,
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
                let hostname = hostname.trim_end_matches('.');
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
            None => Err("could not parse ip layer".into()),
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
            None => Err("could not parse transport layer".into()),
        }
    }

    pub fn from(packet: &[u8]) -> Result<Self, String> {
        match SlicedPacket::from_ip(packet) {
            Ok(pkt) => {
                let (src_ip, dest_ip) = Self::get_ips_from_packet(&pkt)?;
                let (src_port, dest_port, protocol) = Self::get_ports_from_packet(&pkt)?;
                let dest_addr = SocketAddr::new(dest_ip, dest_port);
                let src_addr = SocketAddr::new(src_ip, src_port);
                let pid = Self::find_pid(&src_addr, &dest_addr, protocol).unwrap_or(0);
                let exe = Self::find_name_from_pid(pid);

                let dns_data = Self::parse_dns(pkt.payload);
                Ok(Self {
                    dest_addr,
                    src_addr,
                    protocol,
                    dns_data,
                    pid,
                    exe,
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
                .flat_map(|a| a.iter().rev())
                .fold(String::new(), |string, &oct| {
                    format!("{}{:02X?}", string, oct)
                }),
        }
    }

    fn to_proc_net_text(src_addr: &SocketAddr, dest_addr: &SocketAddr) -> String {
        format!(
            "{}:{:04X?} {}:{:04X?}",
            Self::ip_to_string(src_addr.ip()),
            src_addr.port(),
            Self::ip_to_string(dest_addr.ip()),
            dest_addr.port(),
        )
    }

    fn get_pid_of_inode(inode: &str) -> Option<u32> {
        let link_name = format!("socket:[{}]", inode);
        for entry in (glob(Self::FILE_DESCRIPTOR_GLOB).ok()?).flatten() {
            if let Ok(path_buf) = entry.read_link() {
                if path_buf.to_str()? == link_name.as_str() {
                    return path_buf.iter().nth(2)?.to_str()?.parse().ok();
                }
            } else {
                debug!("could not read link for {}", entry.display());
            }
        }
        warn!("could not find socket {}", link_name);
        None
    }

    fn find_name_from_pid(pid: u32) -> Option<String> {
        if let Ok(path) = read_link(format!("/proc/{}/exe", pid)) {
            if let Some(path_str) = match path.file_name() {
                Some(file_name) => file_name.to_str(),
                None => path.to_str(),
            } {
                return Some(path_str.to_string());
            }
        };
        debug!("could get process name for pid '{}'", pid);
        None
    }

    fn find_network_file(protocol: &'static str, is_ipv6: bool) -> &'static str {
        match (protocol, is_ipv6) {
            ("udp", true) => "/proc/net/udp6",
            ("udp", false) => "/proc/net/udp",
            ("tcp", true) => "/proc/net/tcp6",
            ("tcp", false) => "/proc/net/tcp",
            _ => {
                let dummy = "/dev/null";
                warn!(
                    "ipv{} packet with protocol {} using {} to avoid process detection",
                    if is_ipv6 { 4 } else { 6 },
                    protocol,
                    dummy
                );
                dummy
            }
        }
    }

    fn find_pid(
        src_addr: &SocketAddr,
        dest_addr: &SocketAddr,
        protocol: &'static str,
    ) -> Option<u32> {
        let filename = Self::find_network_file(protocol, dest_addr.is_ipv6());
        let proc_net_text = Self::to_proc_net_text(src_addr, dest_addr);
        let file = File::open(filename).unwrap();
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() != 0 {
            let content = line.trim_start().splitn(2, ' ').last()?;
            if content.starts_with(&proc_net_text) {
                let inode = line.trim_start().split_whitespace().nth(9).unwrap();
                let pid = Self::get_pid_of_inode(inode)?;
                return Some(pid);
            }
            line.clear();
        }
        None
    }
}
