use nfq::Verdict;
use std::net::IpAddr;

use super::packet::TrafficPacket;

pub struct Rule {
    pub app_path: Option<String>,
    pub address: Option<IpAddr>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub verdict: Verdict,
}

impl Rule {
    pub fn applies_to(&self, packet: &TrafficPacket) -> bool {
        if packet.exe.is_some() && self.app_path.is_some() && self.app_path.ne(&packet.exe) {
            false
        } else if self.address.is_some() && self.address.unwrap().ne(&packet.dest_addr.ip()) {
            false
        } else if self.port.is_some() && self.port.unwrap().ne(&packet.dest_addr.port()) {
            false
        } else if self.protocol.is_some() && self.protocol.as_ref().unwrap().ne(&packet.protocol) {
            false
        } else {
            true
        }
    }

    pub fn get_verdict(&self) -> Verdict {
        self.verdict.clone()
    }
}

#[derive(Default)]
pub struct Rules(Vec<Rule>);

impl Rules {
    pub fn add(&mut self, rule: Rule) {
        self.0.push(rule)
    }

    pub fn get_verdict(&self, packet: &TrafficPacket) -> Option<Verdict> {
        if packet.exe.is_none() {
            return Some(Verdict::Drop);
        }
        for rule in &self.0 {
            if rule.applies_to(&packet) {
                return Some(rule.get_verdict());
            }
        }
        None
    }
}
