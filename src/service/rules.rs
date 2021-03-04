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
        (self.app_path.is_none() || packet.exe.is_none() || self.app_path.eq(&packet.exe))
            && (self.address.is_none() || self.address.unwrap().eq(&packet.dest_addr.ip()))
            && (self.port.is_some() || self.port.unwrap().eq(&packet.dest_addr.port()))
            && (self.protocol.is_some() || self.protocol.as_ref().unwrap().eq(&packet.protocol))
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
        for rule in &self.0 {
            if rule.applies_to(&packet) {
                return Some(rule.get_verdict());
            }
        }
        None
    }
}
