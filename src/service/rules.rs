use nfq::Verdict;
use std::{net::IpAddr, str::FromStr};

use super::packet::TrafficPacket;

#[derive(Debug)]
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

const INSUFFICIENT_SPLITS: &'static str = "insufficient splits";
const IP_ADDR_PARSE_FAILED: &'static str = "ip address parse failed";
const PORT_PARSE_FAILED: &'static str = "port parse failed";

impl FromStr for Rule {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = s.split(",");

        let app_path = p.next().ok_or(INSUFFICIENT_SPLITS)?.trim();
        let app_path = if app_path.is_empty() {
            None
        } else {
            Some(app_path.to_string())
        };

        let address = p.next().ok_or(INSUFFICIENT_SPLITS)?.trim();
        let address = if address.is_empty() {
            None
        } else {
            Some(
                address
                    .parse::<IpAddr>()
                    .map_err(|_| IP_ADDR_PARSE_FAILED)?,
            )
        };

        let port = p.next().ok_or(INSUFFICIENT_SPLITS)?.trim();
        let port = if port.is_empty() {
            None
        } else {
            Some(port.parse::<u16>().map_err(|_| PORT_PARSE_FAILED)?)
        };

        let protocol = p.next().ok_or(INSUFFICIENT_SPLITS)?.trim();
        let protocol = if protocol.is_empty() {
            None
        } else {
            Some(protocol.to_string())
        };

        let verdict = p.next().ok_or(INSUFFICIENT_SPLITS)?.trim();
        let verdict = if verdict.to_lowercase().eq("accept") {
            Verdict::Accept
        } else {
            Verdict::Drop
        };
        Ok(Self {
            app_path,
            address,
            port,
            protocol,
            verdict,
        })
    }
}

#[derive(Default, Debug)]
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

    pub fn from_text(rules: &[String]) -> Self {
        let rules = rules
            .iter()
            .filter_map(|r| {
                r.parse::<Rule>()
                    .map_err(|err| {
                        warn!("{}: failed to parse rule {}", err, r);
                        err
                    })
                    .ok()
            })
            .collect();
        Self { 0: rules }
    }
}
