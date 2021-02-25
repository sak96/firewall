mod dns;
mod packet;

use dns::DnsCache;
use nfq::{Queue, Verdict};
use packet::TrafficPacket;
use std::process::Command;

const IPTABLES_RULES: [&str; 3] = [
    // Get DNS responses
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass",
    // Get connection packets
    "OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass",
    // Reject packets marked
    "OUTPUT --protocol tcp -m mark --mark 1 -j REJECT",
];

#[derive(Default)]
pub struct AppWall {
    dns: DnsCache,
}

impl AppWall {
    pub fn start() {
        for rule in IPTABLES_RULES.iter() {
            debug!("executing: iptables -I {}", rule);
            Command::new("iptables")
                .args(std::iter::once("-I").chain(rule.split_whitespace()))
                .output()
                .unwrap();
            debug!("executing: iptables6 -I {}", rule);
            Command::new("ip6tables")
                .args(std::iter::once("-I").chain(rule.split_whitespace()))
                .output()
                .unwrap();
        }
    }

    pub fn run(&mut self) -> std::io::Result<()> {
        let mut queue = Queue::open().unwrap();
        queue.bind(0)?;
        loop {
            let verdict = Verdict::Accept;
            let mut msg = queue.recv()?;
            msg.get_payload();
            let payload = msg.get_payload();
            match TrafficPacket::from(payload) {
                Err(msg) => warn!("error {} occurred while parsing: {:#?}", msg, payload),
                Ok(mut pkt) => {
                    if pkt.dns_data.is_empty() {
                        let dest = if let Some(hostname) = self.dns.get(pkt.dest_addr) {
                            hostname.get(0).unwrap().to_string()
                        } else {
                            pkt.dest_addr.to_string()
                        };
                        info!(
                            "{} connection by '{}' to '{}:{}'",
                            pkt.protocol,
                            pkt.get_process_name().unwrap_or("unknown".into()),
                            dest,
                            pkt.dest_port,
                        );
                    } else {
                        for (hostname, ip) in pkt.dns_data.drain(..) {
                            info!("hostname '{}' maps to '{}'", hostname, ip);
                            self.dns.add(ip, hostname);
                        }
                    }
                }
            }
            msg.set_verdict(verdict);
            queue.verdict(msg)?;
            if false {
                break;
            }
        }
        Ok(())
    }

    pub fn stop() {
        for rule in IPTABLES_RULES.iter() {
            debug!("executing: iptables -D {}", rule);
            Command::new("iptables")
                .args(std::iter::once("-D").chain(rule.split_whitespace()))
                .output()
                .unwrap();
            debug!("executing: iptables6 -D {}", rule);
            Command::new("ip6tables")
                .args(std::iter::once("-D").chain(rule.split_whitespace()))
                .output()
                .unwrap();
        }
    }
}
