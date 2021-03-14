mod dns;
mod packet;
mod prompt;
mod rules;

use dns::DnsCache;
use nfq::{Queue, Verdict};
use packet::TrafficPacket;
use rules::{Rule, Rules};
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
    rules: Rules,
}

impl AppWall {
    fn run_iptables_rule(iptables: &str, operation: &str, rule: &str) {
        debug!("executing: {} {} {}", iptables, operation, rule);
        Command::new(iptables)
            .args(std::iter::once(operation).chain(rule.split_whitespace()))
            .output()
            .unwrap();
    }

    pub fn start(&self) {
        for rule in IPTABLES_RULES.iter() {
            // clean the rule
            Self::run_iptables_rule("iptables", "-D", rule);
            Self::run_iptables_rule("ip6tables", "-D", rule);

            // add the rule
            Self::run_iptables_rule("iptables", "-I", rule);
            Self::run_iptables_rule("ip6tables", "-I", rule);
        }
    }

    fn apply_rules(&mut self, pkt: &TrafficPacket) -> Verdict {
        let verdict;
        let dest = if let Some(hostname) = self.dns.get(pkt.dest_addr.ip()) {
            hostname.get(0).unwrap().to_string()
        } else {
            pkt.dest_addr.to_string()
        };
        let process_name: String = if let Some(ref name) = pkt.exe {
            name.into()
        } else {
            if pkt.src_addr.port() == 53 {
                debug!("ignoring the pkt as it is dns answer");
            } else {
                warn!("could not find process name {:#?}", pkt);
            }
            "unknown".into()
        };

        if let Some(pkt_verdict) = self.rules.get_verdict(&pkt) {
            verdict = pkt_verdict;
        } else {
            verdict = prompt::prompt_verdict(&format!(
                "accept {} connection by '{}' to '{}'",
                pkt.protocol, process_name, dest,
            ));
            self.rules.add(Rule {
                app_path: pkt.exe.clone(),
                address: Some(pkt.dest_addr.ip()),
                port: Some(pkt.dest_addr.port()),
                protocol: Some(pkt.protocol.to_string()),
                verdict: verdict.clone(),
            });
        }
        info!(
            "verdict for {} connection by '{}' to '{}' is {:#?}",
            pkt.protocol, process_name, dest, verdict
        );
        verdict
    }

    pub fn run(&mut self) -> std::io::Result<()> {
        let mut queue = Queue::open().unwrap();
        queue.bind(0)?;
        loop {
            let mut verdict = Verdict::Accept;
            let mut msg = queue.recv()?;
            msg.get_payload();
            let payload = msg.get_payload();
            match TrafficPacket::from(payload) {
                Err(msg) => warn!("error {} occurred while parsing: {:#?}", msg, payload),
                Ok(mut pkt) => {
                    verdict = if !pkt.dns_data.is_empty() {
                        for (hostname, ip) in pkt.dns_data.drain(..) {
                            info!("hostname '{}' maps to '{}'", hostname, ip);
                            self.dns.add(ip, hostname);
                        }
                        Verdict::Accept
                    } else {
                        self.apply_rules(&pkt)
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

    pub fn stop(&self) {
        for rule in IPTABLES_RULES.iter() {
            Self::run_iptables_rule("iptables", "-D", rule);
            Self::run_iptables_rule("ip6tables", "-D", rule);
        }
    }
}
