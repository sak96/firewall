mod config;
mod dns;
mod iptables;
mod packet;
mod prompt;
mod rules;

use dns::DnsCache;
use nfq::{Queue, Verdict};
use packet::TrafficPacket;
use rules::{Rule, Rules};
use signal_hook::{consts::SIGTERM, flag};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct AppWall {
    dns: DnsCache,
    rules: Rules,
    terminate: Arc<AtomicBool>,
}

impl AppWall {
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

    fn setup_logger(level: &str) {
        let env = env_logger::Env::default().default_filter_or(level);
        env_logger::init_from_env(env);
    }

    pub fn run(&mut self) {
        let config = config::Config::load("firewall.ini");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(config.get_log_file())
            .unwrap();
        let daemon = daemonize::Daemonize::new()
            .stderr(log) // env_logger logs to stderr
            .user("root")
            .group("root");

        if daemon.start().is_ok() {
            if flag::register(SIGTERM, Arc::clone(&self.terminate)).is_ok() {
                Self::setup_logger(&config.get_log_level());
                iptables::clear_rules();
                iptables::add_rules();
                if let Err(msg) = self.run_loop() {
                    warn!("run loop failed due to {}", msg);
                };
                iptables::clear_rules();
            }
        }
    }

    fn run_loop(&mut self) -> std::io::Result<()> {
        let mut queue = Queue::open().unwrap();
        queue.bind(0)?;
        while !self.terminate.load(Ordering::Relaxed) {
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
        }
        Ok(())
    }
}
