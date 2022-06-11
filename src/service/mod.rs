mod config;
mod dns;
mod iptables;
mod packet;
mod prompt;
mod rules;

use dns::DnsCache;
use nfq::{async_nfq::AsyncQueue, Queue, Verdict};
use packet::TrafficPacket;
use rules::{Rule, Rules};
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot::Receiver as OneShotReceiver;
use trust_dns_resolver::TokioAsyncResolver;

pub struct AppWall {
    dns: DnsCache,
    rules: Rules,
    terminate: OneShotReceiver<()>,
    resolver: TokioAsyncResolver,
}

impl AppWall {
    const MAX_PROCESSED_QUEUE_LENGTH: usize = 100;

    pub fn new(resolver: TokioAsyncResolver) -> Self {
        // setup ctrl c handler
        let (ctrl_c_handler, terminate) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.unwrap();
            debug!("handling ctrl c");
            ctrl_c_handler.send(()).unwrap();
        });

        Self {
            dns: Default::default(),
            rules: Default::default(),
            terminate,
            resolver,
        }
    }
    async fn apply_rules(
        mut dns: DnsCache,
        resolver: TokioAsyncResolver,
        pkt: &TrafficPacket,
        mut rules: Rules,
    ) -> Verdict {
        let verdict;
        let dest = if let Some(hostname) = dns.get(pkt.dest_addr.ip()) {
            hostname.get(0).unwrap().to_string()
        } else if let Some(address) = resolver
            .reverse_lookup(pkt.dest_addr.ip())
            .await
            .iter()
            .next()
        {
            let name = address.query().name().to_string();
            dbg!("finally a reverse lookup", &name);
            dns.add(pkt.dest_addr.ip(), name.clone());
            name
        } else {
            let resolver = resolver.clone();
            let ip = pkt.dest_addr.ip();
            tokio::spawn(async move {
                if let Some(address) = resolver.reverse_lookup(ip).await.iter().next() {
                    let name = address.query().name().to_string();
                    dbg!("finally a reverse lookup", &name);
                    dns.add(ip, name);
                }
            });
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

        if let Some(pkt_verdict) = rules.get_verdict(pkt) {
            verdict = pkt_verdict;
        } else {
            verdict = prompt::prompt_verdict(&format!(
                "accept {} connection by '{}' to '{}'",
                pkt.protocol, process_name, dest,
            ));
            rules.add(Rule {
                app_path: pkt.exe.clone(),
                address: Some(pkt.dest_addr.ip()),
                port: Some(pkt.dest_addr.port()),
                protocol: Some(pkt.protocol.to_string()),
                verdict,
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

    fn setup_rules(&mut self, config: &config::Config) {
        if let Some(rules) = config.get_rules() {
            self.rules = Rules::from_text(&rules);
            debug!("following rules added.\n{:?}", self.rules);
        }
    }

    pub async fn run(mut self) {
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
            Self::setup_logger(&config.get_log_level());
            self.setup_rules(&config);
            iptables::clear_rules();
            iptables::add_rules();
            if let Err(msg) = self.run_loop().await {
                warn!("run loop failed due to {}", msg);
            };
            iptables::clear_rules();
        }
    }

    async fn run_loop(mut self) -> std::io::Result<()> {
        let mut queue = Queue::open().unwrap();
        queue.bind(0)?;
        let mut queue = AsyncQueue::new(queue)?;
        let (processed_sender, mut processed_queue) = channel(Self::MAX_PROCESSED_QUEUE_LENGTH);
        while self.terminate.try_recv().is_err() {
            tokio::select! {
                Some(msg) = processed_queue.recv() => {
                    queue.verdict(msg).await?;
                }
                Ok(mut msg) = queue.recv() => {
                    let mut verdict = Verdict::Accept;
                    let mut dns = self.dns.clone();
                    let resolver = self.resolver.clone();
                    let rules = self.rules.clone();
                    let processed_sender = processed_sender.clone();
                    tokio::spawn(async move {
                        msg.get_payload();
                        let payload = msg.get_payload();
                        match TrafficPacket::from(payload) {
                            Err(msg) => warn!("error {} occurred while parsing: {:#?}", msg, payload),
                            Ok(mut pkt) => {
                                verdict = if !pkt.dns_data.is_empty() {
                                    for (hostname, ip) in pkt.dns_data.drain(..) {
                                        info!("hostname '{}' maps to '{}'", hostname, ip);
                                        dns.add(ip, hostname);
                                    }
                                    Verdict::Accept
                                } else {
                                    Self::apply_rules(dns, resolver, &pkt, rules).await
                                }
                            }
                        }
                        msg.set_verdict(verdict);
                        processed_sender.send(msg).await.expect("poisoned lock");
                    });
                }
            }
        }
        Ok(())
    }
}
