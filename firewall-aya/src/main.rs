use std::thread::sleep;
use std::time::Duration;

use aya::{include_bytes_aligned, Bpf};
use aya::programs::{KProbe, UProbe};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;
use tokio::runtime::Runtime;
use nfq::{Queue, Verdict};

mod packet;
mod iptables;


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        concat!(env!("CARGO_TARGET_DIR"), "/bpfel-unknown-none/debug/firewall-aya-ebpf")
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        concat!(env!("CARGO_TARGET_DIR"), "/bpfel-unknown-none/release/firewall-aya-ebpf")
    ))?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut KProbe = bpf.program_mut("kprobe_security_socket_connect").unwrap().try_into()?;
    program.load()?;
    program.attach("security_socket_connect", 0)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_dns_entry").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("getaddrinfo"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_dns_exit").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("getaddrinfo"), 0, "libc", None)?;

    let rt = Runtime::new().unwrap();
    rt.spawn_blocking(|| {
       iptables::clear_rules();
       iptables::add_rules();
       let mut queue = Queue::open().unwrap();
       queue.bind(0).unwrap();
       loop {
            let mut msg = match queue.recv(){
                Ok(msg) => msg,
                _ => continue,

            };
            let payload = msg.get_payload();
            if let Ok(packet) = packet::TrafficPacket::from(payload) {
               sleep(Duration::from_secs(1));
               info!("nfq: {:?} -> {:?}",packet.src_addr, packet.dest_addr);
            }

           msg.set_verdict(Verdict::Accept);
           queue.verdict(msg).unwrap();
       }
    }
   );

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
