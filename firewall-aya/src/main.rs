use std::net::IpAddr;
use std::thread::sleep;
use std::time::Duration;

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{KProbe, UProbe};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn};
use tokio::{signal, task};
use tokio::runtime::Runtime;
use nfq::{Queue, Verdict};
use firewall_aya_common::{IPAddr, SocketPacket};

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

    let mut socket_array = AsyncPerfEventArray::try_from(bpf.map_mut("SOCKET_EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = socket_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SocketPacket;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = match data.ip_addr {
                        IPAddr::V4(v4) => IpAddr::V4(v4.into()),
                        IPAddr::V6(v6) => IpAddr::V6(v6.into()),
                    };
                    info!("LOG: SRC {}, PORT {} PID {}", src_addr, data.port, data.pid);
                }
            }
        });
    }


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
