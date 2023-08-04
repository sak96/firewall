#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings_kernel_types;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings_netdb;

use crate::bindings_kernel_types::{sock, sock_common, sockaddr, sockaddr_in, sockaddr_in6};
use crate::bindings_netdb::addrinfo;

use aya_bpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read,
    bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
};
use aya_bpf::macros::{kprobe, map, uprobe, uretprobe};
use aya_bpf::maps::{HashMap, PerCpuArray, PerfEventArray};
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::info;
use firewall_aya_common::{IPAddr, SocketPacket};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
static mut SOCKET_REQUESTS: HashMap<u32, (*const sock, *const sockaddr)> =
    HashMap::with_max_entries(1024, 0);
#[map(name = "SOCKET_EVENTS")]
static SOCKET_EVENTS: PerfEventArray<SocketPacket> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe]
pub fn kprobe_security_socket_connect(ctx: ProbeContext) -> u32 {
    try_kprobe_security_socket_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

fn try_kprobe_security_socket_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid() >> 32;
    let uid = bpf_get_current_uid_gid() >> 32;
    let sock_addr: *mut sockaddr = ctx.arg(1).ok_or(1i64)?;
    let sock_family = unsafe { bpf_probe_read_kernel(&(*sock_addr).sa_family as *const u16)? };
    let prg = bpf_get_current_comm()?;
    let program = unsafe { core::str::from_utf8_unchecked(&prg) };
    match sock_family {
        AF_INET => {
            let sockaddr = unsafe { bpf_probe_read_kernel(sock_addr as *const sockaddr_in)? };
            let ip = u32::from_be(sockaddr.sin_addr.s_addr);
            let port = u16::from_be(sockaddr.sin_port);
            info!(
                &ctx,
                "socket {}/{} by {}->{:ipv4}:{}", program, pid, uid, ip, port
            );
            SOCKET_EVENTS.output(
                &ctx,
                &SocketPacket {
                    ip_addr: IPAddr::from_v4(ip),
                    port,
                    pid,
                },
                0,
            );
            Ok(0)
        }
        AF_INET6 => {
            let sockaddr = unsafe { bpf_probe_read_kernel(sock_addr as *const sockaddr_in6)? };
            let ip = unsafe { sockaddr.sin6_addr.in6_u.u6_addr8 };
            let port: u16 = u16::from_be(sockaddr.sin6_port);
            info!(
                &ctx,
                "socket {}/{} by {}->{:ipv6}:{}", program, pid, uid, ip, port
            );
            SOCKET_EVENTS.output(
                &ctx,
                &SocketPacket {
                    ip_addr: IPAddr::from_v6(ip),
                    port,
                    pid,
                },
                0,
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 253],
}

#[map]
static mut DNS_REQUESTS: HashMap<u32, (*const u8, *const *const addrinfo)> =
    HashMap::with_max_entries(1024, 0);

#[uprobe]
pub fn uprobe_dns_entry(ctx: ProbeContext) -> u32 {
    try_uprobe_dns_entry(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

fn try_uprobe_dns_entry(ctx: ProbeContext) -> Result<u32, i64> {
    let host: *const u8 = ctx.arg(0).ok_or(1i64)?;
    let result: *const *const addrinfo = ctx.arg(3).ok_or(1i64)?;
    let mut buf = [0u8; 32];
    if !result.is_null() & !host.is_null() {
        let _ = unsafe { bpf_probe_read_user_str_bytes(host, &mut buf) };
        let tid: u32 = bpf_get_current_pid_tgid() as u32;
        unsafe { DNS_REQUESTS.insert(&tid, &(host, result), 0)? };
    }
    Ok(0)
}

#[uretprobe]
pub fn uprobe_dns_exit(ctx: ProbeContext) -> u32 {
    try_uprobe_dns_exit(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or(1))
}

#[map]
pub static mut HOSTNAME: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
#[map(name = "DNS_EVENTS")]
static mut DNS_EVENTS: PerfEventArray<()> = PerfEventArray::<()>::with_max_entries(1024, 0);

fn try_uprobe_dns_exit(ctx: ProbeContext) -> Result<u32, i64> {
    let tid: u32 = bpf_get_current_pid_tgid() as u32;
    let (host, result) = unsafe { DNS_REQUESTS.get(&tid).ok_or(1)? };
    let host_buf = unsafe {
        let ptr = HOSTNAME.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };
    let _ = unsafe { bpf_probe_read_user_str_bytes(*host, &mut host_buf.buf)? };
    let hostname = unsafe { core::str::from_utf8_unchecked(&host_buf.buf) };
    let pid = bpf_get_current_pid_tgid() >> 32;
    let prg = bpf_get_current_comm()?;
    let program = unsafe { core::str::from_utf8_unchecked(&prg) };
    let mut result = unsafe { bpf_probe_read(*result)? };
    for _ in 0..32 {
        if result.is_null() {
            break;
        }
        let addr = unsafe { bpf_probe_read(result)? };
        match addr.ai_family as u16 {
            AF_INET => {
                let sockaddr = unsafe { bpf_probe_read(addr.ai_addr as *const sockaddr_in)? };
                let ip = u32::from_be(sockaddr.sin_addr.s_addr);
                info!(&ctx, "{}/{}: {} -> {:ipv4}", program, pid, hostname, ip);
            }
            AF_INET6 => {
                let sockaddr = unsafe { bpf_probe_read(addr.ai_addr as *const sockaddr_in6)? };
                let ip = unsafe { sockaddr.sin6_addr.in6_u.u6_addr8 };
                info!(&ctx, "{}/{}: {} -> {:ipv6}", program, pid, hostname, ip);
            }
            _ => {}
        }
        result = addr.ai_next;
    }
    unsafe {
        DNS_REQUESTS.remove(&tid).map_err(|_| 164)?;
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
