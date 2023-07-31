use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("firewall-aya-ebpf/src");
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &["sockaddr", "sockaddr_in", "sockaddr_in6", "sock", "sock_common"],
        &[],
    )?;
    let mut out = File::create(dir.join("bindings_kernel_types.rs"))?;
    write!(out, "{}", bindings)?;

    let bindings = aya_tool::generate(
        InputFile::Header(PathBuf::from("/usr/include/netdb.h")),
        &["addrinfo"],
        &[],
    )?;
    let mut out = File::create(dir.join("bindings_netdb.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
