#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub enum IPAddr {
    V4(u32),
    V6([u8; 16]),
}

impl IPAddr {
    pub fn from_v4(ip: u32) -> Self {
        Self::V4(ip)
    }
    pub fn from_v6(octects: [u8; 16]) -> Self {
        Self::V6(octects)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketPacket {
    pub ip_addr: IPAddr,
    pub port: u16,
    pub pid: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketPacket {}
