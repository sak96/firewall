use std::{collections::HashMap, net::IpAddr};

#[derive(Default)]
pub struct DnsCache {
    cache: HashMap<IpAddr, Vec<String>>,
}

impl DnsCache {
    pub fn add(&mut self, ip: IpAddr, hostname: String) {
        self.cache.entry(ip).or_insert(vec![]).push(hostname);
    }

    pub fn get(&self, ip: IpAddr) -> Option<&Vec<String>> {
        self.cache.get(&ip)
    }
}
