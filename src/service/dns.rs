use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::IpAddr};

#[derive(Default, Clone)]
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
}

impl DnsCache {
    pub fn add(&mut self, ip: IpAddr, hostname: String) {
        let mut cache = self.cache.lock().expect("Cache poisoned lock");
        cache.entry(ip).or_insert(vec![]).push(hostname);
    }

    pub fn get(&self, ip: IpAddr) -> Option<Vec<String>> {
        let cache = self.cache.lock().expect("Cache poisoned lock");
        cache.get(&ip).cloned()
    }
}
