use log::debug;
use std::process::Command;

const IPTABLES_RULES: [&str; 3] = [
    // Get DNS responses
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass",
    // Get connection packets
    "OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass",
    // Reject packets marked
    "OUTPUT --protocol tcp -m mark --mark 1 -j REJECT",
];

fn run_iptables_rule(iptables: &str, operation: &str, rule: &str) {
    debug!("executing: {} {} {}", iptables, operation, rule);
    Command::new(iptables)
        .args(std::iter::once(operation).chain(rule.split_whitespace()))
        .output()
        .unwrap();
}

pub fn add_rules() {
    for rule in IPTABLES_RULES.iter() {
        run_iptables_rule("iptables", "-I", rule);
        run_iptables_rule("ip6tables", "-I", rule);
    }
}

pub fn clear_rules() {
    for rule in IPTABLES_RULES.iter() {
        run_iptables_rule("iptables", "-D", rule);
        run_iptables_rule("ip6tables", "-D", rule);
    }
}
