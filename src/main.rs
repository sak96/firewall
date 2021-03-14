#[macro_use]
extern crate log;

mod service;

fn main() {
    let log = std::fs::File::create("/tmp/firewall.log").unwrap();
    let daemon = daemonize::Daemonize::new()
        .stderr(log) // env_logger logs to stderr
        .user("root")
        .group("root");

    if daemon.start().is_ok() {
        service::AppWall::default().run();
    }
}
