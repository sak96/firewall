#[macro_use]
extern crate log;

mod service;

fn main() {
    // set up logger
    let log = std::fs::File::create("/tmp/firewall.log").unwrap();
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::init_from_env(env);

    // start the service
    let mut srv = service::AppWall::default();
    let daemon = daemonize::Daemonize::new()
        .stderr(log) // env_logger logs to stderr
        .privileged_action(|| service::AppWall::start())
        .user("root")
        .group("root")
        .exit_action(|| service::AppWall::stop());

    if daemon.start().is_ok() {
        srv.run().unwrap();
    }
}
