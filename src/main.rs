#[macro_use]
extern crate log;

mod service;

fn main() -> std::io::Result<()> {
    // set up logger
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::init_from_env(env);

    // start the service
    let mut srv = service::AppWall::default();
    service::AppWall::stop();
    service::AppWall::start();
    let run_value = srv.run();
    service::AppWall::stop();
    run_value
}
