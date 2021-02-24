pub mod dns;
pub mod packet;
mod service;

fn main() -> std::io::Result<()> {
    let mut srv = service::AppWall::default();
    service::AppWall::stop();
    service::AppWall::start();
    let run_value = srv.run();
    service::AppWall::stop();
    run_value
}
