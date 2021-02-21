pub mod packet;
mod service;

fn main() -> std::io::Result<()> {
    service::AppWall::stop();
    service::AppWall::start();
    let run_value = service::AppWall::run();
    service::AppWall::stop();
    run_value
}
