#[macro_use]
extern crate log;

mod service;

fn main() {
    service::AppWall::new().run();
}
