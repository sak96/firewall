#[macro_use]
extern crate log;

mod service;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::main]
async fn main() {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
        .expect("failed to create cloudflare resolver");
    service::AppWall::new(resolver).run().await;
}
