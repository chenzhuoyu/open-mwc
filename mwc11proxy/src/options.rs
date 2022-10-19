use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "MWC11 Proxy", version = "1.0")]
pub struct Options {
    /// Station address
    #[arg(name = "STATION", long = "station", short = 's')]
    pub station: SocketAddr,
}
