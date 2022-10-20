#![feature(pointer_byte_offsets)]

use std::{io::ErrorKind, net::SocketAddr};

use tokio::net::{TcpListener, TcpStream};

pub mod arp;
pub mod log;
pub mod options;

pub type Unit = Maybe<()>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Maybe<T> = Result<T, Error>;

#[inline]
pub fn as_err<T: std::error::Error + Send + Sync + 'static>(e: T) -> Error {
    Box::new(e) as Error
}

pub async fn tcp_accept(srv: &TcpListener) -> Maybe<(TcpStream, SocketAddr)> {
    loop {
        match srv.accept().await {
            Ok(ret) => return Ok(ret),
            Err(err) if err.kind() != ErrorKind::ConnectionAborted => return Err(as_err(err)),
            Err(_) => {}
        }
    }
}
