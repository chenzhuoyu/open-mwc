#![feature(pointer_byte_offsets)]

use std::{
    io::{ErrorKind, Result as IoResult},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use bytes::BytesMut;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
};

pub mod arp;
pub mod log;
pub mod options;

pub type Unit = Maybe<()>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Maybe<T> = Result<T, Error>;

pub trait FromPort {
    fn from_port(port: u16) -> Self;
}

impl FromPort for SocketAddrV4 {
    fn from_port(port: u16) -> Self {
        Self::new(Ipv4Addr::UNSPECIFIED, port)
    }
}

#[inline]
pub fn as_err<T: std::error::Error + Send + Sync + 'static>(e: T) -> Error {
    Box::new(e) as Error
}

pub async fn udp_recv_v4(udp: &UdpSocket) -> Maybe<(BytesMut, SocketAddrV4)> {
    loop {
        let mut buf = [0u8; 65536];
        let (size, addr) = udp.recv_from(&mut buf).await?;

        /* only accepts IPv4 addresses */
        if let SocketAddr::V4(addr) = addr {
            break Ok((buf[..size].into(), addr));
        }
    }
}

pub async fn tcp_read_buf<T: AsyncReadExt + Unpin>(mut rd: T) -> IoResult<BytesMut> {
    let mut buf = BytesMut::with_capacity(65536);
    let len = rd.read_buf(&mut buf).await?;
    Ok(buf.split_to(len))
}

pub async fn tcp_accept_v4(srv: &TcpListener) -> Maybe<(TcpStream, SocketAddrV4)> {
    loop {
        match srv.accept().await {
            Ok((conn, SocketAddr::V4(addr))) => return Ok((conn, addr)),
            Err(err) if err.kind() != ErrorKind::ConnectionAborted => return Err(as_err(err)),
            _ => {}
        }
    }
}
