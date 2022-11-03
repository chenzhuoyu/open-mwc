use std::{
    collections::HashMap,
    fmt::Display,
    io::{Error as IoError, ErrorKind},
    net::{SocketAddr, SocketAddrV4},
};

use bytes::BytesMut;
use clap::Parser;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use mwc11mux::{
    arp::{self, MACAddress},
    log::ConsoleLogger,
    options::Options,
    tcp_accept_v4, tcp_read_buf, udp_recv_v4, FromPort, Maybe, Unit,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
};

const DSP_COMM_PORT: u16 = 32290;
const COM_SEND_PORT: u16 = 32293;
const COM_RECV_PORT: u16 = 32295;
const UDP_COMM_PORT: u16 = 32392;
const UDP_DATA_PORT: u16 = 32380;

#[derive(Clone, Copy, Debug)]
enum Channel {
    ComSend,
    ComRecv,
    DspComm,
    UdpComm,
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::ComSend => write!(f, "COM_SEND"),
            Channel::ComRecv => write!(f, "COM_RECV"),
            Channel::DspComm => write!(f, "DSP_COMM"),
            Channel::UdpComm => write!(f, "UDP_COMM"),
        }
    }
}

enum MuxEvent {
    Dropped(MACAddress, Channel),
    StaData(MACAddress, BytesMut),
    ComData(MACAddress, BytesMut),
    UdpData(SocketAddrV4, BytesMut),
    ComSend(SocketAddrV4, TcpStream),
    ComRecv(SocketAddrV4, TcpStream),
    DspComm(SocketAddrV4, TcpStream),
    UdpComm(SocketAddrV4, TcpStream),
}

#[repr(u8)]
#[derive(Debug)]
enum PacketType {
    StaInit = 0,
    UdpData = 1,
    ComData = 2,
    DspComm = 3,
    UdpComm = 4,
}

impl TryFrom<u8> for PacketType {
    type Error = IoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::StaInit),
            1 => Ok(Self::UdpData),
            2 => Ok(Self::ComData),
            3 => Ok(Self::DspComm),
            4 => Ok(Self::UdpComm),
            _ => Err(IoError::from(ErrorKind::InvalidInput)),
        }
    }
}

struct Connection {
    buf: BytesMut,
    sta: TcpStream,
    mac: MACAddress,
    com_chan: BytesMut,
    com_send: Option<TcpStream>,
    com_recv: Option<TcpStream>,
    dsp_comm: Option<TcpStream>,
    udp_comm: Option<TcpStream>,
}

impl Connection {
    async fn new(
        sta: SocketAddr,
        mac: MACAddress,
        send: Option<TcpStream>,
        recv: Option<TcpStream>,
    ) -> Maybe<Self> {
        let buf = BytesMut::with_capacity(65536);
        let mut sta = TcpStream::connect(sta).await?;

        /* send the initialization packet */
        sta.write_u8(PacketType::StaInit as u8).await?;
        sta.write_u32(mac.bytes().len() as u32).await?;
        sta.write_all(&mac.bytes()).await?;

        /* construct the new connection */
        Ok(Self {
            buf,
            sta,
            mac,
            com_chan: BytesMut::with_capacity(65536),
            com_send: send,
            com_recv: recv,
            dsp_comm: None,
            udp_comm: None,
        })
    }
}

impl Connection {
    async fn dispatch_req(&mut self) -> Unit {
        loop {
            if self.buf.len() < 5 {
                break Ok(());
            } else {
                self.dispatch_once().await?;
            }
        }
    }

    async fn dispatch_once(&mut self) -> Unit {
        let mem = [self.buf[1], self.buf[2], self.buf[3], self.buf[4]];
        let rlen = u32::from_be_bytes(mem) as usize;

        /* check for buffer length */
        if self.buf.len() < rlen + 5 {
            return Ok(());
        }

        /* extract the packet type and body */
        let tag = PacketType::try_from(self.buf[0])?;
        let mut buf = self.buf.split_to(rlen + 5).split_off(5);

        /* check for packet type */
        match tag {
            PacketType::StaInit => {
                log::warn!("Unexpected STA_INIT packet, dropped.");
                Ok(())
            }
            PacketType::UdpData => {
                log::warn!("Unexpected UDP_DATA packet, dropped.");
                Ok(())
            }
            PacketType::ComData => {
                if let Some(conn) = self.com_send.as_mut() {
                    conn.write_all_buf(&mut buf).await?;
                    Ok(())
                } else {
                    self.com_chan.extend_from_slice(&buf);
                    Ok(())
                }
            }
            PacketType::DspComm => {
                if let Some(conn) = self.dsp_comm.as_mut() {
                    conn.write_all_buf(&mut buf).await?;
                    Ok(())
                } else {
                    log::warn!("DSP_COMM for {} is not ready, dropped.", &self.mac);
                    Ok(())
                }
            }
            PacketType::UdpComm => {
                if let Some(conn) = self.udp_comm.as_mut() {
                    conn.write_all_buf(&mut buf).await?;
                    Ok(())
                } else {
                    log::warn!("UDP_COMM for {} is not ready, dropped.", &self.mac);
                    Ok(())
                }
            }
        }
    }
}

impl Connection {
    async fn handle_sta_recv(&mut self, buf: BytesMut) -> Unit {
        self.buf.extend_from_slice(&buf);
        self.dispatch_req().await?;
        Ok(())
    }

    async fn handle_com_recv(&mut self, mut buf: BytesMut) -> Unit {
        self.sta.write_u8(PacketType::ComData as u8).await?;
        self.sta.write_u32(buf.len() as u32).await?;
        self.sta.write_all_buf(&mut buf).await?;
        Ok(())
    }

    async fn handle_udp_data(&mut self, mut buf: BytesMut) -> Unit {
        self.sta.write_u8(PacketType::UdpData as u8).await?;
        self.sta.write_u32(buf.len() as u32).await?;
        self.sta.write_all_buf(&mut buf).await?;
        Ok(())
    }
}

impl Connection {
    async fn update_com_send(&mut self, mut conn: TcpStream) -> Unit {
        conn.write_all_buf(&mut self.com_chan).await?;
        self.com_send = Some(conn);
        Ok(())
    }
}

impl Connection {
    fn drop_channel(&mut self, chan: Channel) {
        match chan {
            Channel::ComSend => self.com_send = None,
            Channel::ComRecv => self.com_recv = None,
            Channel::DspComm => self.dsp_comm = None,
            Channel::UdpComm => self.udp_comm = None,
        }
    }
}

struct ConnectionMux {
    sta: SocketAddr,
    conn: HashMap<MACAddress, Connection>,
    udp_data: UdpSocket,
    com_recv: TcpListener,
    com_send: TcpListener,
    dsp_comm: TcpListener,
    udp_comm: TcpListener,
}

impl ConnectionMux {
    async fn main() -> Unit {
        let sta = Options::parse().station;
        let conn = HashMap::new();

        /* startup banner */
        log::info!("----------- mwc11 mux -----------");
        log::info!("TCP: COM_RECV at port {}", COM_RECV_PORT);
        log::info!("TCP: COM_SEND at port {}", COM_SEND_PORT);
        log::info!("TCP: DSP_COMM at port {}", DSP_COMM_PORT);
        log::info!("TCP: UDP_COMM at port {}", UDP_COMM_PORT);
        log::info!("UDP: UDP_DATA at port {}", UDP_DATA_PORT);
        log::info!("---------------------------------");

        /* start servers */
        let udp_data = UdpSocket::bind(SocketAddrV4::from_port(UDP_DATA_PORT)).await?;
        let com_recv = TcpListener::bind(SocketAddrV4::from_port(COM_RECV_PORT)).await?;
        let com_send = TcpListener::bind(SocketAddrV4::from_port(COM_SEND_PORT)).await?;
        let dsp_comm = TcpListener::bind(SocketAddrV4::from_port(DSP_COMM_PORT)).await?;
        let udp_comm = TcpListener::bind(SocketAddrV4::from_port(UDP_COMM_PORT)).await?;

        /* construct the mux */
        let mux = Self {
            sta,
            conn,
            udp_data,
            com_recv,
            com_send,
            dsp_comm,
            udp_comm,
        };

        /* start the event loop */
        log::info!("mwc11 mux started successfully.");
        mux.event_loop().await?;
        Ok(())
    }
}

macro_rules! add_udp_server {
    ($fut:expr, $kind:ident, $sock:expr) => {
        $fut.push(Box::pin(async {
            let (buf, addr) = udp_recv_v4($sock).await?;
            Ok(MuxEvent::$kind(addr, buf))
        }));
    };
}

macro_rules! add_tcp_server {
    ($fut:expr, $kind:ident, $sock:expr) => {
        $fut.push(Box::pin(async {
            let (conn, addr) = tcp_accept_v4($sock).await?;
            Ok(MuxEvent::$kind(addr, conn))
        }));
    };
}

macro_rules! add_tcp_read_req {
    ($fut:expr, $kind:ident, $mac:expr, $conn:expr) => {
        $fut.push(Box::pin(async {
            let buf = tcp_read_buf($conn).await?;
            Ok(MuxEvent::$kind($mac, buf))
        }));
    };
}

macro_rules! add_tcp_read_opt {
    ($fut:expr, $kind:ident, $mac:expr, $conn:expr) => {
        if let Some(cc) = $conn.as_mut() {
            $fut.push(Box::pin(async {
                let buf = tcp_read_buf(cc).await?;
                Ok(MuxEvent::$kind($mac, buf))
            }));
        }
    };
}

macro_rules! add_tcp_prob_opt {
    ($fut:expr, $chan:ident, $mac:expr, $conn:expr) => {
        if let Some(cc) = $conn.as_mut() {
            $fut.push(Box::pin(async {
                tcp_read_buf(cc).await?;
                Ok(MuxEvent::Dropped($mac, Channel::$chan))
            }));
        }
    };
}

impl ConnectionMux {
    async fn event_loop(mut self) -> Unit {
        loop {
            let mut fut: FuturesUnordered<
                std::pin::Pin<Box<dyn Future<Output = Maybe<MuxEvent>>>>,
            > = FuturesUnordered::new();

            /* add all the station up-links and all channels */
            for (mac, conn) in self.conn.iter_mut() {
                add_tcp_read_req!(fut, StaData, *mac, &mut conn.sta);
                add_tcp_prob_opt!(fut, ComSend, *mac, conn.com_send);
                add_tcp_read_opt!(fut, ComData, *mac, conn.com_recv);
                add_tcp_prob_opt!(fut, DspComm, *mac, conn.dsp_comm);
                add_tcp_prob_opt!(fut, UdpComm, *mac, conn.udp_comm);
            }

            /* add all server listeners */
            add_tcp_server!(fut, ComSend, &self.com_send);
            add_tcp_server!(fut, ComRecv, &self.com_recv);
            add_tcp_server!(fut, DspComm, &self.dsp_comm);
            add_tcp_server!(fut, UdpComm, &self.udp_comm);
            add_udp_server!(fut, UdpData, &self.udp_data);

            /* select from those futures */
            let event = match fut.next().await {
                Some(v) => v?,
                None => break Ok(()),
            };

            /* manually clear the mutable reference to `self` */
            fut.clear();
            std::mem::drop(fut);

            /* dispatch the event */
            if let Err(err) = self.dispatch_event(event).await {
                log::warn!("Error when handling event: {}", err);
            }

            /* remove dead connections */
            self.conn.retain(|_, cc| {
                cc.com_send.is_some()
                    || cc.com_recv.is_some()
                    || cc.dsp_comm.is_some()
                    || cc.udp_comm.is_some()
            });
        }
    }

    async fn dispatch_event(&mut self, event: MuxEvent) -> Unit {
        match event {
            MuxEvent::Dropped(mac, ch) => {
                if let Some(conn) = self.conn.get_mut(&mac) {
                    log::info!("Channel {} for {} is closed.", ch, &mac);
                    conn.drop_channel(ch);
                    Ok(())
                } else {
                    log::warn!("Dropping non-existing connection {}.", &mac);
                    Ok(())
                }
            }
            MuxEvent::StaData(mac, buf) => {
                if buf.is_empty() {
                    log::info!("Station link for {} is closed.", &mac);
                    self.conn.remove(&mac);
                    Ok(())
                } else if let Some(conn) = self.conn.get_mut(&mac) {
                    conn.handle_sta_recv(buf).await?;
                    Ok(())
                } else {
                    log::warn!("Unexpected station data from {}, dropped.", &mac);
                    Ok(())
                }
            }
            MuxEvent::ComData(mac, buf) => {
                if let Some(conn) = self.conn.get_mut(&mac) {
                    if buf.is_empty() {
                        log::info!("Channel COM_RECV for {} is closed.", &mac);
                        conn.drop_channel(Channel::ComRecv);
                        Ok(())
                    } else {
                        conn.handle_com_recv(buf).await?;
                        Ok(())
                    }
                } else {
                    log::warn!("Unexpected COM_RECV data from {}, dropped.", &mac);
                    Ok(())
                }
            }
            MuxEvent::UdpData(addr, buf) => {
                self.resolve_source_mac(
                    "resolve MAC address for UDP packet",
                    addr,
                    Self::handle_udp_data,
                    buf,
                )
                .await
            }
            MuxEvent::ComSend(addr, conn) => {
                self.resolve_source_mac(
                    "resolve MAC address for COM_SEND channel",
                    addr,
                    Self::accept_com_send,
                    conn,
                )
                .await
            }
            MuxEvent::ComRecv(addr, conn) => {
                self.resolve_source_mac(
                    "resolve MAC address for COM_RECV channel",
                    addr,
                    Self::accept_com_recv,
                    conn,
                )
                .await
            }
            MuxEvent::DspComm(addr, conn) => {
                self.resolve_source_mac(
                    "resolve MAC address for DSP_COMM channel",
                    addr,
                    Self::accept_dsp_comm,
                    conn,
                )
                .await
            }
            MuxEvent::UdpComm(addr, conn) => {
                self.resolve_source_mac(
                    "resolve MAC address for UDP_COMM channel",
                    addr,
                    Self::accept_udp_comm,
                    conn,
                )
                .await
            }
        }
    }
}

impl ConnectionMux {
    async fn resolve_source_mac<'a, T: Future<Output = Unit>, V>(
        &'a mut self,
        desc: &str,
        addr: SocketAddrV4,
        func: impl Fn(&'a mut Self, MACAddress, V) -> T,
        data: V,
    ) -> Unit {
        match arp::lookup(addr.ip()) {
            Ok(mac) => {
                func(self, mac, data).await?;
                Ok(())
            }
            Err(_) => {
                log::warn!("Cannot {} from {}, dropped.", desc, addr);
                Ok(())
            }
        }
    }
}

impl ConnectionMux {
    async fn handle_udp_data(&mut self, mac: MACAddress, buf: BytesMut) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.handle_udp_data(buf).await?;
            Ok(())
        } else {
            log::warn!("Unexpected UDP packet from {}, dropped.", &mac);
            Ok(())
        }
    }

    async fn accept_com_send(&mut self, mac: MACAddress, conn: TcpStream) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.update_com_send(conn).await?;
            log::info!("Updated COM_SEND channel for {}.", &mac);
            Ok(())
        } else {
            match Connection::new(self.sta, mac, Some(conn), None).await {
                Ok(ctx) => {
                    self.conn.insert(mac, ctx);
                    log::info!("Created new COM_SEND channel for {}.", &mac);
                    Ok(())
                }
                Err(err) => {
                    log::warn!("Cannot create COM_SEND for {}. Error: {}", &mac, err);
                    Ok(())
                }
            }
        }
    }

    async fn accept_com_recv(&mut self, mac: MACAddress, conn: TcpStream) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.com_recv = Some(conn);
            log::info!("Updated COM_RECV channel for {}.", &mac);
            Ok(())
        } else {
            match Connection::new(self.sta, mac, None, Some(conn)).await {
                Ok(ctx) => {
                    self.conn.insert(mac, ctx);
                    log::info!("Created new COM_RECV channel for {}.", &mac);
                    Ok(())
                }
                Err(err) => {
                    log::warn!("Cannot create COM_RECV for {}. Error: {}", &mac, err);
                    Ok(())
                }
            }
        }
    }

    async fn accept_dsp_comm(&mut self, mac: MACAddress, conn: TcpStream) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.dsp_comm = Some(conn);
            log::info!("Updated DSP_COMM channel for {}.", &mac);
            Ok(())
        } else {
            log::warn!("Unexpected DSP_COMM channel from {}, dropped.", &mac);
            Ok(())
        }
    }

    async fn accept_udp_comm(&mut self, mac: MACAddress, conn: TcpStream) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.udp_comm = Some(conn);
            log::info!("Updated UDP_COMM channel for {}.", &mac);
            Ok(())
        } else {
            log::warn!("Unexpected UDP_COMM channel from {}, dropped.", &mac);
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Unit {
    ConsoleLogger.init()?;
    ConnectionMux::main().await?;
    Ok(())
}
