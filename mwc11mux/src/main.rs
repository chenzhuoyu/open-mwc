use std::{
    collections::HashMap,
    fmt::Display,
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
};

use bytes::BytesMut;
use clap::Parser;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use mwc11mux::{
    arp::{self, MACAddress},
    as_err,
    log::ConsoleLogger,
    options::Options,
    tcp_accept_v4, tcp_read_buf, udp_recv_v4, FromPort, IntoV4, Maybe, Unit,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
};

const DSP_COMM_PORT: u16 = 32290;
const COM_SEND_PORT: u16 = 32293;
const COM_RECV_PORT: u16 = 32295;
const UDP_SEND_PORT: u16 = 32392;
const UDP_RECV_PORT: u16 = 32380;

#[repr(u8)]
#[derive(Debug)]
enum Event {
    Connected = 0,
    Disconnected = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Channel {
    ComSend = 0,
    ComRecv = 1,
    DspComm = 2,
    UdpSend = 3,
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::ComSend => write!(f, "COM_SEND"),
            Channel::ComRecv => write!(f, "COM_RECV"),
            Channel::DspComm => write!(f, "DSP_COMM"),
            Channel::UdpSend => write!(f, "UDP_SEND"),
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
    UdpSend(SocketAddrV4, TcpStream),
}

#[repr(u8)]
#[derive(Debug)]
enum PacketType {
    StaInit = 0,
    StaConn = 1,
    ComData = 2,
    DspComm = 3,
    UdpData = 4,
}

impl TryFrom<u8> for PacketType {
    type Error = IoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::StaInit),
            1 => Ok(Self::StaConn),
            2 => Ok(Self::ComData),
            3 => Ok(Self::DspComm),
            4 => Ok(Self::UdpData),
            _ => Err(IoError::from(ErrorKind::InvalidInput)),
        }
    }
}

struct AddressPair {
    local: Ipv4Addr,
    remote: Ipv4Addr,
}

struct Connection {
    buf: BytesMut,
    sta: TcpStream,
    mac: MACAddress,
    addr: AddressPair,
    com_send: Option<TcpStream>,
    com_recv: Option<TcpStream>,
    dsp_comm: Option<TcpStream>,
    udp_send: Option<TcpStream>,
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

        /* get the local and remote addresses */
        let addr = match (&send, &recv) {
            (Some(cc), None) | (None, Some(cc)) => {
                match (cc.peer_addr()?.ip(), cc.local_addr()?.ip()) {
                    (IpAddr::V4(r), IpAddr::V4(v)) => AddressPair {
                        local: v,
                        remote: r,
                    },
                    (IpAddr::V6(v), _) | (_, IpAddr::V6(v)) => {
                        return Err(as_err(IoError::new(
                            ErrorKind::Unsupported,
                            format!("IPv6 address {} is not supported", &v),
                        )))
                    }
                }
            }
            (Some(c1), Some(c2)) => match (
                c1.peer_addr()?.ip(),
                c2.peer_addr()?.ip(),
                c1.local_addr()?.ip(),
                c2.local_addr()?.ip(),
            ) {
                (IpAddr::V4(r1), IpAddr::V4(r2), IpAddr::V4(v1), IpAddr::V4(v2))
                    if v1 == v2 && r1 == r2 =>
                {
                    AddressPair {
                        local: v1,
                        remote: r1,
                    }
                }
                (IpAddr::V4(r1), IpAddr::V4(r2), IpAddr::V4(v1), IpAddr::V4(v2)) => {
                    return Err(as_err(IoError::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "MAC address confliction: {} and {}",
                            if v1 == v2 { &r1 } else { &v1 },
                            if v1 == v2 { &r2 } else { &v2 },
                        ),
                    )))
                }
                (IpAddr::V6(v), _, _, _)
                | (_, IpAddr::V6(v), _, _)
                | (_, _, IpAddr::V6(v), _)
                | (_, _, _, IpAddr::V6(v)) => {
                    return Err(as_err(IoError::new(
                        ErrorKind::Unsupported,
                        format!("IPv6 address {} is not supported", &v),
                    )))
                }
            },
            (None, None) => {
                return Err(as_err(IoError::new(
                    ErrorKind::InvalidInput,
                    "either Tx or Rx channel must be present",
                )))
            }
        };

        /* send the initialization packet */
        sta.write_u8(PacketType::StaInit as u8).await?;
        sta.write_u32(14).await?;
        sta.write_all(&mac.bytes()).await?;
        sta.write_u32(addr.local.into()).await?;
        sta.write_u32(addr.remote.into()).await?;

        /* set the COM_SEND port if any */
        if let Some(cc) = send.as_ref() {
            let addr = cc.peer_addr()?.into_v4();
            Self::notify(&mut sta, addr, Channel::ComSend, Event::Connected).await?;
        }

        /* set the COM_RECV port if any */
        if let Some(cc) = recv.as_ref() {
            let addr = cc.peer_addr()?.into_v4();
            Self::notify(&mut sta, addr, Channel::ComRecv, Event::Connected).await?;
        }

        /* construct the new connection */
        Ok(Self {
            buf,
            sta,
            mac,
            addr,
            com_send: send,
            com_recv: recv,
            dsp_comm: None,
            udp_send: None,
        })
    }
}

impl Connection {
    async fn notify(sta: &mut TcpStream, addr: SocketAddrV4, chan: Channel, event: Event) -> Unit {
        sta.write_u8(PacketType::StaConn as u8).await?;
        sta.write_u32(8).await?;
        sta.write_u8(chan as u8).await?;
        sta.write_u8(event as u8).await?;
        sta.write_u16(addr.port()).await?;
        sta.write_u32((*addr.ip()).into()).await?;
        Ok(())
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
            PacketType::StaConn => {
                log::warn!("Unexpected COM_PEER packet, dropped.");
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
                    log::warn!("COM_SEND for {} is not ready, dropped.", &self.mac);
                    Ok(())
                }
            }
            PacketType::DspComm => {
                if let Some(conn) = self.udp_send.as_mut() {
                    conn.write_all_buf(&mut buf).await?;
                    Ok(())
                } else if let Some(conn) = self.dsp_comm.as_mut() {
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
    async fn update_com_send(&mut self, conn: TcpStream) -> Unit {
        match (conn.peer_addr()?, conn.local_addr()?) {
            (SocketAddr::V4(r), SocketAddr::V4(v))
                if *v.ip() == self.addr.local && *r.ip() == self.addr.remote =>
            {
                Self::notify(&mut self.sta, r, Channel::ComSend, Event::Connected).await?;
                self.com_send = Some(conn);
                Ok(())
            }
            (SocketAddr::V4(r), SocketAddr::V4(v)) => Err(as_err(IoError::new(
                ErrorKind::PermissionDenied,
                format!("MAC address confliction: {} and {}", r.ip(), v.ip()),
            ))),
            (SocketAddr::V6(v), _) | (_, SocketAddr::V6(v)) => Err(as_err(IoError::new(
                ErrorKind::Unsupported,
                format!("IPv6 address {} is not supported", v.ip()),
            ))),
        }
    }

    async fn update_com_recv(&mut self, conn: TcpStream) -> Unit {
        match (conn.peer_addr()?, conn.local_addr()?) {
            (SocketAddr::V4(r), SocketAddr::V4(v))
                if *v.ip() == self.addr.local && *r.ip() == self.addr.remote =>
            {
                Self::notify(&mut self.sta, r, Channel::ComRecv, Event::Connected).await?;
                self.com_recv = Some(conn);
                Ok(())
            }
            (SocketAddr::V4(r), SocketAddr::V4(v)) => Err(as_err(IoError::new(
                ErrorKind::PermissionDenied,
                format!("MAC address confliction: {} and {}", r.ip(), v.ip()),
            ))),
            (SocketAddr::V6(v), _) | (_, SocketAddr::V6(v)) => Err(as_err(IoError::new(
                ErrorKind::Unsupported,
                format!("IPv6 address {} is not supported", v.ip()),
            ))),
        }
    }

    async fn update_dsp_comm(&mut self, conn: TcpStream) -> Unit {
        match (conn.peer_addr()?, conn.local_addr()?) {
            (SocketAddr::V4(r), SocketAddr::V4(v))
                if *v.ip() == self.addr.local && *r.ip() == self.addr.remote =>
            {
                Self::notify(&mut self.sta, r, Channel::DspComm, Event::Connected).await?;
                self.dsp_comm = Some(conn);
                Ok(())
            }
            (SocketAddr::V4(r), SocketAddr::V4(v)) => Err(as_err(IoError::new(
                ErrorKind::PermissionDenied,
                format!("MAC address confliction: {} and {}", r.ip(), v.ip()),
            ))),
            (SocketAddr::V6(v), _) | (_, SocketAddr::V6(v)) => Err(as_err(IoError::new(
                ErrorKind::Unsupported,
                format!("IPv6 address {} is not supported", v.ip()),
            ))),
        }
    }

    async fn update_udp_send(&mut self, conn: TcpStream) -> Unit {
        match (conn.peer_addr()?, conn.local_addr()?) {
            (SocketAddr::V4(r), SocketAddr::V4(v))
                if *v.ip() == self.addr.local && *r.ip() == self.addr.remote =>
            {
                Self::notify(&mut self.sta, r, Channel::UdpSend, Event::Connected).await?;
                self.udp_send = Some(conn);
                Ok(())
            }
            (SocketAddr::V4(r), SocketAddr::V4(v)) => Err(as_err(IoError::new(
                ErrorKind::PermissionDenied,
                format!("MAC address confliction: {} and {}", r.ip(), v.ip()),
            ))),
            (SocketAddr::V6(v), _) | (_, SocketAddr::V6(v)) => Err(as_err(IoError::new(
                ErrorKind::Unsupported,
                format!("IPv6 address {} is not supported", v.ip()),
            ))),
        }
    }
}

impl Connection {
    async fn drop_channel(&mut self, chan: Channel) -> Unit {
        if let Some(conn) = match chan {
            Channel::ComSend => self.com_send.take(),
            Channel::ComRecv => self.com_recv.take(),
            Channel::DspComm => self.dsp_comm.take(),
            Channel::UdpSend => self.udp_send.take(),
        } {
            let addr = conn.peer_addr()?.into_v4();
            Self::notify(&mut self.sta, addr, chan, Event::Disconnected).await
        } else {
            Ok(())
        }
    }
}

struct ConnectionMux {
    sta: SocketAddr,
    conn: HashMap<MACAddress, Connection>,
    udp_recv: UdpSocket,
    com_recv: TcpListener,
    com_send: TcpListener,
    dsp_comm: TcpListener,
    udp_send: TcpListener,
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
        log::info!("TCP: UDP_SEND at port {}", UDP_SEND_PORT);
        log::info!("UDP: UDP_RECV at port {}", UDP_RECV_PORT);
        log::info!("---------------------------------");

        /* start servers */
        let udp_recv = UdpSocket::bind(SocketAddrV4::from_port(UDP_RECV_PORT)).await?;
        let com_recv = TcpListener::bind(SocketAddrV4::from_port(COM_RECV_PORT)).await?;
        let com_send = TcpListener::bind(SocketAddrV4::from_port(COM_SEND_PORT)).await?;
        let dsp_comm = TcpListener::bind(SocketAddrV4::from_port(DSP_COMM_PORT)).await?;
        let udp_send = TcpListener::bind(SocketAddrV4::from_port(UDP_SEND_PORT)).await?;

        /* construct the mux */
        let mux = Self {
            sta,
            conn,
            udp_recv,
            com_recv,
            com_send,
            dsp_comm,
            udp_send,
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
                let mut c = cc;
                while !tcp_read_buf(&mut c).await?.is_empty() {}
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
                add_tcp_prob_opt!(fut, UdpSend, *mac, conn.udp_send);
            }

            /* add all server listeners */
            add_tcp_server!(fut, ComSend, &self.com_send);
            add_tcp_server!(fut, ComRecv, &self.com_recv);
            add_tcp_server!(fut, DspComm, &self.dsp_comm);
            add_tcp_server!(fut, UdpSend, &self.udp_send);
            add_udp_server!(fut, UdpData, &self.udp_recv);

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
                    || cc.udp_send.is_some()
            });
        }
    }

    async fn dispatch_event(&mut self, event: MuxEvent) -> Unit {
        match event {
            MuxEvent::Dropped(mac, ch) => {
                if let Some(conn) = self.conn.get_mut(&mac) {
                    log::info!("Channel {} for {} is closed.", ch, &mac);
                    conn.drop_channel(ch).await?;
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
                        conn.drop_channel(Channel::ComRecv).await?;
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
            MuxEvent::UdpSend(addr, conn) => {
                self.resolve_source_mac(
                    "resolve MAC address for UDP_COMM channel",
                    addr,
                    Self::accept_udp_send,
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
            ctx.update_com_recv(conn).await?;
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
            ctx.update_dsp_comm(conn).await?;
            log::info!("Updated DSP_COMM channel for {}.", &mac);
            Ok(())
        } else {
            log::warn!("Unexpected DSP_COMM channel from {}, dropped.", &mac);
            Ok(())
        }
    }

    async fn accept_udp_send(&mut self, mac: MACAddress, conn: TcpStream) -> Unit {
        if let Some(ctx) = self.conn.get_mut(&mac) {
            ctx.update_udp_send(conn).await?;
            log::info!("Updated UDP_SEND channel for {}.", &mac);
            Ok(())
        } else {
            log::warn!("Unexpected UDP_SEND channel from {}, dropped.", &mac);
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
