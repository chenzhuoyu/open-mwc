#![feature(duration_constants)]
#![feature(let_chains)]

use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind, Result as IoResult},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use bytes::BytesMut;
use clap::Parser;
use mwc11proxy::{
    arp::{self, MACAddress},
    as_err,
    log::ConsoleLogger,
    options::Options,
    tcp_accept, Maybe, Unit,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream, UdpSocket,
    },
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
};

const DSP_COMM_PORT: u16 = 32290;
const COM_SEND_PORT: u16 = 32293;
const COM_RECV_PORT: u16 = 32295;
const UDP_COMM_PORT: u16 = 32392;
const UDP_RECV_PORT: u16 = 32380;

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

#[derive(Debug)]
enum ServerEvent {
    Dropped,
    UdpRecv(BytesMut),
    ComRecv(TcpStream),
    ComSend(OwnedWriteHalf),
    DspComm(OwnedWriteHalf),
    UdpComm(OwnedWriteHalf),
}

struct Connection {
    com_send: Mutex<OwnedWriteHalf>,
    dsp_comm: Mutex<Option<OwnedWriteHalf>>,
    udp_comm: Mutex<Option<OwnedWriteHalf>>,
    udp_send: UnboundedSender<BytesMut>,
}

struct Dispatcher {
    buf: BytesMut,
    mac: MACAddress,
    conn: Arc<Connection>,
    com_rx: OwnedReadHalf,
    com_tx: OwnedWriteHalf,
    sta_rx: OwnedReadHalf,
    sta_tx: OwnedWriteHalf,
    udp_rx: UnboundedReceiver<BytesMut>,
    notify: UnboundedSender<(MACAddress, ServerEvent)>,
}

impl Dispatcher {
    async fn start(
        mac: MACAddress,
        sta: SocketAddr,
        notify: UnboundedSender<(MACAddress, ServerEvent)>,
        com_recv: TcpStream,
        com_send: OwnedWriteHalf,
        dsp_comm: Option<OwnedWriteHalf>,
        udp_comm: Option<OwnedWriteHalf>,
    ) -> Maybe<Arc<Connection>> {
        let mut cc = TcpStream::connect(sta).await?;
        let (udp_tx, udp_rx) = unbounded_channel();

        /* send the inital packet */
        cc.write_u8(PacketType::StaInit as u8).await?;
        cc.write_u32(mac.bytes().len() as u32).await?;
        cc.write_all(&mac.bytes()).await?;

        /* construct the connection */
        let conn = Arc::new(Connection {
            com_send: Mutex::new(com_send),
            dsp_comm: Mutex::new(dsp_comm),
            udp_comm: Mutex::new(udp_comm),
            udp_send: udp_tx,
        });

        /* split the reader and writer */
        let ret = conn.clone();
        let buf = BytesMut::with_capacity(65536);
        let (sta_rx, sta_tx) = cc.into_split();
        let (com_rx, com_tx) = com_recv.into_split();

        /* create a dispatcher instance */
        let dis = Dispatcher {
            buf,
            mac,
            conn,
            com_rx,
            com_tx,
            sta_rx,
            sta_tx,
            udp_rx,
            notify,
        };

        /* start the connection */
        tokio::spawn(dis.run());
        Ok(ret)
    }
}

impl Dispatcher {
    async fn read_buf(rd: &mut OwnedReadHalf) -> IoResult<Option<BytesMut>> {
        let mut buf = BytesMut::with_capacity(65536);
        let len = rd.read_buf(&mut buf).await?;

        /* check for EOF */
        if len == 0 {
            Ok(None)
        } else {
            Ok(Some(buf.split_to(len)))
        }
    }
}

impl Dispatcher {
    async fn run(mut self) {
        self.event_loop().await;
        self.com_tx.shutdown().await.unwrap_or_default();
        self.notify.send((self.mac, ServerEvent::Dropped)).unwrap();
    }

    async fn event_loop(&mut self) {
        loop {
            match self.handle_events().await {
                Ok(None) => break,
                Ok(Some(_)) => continue,
                Err(err) => {
                    log::error!("Connection error from {}: {}", &self.mac, err);
                    break;
                }
            }
        }
    }

    async fn handle_events(&mut self) -> Maybe<Option<()>> {
        tokio::select! {
            ret = self.udp_rx.recv() => {
                if let Some(buf) = ret {
                    self.handle_udp_data(buf).await.map(Some)
                } else {
                    log::info!("UDP_DATA for {} was closed.", &self.mac);
                    Ok(None)
                }
            }
            ret = Self::read_buf(&mut self.com_rx) => {
                if let Some(buf) = ret? {
                    self.handle_com_data(buf).await.map(Some)
                } else {
                    log::info!("COM_RECV for {} was closed.", &self.mac);
                    Ok(None)
                }
            }
            ret = Self::read_buf(&mut self.sta_rx) => {
                if let Some(buf) = ret? {
                    self.buf.extend_from_slice(&buf);
                    self.handle_tcp_recv().await.map(Some)
                } else {
                    log::info!("Station link for {} was closed.", &self.mac);
                    Ok(None)
                }
            }
        }
    }

    async fn handle_tcp_recv(&mut self) -> Unit {
        loop {
            let mem;
            let rlen;

            /* header is 5 bytes long */
            if self.buf.len() < 5 {
                return Ok(());
            }

            /* get the length */
            mem = [self.buf[1], self.buf[2], self.buf[3], self.buf[4]];
            rlen = u32::from_be_bytes(mem) as usize;

            /* check for buffer length */
            if self.buf.len() < rlen + 5 {
                return Ok(());
            }

            /* extract the packet type and body */
            let tag = PacketType::try_from(self.buf[0])?;
            let buf = self.buf.split_to(rlen + 5).split_off(5);

            /* check for packet type */
            match tag {
                PacketType::StaInit => log::warn!("Unexpected STA_INIT packet, dropped."),
                PacketType::UdpData => log::warn!("Unexpected UDP_DATA packet, dropped."),
                PacketType::ComData => self.conn.com_send.lock().await.write_all(&buf).await?,
                PacketType::DspComm => {
                    if let Some(conn) = self.conn.dsp_comm.lock().await.as_mut() {
                        conn.write_all(&buf).await?;
                    } else {
                        log::warn!("DSP_COMM for {} is not ready, dropped.", &self.mac);
                    }
                }
                PacketType::UdpComm => {
                    if let Some(conn) = self.conn.udp_comm.lock().await.as_mut() {
                        conn.write_all(&buf).await?;
                    } else {
                        log::warn!("UDP_COMM for {} is not ready, dropped.", &self.mac);
                    }
                }
            }
        }
    }

    async fn handle_com_data(&mut self, buf: BytesMut) -> Unit {
        self.sta_tx.write_u8(PacketType::ComData as u8).await?;
        self.sta_tx.write_u32(buf.len() as u32).await?;
        self.sta_tx.write_all(&buf).await?;
        Ok(())
    }

    async fn handle_udp_data(&mut self, buf: BytesMut) -> Unit {
        self.sta_tx.write_u8(PacketType::UdpData as u8).await?;
        self.sta_tx.write_u32(buf.len() as u32).await?;
        self.sta_tx.write_all(&buf).await?;
        Ok(())
    }
}

struct PendingConnection {
    mac: MACAddress,
    sta: SocketAddr,
    notify: UnboundedSender<(MACAddress, ServerEvent)>,
    com_recv: Option<TcpStream>,
    com_send: Option<OwnedWriteHalf>,
    dsp_comm: Option<OwnedWriteHalf>,
    udp_comm: Option<OwnedWriteHalf>,
}

impl PendingConnection {
    fn new(
        mac: MACAddress,
        sta: SocketAddr,
        notify: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Self {
        Self {
            mac,
            sta,
            notify,
            com_recv: None,
            com_send: None,
            dsp_comm: None,
            udp_comm: None,
        }
    }
}

impl PendingConnection {
    fn is_ready(&self) -> bool {
        self.com_recv.is_some() && self.com_send.is_some()
    }
}

impl PendingConnection {
    fn with_com_recv(mut self, com_recv: TcpStream) -> Self {
        self.com_recv = Some(com_recv);
        self
    }

    fn with_com_send(mut self, com_send: OwnedWriteHalf) -> Self {
        self.com_send = Some(com_send);
        self
    }

    fn with_dsp_comm(mut self, dsp_comm: OwnedWriteHalf) -> Self {
        self.dsp_comm = Some(dsp_comm);
        self
    }

    fn with_udp_comm(mut self, udp_comm: OwnedWriteHalf) -> Self {
        self.udp_comm = Some(udp_comm);
        self
    }
}

impl PendingConnection {
    fn update_com_recv(&mut self, com_recv: TcpStream) -> bool {
        self.com_recv = Some(com_recv);
        self.is_ready()
    }

    fn update_com_send(&mut self, com_send: OwnedWriteHalf) -> bool {
        self.com_send = Some(com_send);
        self.is_ready()
    }
}

impl PendingConnection {
    async fn solidify(self) -> Maybe<Arc<Connection>> {
        Dispatcher::start(
            self.mac,
            self.sta,
            self.notify,
            self.com_recv.expect("COM_RECV is not ready"),
            self.com_send.expect("COM_SEND is not ready"),
            self.dsp_comm,
            self.udp_comm,
        )
        .await
    }
}

struct Aggregator {
    conn: HashMap<MACAddress, Arc<Connection>>,
    pend: HashMap<MACAddress, PendingConnection>,
}

impl Aggregator {
    fn new() -> Self {
        Self {
            conn: HashMap::new(),
            pend: HashMap::new(),
        }
    }
}

impl Aggregator {
    async fn main() -> Unit {
        let sta = Options::parse().station;
        let (send, recv) = unbounded_channel();

        /* start servers */
        let (udp_recv, com_recv, com_send, dsp_comm, udp_comm) = (
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, UDP_RECV_PORT)).await?,
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, COM_RECV_PORT)).await?,
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, COM_SEND_PORT)).await?,
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DSP_COMM_PORT)).await?,
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, UDP_COMM_PORT)).await?,
        );

        /* start all servers */
        tokio::try_join!(
            tokio::spawn(Self::serve_udp_recv(udp_recv, send.clone())),
            tokio::spawn(Self::serve_com_send(com_send, send.clone())),
            tokio::spawn(Self::serve_com_recv(com_recv, send.clone())),
            tokio::spawn(Self::serve_dsp_comm(dsp_comm, send.clone())),
            tokio::spawn(Self::serve_udp_comm(udp_comm, send.clone())),
            tokio::spawn(Self::new().event_loop(sta, send, recv)),
        )
        .map(|_| ())
        .map_err(as_err)
    }
}

impl Aggregator {
    async fn serve_udp_recv(
        udp: UdpSocket,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        loop {
            let mut buf = BytesMut::with_capacity(65536);
            let (size, addr) = udp.recv_from(&mut buf).await?;

            /* must be an IPv4 connection */
            if let IpAddr::V4(addr) = addr.ip() && let Ok(addr) = arp::lookup(&addr) {
                send.send((addr, ServerEvent::UdpRecv(buf.split_to(size))))?;
            } else {
                log::warn!("Invalid UDP packet from {}, dropped.", addr);
            }
        }
    }

    async fn serve_com_recv(
        srv: TcpListener,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        loop {
            let (conn, addr) = tcp_accept(&srv).await?;
            let addr = addr.ip();

            /* must be an IPv4 connection */
            if let IpAddr::V4(addr) = addr && let Ok(addr) = arp::lookup(&addr) {
                send.send((addr, ServerEvent::ComRecv(conn)))?;
            } else {
                log::warn!("Invalid COM_RECV connection from {}, dropped.", addr);
            }
        }
    }

    async fn serve_com_send(
        srv: TcpListener,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        loop {
            let (conn, addr) = tcp_accept(&srv).await?;
            let addr = addr.ip();

            /* must be an IPv4 connection */
            if let IpAddr::V4(addr) = addr && let Ok(addr) = arp::lookup(&addr) {
                let (_, wr) = conn.into_split();
                send.send((addr, ServerEvent::ComSend(wr)))?;
            } else {
                log::warn!("Invalid COM_SEND connection from {}, dropped.", addr);
            }
        }
    }

    async fn serve_dsp_comm(
        srv: TcpListener,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        loop {
            let (conn, addr) = tcp_accept(&srv).await?;
            let addr = addr.ip();

            /* must be an IPv4 connection */
            if let IpAddr::V4(addr) = addr && let Ok(addr) = arp::lookup(&addr) {
                let (_, wr) = conn.into_split();
                send.send((addr, ServerEvent::DspComm(wr)))?;
            } else {
                log::warn!("Invalid DSP_COMM connection from {}, dropped.", addr);
            }
        }
    }

    async fn serve_udp_comm(
        srv: TcpListener,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        loop {
            let (conn, addr) = tcp_accept(&srv).await?;
            let addr = addr.ip();

            /* must be an IPv4 connection */
            if let IpAddr::V4(addr) = addr && let Ok(addr) = arp::lookup(&addr) {
                let (_, wr) = conn.into_split();
                send.send((addr, ServerEvent::UdpComm(wr)))?;
            } else {
                log::warn!("Invalid UDP_COMM connection from {}, dropped.", addr);
            }
        }
    }
}

impl Aggregator {
    async fn event_loop(
        mut self,
        sta: SocketAddr,
        send: UnboundedSender<(MACAddress, ServerEvent)>,
        mut recv: UnboundedReceiver<(MACAddress, ServerEvent)>,
    ) {
        while let Some((mac, event)) = recv.recv().await {
            if let Err(err) = self.handle_event(mac, sta, event, send.clone()).await {
                self.conn.remove(&mac);
                self.pend.remove(&mac);
                log::error!("Connection error from {}, dropped. Error: {}", mac, err);
            }
        }
    }

    async fn handle_event(
        &mut self,
        mac: MACAddress,
        sta: SocketAddr,
        event: ServerEvent,
        notify: UnboundedSender<(MACAddress, ServerEvent)>,
    ) -> Unit {
        match event {
            ServerEvent::Dropped => {
                if let Some(_) = self.pend.remove(&mac) {
                    log::info!("Connection {} was aborted.", mac);
                    Ok(())
                } else if let Some(_) = self.conn.remove(&mac) {
                    log::info!("Connection {} was closed.", mac);
                    Ok(())
                } else {
                    log::warn!("Dropping non-existing connection from {}.", mac);
                    Ok(())
                }
            }
            ServerEvent::UdpRecv(buf) => {
                if let Some(conn) = self.conn.get(&mac) {
                    conn.udp_send.send(buf)?;
                    Ok(())
                } else {
                    log::warn!("Unexpected UDP packet from {}, dropped.", mac);
                    Ok(())
                }
            }
            ServerEvent::ComRecv(com_recv) => {
                if let Some(_) = self.conn.get(&mac) {
                    log::info!("Cannot reset COM_RECV for connection {}, dropped.", mac);
                    Ok(())
                } else if let Some(conn) = self.pend.get_mut(&mac) {
                    if !conn.update_com_recv(com_recv) {
                        log::info!("Update connection {} with COM_RECV (not yet ready).", mac);
                        Ok(())
                    } else {
                        log::info!("Solidify connection {} with COM_RECV.", mac);
                        let conn = self.pend.remove(&mac).unwrap().solidify().await?;
                        self.conn.insert(mac, conn);
                        Ok(())
                    }
                } else {
                    log::info!("Create new connection {} with COM_RECV.", mac);
                    let conn = PendingConnection::new(mac, sta, notify);
                    self.pend.insert(mac, conn.with_com_recv(com_recv));
                    Ok(())
                }
            }
            ServerEvent::ComSend(com_send) => {
                if let Some(conn) = self.conn.get(&mac) {
                    log::info!("Reset COM_SEND for connection {}.", mac);
                    *conn.com_send.lock().await = com_send;
                    Ok(())
                } else if let Some(conn) = self.pend.get_mut(&mac) {
                    if !conn.update_com_send(com_send) {
                        log::info!("Update connection {} with COM_SEND (not yet ready).", mac);
                        Ok(())
                    } else {
                        log::info!("Solidify connection {} with COM_SEND.", mac);
                        let conn = self.pend.remove(&mac).unwrap().solidify().await?;
                        self.conn.insert(mac, conn);
                        Ok(())
                    }
                } else {
                    log::info!("Create new connection {} with COM_SEND.", mac);
                    let conn = PendingConnection::new(mac, sta, notify);
                    self.pend.insert(mac, conn.with_com_send(com_send));
                    Ok(())
                }
            }
            ServerEvent::DspComm(dsp_comm) => {
                if let Some(conn) = self.conn.get(&mac) {
                    log::info!("Reset DSP_COMM for connection {}.", mac);
                    *conn.dsp_comm.lock().await = Some(dsp_comm);
                    Ok(())
                } else if let Some(conn) = self.pend.get_mut(&mac) {
                    log::info!("Update connection {} with DSP_COMM.", mac);
                    conn.dsp_comm = Some(dsp_comm);
                    Ok(())
                } else {
                    log::info!("Create new connection {} with DSP_COMM.", mac);
                    let conn = PendingConnection::new(mac, sta, notify);
                    self.pend.insert(mac, conn.with_dsp_comm(dsp_comm));
                    Ok(())
                }
            }
            ServerEvent::UdpComm(udp_comm) => {
                if let Some(conn) = self.conn.get(&mac) {
                    log::info!("Reset UDP_COMM for connection {}.", mac);
                    *conn.udp_comm.lock().await = Some(udp_comm);
                    Ok(())
                } else if let Some(conn) = self.pend.get_mut(&mac) {
                    log::info!("Update connection {} with UDP_COMM.", mac);
                    conn.udp_comm = Some(udp_comm);
                    Ok(())
                } else {
                    log::info!("Create new connection {} with UDP_COMM.", mac);
                    let conn = PendingConnection::new(mac, sta, notify);
                    self.pend.insert(mac, conn.with_udp_comm(udp_comm));
                    Ok(())
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Unit {
    ConsoleLogger.init()?;
    Aggregator::main().await?;
    Ok(())
}
