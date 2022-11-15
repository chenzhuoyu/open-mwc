#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logs
import time
import socket
import struct
import asyncio
import hexdump
import logging

from enum import IntEnum
from logging import Logger

from typing import Any
from typing import Optional

from asyncio import Queue
from asyncio import Future
from asyncio import Protocol
from asyncio import TimerHandle
from asyncio import StreamReader
from asyncio import StreamWriter
from asyncio import WriteTransport

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

from miot import MiotRPC
from miot import RPCRequest

from mwc1x import StaticKey
from mwc1x import SessionKey
from mwc1x import DeviceTag
from mwc1x import Configuration
from mwc1x import DeviceConfiguration

from props import Properties
from props import ValueProperty

from props import OTAPIID
from props import CameraSIID
from props import DetectionPIID
from props import CameraMiscPIID
from props import CameraControlPIID
from props import DetectionMiscPIID

LOG_FMT         = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL       = logging.DEBUG

REQ_VER         = 2
CAM_VER         = '1.2.1_1981'

COM_RX_PORT     = 32295
STATION_PORT    = 6282
STATION_BIND    = '0.0.0.0'

STREAM_MAGIC    = 0x55aa55aa
SENDER_MAGIC    = 0xff00aaaa
RECVER_MAGIC    = 0xff005555
MALPHA_MAGIC    = 0xaabb1122

class FrameCmd(IntEnum):
    Video01     = 0x01
    VideoHEVC   = 0x02
    Video03     = 0x03
    Video04     = 0x04
    Video05     = 0x05
    Image06     = 0x06
    Image07     = 0x07
    Video08     = 0x08
    Video09     = 0x09
    Video0A     = 0x0a
    Video0B     = 0x0b
    Video0C     = 0x0c
    Video0D     = 0x0d
    Video0E     = 0x0e
    Video0F     = 0x0f
    Audio10     = 0x10
    Audio11     = 0x11
    Audio12     = 0x12
    Audio13     = 0x13
    Audio14     = 0x14
    Audio15     = 0x15
    Audio16     = 0x16
    Audio17     = 0x17
    Audio18     = 0x18
    Audio19     = 0x19
    Audio1A     = 0x1a
    Audio1B     = 0x1b
    Audio1C     = 0x1c
    Audio1D     = 0x1d
    Audio1E     = 0x1e
    Audio1F     = 0x1f
    OTADebug    = 0x20
    SN          = 0x40
    Pipeline    = 0xc1
    CmdPipeline = 0xc2
    # Unknown1  = 0xd0  # did nothing after decrypting the buffer
    Nested      = 0xe0

class PacketCmd(IntEnum):
    WakeupMultiFn                   = 0x0c
    Factory                         = 0x0f
    Wakeup                          = 0x10
    PowerDown                       = 0x11
    Heartbeat                       = 0x12
    PIR                             = 0x13
    Tamper                          = 0x14
    StartStream                     = 0x15
    StopStream                      = 0x16
    ButtonPush                      = 0x17
    SystemStart                     = 0x18
    GetWiFiSignal                   = 0x19
    WiFiSignal                      = 0x1a
    GetBatteryStat                  = 0x1b
    BatteryStat                     = 0x1c
    LowPower                        = 0x1d
    ExternalPower                   = 0x1e
    GetConfigInfo                   = 0x1f
    ConfigInfo                      = 0x20
    ConfigAck                       = 0x21
    TimeSync                        = 0x22
    Unbind                          = 0x23
    ArmingStatus                    = 0x24
    SetArmingStatus                 = 0x25
    GetArmingStatus                 = 0x26
    SetSensitivity                  = 0x27
    Sensitivity                     = 0x28
    GetSensitivity                  = 0x29
    RecordAck                       = 0x2a
    DeviceInfo                      = 0x2b
    ResetDevice                     = 0x2c
    MCUVersion                      = 0x2d
    DebugLog                        = 0x2e
    GetSyslog                       = 0x2f
    UpgradeWiFi                     = 0x30
    UpgradeDSP                      = 0x31
    SetMAC                          = 0x32
    GetMAC                          = 0x33
    SetSN                           = 0x34
    GetSN                           = 0x35
    SetPIRWakeupMode                = 0x36
    PushDeviceUID                   = 0x37
    SetPIRDelay                     = 0x38
    PIRDelay                        = 0x39
    GetPIRDelay                     = 0x3a
    SetTamperState                  = 0x3b
    RequestUSBState                 = 0x3c
    GetTamperState                  = 0x3d
    SetTamperWakeup                 = 0x3e
    GetDeviceTemperature            = 0x3f
    SetBreathLightSWI               = 0x40
    SetRGBLightSWI                  = 0x41
    ReconfigureNetwork              = 0x42
    TestMode                        = 0x43
    SetPIR2Sensitivity              = 0x44
    PIR2Sensitivity                 = 0x45
    GetPIR2Sensitivity              = 0x46
    Shutdown                        = 0x47
    SetPIRQuiescentTime             = 0x48
    SetMicrowaveQuiescentTime       = 0x49
    PIRQuiescentTime                = 0x4a
    MicrowaveQuiescentTime          = 0x4b
    UserAnswerNotify                = 0x4c
    GetTestModeState                = 0x4d
    BatteryInOutState               = 0x4e
    SetPIRZone                      = 0x4f
    PIRZone                         = 0x50
    PushRtSyslog                    = 0x51
    SetGSensorSwitch                = 0x52
    GSensorSwitch                   = 0x53
    SetGSensorSensitivity           = 0x54
    GSensorSensitivity              = 0x55
    GSensorEvent                    = 0x56
    AgingMode                       = 0x5a
    SpeedTest                       = 0x5b
    ControlLED                      = 0x5c
    UARTProxyData                   = 0x64
    BreathLEDSwitch                 = 0x65
    RGBLEDSwitch                    = 0x66
    MicrowaveEvent                  = 0x67
    ExchangeBindInfo                = 0x12c
    ConfirmBindInfo                 = 0x12d
    BindResult                      = 0x12e
    StaticIPAssigned                = 0x12f

class Frame:
    type    : FrameCmd
    index   : int
    payload : bytes

    def __init__(self, ty: FrameCmd, index: int, payload: bytes):
        self.type    = ty
        self.index   = index
        self.payload = payload

    def __repr__(self) -> str:
        return '\n'.join([
            'Frame {',
            '    type    : %s' % self.type,
            '    index   : %d' % self.index,
            '    payload : ' + (self.payload and self._dump_payload() or '(empty)'),
            '}'
        ])

    def _dump_payload(self) -> str:
        return ('\n' + ' ' * 14).join(hexdump.hexdump(self.payload, result = 'generator'))

class Packet:
    ver   : int
    cmd   : PacketCmd
    data  : bytes
    token : bytes

    def __init__(self, ver: int, cmd: PacketCmd, token: bytes, data: bytes = b''):
        self.cmd   = cmd
        self.ver   = ver
        self.data  = data
        self.token = token

    def __repr__(self) -> str:
        return '\n'.join([
            'Packet {',
            '    ver   : %d' % self.ver,
            '    cmd   : %s (%#04x)' % (self.cmd, self.cmd),
            '    token : ' + self.token.hex(),
            '    data  : ' + (self.data and self._dump_data() or '(empty)'),
            '}',
        ])

    def _dump_data(self) -> str:
        return ('\n' + ' ' * 12).join(hexdump.hexdump(self.data, result = 'generator'))

class FrameSerdes:
    @staticmethod
    async def read(rd: StreamReader, key: SessionKey) -> Frame:
        hdr = await rd.readexactly(24)
        magic, ty, seq, size = struct.unpack('IxBH4xH10x', hdr)

        # check for magic number
        if magic != STREAM_MAGIC:
            raise ValueError('invalid packet header: ' + hdr.hex(' '))

        # calculate padded size
        if not (size & 0x0f):
            rlen = size
        else:
            rlen = (size & 0xfff0) + 0x10

        # read and decrypt the frame
        rbuf = await rd.readexactly(rlen)
        return Frame(FrameCmd(ty), seq, key.decrypt(rbuf, size))

class PacketSerdes:
    @staticmethod
    async def read(rd: StreamReader, *, key: Optional[SessionKey] = None) -> Packet:
        data = await rd.readexactly(4)
        magic, = struct.unpack('I', data)

        # check packet magic number
        while len(data) < 1024 and magic != RECVER_MAGIC:
            data += await rd.readexactly(1)
            magic, = struct.unpack_from('I', data, -4)

        # still not synchronizing
        if magic != RECVER_MAGIC:
            raise ValueError('cannot find synchronization point: ' + repr(data))

        # check for skipped garbage data
        if len(data) != 4:
            logging.getLogger('mwc11.serdes').warning(
                'Skipping garbage data:\n' +
                ('\n' + ' ' * 4).join(hexdump.hexdump(data[:-4], result = 'generator'))
            )

        # read the remaining header data
        data = await rd.readexactly(28)
        cmd, size, ver = struct.unpack('III', data[:12])

        # command and signature
        ext = b''
        cmd = PacketCmd(cmd)

        # no data
        if size == 0:
            return Packet(ver, cmd, data[12:])

        # special case of the initial key exchange packet
        if cmd == PacketCmd.ExchangeBindInfo:
            ext = await rd.readexactly(140)
            key, size = SessionKey(ext[:16]), struct.unpack('136xI', ext)[0]

        # unencrypted data, just read the body
        if key is None:
            return Packet(ver, cmd, data[12:], await rd.readexactly(size))

        # add padding size, read and decrypt the body
        rbuf = await rd.readexactly((((size - 1) >> 4) + 1) << 4)
        return Packet(ver, cmd, data[12:], ext + key.decrypt(rbuf, size))

    @staticmethod
    def write(wr: StreamWriter, frame: Packet, *, key: Optional[SessionKey] = None):
        mm = struct.pack('IIII16s', SENDER_MAGIC, frame.cmd, len(frame.data), frame.ver, frame.token)
        wr.write(mm + (frame.data if key is None else key.encrypt(frame.data)))

class FrameDemux:
    log    : Logger
    vidx   : int
    vbuf   : bytes
    frames : Queue

    def __init__(self):
        self.log    = logging.getLogger('mwc11.demux')
        self.vidx   = -1
        self.vbuf   = b''
        self.frames = Queue()

    def _push_video_frame(self):
        self.frames.put_nowait(Frame(FrameCmd.VideoHEVC, self.vidx, self.vbuf))

    def _check_video_frame(self, frame: Frame):
        if self.vidx != frame.index - 1:
            self.log.warning('Frame dropping: %d - %d', self.vidx, frame.index)

    def _parse_video_frame(self, frame: Frame):
        if self.vidx == frame.index:
            self.vbuf += frame.payload
        else:
            self._check_video_frame(frame)
            self._push_video_frame()
            self.vidx = frame.index
            self.vbuf = frame.payload

    def _video_stop(self):
        if self.vbuf and self.vidx >= 0:
            self._push_video_frame()
            self.vidx = -1
            self.vbuf = b''

    def _video_start(self):
        self.vidx = 0
        self.vbuf = b''

    def _handle_signaling_frame(self, frame: Packet):
        if frame.cmd == PacketCmd.StopStream:
            self._video_stop()
        elif frame.cmd == PacketCmd.StartStream:
            self._video_start()

    def add_streaming_frame(self, frame: Frame):
        if self.vidx >= 0:
            if frame.type == FrameCmd.Nested:
                self.frames.put_nowait(frame)
            elif frame.type == FrameCmd.VideoHEVC:
                self._parse_video_frame(frame)
            else:
                self.log.warning('Dropping unsupported stream frame: %r', frame)

    def add_signaling_frame(self, frame: Packet):
        self._handle_signaling_frame(frame)
        self.frames.put_nowait(frame)

class MuxType(IntEnum):
    StaInit = 0
    StaConn = 1
    ComData = 2
    DspComm = 3
    UdpData = 4,

class MuxFrame:
    ty  : MuxType
    buf : bytes

    def __init__(self, ty: MuxType, buf: bytes = b''):
        self.ty  = ty
        self.buf = buf

    def __repr__(self) -> str:
        return '\n'.join([
            'MuxFrame {',
            '    ty  = %s' % self.ty,
            '    buf = %s' % (self.buf and self._dump_buf() or '(empty)'),
            '}',
        ])

    def _dump_buf(self) -> str:
        return ('\n' + ' ' * 10).join(hexdump.hexdump(self.buf, result = 'generator'))

    def to_bytes(self) -> bytes:
        return struct.pack('>IB', self.ty, len(self.buf)) + self.buf

    @classmethod
    async def read(cls, rd: StreamReader) -> 'MuxFrame':
        hdr = await rd.readexactly(5)
        tyv, nb = struct.unpack('>BI', hdr)

        # parse the mux type, and read the body
        try:
            ty = MuxType(tyv)
        except ValueError:
            raise ValueError('invalid packet type %#04x') from None
        else:
            return cls(ty, await rd.readexactly(nb))

class MuxTransport(WriteTransport):
    ty  : MuxType
    wr  : StreamWriter
    log : Logger

    def __init__(self, ty: MuxType, wr: StreamWriter):
        self.ty  = ty
        self.wr  = wr
        self.log = logging.getLogger('mwc11.mux')
        super().__init__(None)

    def get_extra_info(self, name: str, default: Any = None):
        return self.wr.transport.get(name, default)

    def is_closing(self):
        return self.wr.transport.is_closing()

    def close(self):
        self.wr.transport.close()

    def set_write_buffer_limits(self, high: Optional[int] = None, low: Optional[int] = None):
        self.wr.transport.set_write_buffer_limits(high, low)

    def get_write_buffer_size(self) -> int:
        return self.wr.transport.get_write_buffer_size()

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return self.wr.transport.get_write_buffer_limits()

    def write(self, data: bytes):
        t = time.monotonic_ns()
        self.wr.write(struct.pack('>BI', self.ty, len(data)) + data)
        self.log.debug('Packet %s was transmitted in %.3fms.', self.ty, (time.monotonic_ns() - t) / 1e6)

    def write_eof(self):
        self.wr.transport.write_eof()

    def can_write_eof(self) -> bool:
        return self.wr.transport.can_write_eof()

    def abort(self):
        self.wr.transport.abort()

class MuxConnection:
    rd  : StreamReader
    wr  : StreamWriter
    log : Logger
    mux : dict[MuxType, tuple[StreamReader, StreamWriter]]

    def __init__(self, rd: StreamReader, wr: StreamWriter):
        self.rd  = rd
        self.wr  = wr
        self.log = logging.getLogger('mwc11.mux')
        self.mux = { t: self._new_chan(t, wr) for t in MuxType }

    @property
    def closed(self) -> bool:
        return not self.mux

    @staticmethod
    def _new_chan(ty: MuxType, wr: StreamWriter) -> tuple[StreamReader, StreamWriter]:
        rd = StreamReader(loop = asyncio.get_running_loop())
        wr = StreamWriter(MuxTransport(ty, wr), Protocol(), rd, asyncio.get_running_loop())
        return rd, wr

    def _flush_mux(self):
        for rd, wr in self.mux.values():
            rd.feed_eof()
            wr.close()

    def close(self):
        if self.mux:
            self._flush_mux()
            self.mux.clear()
            self.wr.close()

    def reader(self, ty: MuxType) -> StreamReader:
        if not self.mux:
            raise ConnectionResetError('mux connection closed')
        elif ty not in self.mux:
            raise ValueError('invalid frame type %s' % ty)
        else:
            return self.mux[ty][0]

    def writer(self, ty: MuxType) -> StreamWriter:
        if not self.mux:
            raise ConnectionResetError('mux connection closed')
        elif ty not in self.mux:
            raise ValueError('invalid frame type %s' % ty)
        else:
            return self.mux[ty][1]

    async def run(self):
        while self.mux:
            try:
                req = await MuxFrame.read(self.rd)
            except EOFError:
                if self.mux:
                    self.close()
                    self.log.error('EOF when reading frames, closing connection.')
            except Exception as e:
                if self.mux:
                    self.close()
                    self.log.warning('Error when reading frames, closing connection. Error: %s', e)
            else:
                if self.mux:
                    if req.ty not in self.mux:
                        self.log.warning('Invalid frame type %s, dropped.', req.ty)
                    else:
                        self.log.debug('Received a packet with type %s.', req.ty.name)
                        self.mux[req.ty][0].feed_data(req.buf)

class SessionTokens:
    tx   : bytes
    rx   : bytes
    key  : SessionKey
    addr : str

    def __init__(self, key: SessionKey, local: str, remote: str):
        self.tx   = b''
        self.rx   = key.frame_token(remote, COM_RX_PORT)
        self.key  = key
        self.addr = local

    def update(self, port: int):
        self.tx = self.key.frame_token(self.addr, port)

class CommandTransport:
    key    : SessionKey
    mux    : MuxConnection
    token  : SessionTokens
    waiter : dict[PacketCmd, tuple[Future[Packet], TimerHandle]]

    def __init__(self, key: SessionKey, mux: MuxConnection, token: SessionTokens):
        self.key    = key
        self.mux    = mux
        self.token  = token
        self.waiter = {}

    def _drop_timer(self, cmd: PacketCmd):
        if cmd in self.waiter:
            self.waiter.pop(cmd)[1].cancel()

    def _fire_timeout(self, cmd: PacketCmd):
        if cmd in self.waiter:
            fut, _ = self.waiter.pop(cmd)
            fut.cancelled() or fut.set_exception(TimeoutError)

    def _send_request(self, req: Packet, resp: PacketCmd, timeout: float) -> Future[Packet]:
        com = self.mux.writer(MuxType.ComData)
        fut = asyncio.get_running_loop().create_future()
        tmr = asyncio.get_running_loop().call_later(timeout, self._fire_timeout, resp)
        self.waiter[resp] = (fut, tmr)
        PacketSerdes.write(com, req, key = self.key)
        fut.add_done_callback(lambda _: self._drop_timer(resp))
        return fut

    def post(self, cmd: PacketCmd, *, data: bytes = b''):
        req = Packet(REQ_VER, cmd, self.token.tx, data)
        PacketSerdes.write(self.mux.writer(MuxType.ComData), req, key = self.key)

    def send(self, req: PacketCmd, resp: PacketCmd, *, data: bytes = b'', timeout: float = 1.0) -> Future[Packet]:
        if resp in self.waiter:
            raise RuntimeError('multiple waits on the same command: ' + str(resp))
        else:
            return self._send_request(Packet(REQ_VER, req, self.token.tx, data), resp, timeout)

    def handle_packet(self, p: Packet) -> bool:
        cmd = p.cmd
        fut, tmr = self.waiter.pop(cmd, (None, None))

        # check if it is the expected packet
        if tmr is None:
            return False

        # stop the timer, and resolve the future
        fut.set_result(p)
        tmr.cancel()
        return True

class Channel(IntEnum):
    ComSend = 0
    ComRecv = 1
    DspComm = 2
    UdpSend = 3

class ChannelEvent(IntEnum):
    Connected    = 0,
    Disconnected = 1

class Connection:
    mac            : bytes
    log            : Logger
    rpc            : MiotRPC
    mux            : MuxConnection
    dev            : DeviceConfiguration
    port           : CommandTransport
    props          : Properties
    demux          : FrameDemux
    tokens         : SessionTokens
    event_listener : Optional['EventListener']

    class EventListener:
        def on_configuration_changed(self):
            raise NotImplementedError('on_configuration_changed()')

    def __init__(self,
        mac            : bytes,
        rpc            : MiotRPC,
        mux            : MuxConnection,
        dev            : DeviceConfiguration,
        props          : Properties,
        tokens         : SessionTokens,
        *,
        event_listener : Optional[EventListener] = None,
    ):
        self.mac            = mac
        self.rpc            = rpc
        self.mux            = mux
        self.dev            = dev
        self.log            = logging.getLogger('mwc11.conn.' + mac.hex('-'))
        self.port           = CommandTransport(dev.session_key, mux, tokens)
        self.demux          = FrameDemux()
        self.props          = props
        self.tokens         = tokens
        self.event_listener = event_listener

    async def _cmd_nop(self, _: Packet):
        pass

    async def _cmd_heartbeat(self, p: Packet):
        data = memoryview(p.data)
        level, rssi, volt = struct.unpack('I4xi2xH', data[:16])

        # update properties
        self.props[CameraSIID.Misc, CameraMiscPIID.RSSI] = rssi
        self.props[CameraSIID.Misc, CameraMiscPIID.BatteryLevel] = level
        self.props[CameraSIID.Misc, CameraMiscPIID.BatteryVoltage] = volt

    async def _cmd_push_device_uid(self, p: Packet):
        self.dev.tag = DeviceTag.parse(p.data.rstrip(b'\x00').decode('utf-8'))
        self.log.debug('Device tag was updated.')

        # notify the event listener if
        if self.event_listener:
            self.event_listener.on_configuration_changed()

    __command_handlers__ = {
        PacketCmd.Heartbeat       : _cmd_heartbeat,
        PacketCmd.SystemStart     : _cmd_nop,
        PacketCmd.PushDeviceUID   : _cmd_push_device_uid,
        PacketCmd.RequestUSBState : _cmd_nop,
    }

    async def _keepalive(self):
        while not self.mux.closed:
            did = self.dev.tag.did
            rssi = await self.props[CameraSIID.Misc, CameraMiscPIID.RSSI].read()

            # send the keep-alive
            try:
                await self.rpc.send('_sync.subdev_keep_alive', {'did': did, 'rssi': rssi}, timeout = 1.0)
            except TimeoutError:
                self.log.warning('Keepalive timeout, try again.')
                continue

            # wait for the next keep-alive
            for _ in range(10):
                if not self.mux.closed:
                    await asyncio.sleep(1.0)
                else:
                    break

    async def _handle_events(self):
        while True:
            try:
                rd = self.mux.reader(MuxType.StaConn)
                chan, event, port, addr = struct.unpack('BBH4s', await rd.readexactly(8))
            except EOFError:
                break

            # check the channel and event
            try:
                chan = Channel(chan)
                event = ChannelEvent(event)
            except ValueError:
                self.log.error('Invalid event data, dropped.')
                continue

            # log the event
            addr = socket.inet_ntop(socket.AF_INET, addr)
            self.log.debug('Received event from %s:%d. event = %s.%s', addr, port, chan.name, event.name)

            # handle the events
            match chan, event:
                case Channel.ComSend, ChannelEvent.Connected:
                    self.log.debug('Update COM_SEND channel to %s:%d.', addr, port)
                    self.tokens.update(port)

    async def _handle_frames(self):
        while True:
            try:
                rd = self.mux.reader(MuxType.UdpData)
                req = await FrameSerdes.read(rd, self.dev.session_key)
            except EOFError:
                break

            # TODO: this
            if req.type == FrameCmd.Nested:
                print(req)

    async def _handle_requests(self):
        while True:
            try:
                rd = self.mux.reader(MuxType.ComData)
                req = await PacketSerdes.read(rd, key = self.dev.session_key)
            except EOFError:
                break

            # verify token
            if req.token != self.tokens.rx:
                self.log.warning('Cannot verify token, dropped. packet = %s', req)
                continue

            # attempt to handle the command response
            if self.port.handle_packet(req):
                self.log.debug('Received response: %s', req)
                continue

            # handle the command, if possible
            if req.cmd in self.__command_handlers__:
                await self.__command_handlers__[req.cmd](self, req)
            else:
                self.log.debug('Unhandled command %s, dropped.', req.cmd)

    async def run(self):
        did = self.dev.tag.did
        self.log.info('Camera is initializing ...')

        # send the device information
        while True:
            try:
                await self.rpc.send('_sync.subdev_upinfo', did = did, fw_ver = CAM_VER, timeout = 1.0)
            except TimeoutError:
                self.log.warning('State transition timeout, try again.')
            else:
                break

        # mark the online state
        await self.rpc.send('properties_changed', {
            'did'   : did,
            'siid'  : CameraSIID.Misc,
            'piid'  : CameraMiscPIID.Online,
            'value' : True,
        })

        # start all the tasks
        fut = [
            self._keepalive(),
            self._handle_events(),
            self._handle_frames(),
            self._handle_requests(),
        ]

        # wait for them to complete
        self.log.info('Camera is now online.')
        await asyncio.gather(*fut)

class Instance:
    mac   : bytes
    dev   : DeviceConfiguration
    conn  : Optional[Connection]
    props : Properties

    def __init__(self, mac: bytes, dev: DeviceConfiguration):
        self.mac   = mac
        self.dev   = dev
        self.conn  = None
        self.props = Properties(
            ValueProperty ( CameraSIID.Control       , CameraControlPIID.PowerSwitch   , True   ),
            ValueProperty ( CameraSIID.Control       , CameraControlPIID.Flip          , 0      ),
            ValueProperty ( CameraSIID.Control       , CameraControlPIID.NightVision   , 2      ),
            ValueProperty ( CameraSIID.Control       , CameraControlPIID.OSDTimestamp  , True   ),
            ValueProperty ( CameraSIID.Control       , CameraControlPIID.WDR           , True   ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.LED              , True   ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.LiveStream       , 0      ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.Distortion       , True   ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.BatteryLevel     , 0      ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.Resolution       , 0      ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.RSSI             , 0      ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.Online           , False  ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.PowerFreq        , 50     ),
            ValueProperty ( CameraSIID.Misc          , CameraMiscPIID.BatteryVoltage   , 0      ),
            ValueProperty ( CameraSIID.DetectionMisc , DetectionMiscPIID.RecordFreq    , 0      ),
            ValueProperty ( CameraSIID.DetectionMisc , DetectionMiscPIID.RecordLimit   , 10     ),
            ValueProperty ( CameraSIID.DetectionMisc , DetectionMiscPIID.Enabled       , True   ),
            ValueProperty ( CameraSIID.Detection     , DetectionPIID.Enabled           , True   ),
            ValueProperty ( CameraSIID.Detection     , DetectionPIID.RecordInterval    , 30     ),
            ValueProperty ( CameraSIID.Detection     , DetectionPIID.RecordSensitivity , 100    ),
            ValueProperty ( CameraSIID.OTA           , OTAPIID.Progress                , 100    ),
            ValueProperty ( CameraSIID.OTA           , OTAPIID.State                   , 'idle' ),
        )

    @classmethod
    def build(cls, cfg: Configuration) -> dict[bytes, 'Instance']:
        return {
            mac: cls(mac, dev)
            for mac, dev in cfg.devices.items()
        }

class DeviceBinder:
    mac: bytes
    log: Logger
    rpc: MiotRPC
    mux: MuxConnection
    cfg: Configuration
    key: Optional[StaticKey]

    # curve and key size
    __curve__    = SECP256R1()
    __key_size__ = (__curve__.key_size * 2) // 8 + 1

    def __init__(self,
        mac: bytes,
        rpc: MiotRPC,
        mux: MuxConnection,
        cfg: Configuration,
    ):
        self.mac = mac
        self.rpc = rpc
        self.mux = mux
        self.cfg = cfg
        self.key = None
        self.log = logging.getLogger('mwc11.bind')

    def _drop_key(self):
        if self.key is not None:
            self.cfg.remove_static_key(self.key)

    async def _wait_cmd(self, *cmds: PacketCmd, key: Optional[SessionKey] = None) -> Packet:
        while True:
            rd = self.mux.reader(MuxType.ComData)
            req = await PacketSerdes.read(rd, key = key)

            # wait for the expected command
            if req.cmd in cmds:
                return req
            else:
                self.log.debug('Dropping unexpected packet: %s', req)

    async def _bind_device(self) -> Instance:
        req = await self._wait_cmd(PacketCmd.ExchangeBindInfo)
        pkey, skid = struct.unpack('128s4xI4x', req.data[:140])

        # store the static key
        self.key = skid
        self.log.info('Start binding procedure for "%s".', self.mac.hex(':'))

        # perform ECDHE key exchange
        pkey = pkey[:self.__key_size__]
        nkey = generate_private_key(self.__curve__)
        rkey = nkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        skey = nkey.exchange(ECDH(), EllipticCurvePublicKey.from_encoded_point(self.__curve__, pkey))

        # check for static key ID
        if skid not in self.cfg.static_keys:
            raise ValueError('static key %d not found' % skid)

        # calculate the AES key
        salt = StaticKey(skid).key.encode('utf-8')
        ekey = SessionKey(HKDF(SHA256(), 16, salt, b'xmitech-auth-srv').derive(skey))

        # parse the RPC request
        req = RPCRequest.from_bytes(req.data[140:])
        self.log.info('Requesting binding information for "%s".', self.mac.hex(':'))

        # proxy the RPC request
        resp = await self.rpc.proxy(req)
        error = resp.error

        # check for RPC errors
        if error is not None:
            self.log.warning('RPC error when requesting binding information. Error: %s', resp.error)

        # construct the response
        data = resp.to_bytes()
        data = struct.pack('128sIIII4x', pkey, len(pkey), len(data) + 12, MALPHA_MAGIC, len(data)) + data
        sbuf = struct.pack('III20x128sI', SENDER_MAGIC, PacketCmd.ExchangeBindInfo, len(data) + 132, rkey, len(rkey))

        # send it back
        self.mux.writer(MuxType.ComData).write(sbuf + ekey.encrypt(data))
        self.log.info('Binding information was sent to "%s", waiting for response.', self.mac.hex(':'))

        # wait for the response
        req = await asyncio.wait_for(
            fut     = self._wait_cmd(PacketCmd.BindResult, PacketCmd.ConfirmBindInfo, key = ekey),
            timeout = 10.0,
        )

        # should not occure here, but still possible, so handle it
        if req.cmd == PacketCmd.BindResult:
            self.log.warning('Premature bind result, treated as error: %s', req)
            raise ValueError('unexpected packet')

        # parse the packet
        buf = memoryview(req.data)
        xkey, buf = bytes(buf[:128]), buf[128:]
        xlen, buf = struct.unpack_from('I', buf, 0)[0], buf[4:]
        desc, buf = bytes(buf[:16]), buf[16:]
        akey, buf = bytes(buf[:16]), buf[16:]
        info, buf = bytes(buf[:256]), buf[256:]
        rlen, buf = struct.unpack_from('I', buf, 0)[0], buf[4:]

        # check for remaining data
        if len(buf) != rlen:
            self.log.warning('Discarding garbage data:\n%s', hexdump.hexdump(buf[rlen:], 'return'))

        # check the received server public bytes
        if xkey[:xlen] != rkey:
            raise ValueError('server public key mismatch.')

        # parse the device tag and model
        mod = desc.rstrip(b'\x00').decode('utf-8')
        tag = DeviceTag.parse(info.rstrip(b'\x00').decode('utf-8'))

        # parse the RPC request
        req = RPCRequest.from_bytes(bytes(buf))
        self.log.info('Confirming binding information for "%s".', self.mac.hex(':'))

        # proxy the RPC request
        resp = await self.rpc.proxy(req)
        error = resp.error

        # check for RPC errors
        if error is not None:
            self.log.warning('RPC error when confirming binding information. Error: %s', resp.error)

        # build the frame
        data = resp.to_bytes()
        data = struct.pack('II4x', MALPHA_MAGIC, len(data)) + data
        data = Packet(0, PacketCmd.ConfirmBindInfo, bytes(16), data)

        # send it back
        PacketSerdes.write(self.mux.writer(MuxType.ComData), data, key = ekey)
        self.log.info('Binding confirmation was sent to "%s", waiting for response.', self.mac.hex(':'))

        # wait for bind result
        req = await self._wait_cmd(PacketCmd.BindResult, key = ekey)
        code, = struct.unpack('i', req.data)

        # check for error code
        if code != 0:
            raise ValueError('bind error with code %d' % code)

        # bind successful
        self.log.info('Bind successful.')
        return Instance(self.mac, DeviceConfiguration(tag, mod, akey, StaticKey(skid), ekey))

    async def bind(self) -> Instance:
        try:
            return await self._bind_device()
        finally:
            self._drop_key()

class MWC11:
    log: Logger
    rpc: MiotRPC
    cfg: Configuration
    cam: dict[bytes, Instance]

    class EventListener(Connection.EventListener):
        cfg: Configuration

        def __init__(self, cfg: Configuration):
            self.cfg = cfg

        def on_configuration_changed(self):
            self.cfg.save()

    def __init__(self, rpc: MiotRPC, cfg: Configuration):
        self.cfg = cfg
        self.rpc = rpc
        self.log = logging.getLogger('mwc11.station')
        self.cam = Instance.build(cfg)

    def find(self, did: str) -> Optional[Instance]:
        for cam in self.cam.values():
            if cam.dev.tag.did == did:
                return cam
        else:
            return None

    async def serve_forever(self, host: str = STATION_BIND, port: int = STATION_PORT):
        srv = await asyncio.start_server(self._serve_connection, host = host, port = port)
        await srv.serve_forever()

    async def _serve_connection(self, rd: StreamReader, wr: StreamWriter):
        try:
            await self._handle_connection(rd, wr)
        except Exception:
            self.log.exception('Exception when handling connection:')

    async def _handle_connection(self, rd: StreamReader, wr: StreamWriter):
        mux = MuxConnection(rd, wr)
        asyncio.get_running_loop().create_task(mux.run())

        # read the MAC address, local address and remote address
        buf = await mux.reader(MuxType.StaInit).readexactly(14)
        mac, local, remote = struct.unpack('>6s4s4s', buf)

        # find the camera instance
        cam = self.cam.get(mac)
        local = socket.inet_ntop(socket.AF_INET, local)
        remote = socket.inet_ntop(socket.AF_INET, remote)

        # check for MAC addressm
        if cam is None:
            try:
                self.cam[mac] = cam = await DeviceBinder(mac, self.rpc, mux, self.cfg).bind()
                self.cfg.add_device(mac, cam.dev)
            except ValueError as e:
                mux.close()
                self.log.error('Cannot register device "%s": %s', mac.hex(':'), e)
                return
            except TimeoutError:
                mux.close()
                self.log.error('Cannot register device "%s": timeout.', mac.hex(':'))
                return

        # check for duplicated connections
        if cam.conn is not None:
            mux.close()
            self.log.warning('Duplicated connection from "%s", dropped.', mac.hex(':'))
            return

        # create a new connection
        conn = Connection(
            mac            = mac,
            mux            = mux,
            dev            = cam.dev,
            rpc            = self.rpc,
            props          = cam.props,
            tokens         = SessionTokens(cam.dev.session_key, local, remote),
            event_listener = self.EventListener(self.cfg),
        )

        # register the connection, and mark online
        cam.conn = conn
        cam.props[CameraSIID.Misc, CameraMiscPIID.Online] = True
        self.log.info('New connection from "%s".', mac.hex(':'))

        # serve the connection
        try:
            await conn.run()
        except Exception:
            self.log.exception('Unhandled error from connection "%s":', mac.hex(':'))
        else:
            self.log.info('Connection from "%s" closed.', mac.hex(':'))

        # mark offline, unregister and close the connection
        cam.props[CameraSIID.Misc, CameraMiscPIID.Online] = False
        cam.conn = None
        mux.close()

async def main():
    pass

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
