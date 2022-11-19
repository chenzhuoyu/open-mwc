#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
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

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

from miio import Payload
from miio import MACAddress

from miio import RPCError
from miio import RPCRequest
from miio import RPCResponse

from config import DeviceTag
from config import StaticKey
from config import SessionKey
from config import Configuration
from config import ConfigurationFile
from config import DeviceConfiguration

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

class Device:
    online: bool

class Binder:
    rnd: bytes
    mac: bytes
    log: Logger
    mux: MuxConnection

    # curve and key size
    __curve__    = SECP256R1()
    __key_size__ = (__curve__.key_size * 2) // 8 + 1

    class Retry(Exception):
        pass

    def __init__(self, mac: bytes, mux: MuxConnection):
        self.mac = mac
        self.mux = mux
        self.key = None
        self.rnd = os.urandom(16)
        self.log = logging.getLogger('mwc11.bind')

    def _mk_hash(self, did: str, psk: bytes, rand: bytes) -> str:
        key = HKDF(SHA256(), 16, did.encode('utf-8'), b'secure-proxy-auth').derive(psk)
        return Cipher(AES128(key), ECB()).encryptor().update(rand).hex()

    def _exec_rpc(self, req: RPCRequest, dev: DeviceConfiguration) -> RPCResponse:
        func = self.__rpc_handler__.get(req.method)
        self.log.debug('Executing RPC request: %s', req)

        # check for method name
        if func is None:
            self.log.warning('Unsupported RPC method: %s', req.method)
            return RPCResponse(req.id, error = RPCError(RPCError.Code.InvalidParameters, 'unknown method'))

        # execute the RPC handler
        resp = func(self, req, dev)
        self.log.debug('RPC response: %s', resp)
        return resp

    def _exec_auth(self, req: RPCRequest, dev: DeviceConfiguration) -> RPCResponse:
        rid = req.id
        psk = dev.tag.psk

        # parse the arguments
        try:
            did = Payload.type_checked(req.args['did'], str)
            name = Payload.type_checked(req.args['model'], str)
            rand = bytes.fromhex(Payload.type_checked(req.args['random_dev'], str))
        except (KeyError, ValueError):
            self.log.error('Invalid RPC request: %s', req)
            return RPCResponse(rid, error = RPCError(RPCError.Code.InvalidParameters, "invalid args"))

        # compute the response hash
        resp = self.rnd.hex()
        conf = self._mk_hash(did, psk, rand)
        self.log.debug('Authentication from device %s. model = %s', did, name)

        # construct the response
        return RPCResponse(rid, data = {
            "did"            : did,
            "random_server"  : resp,
            "confirm_server" : conf,
        })

    def _exec_bind(self, req: RPCRequest, dev: DeviceConfiguration) -> RPCResponse:
        rid = req.id
        psk = dev.tag.psk

        # parse the arguments
        try:
            did = Payload.type_checked(req.args['did'], str)
            name = Payload.type_checked(req.args['model'], str)
            conf = Payload.type_checked(req.args['confirm_dev'], str)
            addr = MACAddress.parse(Payload.type_checked(req.args['mac'], str))
        except (KeyError, ValueError):
            self.log.error('Invalid RPC request: %s', req)
            return RPCResponse(rid, error = RPCError(RPCError.Code.InvalidParameters, "invalid args"))

        # check the address
        if addr != self.mac:
            self.log.error('MAC address mismatch: %s != %s', addr.hex(':'), self.mac.hex(':'))
            return RPCResponse(rid, error = RPCError(RPCError.Code.InvalidParameters, "MAC address mismatch"))

        # calculate the signature
        rand = self.rnd
        resp = self._mk_hash(did, psk, rand)

        # verify the signature
        if resp != conf:
            self.log.error('Signature mismatch: %s != %s', conf, resp)
            return RPCResponse(rid, error = RPCError(RPCError.Code.InvalidParameters, "signature mismatch"))

        # construct the response
        self.log.info('Accepted bind request from device %s. model = %s', did, name)
        return RPCResponse(rid, data = {'bind_code': 1})

    __rpc_handler__ = {
        '_sync.subdev_secure_bind'   : _exec_bind,
        '_sync.subdev_secure_authen' : _exec_auth,
    }

    async def _wait_cmd(self, *cmds: PacketCmd, key: Optional[SessionKey] = None) -> Packet:
        while True:
            rd = self.mux.reader(MuxType.ComData)
            req = await PacketSerdes.read(rd, key = key)

            # wait for the expected command
            if req.cmd not in cmds:
                self.log.debug('Dropping unexpected packet: %s', req)
                continue

            # log the packet
            self.log.debug('Received packet: %s', req)
            return req

    async def bind(self, dev: DeviceConfiguration):
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

        # calculate the AES key
        salt = StaticKey(skid).key.encode('utf-8')
        ekey = SessionKey(HKDF(SHA256(), 16, salt, b'xmitech-auth-srv').derive(skey))

        # parse the RPC request
        req = RPCRequest.from_bytes(req.data[140:])
        self.log.info('Requesting binding information for "%s".', self.mac.hex(':'))

        # proxy the RPC request
        resp = self._exec_rpc(req, dev)
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
            raise ValueError('server public key mismatch')

        # parse the device tag and model
        mod = desc.rstrip(b'\x00').decode('utf-8')
        tag = DeviceTag.parse(info.rstrip(b'\x00').decode('utf-8'))

        # parse the RPC request
        req = RPCRequest.from_bytes(bytes(buf))
        self.log.info('Confirming binding information for "%s".', self.mac.hex(':'))

        # proxy the RPC request
        resp = self._exec_rpc(req, dev)
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

        # update the configuration
        dev.tag         = tag
        dev.model       = mod
        dev.auth_key    = akey
        dev.static_key  = StaticKey(skid)
        dev.session_key = ekey
        self.log.info('Bind successful.')

    async def query_tag(self) -> DeviceTag:
        PacketSerdes.write(self.mux.writer(MuxType.ComData), Packet(REQ_VER, PacketCmd.GetConfigInfo, bytes(16)))
        PacketSerdes.write(self.mux.writer(MuxType.ComData), Packet(REQ_VER, PacketCmd.SystemStart, bytes(16)))

        # attempt to get a PushDeviceUID packet
        try:
            key = SessionKey.empty()
            req = await asyncio.wait_for(self._wait_cmd(PacketCmd.PushDeviceUID, key = key), 1.0)
        except EOFError:
            self.log.debug('EOF, retry with new connection.')
            raise self.Retry from None
        except asyncio.TimeoutError:
            self.log.debug('Query timeout, retry with new connection.')
            raise self.Retry from None

        # attempt to decode the packet
        try:
            return DeviceTag.parse(req.data.rstrip(b'\x00').decode('utf-8'))
        except ValueError as e:
            self.log.warning('Cannot parse the response, retry with new connection. error = %s', e)
            raise self.Retry from None

class Channel(IntEnum):
    ComSend = 0
    ComRecv = 1
    DspComm = 2
    UdpSend = 3

class ChannelEvent(IntEnum):
    Connected    = 0,
    Disconnected = 1

class Station:
    log: Logger
    run: set[bytes]
    cfg: Configuration

    def __init__(self, cfg: Configuration):
        self.cfg = cfg
        self.run = set()
        self.log = logging.getLogger('mwc11')

    async def serve_forever(self, host: str = STATION_BIND, port: int = STATION_PORT):
        srv = await asyncio.start_server(self._serve_connection, host = host, port = port)
        await srv.serve_forever()

    async def _serve_connection(self, rd: StreamReader, wr: StreamWriter):
        mux = MuxConnection(rd, wr)
        asyncio.get_running_loop().create_task(mux.run())

        # handle the connection
        try:
            await self._handle_connection(mux)
        except Exception:
            self.log.exception('Exception when handling connection:')

        # close the mux and write channel
        mux.close()
        wr.close()

    async def _handle_connection(self, mux: MuxConnection):
        buf = await mux.reader(MuxType.StaInit).readexactly(14)
        buf = memoryview(buf)

        # extract the fields
        mac = bytes(buf[:6])
        local = socket.inet_ntop(socket.AF_INET, buf[6:10])
        remote = socket.inet_ntop(socket.AF_INET, buf[10:])

        # check for paired devices
        if mac not in self.cfg.devices:
            self.log.warning('Unexpected connection from "%s", dropped.', mac.hex(':'))
            return

        # get the device configuration
        dev = self.cfg.devices[mac]
        tag, skey = dev.tag, dev.session_key

        # no device tag, it's a paired but not registered device
        if not tag:
            if mac not in self.run:
                self.run.add(mac)
                self.log.info('Please wait until the camera times out.')
                self.log.info('Please trigger a PIR recording, do whatever you can to achieve this.')
                self.log.info('For example, you can wave your hands in front of the camera.')
                self.log.info('If no PIRs are being triggered long after timeout, start over.')

            # attempt to fetch the device tag
            try:
                dev.tag = await Binder(mac, mux).query_tag()
            except Binder.Retry:
                return

            # save the configuration
            dev.save()
            self.log.info('Device tag fetched successfully, please reset and re-pair the device.')
            self.run.remove(mac)
            return

        # no session key, it's tag is available, but still not registered
        if not skey:
            try:
                await Binder(mac, mux).bind(dev)
            except Exception as e:
                self.log.error('Cannot bind device "%s". Error: %s', mac.hex(), e)
            else:
                dev.save()

        # TODO: device handle logic
        print(mac, local, remote)

async def main():
    await Station(ConfigurationFile.load('mwc11.json')).serve_forever()

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
