#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import socket
import struct
import hashlib
import asyncio
import hexdump
import logging
import coloredlogs

from udp import UdpSocket
from enum import IntEnum
from logging import Logger

from miot import Payload

from typing import Any
from typing import Iterable
from typing import Optional

from asyncio import Queue
from asyncio import TimerHandle
from asyncio import StreamReader
from asyncio import StreamWriter

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import CipherContext

from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

LOG_FMT         = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL       = logging.DEBUG

MUX_TIMEOUT     = 10
PROTOCOL_VER    = 2

DSP_COMM_PORT   = 32290
COM_SEND_PORT   = 32293
COM_RECV_PORT   = 32295
UDP_COMM_PORT   = 32392
VIDEO_FEED_PORT = 32380

SECRET_MAGIC    = 0xee00ff11
STREAM_MAGIC    = 0x55aa55aa
SENDER_MAGIC    = 0xff00aaaa
RECVER_MAGIC    = 0xff005555

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

class DspCmd(IntEnum):      # < 0x5015
    HeartbeatAck            = 0x2754
    LostIFrame              = 0x2711
    BroadcastTipVoice       = 0x2757
    TakeSnapshot            = 0x2742
    # Unknown1              = 0x4e35    # found in DspComSvr thread
    GetVideoEncoderInfo     = 0x4e37

class ComSendCmd(IntEnum):  # >= 0x5015
    EnablePIR               = 0x5016
    GetPIREnabledStatus     = 0x5017    # 0x26
    SetPIRSensitivity       = 0x5019
    GetPIRSensitivity       = 0x501a
    TimeSync                = 0x501b
    ClearCameraMatchInfo    = 0x501c
    SetPIRDelayTime         = 0x501e
    GetPIRDelayTime         = 0x501f
    # Unknown1              = 0x5020    # fired when time-sync is successful
    # Unknown2              = 0x5022    # fired after receiving BatteryStat & Hearbeat (when send_fd is zero)?
    UpdateMCUModule         = 0x5023
    SetPIRWakeupDSP         = 0x5024
    EnableSpeedTest         = 0x5025
    EnableTamper            = 0x5026
    SetQuiescentTime        = 0x502b
    GetQuiescentTime        = 0x502c
    EnableTamperWakeupDSP   = 0x5030
    # Unknown3              = 0x5032    # something related to LEDs?
    FetchWiFiLog            = 0x5033
    # Unknown4              = 0x5035    # fired after time-sync is successful
    Reboot                  = 0x503b
    GetCameraTemperature    = 0x503e
    SetGSensorSwitch        = 0x503f
    SetGSensorSensitivity   = 0x5041

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
    SetGSensorSWI                   = 0x52
    GSensorSWI                      = 0x53
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

class Key:
    num: int
    oob: str
    key: bytes

    def __init__(self, key: bytes, oob: str, num: int):
        self.key = key
        self.oob = oob
        self.num = num

    def __repr__(self) -> str:
        return '\n'.join([
            'Key {',
            '    key = %s' % self.key.hex(),
            '    oob = %s' % self.oob,
            '    num = %d' % self.num,
            '}',
        ])

    def to_dict(self) -> dict[str, Any]:
        return {
            'num': self.num,
            'oob': self.oob,
            'key': base64.b64encode(self.key).decode('utf-8'),
        }

    def encrypt(self, data: bytes) -> bytes:
        pad = (16 - len(data) % 16) % 16
        aes = Cipher(AES128(self.key), CBC(bytes(16))).encryptor()
        return aes.update(data) + aes.update(b'\x00' * pad) + aes.finalize()

    def decrypt(self, data: bytes, size: int) -> bytes:
        aes = Cipher(AES128(self.key), CBC(bytes(16))).decryptor()
        buf = aes.update(data) + aes.finalize()
        return buf[:size]

    def unbind_token(self,  addr: str, port: int) -> bytes:
        return hashlib.md5(self.encrypt(socket.inet_aton(addr) + port.to_bytes(2, 'little'))).digest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Key':
        return cls(
            num = Payload.type_checked(data['num'], 'int'),
            oob = Payload.type_checked(data['oob'], 'str'),
            key = base64.b64decode(Payload.type_checked(data['key'], 'str').encode('utf-8')),
        )

class KeyStore:
    file: str
    keys: dict[str, Key]

    def __init__(self, keys: dict[str, Key], *, file: str = 'mwc11.json'):
        self.file = file
        self.keys = keys

    def save(self):
        with open(self.file, 'w') as fp:
            json.dump(self, fp, indent = 4, sort_keys = True)

    def find(self, addr: str) -> Optional[Key]:
        return self.keys.get(addr)

    def update(self, addr: str, key: Key):
        self.keys[addr] = key
        self.save()

    @classmethod
    def load(cls, file: str = 'mwc11.json') -> 'KeyStore':
        try:
            with open(file) as fp:
                data = Payload.type_checked(json.load(fp), dict)
                keys = { k: Key.from_dict(Payload.type_checked(v, dict)) for k, v in data.items() }
        except (TypeError, ValueError, FileNotFoundError):
            return cls({}, file = file)
        else:
            return cls(keys, file = file)

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
    def decode(self, buf: bytes, key: Key) -> Iterable[Frame]:
        while len(buf) >= 24:
            hdr = buf[:24]
            magic, ty, seq, size = struct.unpack('IxBH4xH10x', hdr)

            # check for magic number
            if magic != STREAM_MAGIC:
                raise ValueError('invalid packet header: ' + hdr.hex(' '))

            # calculate padded size
            if not (size & 0x0f):
                rlen = size
            else:
                rlen = (size & 0xfff0) + 0x10

            # check for buffer length
            if len(buf) < rlen + 24:
                raise ValueError('incomplete packet')

            # read the encrypted data if any
            if not rlen:
                rbuf = b''
            else:
                rbuf = key.decrypt(buf[24:rlen + 24], size)

            # construct the packet
            buf = buf[rlen + 24:]
            yield Frame(FrameCmd(ty), seq, rbuf)

class PacketSerdes:
    async def read(self, rd: StreamReader, key: Optional[Key] = None) -> Packet:
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
        sig = data[16:]
        cmd = PacketCmd(cmd)

        # no data
        if size == 0:
            return Packet(ver, cmd, sig)

        # unencrypted data, just read the body
        if cmd == PacketCmd.StaticIPAssigned:
            return Packet(ver, cmd, sig, await rd.readexactly(size))

        # special case of the initial key exchange packet
        if cmd == PacketCmd.ExchangeBindInfo:
            ext = await rd.readexactly(140)
            key, size = Key(ext[:16], '', 0), struct.unpack('136xI', ext)[0]

        # add padding size, read and decrypt the body
        rbuf = await rd.readexactly((((size - 1) >> 4) + 1) << 4)
        return Packet(ver, cmd, sig, ext + (key.decrypt(rbuf, size) if key else rbuf))

    async def write(self, wr: StreamWriter, key: Key, frame: Packet):
        await wr.write(b''.join((
            struct.pack('IIII', SENDER_MAGIC, frame.cmd, len(frame.data), frame.ver),
            frame.token,
            key.encrypt(frame.data),
        )))

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

class Connection:
    log      : Logger
    key      : Optional[Key]
    keys     : KeyStore
    dmux     : FrameDemux
    udps     : FrameSerdes
    srds     : PacketSerdes
    com_recv : Optional[StreamReader]
    com_send : Optional[StreamWriter]
    dsp_comm : Optional[StreamWriter]
    udp_comm : Optional[StreamWriter]

    def __init__(self, addr: str, keys: KeyStore):
        self.key      = keys.find(addr)
        self.log      = logging.getLogger('mwc11.conn.' + addr.replace('.', '_'))
        self.keys     = keys
        self.dmux     = FrameDemux()
        self.udps     = FrameSerdes()
        self.srds     = PacketSerdes()
        self.com_recv = None
        self.com_send = None
        self.dsp_comm = None
        self.udp_comm = None

    @property
    def ready(self) -> bool:
        return self.com_send is not None and self.com_recv is not None

    def close(self):
        for conn in (self.com_send, self.dsp_comm, self.udp_comm):
            if conn is not None:
                conn.close()

    def handle_udp(self, data: bytes):
        if self.key is None:
            self.log.warning('Dropping UDP packets: key is not initialized.')
        else:
            for frame in self.udps.decode(data, self.key):
                self.dmux.add_streaming_frame(frame)

    async def connection_ready(self):
        while self.key is None:
            req = await self.srds.read(self.com_recv)
            cmd = req.cmd

    async def _perform_handshake(self):
        pass

    async def _dispatch_requests(self):
        pass

class MWC11:
    log    : Logger
    keys   : KeyStore
    conn   : dict[str, Connection]
    waiter : dict[str, tuple[TimerHandle, Connection]]

    def __init__(self, keys: KeyStore):
        self.log    = logging.getLogger('mwc10.station')
        self.keys   = keys
        self.conn   = {}
        self.waiter = {}

    async def serve_forever(self, host: str = '0.0.0.0'):
        loop = asyncio.get_running_loop()
        udps = await UdpSocket.new((host, VIDEO_FEED_PORT))
        dspr = await asyncio.start_server(self._serve_dsp_comm, host = host, port = DSP_COMM_PORT)
        udpc = await asyncio.start_server(self._serve_udp_comm, host = host, port = UDP_COMM_PORT)
        send = await asyncio.start_server(self._serve_com_send, host = host, port = COM_SEND_PORT)
        recv = await asyncio.start_server(self._serve_com_recv, host = host, port = COM_RECV_PORT)

        # wait for all services
        await asyncio.wait(
            return_when = asyncio.FIRST_COMPLETED,
            fs          = [
                loop.create_task(dspr.serve_forever()),
                loop.create_task(udpc.serve_forever()),
                loop.create_task(send.serve_forever()),
                loop.create_task(recv.serve_forever()),
                loop.create_task(self._dispatch_udp_packets(udps)),
            ],
        )

    def _add_conn(self, addr: str) -> Connection:
        con = Connection(addr, self.keys)
        tmr = asyncio.get_running_loop().call_later(MUX_TIMEOUT, self._cancel_conn, addr)
        self.waiter[addr] = (tmr, con)
        return con

    def _cancel_conn(self, addr: str):
        buf = self.waiter
        tmr, conn = buf.pop(addr, (None, None))

        # drop the connection if needed
        if tmr and conn:
            tmr.cancel()
            conn.close()
            self.log.error('Aggregation timeout, connection "%s" was dropped.', addr)

    def _dispatch_conn(self, kind: str, wr: StreamWriter, attr: str, value: Any):
        addr = wr.transport.get_extra_info('peername')[0]
        conn = self.conn.get(addr)

        # if not found, attempt to find a pending connection
        if conn is None:
            _, conn = self.waiter.get(addr, (None, None))

        # if still not found, create a new connection
        if conn is None:
            conn = self._add_conn(addr)
            self.log.info('New connection "%s".', addr)

        # update the attribute
        setattr(conn, attr, value)
        self.log.info('Link %s connection to "%s".', kind, addr)

        # check if the connection is ready
        if not conn.ready:
            return
        else:
            self.log.info('Connection "%s" is ready.', addr)

        # remove the connection from pending list into connection list
        tmr, conn = self.waiter.pop(addr)
        self.conn[addr] = conn

        # notify the connection
        tmr.cancel()
        asyncio.create_task(conn.connection_ready())

    async def _serve_dsp_comm(self, _: StreamReader, wr: StreamWriter):
        self._dispatch_conn('DSP Signaling', wr, 'dsp_comm', wr)

    async def _serve_udp_comm(self, _: StreamReader, wr: StreamWriter):
        self._dispatch_conn('Upstream Audio', wr, 'udp_comm', wr)

    async def _serve_com_send(self, _: StreamReader, wr: StreamWriter):
        self._dispatch_conn('Upstream Signaling', wr, 'com_send', wr)

    async def _serve_com_recv(self, rd: StreamReader, wr: StreamWriter):
        self._dispatch_conn('Downstream Signaling', wr, 'com_recv', rd)

    async def _dispatch_udp_packets(self, udp: UdpSocket):
        while True:
            data, addr = await udp.recvfrom()
            addr, port = addr

            # check for connection
            if addr not in self.conn:
                self.log.warning('Unexpected UDP packet from %s:%d, dropped.', addr, port)
            else:
                self.conn[addr].handle_udp(data)

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(MWC11(KeyStore.load()).serve_forever())
