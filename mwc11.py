#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import hashlib
import asyncio
import hexdump
import logging
import coloredlogs

from enum import IntEnum
from logging import Logger

from typing import List
from typing import Tuple
from typing import Union
from typing import Iterable
from typing import Optional

from asyncio import Queue
from asyncio import StreamReader
from asyncio import StreamWriter

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import CipherContext

from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

LOG_FMT         = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL       = logging.DEBUG

DEVICE_CHAN     = 0
SERVER_ADDR     = '192.168.99.1'
PROTOCOL_VER    = 2

DSP_COMM_PORT   = 32290
COM_SEND_PORT   = 32293
COM_RECV_PORT   = 32295
UDP_COMM_PORT   = 32392
SPEED_TEST_PORT = 5001
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
    RequestUSBState                 = 0x3c  # 0x4ea5
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

class Secret:
    model       : str
    auth_key    : bytes
    session_key : List[bytes]
    mac         : List[bytes]
    traid_info  : List[str]
    static_num  : List[int]

    def __repr__(self) -> str:
        return '\n'.join([
            'Secret {',
            '    model       : ' + self.model,
            '    auth_key    : ' + self.auth_key.hex(' '),
            '    session_key : {',
        ] + [
            '        [%2d] = %s' % (i, v.hex(' '))
            for i, v in enumerate(self.session_key)
        ] + [
            '    }',
            '    mac : {',
        ] + [
            '        [%2d] = %s' % (i, v.hex(':'))
            for i, v in enumerate(self.mac)
        ] + [
            '    }',
            '    traid_info : {',
        ] + [
            '        [%2d] = %s' % (i, v)
            for i, v in enumerate(self.traid_info)
        ] + [
            '    }',
            '    static_num : {',
        ] + [
            '        [%2d] = 0x%08x' % (i, v)
            for i, v in enumerate(self.static_num)
        ] + [
            '    }',
            '}'
        ])

    def _cipher(self, chan: int) -> Cipher:
        return Cipher(AES128(self.session_key[chan]), CBC(bytes(16)))

    def _transform(self, ctx: CipherContext, data: bytes) -> bytes:
        return ctx.update(data) + ctx.finalize()

    def encrypt(self, chan: int, data: bytes) -> bytes:
        data = data.ljust(((len(data) - 1 >> 4) + 1 << 4), b'\0')
        return self._transform(self._cipher(chan).encryptor(), data)

    def decrypt(self, chan: int, data: bytes, size: int) -> bytes:
        return self._transform(self._cipher(chan).decryptor(), data)[:size]

    def calc_unbind_token(self, chan: int, addr: str, port: int) -> bytes:
        return hashlib.md5(self.encrypt(chan, socket.inet_aton(addr) + port.to_bytes(2, 'little'))).digest()

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

class StreamSerdes:
    rbuf   : bytes
    secret : Secret

    def __init__(self, secret: Secret):
        self.rbuf   = b''
        self.secret = secret

    def _decode_iter(self, chan: int) -> Iterable[Frame]:
        while len(self.rbuf) >= 24:
            buf = self.rbuf[:24]
            magic, ty, seq, size = struct.unpack('IxBH4xH10x', buf)

            # check for magic number
            if magic != STREAM_MAGIC:
                raise ValueError('invalid packet header: ' + buf.hex(' '))

            # calculate padded size
            if not (size & 0x0f):
                rlen = size
            else:
                rlen = (size & 0xfff0) + 0x10

            # check for buffer length
            if len(self.rbuf) < rlen + 24:
                break

            # read the encrypted data if any
            if not rlen:
                rbuf = b''
            else:
                rbuf = self.secret.decrypt(chan, self.rbuf[24:rlen + 24], size)

            # construct the packet
            yield Frame(FrameCmd(ty), seq, rbuf)
            self.rbuf = self.rbuf[rlen + 24:]

    def decode(self, buf: bytes, chan: int) -> Iterable[Frame]:
        self.rbuf += buf
        yield from self._decode_iter(chan)

class PacketSerdes:
    log    : Logger
    secret : Secret

    def __init__(self, secret: Secret):
        self.log    = logging.getLogger('mwc11.serdes')
        self.secret = secret

    async def read(self, rd: StreamReader, chan: int) -> Packet:
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
            self.log.warning(
                'Skipping garbage data:\n' +
                ('\n' + ' ' * 4).join(hexdump.hexdump(data[:-4], result = 'generator'))
            )

        # read the remaining header data
        data = await rd.readexactly(28)
        cmd, size, ver = struct.unpack('III', data[:12])

        # command and signature
        sig = data[16:]
        cmd = PacketCmd(cmd)

        # no data
        if size == 0:
            return Packet(ver, cmd, sig)

        # unencrypted data, just read the body
        if cmd == PacketCmd.StaticIPAssigned:
            return Packet(ver, cmd, sig, await rd.readexactly(size))

        # add padding size, read and decrypt the body
        rbuf = await rd.readexactly((((size - 1) >> 4) + 1) << 4)
        return Packet(ver, cmd, sig, self.secret.decrypt(chan, rbuf, size))

    async def write(self, wr: StreamWriter, chan: int, frame: Packet):
        await wr.write(b''.join((
            struct.pack('IIII', SENDER_MAGIC, frame.cmd, len(frame.data), frame.ver),
            frame.token,
            self.secret.encrypt(chan, frame.data),
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
            self.log.warning('Frame dropping: %d - %d' % (self.vidx, frame.index))

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
                self.log.warning('Dropping unsupported stream frame: ' + repr(frame))

    def add_signaling_frame(self, frame: Packet):
        self._handle_signaling_frame(frame)
        self.frames.put_nowait(frame)

class MiCameraHandler:
    sbuf  : Queue
    token : bytes

    def __init__(self):
        self.sbuf  = Queue()
        self.token = b''

    def send(self, cmd: IntEnum, data: bytes):
        self.sbuf.put_nowait(Packet(PROTOCOL_VER, cmd, self.token, data))

    async def handle_frame(self, frame: Frame):
        if frame.type == FrameCmd.VideoHEVC:
            self._vfp.write(frame.payload)
        else:
            print(frame)

    async def handle_packet(self, frame: Packet):
        if frame.cmd == PacketCmd.StopStream:
            self._vfp.close()
        elif frame.cmd == PacketCmd.StartStream:
            self._vfp = open('test.hevc', 'wb')
        else:
            print(frame)

class MiCameraStation:
    rbuf: FrameDemux
    udps: StreamSerdes
    srds: PacketSerdes
    conn: Optional[MiCameraHandler]

    class VideoHandler(asyncio.DatagramProtocol):
        conn: 'MiCameraStation'
        port: Optional[asyncio.DatagramTransport]

        def __init__(self, conn: 'MiCameraStation'):
            self.conn = conn
            self.port = None

        def connection_made(self, port: asyncio.DatagramTransport):
            self.port = port

        def datagram_received(self, data: bytes, _: Tuple[str, int]):
            for v in self.conn.udps.decode(data, DEVICE_CHAN):
                self.conn.rbuf.add_streaming_frame(v)

    def __init__(self, secret: Secret):
        self.rbuf = FrameDemux()
        self.udps = StreamSerdes(secret)
        self.srds = PacketSerdes(secret)
        self.conn = MiCameraHandler()

    async def serve_forever(self, host: str = '0.0.0.0'):
        loop = asyncio.get_running_loop()
        dspr = await asyncio.start_server(self._serve_dsp_comm, host = host, port = DSP_COMM_PORT)
        udpr = await asyncio.start_server(self._serve_udp_comm, host = host, port = UDP_COMM_PORT)
        send = await asyncio.start_server(self._serve_com_send, host = host, port = COM_SEND_PORT)
        recv = await asyncio.start_server(self._serve_com_recv, host = host, port = COM_RECV_PORT)

        # create the video feed socket
        await loop.create_datagram_endpoint(
            local_addr       = (host, VIDEO_FEED_PORT),
            protocol_factory = lambda: self.VideoHandler(self),
        )

        # wait for all services
        await asyncio.wait(
            return_when = asyncio.FIRST_COMPLETED,
            fs          = [
                loop.create_task(dspr.serve_forever()),
                loop.create_task(udpr.serve_forever()),
                loop.create_task(send.serve_forever()),
                loop.create_task(recv.serve_forever()),
                loop.create_task(self._dispatch_frames()),
            ],
        )

    async def _serve_dsp_comm(self, _: StreamReader, wr: StreamWriter):
        while True:
            await asyncio.sleep(1)  # TODO: handle DspCommSvr logic

    async def _serve_udp_comm(self, _: StreamReader, wr: StreamWriter):
        while True:
            await asyncio.sleep(1)  # TODO: handle UDPComSvr logic

    async def _serve_com_send(self, _: StreamReader, wr: StreamWriter):
        _, port = wr.transport.get_extra_info('peername')
        self.conn.token = self.srds.secret.calc_unbind_token(DEVICE_CHAN, SERVER_ADDR, port)

        # poll for frames
        while True:
            fr = await self.conn.sbuf.get()
            await self.srds.write(wr, fr)

    async def _serve_com_recv(self, rd: StreamReader, _: StreamWriter):
        try:
            while True:
                fr = await self.srds.read(rd, DEVICE_CHAN)
                self.rbuf.add_signaling_frame(fr)
        except ConnectionResetError:
            pass
        except asyncio.IncompleteReadError as e:
            if e.partial:
                raise

    async def _dispatch_frames(self):
        while True:
            fr = await self.rbuf.frames.get()
            await self._dispatch_single_frame(fr)

    async def _dispatch_single_frame(self, frame: Union[Packet, Frame]):
        if isinstance(frame, Frame):
            await self.conn.handle_frame(frame)
        elif isinstance(frame, Packet):
            await self.conn.handle_packet(frame)
        else:
            raise RuntimeError('invalid frame ' + repr(frame))

def parse_secret(s: bytes) -> Secret:
    magic, ver = struct.unpack('II', s[:8])
    if magic != SECRET_MAGIC:
        raise ValueError('invalid secret magic: ' + repr(s))
    if ver != 0:
        raise ValueError('unsupported secret version: ' + repr(s))
    s = s[8:]
    model, s = s[:16], s[16:]
    akey, s = s[:16], s[16:]
    skey, s = s[:320], s[320:]
    mac, s = s[:120], s[120:]
    tinfo, s = s[:2000], s[2000:]
    snum, s = s[:80], s[80:]
    if s:
        raise ValueError('garbage after secret: ' + repr(s))
    def rdstr(v: bytes) -> str:
        return v.rstrip(b'\0').decode('utf-8')
    ret = Secret()
    ret.model = rdstr(model)
    ret.auth_key = akey
    ret.session_key = list(map(bytes, zip(*[iter(skey)] * 16)))
    ret.mac = list(map(bytes, zip(*[iter(mac)] * 6)))
    ret.traid_info = list(map(rdstr, map(bytes, zip(*[iter(tinfo)] * 100))))
    ret.static_num = list(struct.unpack('I' * 20, snum))
    return ret

async def main():
    with open('auth_info.bin', 'rb') as fp:
        secret = parse_secret(fp.read())
        print(secret)

    # with open('packets.raw') as fp:
    #     for v in fp.read().splitlines():
    #         v = bytes.fromhex(v)
    #         print('magic: %#x, unk1: %#04x, ty: %#04x, seq: %3d, unk2: %#010x, size: %4d, unk3: %r' % struct.unpack('IBBHIH10s', v[:24]))

    # with open('packets.raw') as fp:
    #     for v in fp.read().splitlines():
    #         v = bytes.fromhex(v)
    #         hdr, sig, data = v[:16], v[16:32], v[32:]
    #         magic, cmd, size, ver = struct.unpack('IIII', hdr)
    #         print('magic: %#x, cmd: %s (%#x), size: %d, ver: %d, sig: %s' % (magic, PacketCmd(cmd), cmd, size, ver, sig.hex()))
    #         if data:
    #             print(' data: ')
    #             hexdump.hexdump(secret.decrypt(0, data, size))

    # with open('packets.raw') as fp:
    #     dec = StreamSerdes(secret)
    #     for p in dec.decode(b''.join([bytes.fromhex(v) for v in fp.read().splitlines()]), 0):
    #         print(p.type)

    await MiCameraStation(secret).serve_forever()

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(main())
