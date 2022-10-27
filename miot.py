#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import os
import ssl
import sys
import asn1
import json
import time
import base64
import struct
import hashlib
import asyncio
import logging
import argparse
import requests
import importlib.util

from enum import IntEnum
from logging import Logger
from weakref import ReferenceType
from functools import cached_property

from ssl import SSLContext
from ssl import DER_cert_to_PEM_cert

from mjac import MJAC
from mjac import Zone

from typing import Any
from typing import Type
from typing import Union
from typing import Optional
from typing import Sequence

from asyncio import Future
from asyncio import TimerHandle
from asyncio import StreamReader
from asyncio import StreamWriter

HEADER_SIZE         = 8
REQUEST_TIMEOUT     = 10
TIMESYNC_INTERVAL   = 30
HEARTBEAT_INTERVAL  = 10

class Payload:
    def to_bytes(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, _: bytes) -> 'Payload':
        raise NotImplementedError

    @staticmethod
    def type_checked(v: Any, ty: Type) -> Any:
        if not isinstance(v, ty):
            raise ValueError('invalid type: expect %r, got %r' % (ty, type(v)))
        else:
            return v

class RPCError(Exception):
    code    : int
    data    : Any
    message : str

    class Code(IntEnum):
        NoSuchProperty      = -4003
        InvalidParameters   = -32602

    def __init__(self, code: int, message: str, *, data: Any = None):
        self.code    = code
        self.data    = data
        self.message = message

    def __str__(self) -> str:
        if self.data is None:
            return '[error %d] %s' % (self.code, self.message)
        else:
            return '[error %d] %s: %r' % (self.code, self.message, self.data)

    def to_dict(self) -> dict[str, Any]:
        if self.data is None:
            return { 'code': self.code, 'message': self.message }
        else:
            return { 'code': self.code, 'message': self.message, 'data': self.data }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'RPCError':
        code = Payload.type_checked(data['code'], int)
        message = Payload.type_checked(data['message'], str)
        return cls(code, message, data = data.get('data'))

class RPCRequest(Payload):
    id     : Optional[int]
    args   : Union[Sequence, dict[str, Any]]
    method : str

    def __init__(self, method: str, *, id: Optional[int] = None, args: Union[None, Sequence, dict[str, Any]] = None):
        self.id     = id
        self.args   = args or {}
        self.method = method

    @property
    def _readable_args(self) -> str:
        return ('\n' + ' ' * 4).join(json.dumps(self.args, indent = 4, sort_keys = True).splitlines())

    def __repr__(self) -> str:
        return '\n'.join([
            'RPCRequest {',
            '    id     = %d' % self.id,
            '    method = %s' % self.method,
            '    args   = %s' % self._readable_args,
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'id'     , self.id           ),
                    ( 'method' , self.method       ),
                    ( 'params' , self.args or None ),
                )
                if v is not None
            }
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_json(cls, data: str) -> 'RPCRequest':
        obj = json.loads(data)
        rid = Payload.type_checked(obj.get('id', None), (int, None))
        args = Payload.type_checked(obj.get('params', {}), (str, list, dict))
        method = Payload.type_checked(obj['method'], str)

        # handle the special case of an empty string
        if not isinstance(args, str):
            return cls(method, id = rid, args = args)
        elif args == '':
            return cls(method, id = rid)
        else:
            raise ValueError('invalid parameter type: must be list or dict')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RPCRequest':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class RPCResponse(Payload):
    id    : int
    data  : Any
    error : Optional[RPCError]

    def __init__(self, id: int, *, data: Any = None, error: Optional[RPCError] = None):
        self.id    = id
        self.data  = data
        self.error = error

    @property
    def _readable_data(self) -> str:
        return ('\n' + ' ' * 4).join(json.dumps(self.data, indent = 4, sort_keys = True).splitlines())

    def __repr__(self) -> str:
        return ''.join([
            'RPCResponse {\n',
            '    id    = %d\n' % self.id,
            self.data and '    data  = %s\n' % self._readable_data or '',
            self.error and '    error = %s\n' % self.error or '',
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'id'     , self.id   ),
                    ( 'result' , self.data or None ),
                    ( 'error'  , self.error and {
                        kk: vv
                        for kk, vv in (
                            ( 'code'    , self.error.code    ),
                            ( 'data'    , self.error.data    ),
                            ( 'message' , self.error.message ),
                        )
                        if vv is not None
                    }),
                )
                if v is not None
            }
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_json(cls, data: str) -> 'RPCRequest':
        obj = json.loads(data)
        rid = Payload.type_checked(obj['id'], int)
        error = Payload.type_checked(obj.get('error', {}), dict)
        return cls(rid, data = obj.get('result'), error = error and RPCError.from_dict(error) or None)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RPCRequest':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class SyncRequest(Payload):
    uptime: int

    def __init__(self, uptime: int):
        self.uptime = uptime

    def __repr__(self) -> str:
        return 'Sync { t = %d }' % self.uptime

    def to_bytes(self) -> bytes:
        return struct.pack('>Q8x', self.uptime)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SyncRequest':
        uptime, = struct.unpack('>Q8x', data)
        return cls(uptime)

class SyncResponse(Payload):
    unk    : int
    utc_ms : int

    def __init__(self, unk: int, utc_ms: int):
        self.unk    = unk
        self.utc_ms = utc_ms

    def __repr__(self) -> str:
        return 'SyncAck { t = %d }' % self.utc_ms

    def to_bytes(self) -> bytes:
        return struct.pack('>QQ', self.unk, self.utc_ms)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SyncResponse':
        unk, utc_ms = struct.unpack('>QQ', data)
        return SyncResponse(unk, utc_ms)

class SignSuite(IntEnum):
    Invalid = 0
    HMAC    = 1
    MJAC    = 2

class LoginRequest(Payload):
    did  : int
    cert : str
    rand : str
    sign : str
    algo : list[SignSuite]

    def __init__(
        self,
        did  : int,
        cert : str = '',
        rand : str = '',
        sign : bytes = b'',
        algo : Optional[list[SignSuite]] = None,
    ):
        self.did  = did
        self.cert = cert
        self.rand = rand
        self.sign = sign
        self.algo = algo or []

    @property
    def sign_str(self) -> str:
        return base64.b64encode(self.sign).decode('utf-8')

    def __repr__(self) -> str:
        return ''.join([
            'Login {\n',
            '    did  = %d\n' % self.did,
            self.algo and '    algo = %s\n' % ', '.join(map(str, self.algo)) or '',
            self.rand and '    rand = %s\n' % self.rand or '',
            self.sign and '    sign = %s\n' % self.sign.hex() or '',
            self.cert and '    cert = %s\n' % ('\n' + ' ' * 11).join(str(self.cert).splitlines()),
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'did'           , self.did      ),
                    ( 'sign'          , self.sign_str ),
                    ( 'device_random' , self.rand     ),
                    ( 'sign_suites'   , self.algo     ),
                    ( 'cert'          , self.cert     ),
                )
                if v
            },
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_json(cls, data: str) -> 'LoginRequest':
        obj = json.loads(data)
        did = Payload.type_checked(obj['did'], int)
        cert = Payload.type_checked(obj.get('cert', ''), str)
        rand = Payload.type_checked(obj.get('device_random', ''), str)
        sign = base64.b64decode(Payload.type_checked(obj.get('sign', ''), str))
        algo = [SignSuite(Payload.type_checked(v, int)) for v in Payload.type_checked(obj.get('sign_suites', []), list)]
        return cls(did, cert = cert, sign = sign, rand = rand, algo = algo)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'LoginRequest':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class LoginStatus(IntEnum):
    Ok      = 0
    Stage2  = 1
    Error   = -1
    NoCode  = 1 << 65

class LoginResponse(Payload):
    msg  : str
    rand : str
    code : LoginStatus
    algo : SignSuite

    def __init__(self, code: LoginStatus, msg: str, algo: SignSuite, rand: str):
        self.msg  = msg
        self.algo = algo
        self.code = code
        self.rand = rand

    def __repr__(self) -> str:
        return '\n'.join([
            'LoginAck {',
            '    code = %s' % ('(n/a)' if self.code == LoginStatus.NoCode else self.code),
            '    msg  = %s' % repr(self.msg),
            '    algo = %s' % ('(n/a)' if self.algo == SignSuite.Invalid else self.algo),
            '    rand = %s' % (self.rand or '(empty)'),
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'code'         , self.code ),
                    ( 'message'      , self.msg  ),
                    ( 'sign_suite'   , self.algo ),
                    ( 'cloud_random' , self.rand ),
                )
                if v and v != LoginStatus.NoCode
            },
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_json(cls, data: str) -> 'LoginResponse':
        obj = json.loads(data)
        msg = Payload.type_checked(obj.get('message', ''), str)
        rand = Payload.type_checked(obj.get('cloud_random', ''), str)
        algo = SignSuite(Payload.type_checked(obj.get('sign_suite', SignSuite.Invalid), int))
        code = LoginStatus(Payload.type_checked(obj.get('code', LoginStatus.NoCode), int))
        return cls(code, msg, algo, rand)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'LoginResponse':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class PacketType(IntEnum):
    Login           = 0
    LoginAck        = 1
    Keepalive       = 2
    KeepaliveAck    = 3
    Sync            = 4
    SyncAck         = 5
    RPC             = 6
    RPCAck          = 7

    __factory__ = {
        Login           : LoginRequest,
        LoginAck        : LoginResponse,
        Keepalive       : None,
        KeepaliveAck    : None,
        Sync            : SyncRequest,
        SyncAck         : SyncResponse,
        RPC             : RPCRequest,
        RPCAck          : RPCResponse,
    }

    @classmethod
    def parse(cls, ty: 'PacketType', data: bytes) -> Optional[Payload]:
        ctor = cls.__factory__[ty]
        return ctor and ctor.from_bytes(data)

class Packet:
    ty   : PacketType
    seq  : int
    data : Optional[Payload]

    def __init__(self, ty: PacketType, seq: int, data: Optional[Payload] = None):
        self.ty   = ty
        self.seq  = seq
        self.data = data

    def __repr__(self) -> str:
        return '\n'.join([
            'Packet {',
            '    ty   = %s (%d)' % (self.ty, self.ty),
            '    seq  = %d' % self.seq,
            '    data = %s' % ('\n' + ' ' * 4).join(str(self.data or '(empty)').splitlines()),
            '}'
        ])

    def to_bytes(self) -> bytes:
        data = self.data and self.data.to_bytes() or b''
        return struct.pack('>BH2xBH', 1, self.seq, self.ty, len(data)) + data

    @classmethod
    def sync(cls, seq: int, uptime: int) -> 'Packet':
        return Packet(PacketType.Sync, seq, SyncRequest(uptime))

    @classmethod
    def login(
        cls,
        seq  : int,
        did  : int,
        cert : str = '',
        rand : str = '',
        sign : bytes = b'',
        algo : Optional[list[SignSuite]] = None,
    ) -> 'Packet':
        return Packet(PacketType.Login, seq, LoginRequest(did, cert, rand, sign, algo))

    @classmethod
    def request(cls, seq: int, req: RPCRequest) -> 'Packet':
        return Packet(PacketType.RPC, seq, req)

    @classmethod
    def response(cls, seq: int, resp: RPCResponse) -> 'Packet':
        return Packet(PacketType.RPCAck, seq, resp)

    @classmethod
    def keepalive(cls, seq: int) -> 'Packet':
        return Packet(PacketType.Keepalive, seq)

    @classmethod
    async def read_from(cls, rd: StreamReader) -> 'Packet':
        i, t, n = struct.unpack('>xH2xBH', await rd.readexactly(8))
        return Packet(PacketType(t), i, PacketType.parse(PacketType(t), await rd.readexactly(n)))

class Signature:
    r: int
    s: int

    def __init__(self, r: bytes, s: bytes):
        self.r = int.from_bytes(r, 'big')
        self.s = int.from_bytes(s, 'big')

    def to_asn1(self) -> bytes:
        enc = asn1.Encoder()
        enc.start()
        enc.enter(asn1.Numbers.Sequence)
        enc.write(self.r, asn1.Numbers.Integer)
        enc.write(self.s, asn1.Numbers.Integer)
        enc.leave()
        return enc.output()

class MiotSecurityProvider:
    @property
    def device_id(self) -> int:
        raise NotImplementedError('device_id')

    @property
    def root_cert(self) -> str:
        raise NotImplementedError('root_cert')

    @property
    def vendor_cert(self) -> str:
        raise NotImplementedError('vendor_cert')

    @property
    def device_cert(self) -> str:
        raise NotImplementedError('device_cert')

    def generate_signature(self, data: bytes) -> Signature:
        raise NotImplementedError('generate_signature()', data)

class MiotMJACSecurityProvider(MiotSecurityProvider):
    dev: MJAC

    def __init__(
        self,
        ftdi     : str = 'ftdi://ftdi:2232h/1',
        rst_pin  : int = 3,
        i2c_addr : int = 0x2a,
        i2c_freq : int = 1000000,
    ):
        self.dev = MJAC(ftdi, rst_pin, i2c_addr, i2c_freq)
        self.dev.reset()

    @cached_property
    def device_id(self) -> int:
        did, = struct.unpack('>Q', self.dev.read(Zone.DeviceId, 2, 8))
        return did

    @cached_property
    def root_cert(self) -> str:
        return DER_cert_to_PEM_cert(self.dev.read_cert(Zone.RootCert))

    @cached_property
    def vendor_cert(self) -> str:
        return DER_cert_to_PEM_cert(self.dev.read_cert(Zone.VendorCert))

    @cached_property
    def device_cert(self) -> str:
        return DER_cert_to_PEM_cert(self.dev.read_cert(Zone.DeviceCert))

    def generate_signature(self, data: bytes) -> Signature:
        sha = hashlib.sha256(data).digest()
        ret = self.dev.generate_signature(b'\x00\x20' + sha)
        return Signature(ret[2:34], ret[36:])

class LoginCtx:
    algo     : SignSuite
    secp     : MiotSecurityProvider
    dev_rand : str
    srv_rand : str

    __suites__ = [
        SignSuite.MJAC,
    ]

    def __init__(self, secp: MiotSecurityProvider):
        self.secp     = secp
        self.algo     = SignSuite.Invalid
        self.srv_rand = ''
        self.dev_rand = ''

    @property
    def next_rand(self) -> str:
        self.dev_rand = os.urandom(16).hex()
        return self.dev_rand

    def _sign_hmac(self) -> bytes:
        raise NotImplementedError('HMAC signature suite is not supported')

    def _sign_mjac(self) -> bytes:
        data = self.dev_rand + self.srv_rand
        return self.secp.generate_signature(data.encode('utf-8')).to_asn1()

    def sign(self) -> bytes:
        if self.algo == SignSuite.HMAC:
            raise NotImplementedError('HMAC signature suite is not supported')
        elif self.algo == SignSuite.MJAC:
            return self._sign_mjac()
        else:
            raise ValueError('invalid signature algorithm')

    def stage1(self, seq: int) -> LoginRequest:
        return Packet.login(
            seq  = seq,
            did  = self.secp.device_id,
            cert = self.secp.vendor_cert + self.secp.device_cert,
            rand = self.next_rand,
            algo = self.__suites__,
        )

    def stage2(self, seq: int) -> LoginRequest:
        return Packet.login(
            seq  = seq,
            did  = self.secp.device_id,
            sign = self.sign(),
        )

    def update(self, data: LoginResponse):
        self.algo = data.algo
        self.srv_rand = data.rand

class Sender:
    def next_seq(self) -> int:
        raise NotImplementedError('next_seq()')

    def send_packet(self, packet: Packet):
        raise NotImplementedError('send_packet()', packet)

class MiotRPC:
    log    : Logger
    incr   : int
    sender : ReferenceType[Sender]
    waiter : dict[int, tuple[Future[RPCResponse], TimerHandle]]

    def __init__(self, sender: ReferenceType[Sender]):
        self.log    = logging.getLogger('miot.rpc')
        self.incr   = 0
        self.waiter = {}
        self.sender = sender

    def _next_id(self) -> int:
        while True:
            rng = struct.unpack('H', os.urandom(2))[0]
            rid = (self.incr & 0xffff) | ((rng & 0x7fff) << 16)

            # avoid ID confliction
            if rid not in self.waiter:
                self.incr += 1
                return rid

    def _fire_timeout(self, pid: int):
        fut = self.waiter.pop(pid, None)
        fut and fut[0].set_exception(TimeoutError)

    def _send_request(self, req: RPCRequest) -> Future[RPCResponse]:
        snd = self.sender()
        fut = asyncio.get_running_loop().create_future()
        tmr = asyncio.get_running_loop().call_later(REQUEST_TIMEOUT, self._fire_timeout, req.id)
        snd.send_packet(Packet.request(snd.next_seq(), req))
        self.waiter[req.id] = (fut, tmr)
        return fut

    @staticmethod
    def _update_request_id(fut: Future[RPCResponse], rid: int):
        if fut.done() and not fut.cancelled() and fut.exception() is None:
            fut.result().id = rid

    def send(self, method: str, *args, **kwargs) -> Future[RPCResponse]:
        if args and kwargs:
            raise ValueError('args and kwargs cannot be present at the same time')
        else:
            return self._send_request(RPCRequest(method, id = self._next_id(), args = args or kwargs))

    def proxy(self, req: RPCRequest) -> Future[RPCResponse]:
        if req.id not in self.waiter:
            return self._send_request(req)
        else:
            ret = self._send_request(RPCRequest(req.method, id = self._next_id(), args = req.args))
            ret.add_done_callback(lambda f: self._update_request_id(f, req.id))
            return ret

    def notify(self, method: str, *args, **kwargs):
        if args and kwargs:
            raise ValueError('args and kwargs cannot be present at the same time')
        else:
            snd = self.sender()
            snd.send_packet(Packet.request(snd.next_seq(), RPCRequest(method, args = args or kwargs)))

    def reply_to(self, p: RPCRequest, *, data: Optional[Any] = None, error: Optional[RPCError] = None):
        snd = self.sender()
        snd.send_packet(Packet.response(snd.next_seq(), RPCResponse(p.id, data = data, error = error)))

    def handle_response(self, p: RPCResponse):
        pid = p.id
        fut, tmr = self.waiter.pop(pid, (None, None))

        # check if it's a valid response
        if fut is None:
            self.log.warning('Unexpected RPC response, dropped: %r', p)
            return

        # cancel the timeout, and resolve the future
        tmr.cancel()
        fut.set_result(p)

class MiotConfiguration:
    args              : list[str]
    uptime            : float
    app_class         : type['MiotApplication']
    security_provider : MiotSecurityProvider

    def __init__(self,
        app_class         : type['MiotApplication'],
        security_provider : Optional[MiotSecurityProvider] = None,
        *args             : str,
    ):
        self.args              = list(args)
        self.uptime            = time.monotonic()
        self.app_class         = app_class
        self.security_provider = security_provider or MiotMJACSecurityProvider()

    async def resolve(self, dns: str = 'dns.io.mi.com', host: str = 'ots.io.mi.com') -> tuple[str, int]:
        resp = requests.get(
            url    = 'https://%s/gslb' % dns,
            params = {
                'dm'        : host,
                'id'        : self.security_provider.device_id,
                'tver'      : 2,
                'model'     : self.app_class.device_model(),
                'timestamp' : 1,
            },
            headers = {
                'User-Agent': 'MIoT'
            }
        )

        # parse the response
        resp.raise_for_status()
        resp = resp.json()

        # check if HTTP DNS is enabled
        if not resp['info']['enable']:
            raise RuntimeError('HTTP DNS is not enabled')

        # use the first address
        addr = resp['info']['host_list'][0]
        return addr['ip'], addr['port']

    async def connect(self, host: str = 'ots.io.mi.com', port: int = 443, **kwargs) -> 'MiotConnection':
        kwargs.pop('cafile', None)
        kwargs.pop('capath', None)
        kwargs['cadata'] = self.security_provider.root_cert

        # create a SSL context
        ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_verify_locations(**kwargs)

        # connect to MiIO OT server
        rd, wr = await asyncio.open_connection(host, port, ssl = ctx)
        return MiotConnection(rd, wr, ctx, cfg = self)

class MiotApplication:
    def __init__(self, rpc: MiotRPC, cfg: MiotConfiguration):
        raise NotImplementedError('__init__()', rpc, cfg)

    @classmethod
    def device_model(cls) -> str:
        raise NotImplementedError('device_model()')

    async def device_ready(self):
        raise NotImplementedError('async device_ready()')

    async def handle_request(self, p: RPCRequest):
        raise NotImplementedError('async handle_request()', p)

class MiotConnection(Sender):
    rd    : StreamReader
    wr    : StreamWriter
    app   : MiotApplication
    seq   : int
    log   : Logger
    rpc   : MiotRPC
    ctx   : SSLContext
    cfg   : MiotConfiguration
    state : str
    login : LoginCtx

    def __init__(self, rd: StreamReader, wr: StreamWriter, ctx: SSLContext, cfg: MiotConfiguration):
        self.rd    = rd
        self.wr    = wr
        self.seq   = -1
        self.cfg   = cfg
        self.ctx   = ctx
        self.log   = logging.getLogger('miot')
        self.rpc   = MiotRPC(ReferenceType(self))
        self.app   = cfg.app_class(self.rpc, cfg)
        self.state = 'login_1'
        self.login = LoginCtx(cfg.security_provider)

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send_packet(self, p: Packet):
        t = time.monotonic_ns()
        self.wr.write(p.to_bytes())
        self.log.debug('Packet %s with Seq %d was transmitted in %.3fms.', p.ty.name, p.seq, (time.monotonic_ns() - t) / 1e6)

    async def _timesync(self):
        while True:
            dt = time.monotonic() - self.cfg.uptime
            self.log.debug('Time-sync with uptime %.3fs.', dt)
            self.send_packet(Packet.sync(self.next_seq(), int(dt * 1000)))
            await asyncio.sleep(TIMESYNC_INTERVAL)

    async def _heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            self.log.debug('Keep alive.')
            self.send_packet(Packet.keepalive(self.next_seq()))

    async def _login_poller(self):
        while True:
            match self.state:
                case 'idle':
                    await asyncio.sleep(1)
                case 'online':
                    self.state = 'idle'
                    asyncio.get_running_loop().create_task(self.app.device_ready())
                case 'login_1':
                    self.state = 'wait_login_1'
                    self.log.debug('Login sequence stage 1.')
                    self.send_packet(self.login.stage1(self.next_seq()))
                case 'wait_login_1':
                    self.log.debug('Waiting for initial key exchange ...')
                    await asyncio.sleep(1)
                case 'retry_login_1':
                    self.state = 'login_1'
                    await asyncio.sleep(1)
                case 'login_2':
                    self.state = 'wait_login_2'
                    self.log.debug('Login sequence stage 2.')
                    self.send_packet(self.login.stage2(self.next_seq()))
                case 'wait_login_2':
                    self.log.debug('Waiting for signature verification ...')
                    await asyncio.sleep(1)
                case _:
                    raise RuntimeError('invalid state: ' + repr(self.state))

    async def _network_handler(self, p: Packet):
        match p.ty:
            case PacketType.RPC:
                await self.app.handle_request(p.data)
            case PacketType.RPCAck:
                self.rpc.handle_response(p.data)
            case PacketType.SyncAck:
                self.log.debug('Time-sync from server. utc_ms = %d', p.data.utc_ms)
            case PacketType.KeepaliveAck:
                self.log.debug('Keep-alive from server.')
            case PacketType.LoginAck:
                match self.state:
                    case 'wait_login_1':
                        if p.data.code == LoginStatus.Stage2:
                            self.state = 'login_2'
                            self.login.update(p.data)
                        elif p.data.code == LoginStatus.NoCode:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: unknown error')
                        else:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: %s: %s', p.data.code, p.data.msg)
                    case 'wait_login_2':
                        if p.data.code == LoginStatus.Ok:
                            self.state = 'online'
                            self.log.info('Login successful')
                        elif p.data.code == LoginStatus.NoCode:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: unknown error')
                        else:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: %s: %s', p.data.code, p.data.msg)
                    case state:
                        self.log.warning('LoginAck at the wrong state (%s), dropped.' % state)
            case _:
                self.log.warning('Unexpected packet, dropped: %r', p)

    async def _network_receiver(self):
        while True:
            p = await Packet.read_from(self.rd)
            self.log.debug('Received %s packet with Seq %d.', p.ty.name, p.seq)
            await self._network_handler(p)

    async def run_forever(self):
        await asyncio.wait(
            return_when = asyncio.FIRST_COMPLETED,
            fs          = [
                asyncio.ensure_future(self._timesync()),
                asyncio.ensure_future(self._heartbeat()),
                asyncio.ensure_future(self._login_poller()),
                asyncio.ensure_future(self._network_receiver()),
            ],
        )

class MiotAppLoader:
    __providers__ = {
        'mjac': MiotMJACSecurityProvider,
    }

    __arguments__ = [
        ('-m', '--app', dict(
            type     = str,
            help     = 'path of the application module',
            required = True,
        )),
        ('-c', '--class', dict(
            type     = str,
            dest     = 'klass',
            help     = 'name of the application class',
            default  = 'MiotApp',
            required = False,
        )),
        ('-p', '--security-provider', dict(
            type     = str,
            help     = 'security provider name',
            default  = 'mjac',
            choices  = __providers__,
            required = False,
        )),
        ('args', dict(
            help    = 'arguments passed to application',
            type    = str,
            nargs   = '*',
            metavar = 'ARGS',
        ))
    ]

    @classmethod
    async def main(cls, args: Sequence[str]):
        d = cls.__arguments__
        p = argparse.ArgumentParser(description = 'MiIO Client v1.0')

        # add argumnets
        for v in d:
            p.add_argument(*v[:-1], **v[-1])

        # parse the args
        ns = p.parse_args(args)
        mod, klass, secp = ns.app, ns.klass, ns.security_provider

        # load the module
        spec = importlib.util.spec_from_file_location('miot_app', mod)
        smod = importlib.util.module_from_spec(spec)

        # insert into modules
        sys.modules['miot_app'] = smod
        spec.loader.exec_module(smod)

        # find the class
        try:
            app_class = getattr(smod, klass)
        except AttributeError:
            print('* error: class not found: %s:%s' % (mod, klass))
            sys.exit(1)

        # check for subclass
        if not isinstance(app_class, type) or not issubclass(app_class, MiotApplication):
            print('* error: application must be a subclass of MiotApplication: %s:%s' % (mod, klass))
            sys.exit(1)

        # construct the configuration
        cfg = MiotConfiguration(
            app_class,
            cls.__providers__[secp](),
            *ns.args,
        )

        # start the connection
        addr = await cfg.resolve()
        conn = await cfg.connect(*addr)
        await conn.run_forever()
