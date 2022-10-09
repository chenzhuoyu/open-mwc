#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import os
import ssl
import asn1
import json
import time
import base64
import struct
import hashlib
import asyncio
import logging
import requests
import coloredlogs

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

from asyncio import Task
from asyncio import Queue
from asyncio import Future
from asyncio import TimerHandle
from asyncio import StreamReader
from asyncio import StreamWriter

LOG_FMT             = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL           = logging.DEBUG

HW_VER              = 'Linux'
FW_VER              = '4.1.6_1999'
MIIO_VER            = '0.0.9'
MIIO_CLI_VER        = '4.1.6'

DEVICE_MAC          = 'E0:A2:5A:0D:DC:1C'
DEVICE_MODEL        = 'mxiang.camera.mwc10'

HEADER_SIZE         = 8
REQUEST_TIMEOUT     = 10
TIMESYNC_INTERVAL   = 30
HEARTBEAT_INTERVAL  = 10

AP_ETH_WIRED = {
    'ssid'  : 'Wired Ethernet',
    'bssid' : 'FF:FF:FF:FF:FF:FF',
    'rssi'  : '0',
    'freq'  : 2412,
}

class LoginStatus(IntEnum):
    Ok      = 0
    Stage2  = 1
    Error   = -1
    NoCode  = 1 << 65

class SignAlgorithm(IntEnum):
    Invalid = 0
    HMAC    = 1
    MJAC    = 2

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
        code = cls.type_checked(data['code'], int)
        message = cls.type_checked(data['message'], str)
        return cls(code, message, data = data.get('data'))

class RPCRequest(Payload):
    id     : Optional[int]
    args   : Union[Sequence, dict[str, Any]]
    method : str

    def __init__(self, method: str, *, id: Optional[int] = None, args: Union[None, Sequence, dict[str, Any]] = None):
        self.id     = id
        self.args   = args or {}
        self.method = method

    def __repr__(self) -> str:
        return '\n'.join([
            'RPCRequest {',
            '    id     = %d' % self.id,
            '    method = %s' % self.method,
            '    args   = %s' % ('\n' + ' ' * 4).join(json.dumps(self.args, indent = 4).splitlines()),
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'id'     , self.id           ),
                    ( 'params' , self.args or None ),
                    ( 'method' , self.method       ),
                )
                if v is not None
            }
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_json(cls, data: str) -> 'RPCRequest':
        obj = json.loads(data)
        rid = cls.type_checked(obj.get('id', None), (int, None))
        args = cls.type_checked(obj.get('params', {}), (list, dict))
        method = cls.type_checked(obj['method'], str)
        return cls(method, id = rid, args = args)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RPCRequest':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class RPCResponse(Payload):
    id    : int
    data  : Optional[Any]
    error : Optional[RPCError]

    def __init__(self, id: int, *, data: Optional[Any] = None, error: Optional[RPCError] = None):
        self.id    = id
        self.data  = data
        self.error = error

    def __repr__(self) -> str:
        return ''.join([
            'RPCResponse {\n',
            '    id    = %d\n' % self.id,
            self.data and '    data  = %s\n' % ('\n' + ' ' * 4).join(json.dumps(self.data, indent = 4).splitlines()) or '',
            self.error and '    error = %s\n' % self.error or '',
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'id'    , self.id    ),
                    ( 'data'  , self.data  ),
                    ( 'error' , self.error and {
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
        rid = cls.type_checked(obj['id'], int)
        error = cls.type_checked(obj.get('error', {}), dict)
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

class LoginRequest(Payload):
    did  : int
    cert : str
    rand : str
    sign : str
    algo : list[SignAlgorithm]

    def __init__(
        self,
        did  : int,
        cert : str = '',
        rand : str = '',
        sign : bytes = b'',
        algo : Optional[list[SignAlgorithm]] = None,
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
        did = cls.type_checked(obj['did'], int)
        cert = cls.type_checked(obj.get('cert', ''), str)
        rand = cls.type_checked(obj.get('device_random', ''), str)
        sign = base64.b64decode(cls.type_checked(obj.get('sign', ''), str))
        algo = [SignAlgorithm(cls.type_checked(v, int)) for v in cls.type_checked(obj.get('sign_suites', []), list)]
        return cls(did, cert = cert, sign = sign, rand = rand, algo = algo)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'LoginRequest':
        return cls.from_json(data.rstrip(b'\x00').decode('utf-8'))

class LoginResponse(Payload):
    msg  : str
    rand : str
    code : LoginStatus
    algo : SignAlgorithm

    def __init__(self, code: LoginStatus, msg: str, algo: SignAlgorithm, rand: str):
        self.msg  = msg
        self.algo = algo
        self.code = code
        self.rand = rand

    def __repr__(self) -> str:
        return '\n'.join([
            'LoginAck {',
            '    code = %s' % ('(n/a)' if self.code == LoginStatus.NoCode else self.code),
            '    msg  = %s' % repr(self.msg),
            '    algo = %s' % ('(n/a)' if self.algo == SignAlgorithm.Invalid else self.algo),
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
        msg = cls.type_checked(obj.get('message', ''), str)
        rand = cls.type_checked(obj.get('cloud_random', ''), str)
        code = LoginStatus(cls.type_checked(obj.get('code', LoginStatus.NoCode), int))
        algo = SignAlgorithm(cls.type_checked(obj.get('sign_suite', SignAlgorithm.Invalid), int))
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
        algo : Optional[list[SignAlgorithm]] = None,
    ) -> 'Packet':
        return Packet(PacketType.Login, seq, LoginRequest(did, cert, rand, sign, algo))

    @classmethod
    def notify(cls, seq: int, method: str, *args, **kwargs) -> 'Packet':
        if args and kwargs:
            raise ValueError('args and kwargs cannot be present at the same time')
        else:
            return Packet(PacketType.RPC, seq, RPCRequest(method, args = args or kwargs))

    @classmethod
    def request(cls, seq: int, id: int, method: str, *args, **kwargs) -> 'Packet':
        if args and kwargs:
            raise ValueError('args and kwargs cannot be present at the same time')
        else:
            return Packet(PacketType.RPC, seq, RPCRequest(method, id = id, args = args or kwargs))

    @classmethod
    def response(cls, seq: int, id: int, *, data: Optional[Any] = None, error: Optional[RPCError] = None) -> 'Packet':
        return Packet(PacketType.RPCAck, seq, RPCResponse(id, data = data, error = error))

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

class SecurityProvider:
    @property
    def device_id(self) -> int:
        raise NotImplementedError()

    @property
    def root_cert(self) -> str:
        raise NotImplementedError()

    @property
    def vendor_cert(self) -> str:
        raise NotImplementedError()

    @property
    def device_cert(self) -> str:
        raise NotImplementedError()

    def generate_signature(self, _: bytes) -> Signature:
        raise NotImplementedError()

class MJACSecurityProvider(SecurityProvider):
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
    algo     : SignAlgorithm
    secp     : SecurityProvider
    dev_rand : str
    srv_rand : str

    __algorithms__ = [
        SignAlgorithm.MJAC,
    ]

    def __init__(self, secp: SecurityProvider):
        self.secp     = secp
        self.algo     = SignAlgorithm.Invalid
        self.srv_rand = ''
        self.dev_rand = ''

    @property
    def next_rand(self) -> str:
        self.dev_rand = os.urandom(16).hex()
        return self.dev_rand

    def _sign_hmac(self) -> bytes:
        raise NotImplementedError('HMAC signature algorithm is not supported')

    def _sign_mjac(self) -> bytes:
        data = self.dev_rand + self.srv_rand
        return self.secp.generate_signature(data.encode('utf-8')).to_asn1()

    def sign(self) -> bytes:
        if self.algo == SignAlgorithm.HMAC:
            raise NotImplementedError('HMAC signature algorithm is not supported')
        elif self.algo == SignAlgorithm.MJAC:
            return self._sign_mjac()
        else:
            raise ValueError('invalid signature algorithm')

    def stage1(self, seq: int) -> LoginRequest:
        return Packet.login(
            seq  = seq,
            did  = self.secp.device_id,
            cert = self.secp.vendor_cert + self.secp.device_cert,
            rand = self.next_rand,
            algo = self.__algorithms__,
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
        raise NotImplementedError

    def send_packet(self, _: Packet):
        raise NotImplementedError

class MiioRPC:
    log    : Logger
    incr   : int
    sender : ReferenceType[Sender]
    waiter : dict[int, tuple[Future[RPCResponse], TimerHandle]]

    def __init__(self, sender: ReferenceType[Sender]):
        self.log    = logging.getLogger('miio.rpc')
        self.incr   = 0
        self.waiter = {}
        self.sender = sender

    def _rand(self) -> int:
        ret, = struct.unpack('H', os.urandom(2))
        return ret

    def _next_id(self) -> int:
        self.incr += 1
        return (self.incr & 0xffff) | (self._rand() & 0x7fff) << 16

    def _fire_timeout(self, pid: int):
        fut = self.waiter.pop(pid, None)
        fut and fut[0].set_exception(TimeoutError)

    def send(self, method: str, *args, **kwargs) -> Future[RPCResponse]:
        snd = self.sender()
        pid = self._next_id()
        fut = asyncio.get_running_loop().create_future()
        tmr = asyncio.get_running_loop().call_later(REQUEST_TIMEOUT, self._fire_timeout, pid)
        snd.send_packet(Packet.request(snd.next_seq(), pid, method, *args, **kwargs))
        self.waiter[pid] = (fut, tmr)
        return fut

    def notify(self, method: str, *args, **kwargs):
        snd = self.sender()
        snd.send_packet(Packet.notify(snd.next_seq(), method, *args, **kwargs))

    def reply_to(self, p: RPCRequest, *, data: Optional[Any] = None, error: Optional[RPCError] = None):
        snd = self.sender()
        snd.send_packet(Packet.response(snd.next_seq(), p.id, data = data, error = error))

    def handle_response(self, p: RPCResponse):
        pid = p.id
        fut, tmr = self.waiter.pop(pid, (None, None))

        # check if it's a valid response
        if fut is None:
            self.log.warning('Unexpected RPC response, dropped: ' + repr(p))
            return

        # cancel the timeout, and resolve the future
        tmr.cancel()
        fut.set_result(p)

class CameraSIID(IntEnum):
    pass

class GatewaySIID(IntEnum):
    CameraControl   = 2
    StorageSD       = 3
    StorageUSB      = 4
    StorageControl  = 5
    OTA             = 6

class OTAPIID(IntEnum):
    Progress        = 1
    State           = 2

class StoragePIID(IntEnum):
    Enabled         = 1
    TotalSize       = 2
    FreeSize        = 3
    UsedSize        = 4
    Status          = 5

class CameraControlPIID(IntEnum):
    PowerSwitch     = 1

class StorageControlPIID(IntEnum):
    StorageSwitch   = 1
    Type            = 2
    LightIndicator  = 3

SIID = Union[
    CameraSIID,
    GatewaySIID,
]

PIID = Union[
    OTAPIID,
    StoragePIID,
    CameraControlPIID,
    StorageControlPIID,
]

class MiioProperties:
    @property
    def storage(self) -> dict[SIID, dict[PIID, Any]]:
        raise NotImplemented

    def get(self, siid: SIID, piid: PIID) -> Any:
        if siid not in self.storage:
            raise ValueError('invalid SIID ' + str(siid))
        elif piid not in self.storage[siid]:
            raise ValueError('invalid PIID %s for SIID %s' % (piid, siid))
        else:
            return self.storage[siid][piid]

    def set(self, siid: SIID, piid: PIID, value: Any):
        if siid not in self.storage:
            raise ValueError('invalid SIID: ' + str(siid))
        elif piid not in self.storage[siid]:
            raise ValueError('invalid PIID for SIID %s: %s' % (siid, piid))
        elif type(value) is not type(self.storage[siid][piid]):
            raise TypeError('%s expected for SIID %s and PIID %s, got %s' % (type(self.storage[siid][piid]), siid, piid, type(value)))
        else:
            self.storage[siid][piid] = value

class MiioCameraProperties(MiioProperties):
    @cached_property
    def storage(self) -> dict[CameraSIID, dict[PIID, Any]]:
        return {}

class MiioGatewayProperties(MiioProperties):
    @cached_property
    def storage(self) -> dict[GatewaySIID, dict[PIID, Any]]:
        return {
            GatewaySIID.CameraControl: {
                CameraControlPIID.PowerSwitch: False,
            },
            GatewaySIID.StorageSD: {
                StoragePIID.Enabled   : False,
                StoragePIID.TotalSize : 0,
                StoragePIID.FreeSize  : 0,
                StoragePIID.UsedSize  : 0,
                StoragePIID.Status    : 0,
            },
            GatewaySIID.StorageUSB: {
                StoragePIID.Enabled   : False,
                StoragePIID.TotalSize : 0,
                StoragePIID.FreeSize  : 0,
                StoragePIID.UsedSize  : 0,
                StoragePIID.Status    : 0,
            },
            GatewaySIID.StorageControl: {
                StorageControlPIID.StorageSwitch  : False,
                StorageControlPIID.Type           : 0,
                StorageControlPIID.LightIndicator : False,
            },
            GatewaySIID.OTA: {
                OTAPIID.Progress : 0,
                OTAPIID.State    : 'idle',
            },
        }

class MiioEvents:
    did       : int
    log       : Logger
    rpc       : MiioRPC
    uptime    : int
    gw_props  : MiioGatewayProperties
    cam_props : dict[str, MiioCameraProperties]

    def __init__(self, did: int, rpc: MiioRPC, uptime: int):
        self.did       = did
        self.rpc       = rpc
        self.log       = logging.getLogger('miio.events')
        self.uptime    = uptime
        self.gw_props  = MiioGatewayProperties()
        self.cam_props = {}

    async def device_ready(self):
        await asyncio.wait([
            self.rpc.send('props', ota_state = 'idle'),
            self.rpc.send('_async.stat',
                model           = DEVICE_MODEL,
                fw_ver          = FW_VER,
                miio_client_ver = MIIO_CLI_VER,
                **{
                    'miio.sc_type': {
                        'device_sc_type': [16],
                        'user_sc_type': -1,
                    },
                }
            ),
            self.rpc.send('_otc.info',
                life            = int(time.monotonic() - self.uptime),
                uid             = 6598941468,
                model           = DEVICE_MODEL,
                token           = '6c686b35314175486c5a426851444a56',
                ipflag          = 1,
                miio_ver        = MIIO_VER,
                mac             = DEVICE_MAC,
                fw_ver          = FW_VER,
                hw_ver          = HW_VER,
                miio_client_ver = MIIO_CLI_VER,
                VmPeak          = 0,
                VmRSS           = 0,
                MemFree         = 0,
                ap              = AP_ETH_WIRED,
                miio_times      = [0] * 4,
                netif           = {
                    'localIp' : '172.20.0.226',
                    'mask'    : '255.255.255.0',
                    'gw'      : '172.20.0.254'
                },
            ),
        ])
        # print('_sync.subdev_upinfo', await self.rpc.send('_sync.subdev_upinfo', did = '589340360', fw_ver = '1.2.1_1999'))
        # self.task = asyncio.create_task(self._keepalive())

    async def handle_request(self, p: RPCRequest):
        meth = p.method
        func = self.__rpc_handlers__.get(meth)
        self.log.debug('RPC request: ' + str(p))

        # check for method
        if func is None:
            self.log.error('Unknown RPC method %r. request = %s' % (meth, p))
            self.rpc.reply_to(p, error = RPCError(-1, 'invalid request'))
            return

        # attempt to handle the request
        try:
            resp = await func(self, p)
        except RPCError as e:
            self.rpc.reply_to(p, error = e)
        except Exception:
            self.log.exception('Exception when handling RPC request: ' + str(p))
            self.rpc.reply_to(p, error = RPCError(-1, 'unhandled exception'))
        else:
            if resp is not None:
                self.rpc.reply_to(p, data = resp)

    async def _rpc_nop(self, _: RPCRequest):
        pass

    async def _rpc_get_properties(self, p: RPCRequest) -> list[dict[str, Any]]:
        vals = []
        args = p.args

        # fetch every property
        for item in args:
            try:
                did = Payload.type_checked(item['did'], str)
                siid = Payload.type_checked(item['siid'], int)
                piid = Payload.type_checked(item['piid'], int)
            except (KeyError, TypeError, ValueError) as e:
                self.log.error('Invalid RPC request: ' + str(e))
                raise RPCError(-1, 'invalid request') from None
            else:
                if did == str(self.did):
                    try:
                        vals.append((did, siid, piid, self.gw_props.get(siid, piid)))
                    except ValueError as e:
                        self.log.error('Cannot read property %s.%d.%d: %s' % (did, siid, piid, e))
                        raise RPCError(-1, 'cannot read property: ' + str(e)) from None
                # TODO: handle camera properties
                else:
                    self.log.warning('No such device: %s.' % did)
                    raise RPCError(-2, 'no such device')

        # construct the reply
        return [{
            'did'   : did,
            'code'  : 0,
            'siid'  : siid,
            'piid'  : piid,
            'value' : value,
        } for did, siid, piid, value in vals ]

    __rpc_handlers__ = {
        'get_properties' : _rpc_get_properties,
    }

class MiioClient(Sender):
    rd     : StreamReader
    wr     : StreamWriter
    seq    : int
    log    : Logger
    rpc    : MiioRPC
    ctx    : SSLContext
    wbuf   : Queue
    login  : LoginCtx
    events : MiioEvents
    uptime : float

    def __init__(
        self,
        rd     : StreamReader,
        wr     : StreamWriter,
        ctx    : SSLContext,
        secp   : SecurityProvider,
        uptime : int,
    ):
        self.rd     = rd
        self.wr     = wr
        self.seq    = -1
        self.ctx    = ctx
        self.log    = logging.getLogger('miio')
        self.rpc    = MiioRPC(ReferenceType(self))
        self.rand   = b''
        self.wbuf   = Queue()
        self.state  = 'login_1'
        self.login  = LoginCtx(secp)
        self.events = MiioEvents(secp.device_id, self.rpc, uptime)
        self.uptime = uptime

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send_packet(self, p: Packet):
        self.wbuf.put_nowait(p)

    async def _timesync(self):
        while True:
            dt = time.monotonic() - self.uptime
            self.log.debug('Time-sync with uptime %.3fs' % dt)
            self.send_packet(Packet.sync(self.next_seq(), int(dt * 1000)))
            await asyncio.sleep(TIMESYNC_INTERVAL)

    async def _heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            self.log.debug('Keep alive')
            self.send_packet(Packet.keepalive(self.next_seq()))

    async def _login_poller(self):
        while True:
            match self.state:
                case 'idle':
                    await asyncio.sleep(1)
                case 'online':
                    self.state = 'idle'
                    asyncio.get_running_loop().create_task(self.events.device_ready())
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
                await self.events.handle_request(p.data)
            case PacketType.RPCAck:
                self.rpc.handle_response(p.data)
            case PacketType.SyncAck:
                self.log.debug('Time-sync from server. utc_ms = %d' % p.data.utc_ms)
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
                            self.log.warning('Login failure, retry after 1 second: %s: %s' % (p.data.code, p.data.msg))
                    case 'wait_login_2':
                        if p.data.code == LoginStatus.Ok:
                            self.state = 'online'
                            self.log.info('Login successful')
                        elif p.data.code == LoginStatus.NoCode:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: unknown error')
                        else:
                            self.state = 'retry_login_1'
                            self.log.warning('Login failure, retry after 1 second: %s: %s' % (p.data.code, p.data.msg))
                    case state:
                        self.log.warning('LoginAck at the wrong state (%s), dropped.' % state)
            case _:
                self.log.warning('Unexpected packet, dropped. packet = %s' % p)

    async def _network_receiver(self):
        while True:
            p = await Packet.read_from(self.rd)
            self.log.debug('Received %s packet with Seq %d' % (p.ty.name, p.seq))
            await self._network_handler(p)

    async def _network_transmitter(self):
        while True:
            p = await self.wbuf.get()
            t = time.monotonic_ns()
            self.wr.write(p.to_bytes())
            self.log.debug('Packet %s with Seq %d was transmitted in %.3fms' % (p.ty.name, p.seq, (time.monotonic_ns() - t) / 1e6))

    async def run_forever(self):
        await asyncio.wait(
            return_when = asyncio.FIRST_COMPLETED,
            fs          = [
                asyncio.ensure_future(self._timesync()),
                asyncio.ensure_future(self._heartbeat()),
                asyncio.ensure_future(self._login_poller()),
                asyncio.ensure_future(self._network_receiver()),
                asyncio.ensure_future(self._network_transmitter()),
            ],
        )

    @staticmethod
    async def resolve(
        dns               : str = 'dns.io.mi.com',
        host              : str = 'ots.io.mi.com',
        security_provider : Optional[SecurityProvider] = None,
    ) -> tuple[str, int]:
        secp = security_provider or MJACSecurityProvider()
        resp = requests.get(
            url    = 'https://%s/gslb' % dns,
            params = {
                'dm'        : host,
                'id'        : secp.device_id,
                'tver'      : 2,
                'model'     : DEVICE_MODEL,
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

    @classmethod
    async def connect(
        cls,
        host              : str = 'ots.io.mi.com',
        port              : int = 443,
        security_provider : Optional[SecurityProvider] = None,
        **kwargs,
    ) -> 'MiioClient':
        t0 = time.monotonic()
        secp = security_provider or MJACSecurityProvider()

        # prevent certificate confliction
        kwargs.pop('cafile', None)
        kwargs.pop('capath', None)
        kwargs['cadata'] = secp.root_cert

        # create a SSL context
        ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_verify_locations(**kwargs)

        # connect to MiIO OT server
        rd, wr = await asyncio.open_connection(host, port, ssl = ctx)
        return MiioClient(rd, wr, ctx = ctx, secp = secp, uptime = t0)

async def main():
    # with open('packets.gdbdump') as fp:
    #     idx = 0
    #     host = ''
    #     date = ''
    #     name = '(n/a)'
    #     state = 'host'
    #     domain = ''
    #     for line in fp.read().splitlines():
    #         line = line.strip()
    #         if not line:
    #             continue
    #         if line.startswith('Breakpoint'):
    #             date = ''
    #             name = line.split()[-2]
    #             continue
    #         if date == '':
    #             date = '[' + line.strip() + ']'
    #             continue
    #         if not line.startswith('$'):
    #             continue
    #         if name == 'd0_tls_open':
    #             val = line.split(maxsplit = 3)[-1]
    #             if state == 'host':
    #                 host = val
    #                 state = 'domain'
    #                 continue
    #             elif state == 'domain':
    #                 domain = val
    #                 state = 'port'
    #                 continue
    #             elif state == 'port':
    #                 name = '(n/a)'
    #                 state = 'host'
    #                 print(date, 'd0_tls_open: host', host, 'domain', domain, 'port', val)
    #                 print()
    #                 continue
    #             else:
    #                 raise RuntimeError()
    #         line = line.split('=', 1)[1].strip()
    #         def gendata():
    #             for v in line[1:-1].split(','):
    #                 v = [x.strip() for x in v.split()]
    #                 x = int(v[0], 16)
    #                 if len(v) == 1:
    #                     yield x
    #                 else:
    #                     yield from [x] * int(v[2])
    #         rbuf = bytes(gendata())
    #         data = StreamReader()
    #         data.feed_data(rbuf)
    #         try:
    #             pkt = await Packet.read_from(data)
    #             print(date, 'Seq %d:' % idx, name, pkt.ty, pkt.data)
    #         except ValueError as e:
    #             print(e)
    #             print(date, 'Seq %d:' % idx, name, rbuf)
    #         print()
    #         idx += 1
    #         name = '(n/a)'
    secp = MJACSecurityProvider()
    host, port = await MiioClient.resolve(security_provider = secp)
    conn = await MiioClient.connect(host, port, security_provider = secp)
    await conn.run_forever()

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(main())