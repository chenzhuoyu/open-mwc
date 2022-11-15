#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import base64
import struct
import hashlib
import binascii

from enum import IntEnum
from urllib import parse

from typing import Any
from typing import Type
from typing import Callable
from typing import Optional
from typing import Sequence

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.constant_time import bytes_eq

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve

HEADER_SIZE  = 32
HEADER_MAGIC = 0x2131

class Seq:
    @staticmethod
    def foreach(func: Callable[[bytes], None], seq: Sequence[bytes]):
        for v in seq:
            func(v)

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

class MACAddress:
    @staticmethod
    def parse(mac: str) -> bytes:
        return MACAddress.validated(binascii.unhexlify(mac.replace(':', '')))

    @staticmethod
    def validated(mac: bytes) -> bytes:
        if len(mac) != 6:
            raise ValueError('invalid mac address: ' + mac.hex(':'))
        else:
            return mac

class SignSuite(IntEnum):
    Invalid = 0
    HMAC    = 1
    MJAC    = 2

class CurveSuite(IntEnum):
    SECP256R1 = 3
    SECP384R1 = 4

    def to_ec_curve(self) -> EllipticCurve:
        match self:
            case self.SECP256R1 : return SECP256R1()
            case self.SECP384R1 : return SECP384R1()
            case _              : raise RuntimeError('unreachable')

    @classmethod
    def selection_order(cls) -> list['CurveSuite']:
        return [
            cls.SECP256R1,
            cls.SECP384R1,
        ]

class PinMode(IntEnum):
    Unknown1    = 1
    RandomInt   = 2
    UniqueToken = 3
    Unknown4    = 4

class Pin:
    oob  : bytes
    mode : PinMode

    def __init__(self, mode: PinMode, oob: bytes = b''):
        self.oob = oob
        self.mode = mode

    @classmethod
    def random(cls) -> 'Pin':
        return cls(PinMode.RandomInt, os.urandom(4))

    @classmethod
    def from_oob(cls, oob: bytes) -> 'Pin':
        return cls(PinMode.UniqueToken, oob)

class Key:
    iv    : bytes
    key   : bytes
    token : bytes

    def __init__(self, iv: bytes, key: bytes, token: bytes):
        self.iv    = iv
        self.key   = key
        self.token = token

    def __repr__(self) -> str:
        return '\n'.join([
            'Key {',
            '    iv    = ' + self.iv.hex(),
            '    key   = ' + self.key.hex(),
            '    token = ' + self.token.hex(),
            '}',
        ])

    def sign(self, *data: bytes) -> bytes:
        hmac = HMAC(self.key, SHA256())
        Seq.foreach(hmac.update, data)
        return hmac.finalize()

    def verify(self, sign: bytes, *data: bytes) -> bool:
        return bytes_eq(sign, self.sign(*data))

    def encrypt(self, data: bytes) -> bytes:
        pad = 16 - (len(data) % 16)
        aes = Cipher(AES128(self.key), CBC(self.iv)).encryptor()
        return aes.update(data) + aes.update(bytes([pad] * pad)) + aes.finalize()

    def decrypt(self, data: bytes) -> bytes:
        aes = Cipher(AES128(self.key), CBC(self.iv)).decryptor()
        buf = aes.update(data) + aes.finalize()
        return buf[:-buf[-1]]

    @classmethod
    def empty(cls) -> 'Key':
        return cls(b'', b'', b'')

    @classmethod
    def from_key(cls, key: bytes) -> 'Key':
        return cls(bytes(16), key, b'')

    @classmethod
    def from_token(cls, token: bytes) -> 'Key':
        key = hashlib.md5(token).digest()
        return cls(hashlib.md5(key + token).digest(), key, token)

class DeviceInfo:
    did: int
    key: Key
    pin: Pin
    mac: bytes

    def __init__(self, did: int, mac: bytes, key: Key, pin: Pin):
        self.did = did
        self.key = key
        self.pin = pin
        self.mac = mac

    @classmethod
    def parse(cls, url: str, *, token: bytes = b'') -> 'DeviceInfo':
        args = {}
        refs = parse.urlparse(url)

        # check for device identification URL
        if refs.scheme != 'https' or refs.netloc != 'home.mi.com' or refs.path != '/do/home.html':
            raise ValueError('not a valid device identification URL')

        # everything must appear exactly once
        for qs in refs.query.split('&'):
            val = qs.split('=', 1)
            name = val[0]

            # check for duplications
            if name in args:
                raise ValueError('not a valid device identification URL')
            else:
                args[name] = parse.unquote(val[1])

        # extract the URL parts
        try:
            did = int(args['d'])
            mac = str(args['m']).lower()
            oob = str(args['O']).encode('utf-8')
        except (KeyError, ValueError):
            raise ValueError('not a valid device identification URL') from None

        # cosntuct the device info
        return cls(
            did,
            MACAddress.parse(mac),
            Key.from_token(token or base64.b64encode(os.urandom(12))),
            Pin.from_oob(oob),
        )

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
    args   : Any
    method : str

    def __init__(self, method: str, *, id: Optional[int] = None, args: Any = None):
        self.id     = id
        self.args   = args
        self.method = method

    @property
    def _readable_args(self) -> str:
        return ('\n' + ' ' * 4).join(json.dumps(self.args, indent = 4, sort_keys = True).splitlines())

    def __repr__(self) -> str:
        return ''.join([
            'RPCRequest {\n',
            '    id     = %d\n' % self.id if self.id is not None else '',
            '    method = %s\n' % self.method,
            '    args   = %s\n' % self._readable_args,
            '}',
        ])

    def to_json(self) -> str:
        return json.dumps(
            separators = (',', ':'),
            obj        = {
                k: v
                for k, v in (
                    ( 'id'     , self.id     ),
                    ( 'params' , self.args   ),
                    ( 'method' , self.method ),
                )
                if v is not None
            }
        )

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'RPCRequest':
        rid = Payload.type_checked(data.get('id', None), (int, None))
        args = Payload.type_checked(data.get('params', {}), (str, list, dict))
        method = Payload.type_checked(data['method'], str)

        # handle the special case of an empty string
        if not isinstance(args, str):
            return cls(method, id = rid, args = args)
        elif args == '':
            return cls(method, id = rid)
        else:
            raise ValueError('invalid parameter type: must be list or dict')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RPCRequest':
        return cls.from_dict(Payload.type_checked(json.loads(data.rstrip(b'\x00').decode('utf-8')), dict))

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
            '    data  = %s\n' % self._readable_data if self.data else '',
            '    error = %s\n' % self.error if self.error else '',
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

    def raise_for_error(self):
        if self.error is not None:
            raise self.error

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'RPCRequest':
        rid = Payload.type_checked(data['id'], int)
        error = Payload.type_checked(data.get('error', {}), dict)
        return cls(rid, data = data.get('result'), error = error and RPCError.from_dict(error) or None)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'RPCRequest':
        return cls.from_dict(Payload.type_checked(json.loads(data.rstrip(b'\x00').decode('utf-8')), dict))

class PacketType(IntEnum):
    RPC         = 1
    Probe       = 2
    Keepalive   = 3

class Packet:
    ts    : int
    did   : int
    data  : Optional[Payload]
    type  : PacketType
    token : bytes

    class Gen:
        ts: float
        ty: type['Packet']

        def __init__(self):
            self.ty = Packet
            self.ts = time.monotonic()

        def now(self) -> int:
            return int((time.monotonic() - self.ts) * 1000)

        def ack(self, did: int, ack: bytes) -> 'Packet':
            return self.ty(self.now(), did, None, PacketType.Probe, ack)

        def rpc(self, did: int, data: Payload) -> 'Packet':
            return self.ty(self.now(), did, data, PacketType.RPC, b'')

        def sync(self, ts: int):
            self.ts = time.monotonic() - ts / 1000

        def parse(self, data: bytes, *, key: Optional[Key] = None) -> 'Packet':
            ret = Packet.parse(data, key = key)
            self.sync(ret.ts)
            return ret

    def __init__(self, ts: int, did: int, data: Optional[Payload], type: PacketType, token: bytes):
        self.ts    = ts
        self.did   = did
        self.data  = data
        self.type  = type
        self.token = token

    def __repr__(self) -> str:
        return ''.join([
            'Packet {\n',
            '    type  = %s\n' % self.type,
            '    ts    = %d\n' % self.ts if self.ts  != -1 else '',
            '    did   = %d\n' % self.did if self.did != -1 else '',
            '    token = %s\n' % self.token.hex() if self.token else '',
            '    data  = %s\n' % ('\n' + ' ' * 4).join(str(self.data).splitlines()) if self.data else '',
            '}',
        ])

    def to_bytes(self, key: Key) -> bytes:
        ty = self.type
        data = self.data

        # encrypt the body if needed
        if data is None:
            if ty == PacketType.RPC:
                raise ValueError('%s packet must have a body' % ty.name)
            else:
                out = b''
        else:
            if ty != PacketType.RPC:
                raise ValueError('%s packet does not have body' % ty.name)
            else:
                out = key.encrypt(data.to_bytes())

        # pack the header
        nb = len(out) + HEADER_SIZE
        buf = bytearray(struct.pack('>HHqi16s', HEADER_MAGIC, nb, self.did, self.ts, key.token) + out)

        # special case of the probe packet
        if ty == PacketType.Probe:
            cksum = self.token
        else:
            cksum = hashlib.md5(buf).digest()

        # update the checksum field
        struct.pack_into('16s', buf, 16, cksum)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes, *, key: Optional[Key] = None) -> 'Packet':
        hdr = data[:HEADER_SIZE]
        magic, size, did, ts, cksum = struct.unpack('>HHqi16s', hdr)

        # check packet magic
        if magic != HEADER_MAGIC:
            raise ValueError('invalid packet magic')

        # check for packet length
        if size != len(data):
            raise ValueError('incorrect packet length')

        # determain packet type
        if size != HEADER_SIZE:
            if key is not None:
                ty = PacketType.RPC
            else:
                raise ValueError('invalid probe packet')
        else:
            if did == -1 or key is None:
                ty = PacketType.Probe
            else:
                ty = PacketType.Keepalive

        # probe packet does not have checksum
        if ty == PacketType.Probe:
            return Packet(ts, did, b'', ty, cksum)

        # at this point, the key is required
        if key is None:
            raise ValueError('key is required for %s packets' % ty.name)

        # calculate the checksum
        md5 = hashlib.md5(data[:HEADER_SIZE - 16])
        md5.update(key.token)
        md5.update(data[HEADER_SIZE:])

        # verify the checksum
        if cksum != md5.digest():
            raise ValueError('%s packet checksum mismatch: %s != %s' % (ty.name, cksum.hex(), md5.hexdigest()))

        # no payload data
        if ty == PacketType.Keepalive:
            return cls(ts, did, b'', ty, cksum)

        # decrypt the payload
        data = data[HEADER_SIZE:]
        data = json.loads(key.decrypt(data).rstrip(b'\x00').decode('utf-8'))

        # check if it is a request
        if 'method' in data:
            return cls(ts, did, RPCRequest.from_dict(data), ty, cksum)
        else:
            return cls(ts, did, RPCResponse.from_dict(data), ty, cksum)

    @staticmethod
    def probe_bytes() -> bytes:
        return struct.pack('>HHqi16s', HEADER_MAGIC, HEADER_SIZE, -1, -1, b'\xff' * 16)
