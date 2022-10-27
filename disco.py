#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import base64
import struct
import logging
import hashlib
import asyncio
import argparse
import binascii
import coloredlogs

from udp import UdpSocket
from enum import IntEnum
from urllib import parse
from logging import Logger

from miot import Payload
from miot import RPCError
from miot import RPCRequest
from miot import RPCResponse
from miot import SignSuite

from typing import Any
from typing import Callable
from typing import Optional
from typing import Sequence
from typing import NamedTuple

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.constant_time import bytes_eq

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

from mwc1x import MACAddress
from mwc1x import Configuration
from mwc1x import ApConfiguration
from mwc1x import StationConfiguration

LOG_FMT      = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL    = logging.DEBUG

HEADER_SIZE  = 32
HEADER_MAGIC = 0x2131

class Seq:
    @staticmethod
    def foreach(func: Callable[[bytes], None], seq: Sequence[bytes]):
        for v in seq:
            func(v)

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
    def from_token(cls, token: bytes) -> 'Key':
        key = hashlib.md5(token).digest()
        return cls(hashlib.md5(key + token).digest(), key, token)

class PacketType(IntEnum):
    RPC         = 1
    Probe       = 2
    Keepalive   = 3

class Packet:
    t0    : float = time.time()
    ts    : int
    did   : int
    data  : Optional[Payload]
    type  : PacketType
    token : bytes

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
            self.ts  != -1 and '    ts    = %d\n' % self.ts or '',
            self.did != -1 and '    did   = %d\n' % self.did or '',
            self.token     and '    token = %s\n' % self.token.hex() or '',
            self.data      and '    data  = %s\n' % ('\n' + ' ' * 4).join(str(self.data).splitlines()) or '',
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
    def parse(cls, key: Key, data: bytes) -> 'Packet':
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
            ty = PacketType.RPC
        elif did == -1:
            ty = PacketType.Probe
        else:
            ty = PacketType.Keepalive

        # probe packet does not have checksum
        if ty == PacketType.Probe:
            return Packet(ts, did, b'', ty, cksum)

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

        # decrypt and parse the payload
        data = key.decrypt(data[HEADER_SIZE:])
        return cls(ts, did, RPCRequest.from_bytes(data), ty, cksum)

    @classmethod
    def now(cls) -> int:
        return int((time.time() - cls.t0) * 1000)

    @classmethod
    def rpc(cls, did: int, data: Payload) -> 'Packet':
        return cls(cls.now(), did, data, PacketType.RPC, b'')

    @classmethod
    def probe_ack(cls, did: int, token: bytes) -> 'Packet':
        return cls(cls.now(), did, None, PacketType.Probe, token)

class CurveSuite(IntEnum):
    SECP256R1   = 3
    SECP384R1   = 4

    def to_ec_curve(self):
        match self:
            case self.SECP256R1 : return SECP256R1()
            case self.SECP384R1 : return SECP384R1()
            case _              : raise RuntimeError('unreachable')

class Handshake:
    key   : Key
    pin   : Pin
    rand  : bytes
    sign  : bytes
    token : bytes
    stage : int

    def __init__(self, pin: Pin, token: bytes):
        self.pin   = pin
        self.key   = Key.empty()
        self.rand  = b''
        self.sign  = b''
        self.token = token
        self.stage = 1

    @property
    def ok(self) -> bool:
        return self.stage == 0

    def _advance(self, s: int, d: int) -> bool:
        if self.stage != s:
            return False
        else:
            self.stage = d
            return True

    def _stage_1(self) -> dict[str, Any]:
        if not self._advance(1, 2):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 1')
        else:
            return {
                'type': 1,
                'ecdh': {
                    'sign_suites'  : [ SignSuite.HMAC ],
                    'curve_suites' : [ CurveSuite.SECP256R1, CurveSuite.SECP384R1 ],
                },
                'oob': {
                    'modes'   : [ self.pin.mode ],
                    'extents' : [ len(self.pin.oob) ],
                }
            }

    def _stage_2(self, p: RPCRequest) -> dict[str, Any]:
        algo = SignSuite(Payload.type_checked(p.args['ecdh']['sign_suite'], int))
        curve = CurveSuite(Payload.type_checked(p.args['ecdh']['curve_suite'], int))
        pubkey = base64.b64decode(Payload.type_checked(p.args['ecdh']['public_key'], str))

        # check for stage
        if not self._advance(2, 31):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 2')

        # only support HMAC now
        if algo != SignSuite.HMAC:
            raise RPCError(RPCError.Code.InvalidParameters, 'sign suite %s is not implemented' % algo)

        # generate and exchange keys with ECDH
        nkey = generate_private_key(curve.to_ec_curve())
        rkey = nkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        skey = nkey.exchange(ECDH(), EllipticCurvePublicKey.from_encoded_point(curve.to_ec_curve(), pubkey))

        # derive the encryption key with HKDF
        token = self.token.hex().encode('utf-8')
        self.key.key = HKDF(SHA256(), 16, token, b'').derive(skey)

        # sign the public key, and construct the response
        return {
            'type': 2,
            'ecdh': {
                'sign'       : base64.b64encode(self.key.sign(rkey)).decode('utf-8'),
                'public_key' : base64.b64encode(rkey).decode('utf-8'),
            },
        }

    def _stage_3(self, p: RPCRequest) -> dict[str, Any]:
        if not (31 <= self.stage <= 33):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 3')
        else:
            match Payload.type_checked(p.args['oob']['step'], int):
                case 1: return self._stage_3_step_1(p)
                case 2: return self._stage_3_step_2(p)
                case 3: return self._stage_3_step_3(p)
                case s: raise RPCError(-1, 'invalid step: %d' % s)

    def _stage_3_step_1(self, p: RPCRequest) -> dict[str, Any]:
        mode = p.args['oob']['mode']
        mode = PinMode(Payload.type_checked(mode, int))

        # check for pin mode and step
        if mode != self.pin.mode:
            raise RPCError(RPCError.Code.InvalidParameters, 'invalid pin mode')
        elif not self._advance(31, 32):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 3 step 1')

        # generate the local random
        oob = self.pin.oob
        self.rand = os.urandom(16)

        # sign the random number with the pin token, and compose the response
        return {
            'type' : 3,
            'oob'  : {
                'step': 1,
                'sign': base64.b64encode(self.key.sign(self.rand, oob)).decode('utf-8'),
            }
        }

    def _stage_3_step_2(self, p: RPCRequest) -> dict[str, Any]:
        sign = p.args['oob']['sign']
        sign = Payload.type_checked(sign, str)

        # check for stage, and decode the sign bytes
        if not self._advance(32, 33):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 3 step 2')
        else:
            self.sign = base64.b64decode(sign)

        # compose the response
        return {
            'type' : 3,
            'oob'  : {
                'step'   : 2,
                'random' : base64.b64encode(self.rand).decode('utf-8'),
            }
        }

    def _stage_3_step_3(self, p: RPCRequest) -> dict[str, Any]:
        rand = p.args['oob']['random']
        rand = Payload.type_checked(rand, str)

        # check for stage
        if not self._advance(33, 0):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 3 step 3')

        # verify the signature
        if not self.key.verify(self.sign, base64.b64decode(rand), self.pin.oob):
            raise RPCError(RPCError.Code.InvalidParameters, 'signature mismatch in handshake stage 3 step 3')

        # generate a random IV
        self.key.iv    = os.urandom(16)
        self.key.token = self.pin.oob

        # compose the response
        return {
            'type' : 3,
            'oob'  : {
                'iv'   : base64.b64encode(self.key.iv).decode('utf-8'),
                'step' : 3,
            }
        }

    def reset(self):
        self.key   = Key.empty()
        self.rand  = b''
        self.sign  = b''
        self.stage = 1

    def handle(self, p: RPCRequest) -> dict[str, Any]:
        try:
            match Payload.type_checked(p.args['type'], int):
                case 1: return self._stage_1()
                case 2: return self._stage_2(p)
                case 3: return self._stage_3(p)
                case t: raise RPCError(-1, 'invalid type: %d' % t)
        except Exception:
            self.stage = 1
            raise

class RPCHandler:
    hs  : Handshake
    log : Logger
    cfg : Optional['Config']

    class Config(NamedTuple):
        uid      : int
        ssid     : str
        passwd   : str
        bind_key : str

    def __init__(self, pin: Pin, token: bytes):
        self.hs  = Handshake(pin, token)
        self.cfg = None
        self.log = logging.getLogger('disco.rpc')

    async def handle_request(self, p: RPCRequest) -> Optional[RPCResponse]:
        meth = p.method
        func = self.__rpc_handlers__.get(meth)

        # check for method
        if func is None:
            self.log.error('Unknown RPC method %r', meth)
            return RPCResponse(p.id, error = RPCError(-1, 'unknown RPC method'))

        # attempt to handle the request
        try:
            resp = await func(self, p)
        except RPCError as e:
            return RPCResponse(p.id, error = e)
        except Exception:
            self.log.exception('Exception when handling RPC request:')
            return RPCResponse(p.id, error = RPCError(-1, 'unhandled exception'))

        # construct the response if needed
        if resp is None:
            return None
        else:
            return RPCResponse(p.id, data = resp)

    async def _rpc_nop(self, _: RPCRequest) -> list[str]:
        return ['ok']

    async def _rpc_miio_handshake(self, p: RPCRequest) -> dict[str, Any]:
        return self.hs.handle(p)

    async def _rpc_miio_config_router_safe(self, p: RPCRequest) -> list[str]:
        data = base64.b64decode(Payload.type_checked(p.args['data'], str))
        sign = base64.b64decode(Payload.type_checked(p.args['sign'], str))

        # check for signature
        if not self.hs.ok or not self.hs.key.verify(sign, data):
            raise RPCError(RPCError.Code.InvalidParameters, 'invalid signature')

        # decrypt and parse the configuration
        buf = self.hs.key.decrypt(data)
        cfg = json.loads(buf.decode('utf-8'))
        uid = Payload.type_checked(cfg['uid'], int)
        sid = Payload.type_checked(cfg['ssid'], str)
        pwd = Payload.type_checked(cfg['passwd'], str)
        key = Payload.type_checked(cfg['bind_key'], str)

        # save the configuration
        self.cfg = self.Config(uid, sid, pwd, key)
        return ['ok']

    __rpc_handlers__ = {
        'miIO.handshake'          : _rpc_miio_handshake,
        'miIO.stop_diag_mode'     : _rpc_nop,
        'miIO.config_router_safe' : _rpc_miio_config_router_safe,
    }

class Discovery:
    did: int
    key: Key
    pin: Pin
    mac: bytes
    log: Logger
    rpc: RPCHandler

    def __init__(self, did: int, mac: bytes, key: Key, pin: Pin):
        self.did = did
        self.key = key
        self.pin = pin
        self.mac = mac
        self.rpc = RPCHandler(pin, key.token)
        self.log = logging.getLogger('disco')

    async def run(self) -> Configuration:
        sock = await UdpSocket.new(('0.0.0.0', 54321))
        self.log.info('Discovery is now listening at port 54321')

        # listen for packets
        while self.rpc.cfg is None:
            resp = None
            rbuf, addr = await sock.recvfrom()

            # attempt to parse the request
            try:
                req = Packet.parse(self.key, rbuf)
            except Exception:
                self.log.exception('Cannot parse the request:')
                continue
            else:
                self.log.debug('Received packet: %r', req)

            # dispatch by packet type
            match req.type:
                case PacketType.RPC:
                    resp = await self.rpc.handle_request(req.data)
                    resp = resp and Packet.rpc(self.did, resp)
                case PacketType.Probe:
                    self.rpc.hs.reset()
                    resp = Packet.probe_ack(self.did, self.key.token)
                case PacketType.Keepalive:
                    self.log.debug('Keepalive from client.')
                case _:
                    self.log.warning('Unknown packet type, dropped: %r', req)

            # send response if any
            if resp is not None:
                sock.sendto(resp.to_bytes(self.key), addr)
                self.log.debug('Transmitted packet: %r', resp)

        # close the socket
        sock.close()
        self.log.info('Discovery procedure finished successfully.')

        # construct the configuration
        return Configuration(
            ap = ApConfiguration(
                ssid   = self.rpc.cfg.ssid,
                passwd = self.rpc.cfg.passwd,
            ),
            station = StationConfiguration(
                did      = self.did,
                uid      = self.rpc.cfg.uid,
                mac      = self.mac,
                oob      = self.pin.oob,
                token    = self.key.token,
                bind_key = self.rpc.cfg.bind_key.encode('utf-8'),
            ),
        )

    @classmethod
    async def discover(cls, url: str, *, token: bytes = b'') -> Configuration:
        url = parse.urlparse(url)
        query = parse.parse_qs(url.query)

        # check for device identification URL
        if url.scheme != 'https' or url.netloc != 'home.mi.com' or url.path != '/do/home.html':
            raise ValueError('not a valid device identification URL')

        # everything must appear exactly once
        for val in query.values():
            if len(val) != 1:
                raise ValueError('not a valid device identification URL')

        # extract the URL parts
        try:
            did = int(query['d'][0])
            mac = str(query['m'][0]).lower()
            oob = str(query['O'][0]).encode('utf-8')
        except (KeyError, ValueError):
            raise ValueError('not a valid device identification URL') from None

        # generate a random token if needed
        if not token:
            token = base64.b64encode(os.urandom(12))

        # start the discovery
        pin = Pin.from_oob(oob)
        key = Key.from_token(token)
        mac = MACAddress.parse(mac)
        return await cls(did, mac, key, pin).run()

async def main():
    p = argparse.ArgumentParser()
    p.add_argument('-c', '--config', metavar = 'FILE', type = str, help = 'path to save the config file', default = 'mwc1x.json')
    p.add_argument('url', type = str, help = 'device identification URL')

    # start the discovery
    ns = p.parse_args()
    cfg = await Discovery.discover(ns.url)

    # dump the configuration before saving to avoid destroying the old config
    data = json.dumps(
        obj       = cfg.to_dict(),
        indent    = 4,
        sort_keys = True,
    )

    # save the configuration to file
    with open(ns.config, 'w') as fp:
        fp.write(data)
        logging.getLogger('disco').info('Configuration was saved to "%s".', ns.config)

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(main())
