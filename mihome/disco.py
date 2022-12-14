#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import base64
import logging
import asyncio
import argparse
import coloredlogs

from udp import UdpSocket
from typing import NamedTuple
from logging import Logger

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

from miio import Key
from miio import Pin
from miio import Packet
from miio import Payload
from miio import DeviceInfo

from miio import RPCError
from miio import RPCRequest
from miio import RPCResponse

from miio import PinMode
from miio import SignSuite
from miio import CurveSuite
from miio import PacketType

from mwc1x import Configuration
from mwc1x import ApConfiguration
from mwc1x import StationConfiguration

LOG_FMT      = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL    = logging.DEBUG

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

    def _stage_1(self) -> dict[str, object]:
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

    def _stage_2(self, p: RPCRequest) -> dict[str, object]:
        ecdh = Payload.type_checked(p.dict['ecdh'], dict)
        algo = SignSuite(Payload.type_checked(ecdh['sign_suite'], int))
        curve = CurveSuite(Payload.type_checked(ecdh['curve_suite'], int))
        pubkey = base64.b64decode(Payload.type_checked(ecdh['public_key'], str))

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

    def _stage_3(self, p: RPCRequest) -> dict[str, object]:
        if not (31 <= self.stage <= 33):
            raise RPCError(RPCError.Code.InvalidParameters, 'unexpected handshake stage 3')
        else:
            match Payload.type_checked(Payload.type_checked(p.dict['oob'], dict)['step'], int):
                case 1: return self._stage_3_step_1(p)
                case 2: return self._stage_3_step_2(p)
                case 3: return self._stage_3_step_3(p)
                case s: raise RPCError(-1, 'invalid step: %d' % s)

    def _stage_3_step_1(self, p: RPCRequest) -> dict[str, object]:
        oob = Payload.type_checked(p.dict['oob'], dict)
        mode = PinMode(Payload.type_checked(oob['mode'], int))

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

    def _stage_3_step_2(self, p: RPCRequest) -> dict[str, object]:
        oob = Payload.type_checked(p.dict['oob'], dict)
        sign = Payload.type_checked(oob['sign'], str)

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

    def _stage_3_step_3(self, p: RPCRequest) -> dict[str, object]:
        oob = Payload.type_checked(p.dict['oob'], dict)
        rand = Payload.type_checked(oob['random'], str)

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

    def handle(self, p: RPCRequest) -> dict[str, object]:
        try:
            match Payload.type_checked(p.dict['type'], int):
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
    cfg : 'Config' | None

    class Config(NamedTuple):
        uid      : int
        ssid     : str
        passwd   : str
        bind_key : str

    def __init__(self, pin: Pin, token: bytes):
        self.hs  = Handshake(pin, token)
        self.cfg = None
        self.log = logging.getLogger('disco.rpc')

    async def handle_request(self, p: RPCRequest) -> RPCResponse | None:
        meth = p.method
        func = self.__rpc_handlers__.get(meth)

        # must have an ID
        if p.id is None:
            return RPCResponse(0, error = RPCError(-1, 'invalid request ID'))

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

    async def _rpc_miio_handshake(self, p: RPCRequest) -> dict[str, object]:
        return self.hs.handle(p)

    async def _rpc_miio_config_router_safe(self, p: RPCRequest) -> list[str]:
        data = base64.b64decode(Payload.type_checked(p.dict['data'], str))
        sign = base64.b64decode(Payload.type_checked(p.dict['sign'], str))

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
    log: Logger
    rpc: RPCHandler
    dev: DeviceInfo

    def __init__(self, dev: DeviceInfo):
        self.dev = dev
        self.log = logging.getLogger('disco')
        self.rpc = RPCHandler(dev.pin, dev.key.token)

    async def run(self) -> Configuration:
        repo = Packet.Gen()
        sock = await UdpSocket.new(('0.0.0.0', 54321))
        self.log.info('Discovery is now listening at port 54321')

        # listen for packets
        while self.rpc.cfg is None:
            resp = None
            rbuf, addr = await sock.recvfrom()

            # attempt to parse the request
            try:
                req = repo.parse(rbuf, key = self.dev.key)
            except Exception:
                self.log.exception('Cannot parse the request:')
                continue

            # wait for 100ms every packet, to make the time sync happy
            self.log.debug('Received packet: %r', req)
            await asyncio.sleep(0.1)

            # dispatch by packet type
            match req.type:
                case PacketType.RPC:
                    resp = await self.rpc.handle_request(Payload.type_checked(req.data, RPCRequest))
                    resp = resp and repo.rpc(self.dev.did, resp)
                case PacketType.Probe:
                    self.rpc.hs.reset()
                    resp = repo.ack(self.dev.did, self.dev.key.token)
                case PacketType.Keepalive:
                    self.log.debug('Keepalive from client.')
                case _:
                    self.log.warning('Unknown packet type, dropped: %r', req)

            # send response if any
            if resp is not None:
                sock.sendto(resp.to_bytes(self.dev.key), addr)
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
                did      = self.dev.did,
                uid      = self.rpc.cfg.uid,
                mac      = self.dev.mac,
                oob      = self.dev.pin.oob,
                token    = self.dev.key.token,
                bind_key = self.rpc.cfg.bind_key.encode('utf-8'),
            ),
        )

async def main():
    p = argparse.ArgumentParser()
    p.add_argument('-c', '--config', metavar = 'FILE', type = str, help = 'path to save the config file', default = 'mwc1x.json')
    p.add_argument('url', type = str, help = 'device identification URL')

    # start the discovery
    ns = p.parse_args()
    cfg = await Discovery(DeviceInfo.parse(ns.url)).run()

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
