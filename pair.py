#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logs
import json
import time
import base64
import asyncio
import logging
import argparse

from udp import UdpSocket
from typing import Any
from logging import Logger

from miio import Payload
from miio import RPCRequest
from miio import RPCResponse

from miio import Key
from miio import Packet
from miio import DeviceInfo

from miio import PinMode
from miio import SignSuite
from miio import CurveSuite
from miio import PacketType

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

RETRY_COUNT     = 10
REQUEST_TIMEOUT = 3.0

class ApSettings:
    ssid   : str
    passwd : str

    def __init__(self, ssid: str, passwd: str):
        self.ssid   = ssid
        self.passwd = passwd

    def __repr__(self) -> str:
        return '{SSID=%s}' % self.ssid

    @classmethod
    def load(cls, fn: str) -> 'ApSettings':
        with open(fn) as fp:
            return cls.from_json(fp.read())

    @classmethod
    def from_json(cls, src: str) -> 'ApSettings':
        return cls.from_dict(Payload.type_checked(json.loads(src), dict))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ApSettings':
        return cls(
            ssid   = Payload.type_checked(data['ssid'], str),
            passwd = Payload.type_checked(data['passwd'], str),
        )

class PairingSession:
    rid  : int
    log  : Logger
    cfg  : ApSettings
    dev  : DeviceInfo
    conn : UdpSocket
    repo : Packet.Gen

    def __init__(self, cfg: ApSettings, dev: DeviceInfo, conn: UdpSocket, repo: Packet.Gen):
        self.rid  = 1
        self.cfg  = cfg
        self.dev  = dev
        self.log  = logging.getLogger('pair')
        self.conn = conn
        self.repo = repo

    async def _recv(self) -> RPCResponse:
        while True:
            data, _ = await asyncio.wait_for(self.conn.recvfrom(), REQUEST_TIMEOUT)
            resp = self.repo.parse(data, key = self.dev.key)

            # filter out unwanted packets
            match resp.type:
                case PacketType.RPC if isinstance(resp.data, RPCResponse):
                    return resp.data
                case PacketType.RPC:
                    self.log.warning('Unexpected RPC request, dropped. packet = %s', resp)
                case PacketType.Probe:
                    self.log.warning('Unexpected Probe packet, dropped. packet = %s', resp)
                case PacketType.Keepalive:
                    self.log.debug('Keep-alive from device.')

    async def _request(self, method: str, **kwargs) -> RPCResponse:
        req = self.repo.rpc(self.dev.did, RPCRequest(method, id = self.rid, args = kwargs or {}))
        buf = req.to_bytes(self.dev.key)
        self.log.debug('RPC request: %s', req)

        # send to remote, with timeout and retry
        for _ in range(RETRY_COUNT):
            try:
                self.conn.sendto(buf)
                resp = await self._recv()
            except asyncio.TimeoutError:
                self.log.warning('Request timeout, try again.')
            else:
                break
        else:
            raise TimeoutError

        # increase the request ID
        self.rid += 1
        self.log.debug('RPC response: %s', resp)

        # check for response errors
        resp.raise_for_error()
        return resp

    async def pair(self):
        self.log.info('Querying device information ...')
        resp = await self._request('miIO.info')

        # extract the response fields
        try:
            token = bytes.fromhex(Payload.type_checked(resp.data['token'], str))
        except KeyError:
            raise ValueError('invalid handshake stage 1 response') from None

        # check the token
        if self.dev.key.token != token:
            raise ValueError('pairing token mismatch: %s != %s' % (token.hex(), self.key.token.hex()))

        # extract the device information
        uid = Payload.type_checked(resp.data['uid'], int)
        model = Payload.type_checked(resp.data['model'], str)
        miio_ver = Payload.type_checked(resp.data['miio_ver'], str)

        # query device capabilities
        self.log.info('UID: %d, Device model: %s, MiIO version: %s', uid, model, miio_ver)
        self.log.info('Stage 1: Querying device capabilities ...')
        resp = await self._request('miIO.handshake', type = 1)

        # extract the response fields
        try:
            ty = Payload.type_checked(resp.data['type'], int)
            oob = Payload.type_checked(resp.data['oob'], dict)
            ecdh = Payload.type_checked(resp.data['ecdh'], dict)
        except KeyError:
            raise ValueError('invalid handshake stage 1 response') from None

        # verify the stage
        if ty != 1:
            raise ValueError('unexpected handshake stage')

        # extract the key exchange parameters
        try:
            modes = Payload.type_checked(oob['modes'], list)
            sizes = Payload.type_checked(oob['extents'], list)
            algos = Payload.type_checked(ecdh['sign_suites'], list)
            curves = Payload.type_checked(ecdh['curve_suites'], list)
        except KeyError:
            raise ValueError('invalid handshake stage 1 response') from None

        # they should be identical in length
        if len(modes) != len(sizes):
            raise ValueError('invalid pin mode or extent')

        # select signature suite (currently HMAC only)
        if SignSuite.HMAC in algos:
            algo = SignSuite.HMAC
        else:
            raise PermissionError('no supported signature suites can be selected: ' + repr(algos))

        # select curve suites
        for curve in CurveSuite.selection_order():
            if curve in curves:
                break
        else:
            raise PermissionError('no supported curves can be selected: ' + repr(algos))

        # select pin mode
        for mode in PinMode:
            if mode in modes and mode == self.dev.pin.mode:
                if sizes[modes.index(mode)] != len(self.dev.pin.oob):
                    raise ValueError('pin size mismatch: %d != %d', len(self.dev.pin.oob), sizes[modes.index(mode)])
                else:
                    break
        else:
            raise PermissionError('no supported pin modes can be selected: ' + repr(algos))

        # generate a new ECDH key
        nkey = generate_private_key(curve.to_ec_curve())
        rkey = nkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

        # exchange with the device
        self.log.info('Stage 2: Performing ECDH key exchange with the device ...')
        resp = await self._request('miIO.handshake', type = 2, ecdh = {
            'public_key'  : base64.b64encode(rkey).decode('utf-8'),
            'sign_suite'  : algo,
            'curve_suite' : curve,
        })

        # extract the response fields
        try:
            ty = Payload.type_checked(resp.data['type'], int)
            ecdh = Payload.type_checked(resp.data['ecdh'], dict)
        except KeyError:
            raise ValueError('invalid handshake stage 2 response') from None

        # verify the stage
        if ty != 2:
            raise ValueError('unexpected handshake stage')

        # extract stage 2 fields
        try:
            sign = base64.b64decode(Payload.type_checked(ecdh['sign'], str))
            pubkey = base64.b64decode(Payload.type_checked(ecdh['public_key'], str))
        except KeyError:
            raise ValueError('invalid handshake stage 2 response') from None

        # perform the key exchange
        skey = nkey.exchange(ECDH(), EllipticCurvePublicKey.from_encoded_point(curve.to_ec_curve(), pubkey))
        ekey = Key.from_key(HKDF(SHA256(), 16, self.dev.key.token.hex().encode('utf-8'), b'').derive(skey))

        # verify public key signature
        if ekey.sign(pubkey) != sign:
            raise ValueError('handshake stage 2 key signature mismatch')

        # verify the encryption key by decrypting the extent field
        try:
            extent = json.loads(ekey.decrypt(base64.b64decode(ecdh['extent'])).decode('utf-8'))
        except ValueError:
            raise ValueError('incorrect encryption key') from None
        else:
            self.log.debug('Decrypted extent: %s', json.dumps(extent, indent = 4))

        # query device signature
        self.log.info('Stage 3: Step 1: Quering device signature ...')
        resp = await self._request('miIO.handshake', type = 3, oob = {
            'step': 1,
            'mode': self.dev.pin.mode,
        })

        # extract the response fields
        try:
            ty = Payload.type_checked(resp.data['type'], int)
            step = Payload.type_checked(resp.data['oob']['step'], int)
            ssign = base64.b64decode(Payload.type_checked(resp.data['oob']['sign'], str))
        except (KeyError, TypeError):
            raise ValueError('invalid handshake stage 3 step 1 response') from None

        # verify the stage
        if ty != 3 or step != 1:
            raise ValueError('unexpected handshake stage or step')

        # generate client random and sign it
        rand = os.urandom(16)
        sign = ekey.sign(rand, self.dev.pin.oob)

        # query device random
        self.log.info('Stage 3: Step 2: Querying device random ...')
        resp = await self._request('miIO.handshake', type = 3, oob = {
            'step': 2,
            'sign': base64.b64encode(sign).decode('utf-8'),
        })

        # extract the response fields
        try:
            ty = Payload.type_checked(resp.data['type'], int)
            step = Payload.type_checked(resp.data['oob']['step'], int)
            srand = base64.b64decode(Payload.type_checked(resp.data['oob']['random'], str))
        except (KeyError, TypeError):
            raise ValueError('invalid handshake stage 3 step 2 response') from None

        # verify the stage
        if ty != 3 or step != 2:
            raise ValueError('unexpected handshake stage or step')

        # verify the signature
        if not ekey.verify(ssign, srand, self.dev.pin.oob):
            raise ValueError('handshake random signature mismatch')

        # exchange the client random
        self.log.info('Stage 3: Step 3: Exchanging client random ...')
        resp = await self._request('miIO.handshake', type = 3, oob = {
            'step'   : 3,
            'random' : base64.b64encode(rand).decode('utf-8'),
        })

        # extract the response fields
        try:
            ty = Payload.type_checked(resp.data['type'], int)
            step = Payload.type_checked(resp.data['oob']['step'], int)
            ivec = base64.b64decode(Payload.type_checked(resp.data['oob']['iv'], str))
        except (KeyError, TypeError):
            raise ValueError('invalid handshake stage 3 step 3 response') from None

        # verify the stage
        if ty != 3 or step != 3:
            raise ValueError('unexpected handshake stage or step')

        # update IV and token
        ekey.iv    = ivec
        ekey.token = self.dev.pin.oob

        # calculate timezone offset
        offset = time.altzone if time.localtime().tm_isdst else time.timezone
        offset = -offset // 3600

        # dump the configuration
        ap_config = json.dumps(separators = (',', ':'), obj = {
            'uid'         : uid,
            'ssid'        : self.cfg.ssid,
            'passwd'      : self.cfg.passwd,
            'bind_key'    : 'a',
            'config_type' : 'app',
            'gmt_offset'  : offset,
            'tz'          : time.tzname[time.daylight],
            'wifi_config' : {'cc': 'CN'},
        })

        # encrypt and sign the AP configuration
        data = ekey.encrypt(ap_config.encode('utf-8'))
        sign = ekey.sign(data)

        # configure the device
        self.log.info('Configuring the device ...')
        resp = await self._request('miIO.config_router_safe',
            sign = base64.b64encode(sign).decode('utf-8'),
            data = base64.b64encode(data).decode('utf-8'),
        )

        # check for response
        if 'ok' in resp.data:
            self.log.info('Configuration successful.')
        else:
            raise ValueError('unexpected device response')

    @classmethod
    async def probe(cls, url: str, cfg: ApSettings, addr: tuple[str, int]) -> 'PairingSession':
        log = logging.getLogger('pair')
        log.info('Probing for devices ...')

        # receive the probe response
        for _ in range(RETRY_COUNT):
            conn = await UdpSocket.new(remote_addr = addr)
            conn.sendto(Packet.probe_bytes())

            # attempt to receive the ACK
            try:
                data, src = await asyncio.wait_for(conn.recvfrom(), REQUEST_TIMEOUT)
            except asyncio.TimeoutError:
                log.warning('Read timeout, try again.')
                conn.close()
                continue

            # check for addresses
            if src == addr:
                break

            # resoponse does not come from the intended device
            log.warning('Address mismatch, try again.')
            conn.close()

        # exceeds maximum retry count
        else:
            raise TimeoutError('timeout probing for devices')

        # parse the probing response
        repo = Packet.Gen()
        resp = repo.parse(data)
        info = DeviceInfo.parse(url, token = resp.token)

        # check for device ID
        if info.did != resp.did:
            raise ValueError('device ID mismatch: %d != %d', info.did, resp.did)

        # probing successful
        log.info('Connected to device at address %s:%d', *addr)
        return cls(cfg, info, conn, repo)

__arguments__ = [
    ('-s', '--ssid', dict(
        help    = 'name of your Wi-Fi',
        type    = str,
        metavar = 'SSID',
    )),
    ('-p', '--passwd', dict(
        help    = 'password of your Wi-Fi',
        type    = str,
        metavar = 'PASSWD',
    )),
    ('-c', '--ap-config', dict(
        help    = 'configuration file of your WiFi',
        type    = str,
        metavar = 'PASSWD',
    )),
    ('--device-addr', dict(
        help    = 'device address, default to 192.168.1.1',
        type    = str,
        metavar = 'ADDR',
        default = '192.168.1.1',
    )),
    ('--device-port', dict(
        help    = 'device port, default to 54321',
        type    = int,
        metavar = 'PORT',
        default = 54321,
    )),
    ('url', dict(
        help = 'device identification URL',
        type = str,
    )),
]

async def main():
    d = __arguments__
    p = argparse.ArgumentParser()

    # add argumnets
    for v in d:
        p.add_argument(*v[:-1], **v[-1])

    # parse the command line
    ns = p.parse_args()
    log = logging.getLogger('pair')

    # load the AP configuration
    if ns.ap_config:
        cfg = ApSettings.load(ns.ap_config)
    elif ns.ssid and ns.passwd:
        cfg = ApSettings(ns.ssid, ns.passwd)
    else:
        p.error('One of SSID / Password pair or AP configuration file must be specified.')

    # log the pairing configuration
    log.info('AP SSID        : %s', cfg.ssid)
    log.info('Device Address : %s', ns.device_addr)
    log.info('Device Port    : %s', ns.device_port)

    # start the discovery
    ps = await PairingSession.probe(ns.url, cfg, (ns.device_addr, ns.device_port))
    await ps.pair()

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
