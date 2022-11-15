#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging

from enum import IntEnum
from logging import Logger

from nacl.public import SealedBox
from nacl.public import PrivateKey

from miot import MiotRPC
from miot import Payload

class MissVendor(IntEnum):
    ThroughTek  = 1
    Agora       = 3
    CS2         = 4

class MissServer:
    log   : Logger
    rpc   : MiotRPC
    token : bytes

    def __init__(self, rpc: MiotRPC, token: bytes):
        self.rpc   = rpc
        self.log   = logging.getLogger('miss')
        self.token = token

    async def handshake(self) -> bool:
        reqkey = os.urandom(16)
        seckey = PrivateKey.generate()
        self.log.debug('Start vendor key exchange.')

        # request the MISS protocol vendor
        resp = await self.rpc.send('_sync.miss_get_vendor',
            miss_version    = '3.2.3.0',
            p2pkey_version  = 1,
            public_key      = seckey.public_key.encode().hex(),
            req_key         = reqkey.hex(),
            support_vendors = 'CS2',
            token           = self.token.hex(),
        )

        # check for errors
        if resp.error is not None:
            self.log.error('Cannot register MISS stream. Error: %s', resp.error)
            return False

        # extract the result
        try:
            key = Payload.type_checked(resp.data['p2p_key'], str)
            req = Payload.type_checked(resp.data['vendor_params'], dict)
            vid = MissVendor(Payload.type_checked(resp.data['vendor'], int))
        except (KeyError, ValueError):
            self.log.error('Invalid response from MISS server: %s', resp)
            return False

        # check for vendor type (only supports CS2)
        if vid != MissVendor.CS2:
            self.log.error('Unsupported vendor ID: %s', vid.name)
            return False

        # extract the parameters
        try:
            pid = Payload.type_checked(req['p2p_id'], str)
            crc = Payload.type_checked(req['crc_key'], str)
            lic = Payload.type_checked(req['license'], str)
            ins = Payload.type_checked(req['init_string'], str)
        except (KeyError, ValueError):
            self.log.error('Invalid response from MISS server: %s', resp)
            return False

        print('p2p_id     ', pid)
        print('p2p_key    ', key)
        print('crc_key    ', crc)
        print('license    ', lic)
        print('init_string', ins)
