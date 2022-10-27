#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import base64
import asyncio
import logging
import argparse
import netifaces

from logging import Logger

from typing import Any
from typing import Optional

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat

from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from miot import Payload
from miot import RPCError
from miot import RPCRequest
from miot import RPCResponse

from miot import MiotRPC
from miot import MiotApplication
from miot import MiotConfiguration

from mwc11 import MWC11
from mwc11 import STATION_BIND
from mwc11 import STATION_PORT
from mwc1x import Configuration
from mwc1x import ConfigurationFile

from props import Properties
from props import ConstProperty

from props import OTAPIID
from props import StationSIID
from props import StoragePIID
from props import CameraControlPIID
from props import StorageControlPIID

HW_VER       = 'Linux'
FW_VER       = '4.1.6_1999'
MIIO_VER     = '0.0.9'
MIIO_CLI_VER = '4.1.6'
DEVICE_MODEL = 'mxiang.camera.mwc10'

class MiotApp(MiotApplication):
    did    : int
    cam    : MWC11
    log    : Logger
    rpc    : MiotRPC
    cfg    : Configuration
    props  : Properties
    uptime : int

    __arguments__ = [
        ('-c', '--config', dict(
            help    = 'config file path',
            type    = str,
            metavar = 'FILE',
            default = 'mwc1x.json',
        )),
        ('--mwc11-bind', dict(
            help    = 'MWC11 bind address',
            type    = str,
            metavar = 'BIND',
            default = STATION_BIND,
        )),
        ('--mwc11-port', dict(
            help    = 'MWC11 bind port',
            type    = int,
            metavar = 'PORT',
            default = STATION_PORT,
        )),
    ]

    def __init__(self, rpc: MiotRPC, cfg: MiotConfiguration):
        d = self.__arguments__
        p = argparse.ArgumentParser('mwc10')

        # add argumnets
        for v in d:
            p.add_argument(*v[:-1], **v[-1])

        # parse the options
        ns = p.parse_args(cfg.args)
        fn, bind, port = ns.config, ns.mwc11_bind, ns.mwc11_port

        # initialize the application
        self.rpc    = rpc
        self.cfg    = ConfigurationFile.load(fn)
        self.cam    = MWC11(rpc, self.cfg)
        self.did    = cfg.security_provider.device_id
        self.log    = logging.getLogger('mwc10')
        self.uptime = cfg.uptime

        # initialize properties
        self.props = Properties(
            ConstProperty ( StationSIID.CameraControl  , CameraControlPIID.PowerSwitch     , True   ),
            ConstProperty ( StationSIID.CameraControl  , CameraControlPIID.Flip            , 0      ),
            ConstProperty ( StationSIID.CameraControl  , CameraControlPIID.NightVision     , 2      ),
            ConstProperty ( StationSIID.CameraControl  , CameraControlPIID.OSDTimestamp    , True   ),
            ConstProperty ( StationSIID.CameraControl  , CameraControlPIID.WDR             , True   ),
            ConstProperty ( StationSIID.StorageSD      , StoragePIID.Enabled               , False  ),
            ConstProperty ( StationSIID.StorageSD      , StoragePIID.TotalSize             , 0      ),
            ConstProperty ( StationSIID.StorageSD      , StoragePIID.FreeSize              , 0      ),
            ConstProperty ( StationSIID.StorageSD      , StoragePIID.UsedSize              , 0      ),
            ConstProperty ( StationSIID.StorageSD      , StoragePIID.Status                , 0      ),
            ConstProperty ( StationSIID.StorageUSB     , StoragePIID.Enabled               , False  ),
            ConstProperty ( StationSIID.StorageUSB     , StoragePIID.TotalSize             , 0      ),
            ConstProperty ( StationSIID.StorageUSB     , StoragePIID.FreeSize              , 0      ),
            ConstProperty ( StationSIID.StorageUSB     , StoragePIID.UsedSize              , 0      ),
            ConstProperty ( StationSIID.StorageUSB     , StoragePIID.Status                , 0      ),
            ConstProperty ( StationSIID.StorageControl , StorageControlPIID.StorageSwitch  , True   ),
            ConstProperty ( StationSIID.StorageControl , StorageControlPIID.Type           , 0      ),
            ConstProperty ( StationSIID.StorageControl , StorageControlPIID.LightIndicator , True   ),
            ConstProperty ( StationSIID.OTA            , OTAPIID.Progress                  , 100    ),
            ConstProperty ( StationSIID.OTA            , OTAPIID.State                     , 'idle' ),
        )

        # start the MWC11 client
        loop = asyncio.get_running_loop()
        loop.create_task(self.cam.serve_forever(bind, port))

    @classmethod
    def device_model(cls) -> str:
        return DEVICE_MODEL

    def _net_info(self) -> dict[str, str]:
        try:
            addr, ifn = netifaces.gateways()['default'][netifaces.AF_INET]
            info = netifaces.ifaddresses(ifn)[netifaces.AF_INET][0]
        except KeyError:
            return { 'localIp': '0.0.0.0', 'mask': '0.0.0.0', 'gw': '0.0.0.0' }
        else:
            return { 'localIp': info['addr'], 'mask': info['netmask'], 'gw': addr }

    def _send_reply(self, p: RPCRequest, *, data: Any = None, error: Optional[Exception] = None):
        self.log.debug('RPC response: %r', RPCResponse(p.id, data = data, error = error))
        self.rpc.reply_to(p, data = data, error = error)

    async def device_ready(self):
        await asyncio.wait([
            self.rpc.send('props', ota_state = 'idle'),
            self.rpc.send('_async.stat',
                model           = DEVICE_MODEL,
                fw_ver          = FW_VER,
                miio_client_ver = MIIO_CLI_VER,
                **{
                    'miot.sc_type': {
                        'device_sc_type': [16],
                        'user_sc_type': -1,
                    },
                }
            ),
            self.rpc.send('_otc.info',
                life            = int(time.monotonic() - self.uptime),
                uid             = self.cfg.station.uid,
                model           = DEVICE_MODEL,
                token           = self.cfg.station.bind_key.hex(),
                ipflag          = 1,
                miio_ver        = MIIO_VER,
                mac             = self.cfg.station.mac.hex().upper(),
                fw_ver          = FW_VER,
                hw_ver          = HW_VER,
                miio_client_ver = MIIO_CLI_VER,
                VmPeak          = 0,
                VmRSS           = 0,
                MemFree         = 0,
                miio_times      = [0, 0, 0, 0],
                netif           = self._net_info(),
                ap              = {
                    'ssid'  : self.cfg.ap.ssid,
                    'bssid' : '11:22:33:44:55:66',
                    'rssi'  : '-40',
                    'freq'  : 2412,
                },
            ),
        ])
        # print('_sync.subdev_upinfo', await self.rpc.send('_sync.subdev_upinfo', did = '589340360', fw_ver = '1.2.1_1999'))
        # self.task = asyncio.create_task(self._keepalive())

    async def handle_request(self, p: RPCRequest):
        meth = p.method
        func = self.__rpc_handlers__.get(meth)
        self.log.debug('RPC request: %r', p)

        # check for method
        if func is None:
            self.log.error('Unknown RPC method %r. request = %s', meth, p)
            self._send_reply(p, error = RPCError(-1, 'unknown RPC method'))
            return

        # attempt to handle the request
        try:
            resp = await func(self, p)
        except RPCError as e:
            self._send_reply(p, error = e)
        except Exception:
            self.log.exception('Exception when handling RPC request: %r', p)
            self._send_reply(p, error = RPCError(-1, 'unhandled exception'))
        else:
            self._send_reply(p, data = resp)

    async def _rpc_get_gwinfo(self, p: RPCRequest) -> dict[str, Any]:
        pkey = base64.b64decode(Payload.type_checked(p.args['app_pub_key'], str))
        skey = self.cfg.new_static_key()

        # compose the plain text
        data = json.dumps(
            separators = (',', ':'),
            obj        = {
                'ssid'           : self.cfg.ap.ssid,
                'passwd'         : self.cfg.ap.passwd,
                'static_key'     : skey.key,
                'static_key_num' : skey,
            },
        )

        # generate and exchange keys with ECDH, and derive the encryption key with HKDF
        nkey = generate_private_key(SECP256R1())
        skey = nkey.exchange(ECDH(), EllipticCurvePublicKey.from_encoded_point(SECP256R1(), pkey))
        aesc = Cipher(AES128(HKDF(SHA256(), 16, self.cfg.station.oob, b'').derive(skey)), CBC(bytes(16))).encryptor()

        # encrypt the response data
        data = data.encode('utf-8')
        pads = bytes([16 - (len(data) % 16)])
        rbuf = aesc.update(data + pads * pads[0]) + aesc.finalize()
        rkey = nkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

        # construct the response
        return {
            'gw_pub_key'   : base64.b64encode(rkey).decode('utf-8'),
            'encrypt_data' : base64.b64encode(rbuf).decode('utf-8'),
        }

    async def _rpc_get_properties(self, p: RPCRequest) -> list[dict[str, Any]]:
        rets = []
        null = object()

        # fetch every property
        for item in p.args:
            try:
                did  = Payload.type_checked(item['did'], str)
                siid = Payload.type_checked(item['siid'], int)
                piid = Payload.type_checked(item['piid'], int)
            except (KeyError, TypeError, ValueError) as e:
                self.log.error('Invalid RPC request: %s', e)
                raise RPCError(-1, 'invalid request') from None

            # find the device
            cam = self.cam
            dev = cam.find(did)

            # read the properties
            try:
                if dev is not None:
                    prop = dev.props[siid, piid]
                    data = await prop.read()
                    rets.append((did, siid, piid, 0, data))
                    self.log.info('Get device property %s.%s: %r', did, prop.name, data)
                elif did == str(self.did):
                    prop = self.props[siid, piid]
                    data = await prop.read()
                    rets.append((did, siid, piid, 0, data))
                    self.log.info('Get station property %s: %r', prop.name, data)
                else:
                    rets.append((did, siid, piid, RPCError.Code.NoSuchProperty, null))
                    self.log.warning('Cannot read property %s.%d.%d: device not found', did, siid, piid)
            except (ValueError, PermissionError) as e:
                rets.append((did, siid, piid, RPCError.Code.NoSuchProperty, null))
                self.log.warning('Cannot read property %s.%d.%d: %s', did, siid, piid, e)

        # construct the response
        return [
            {
                k: v
                for k, v in [
                    ( 'did'   , did   ),
                    ( 'siid'  , siid  ),
                    ( 'piid'  , piid  ),
                    ( 'code'  , code  ),
                    ( 'value' , value ),
                ]
                if v is not null
            }
            for did, siid, piid, code, value in rets
        ]

    async def _rpc_set_properties(self, p: RPCRequest) -> list[dict[str, Any]]:
        rets = []
        args = p.args

        # fetch every property
        for item in args:
            try:
                did   = Payload.type_checked(item['did'], str)
                siid  = Payload.type_checked(item['siid'], int)
                piid  = Payload.type_checked(item['piid'], int)
                value = item['value']
            except (KeyError, TypeError, ValueError) as e:
                self.log.error('Invalid RPC request: %s', e)
                raise RPCError(-1, 'invalid request') from None

            # find the device
            cam = self.cam
            dev = cam.find(did)

            # read the properties
            try:
                if dev is not None:
                    prop = dev.props[siid, piid]
                    self.log.info('Set device property %s.%s to %r', did, prop.name, value)
                    await prop.write(value)
                    rets.append((did, siid, piid, 0))
                elif did == str(self.did):
                    prop = self.props[siid, piid]
                    self.log.info('Set station property %s to %r', prop.name, value)
                    await prop.write(value)
                    rets.append((did, siid, piid, 0))
                else:
                    rets.append((did, siid, piid, RPCError.Code.NoSuchProperty))
                    self.log.warning('Cannot write %r to property %s.%d.%d: device not found', value, did, siid, piid)
            except (ValueError, PermissionError) as e:
                rets.append((did, siid, piid, RPCError.Code.NoSuchProperty))
                self.log.warning('Cannot write %r to property %s.%d.%d: %s', value, did, siid, piid, e)

        # construct the response
        return [
            {
                'did'  : did,
                'siid' : siid,
                'piid' : piid,
                'code' : code,
            }
            for did, siid, piid, code in rets
        ]

    __rpc_handlers__ = {
        'get_gwinfo'     : _rpc_get_gwinfo,
        'get_properties' : _rpc_get_properties,
        'set_properties' : _rpc_set_properties,
    }
