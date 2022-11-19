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

from miio import Payload
from miio import RPCError
from miio import RPCRequest
from miio import RPCResponse

from miot import MiotRPC
from miot import MiotApplication
from miot import MiotConfiguration

from mwc11 import MWC11
from mwc11 import STATION_BIND
from mwc11 import STATION_PORT
from mwc1x import Configuration
from mwc1x import ConfigurationFile

from props import SIID
from props import PIID
from props import Property
from props import Properties
from props import ValueProperty

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
    run    : bool
    cam    : MWC11
    log    : Logger
    rpc    : MiotRPC
    cfg    : Configuration
    bind   : str
    port   : int
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
        self.run    = True
        self.cfg    = ConfigurationFile.load(fn)
        self.cam    = MWC11(rpc, self.cfg)
        self.did    = cfg.security_provider.device_id
        self.log    = logging.getLogger('mwc10')
        self.bind   = bind
        self.port   = port
        self.uptime = cfg.uptime

        # initialize all const properties
        self.props = Properties(
            ValueProperty ( StationSIID.CameraControl  , CameraControlPIID.PowerSwitch     , True   ),
            ValueProperty ( StationSIID.CameraControl  , CameraControlPIID.Flip            , 0      ),
            ValueProperty ( StationSIID.CameraControl  , CameraControlPIID.NightVision     , 2      ),
            ValueProperty ( StationSIID.CameraControl  , CameraControlPIID.OSDTimestamp    , True   ),
            ValueProperty ( StationSIID.CameraControl  , CameraControlPIID.WDR             , True   ),
            ValueProperty ( StationSIID.StorageSD      , StoragePIID.Enabled               , False  ),
            ValueProperty ( StationSIID.StorageSD      , StoragePIID.TotalSize             , 0      ),
            ValueProperty ( StationSIID.StorageSD      , StoragePIID.FreeSize              , 0      ),
            ValueProperty ( StationSIID.StorageSD      , StoragePIID.UsedSize              , 0      ),
            ValueProperty ( StationSIID.StorageSD      , StoragePIID.Status                , 0      ),
            ValueProperty ( StationSIID.StorageUSB     , StoragePIID.Enabled               , False  ),
            ValueProperty ( StationSIID.StorageUSB     , StoragePIID.TotalSize             , 0      ),
            ValueProperty ( StationSIID.StorageUSB     , StoragePIID.FreeSize              , 0      ),
            ValueProperty ( StationSIID.StorageUSB     , StoragePIID.UsedSize              , 0      ),
            ValueProperty ( StationSIID.StorageUSB     , StoragePIID.Status                , 0      ),
            ValueProperty ( StationSIID.StorageControl , StorageControlPIID.StorageSwitch  , True   ),
            ValueProperty ( StationSIID.StorageControl , StorageControlPIID.Type           , 0      ),
            ValueProperty ( StationSIID.StorageControl , StorageControlPIID.LightIndicator , True   ),
            ValueProperty ( StationSIID.OTA            , OTAPIID.Progress                  , 100    ),
            ValueProperty ( StationSIID.OTA            , OTAPIID.State                     , 'idle' ),
        )

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

    async def _stats(self):
        for _ in range(3):
            if not self.run:
                return
            else:
                try:
                    await asyncio.gather(
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
                    )
                except TimeoutError:
                    self.log.warning('Keep-alive timeout, try again.')
                except Exception:
                    self.log.exception('Unhandled error when performing keep-alive, try again later.')
                    return
                else:
                    break
        else:
            self.log.error('Keep-alive failed after 3 attempts, try again later.')

    async def _keepalive(self):
        while self.run:
            for i in range(31):
                if i == 0:
                    await self._stats()
                elif self.run:
                    await asyncio.sleep(1.0)
                else:
                    break

    async def device_ready(self):
        port = self.port
        bind = self.bind
        task = asyncio.get_running_loop().create_task(self._keepalive())

        # perform the handshake, and start the application
        try:
            await self.cam.serve_forever(bind, port)
        except Exception:
            self.log.exception('Error when handling requests:')

        # wait for keep-alive to stop
        self.run = False
        await task

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

        # property getter
        async def read_prop(did: str, prop: Property) -> tuple[str, SIID, PIID, int, Any]:
            try:
                data = await prop.read()
            except (ValueError, PermissionError) as e:
                self.log.warning('Cannot read property %s.%d.%d: %s', did, prop.siid, prop.piid, e)
                return did, prop.siid, prop.piid, RPCError.Code.NoSuchProperty, null
            else:
                self.log.info('Get property %s.%s: %r', did, prop.name, data)
                return did, prop.siid, prop.piid, 0, data

        # property errors
        async def error_prop(did: str, siid: SIID, piid: PIID) -> tuple[str, SIID, PIID, int, Any]:
            self.log.warning('Cannot read property %s.%d.%d: device not found', did, siid, piid)
            return did, siid, piid, RPCError.Code.NoSuchProperty, null

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
            devid = str(self.did)
            subdev = self.cam.find(did)

            # read the properties
            if did == devid:
                rets.append(read_prop(did, self.props[siid, piid]))
            elif subdev is not None:
                rets.append(read_prop(did, subdev.props[siid, piid]))
            else:
                rets.append(error_prop(did, siid, piid))

        # wait for the result, and construct the response
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
            for did, siid, piid, code, value in await asyncio.gather(*rets)
        ]

    async def _rpc_set_properties(self, p: RPCRequest) -> list[dict[str, Any]]:
        rets = []
        args = p.args

        # property setter
        async def write_prop(did: str, prop: Property, value: Any) -> tuple[str, SIID, PIID, int]:
            try:
                await prop.write(value)
            except (ValueError, PermissionError) as e:
                self.log.warning('Cannot write %r to property %s.%d.%d: %s', value, did, prop.siid, prop.piid, e)
                return did, prop.siid, prop.piid, RPCError.Code.NoSuchProperty
            else:
                self.log.info('Set property %s.%s to %r', did, prop.name, value)
                return did, prop.siid, prop.piid, 0

        # property errors
        async def error_prop(did: str, siid: SIID, piid: PIID, value: Any) -> tuple[str, SIID, PIID, int]:
            self.log.warning('Cannot write %r to property %s.%d.%d: device not found', value, did, siid, piid)
            return did, siid, piid, RPCError.Code.NoSuchProperty

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
            devid = str(self.did)
            subdev = self.cam.find(did)

            # write the properties
            if did == devid:
                rets.append(write_prop(did, self.props[siid, piid], value))
            elif subdev is not None:
                rets.append(write_prop(did, subdev.props[siid, piid], value))
            else:
                rets.append(error_prop(did, siid, piid, value))

        # wait for the result, and construct the response
        return [
            {
                'did'  : did,
                'siid' : siid,
                'piid' : piid,
                'code' : code,
            }
            for did, siid, piid, code in await asyncio.gather(*rets)
        ]

    __rpc_handlers__ = {
        'get_gwinfo'     : _rpc_get_gwinfo,
        'get_properties' : _rpc_get_properties,
        'set_properties' : _rpc_set_properties,
    }
