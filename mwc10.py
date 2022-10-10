#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import base64
import struct
import hashlib
import asyncio
import logging

from enum import IntEnum
from logging import Logger
from functools import cached_property

from typing import Any
from typing import Union
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

from miio import MiioRPC
from miio import MiioAppConfig
from miio import MiioApplication

HW_VER       = 'Linux'
FW_VER       = '4.1.6_1999'
MIIO_VER     = '0.0.9'
MIIO_CLI_VER = '4.1.6'
DEVICE_MODEL = 'mxiang.camera.mwc10'

class CameraSIID(IntEnum):
    Control             = 2
    Misc                = 3
    DetectionMisc       = 4
    Detection           = 5
    OTA                 = 6
    # GoogleSupport     = 7     # not implemented
    # AlexaSupport      = 8     # not implemented

class GatewaySIID(IntEnum):
    CameraControl       = 2
    StorageSD           = 3
    StorageUSB          = 4
    StorageControl      = 5
    OTA                 = 6

class OTAPIID(IntEnum):
    Progress            = 1     # u8    = 100
    State               = 2     # str   = 'idle'

class StoragePIID(IntEnum):
    Enabled             = 1     # bool  = False
    TotalSize           = 2     # u64   = 0
    FreeSize            = 3     # u64   = 0
    UsedSize            = 4     # u64   = 0
    Status              = 5     # i32   = 0

class DetectionPIID(IntEnum):
    Enabled             = 1     # bool  = True
    RecordInterval      = 2     # u16   = 30
    RecordSensitivity   = 3     # u16   = 100

class CameraMiscPIID(IntEnum):
    LED                 = 1     # bool  = True
    LiveStream          = 2     # u8    = 0
    Distortion          = 3     # bool  = True
    BatteryLevel        = 4     # u8    = 100
    Resolution          = 5     # u8    = 0
    RSSI                = 6     # i16   = -100
    Online              = 7     # bool  = False
    PowerFreq           = 8     # u8    = 50

class DetectionMiscPIID(IntEnum):
    RecordFreq          = 1     # u16   = 0
    RecordLimit         = 2     # u16   = 10
    Enabled             = 3     # bool  = True

class CameraControlPIID(IntEnum):
    PowerSwitch         = 1     # bool  = True
    Flip                = 2     # u16   = 0
    NightVision         = 3     # u8    = 2
    OSDTimestamp        = 4     # bool  = True
    WDR                 = 5     # bool  = True

class StorageControlPIID(IntEnum):
    StorageSwitch       = 1     # bool  = True
    Type                = 2     # u8    = 0
    LightIndicator      = 3     # bool  = True

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

class Properties:
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

class CameraProperties(Properties):
    @cached_property
    def storage(self) -> dict[CameraSIID, dict[PIID, Any]]:
        return {
            CameraSIID.Control: {
                CameraControlPIID.PowerSwitch  : True,
                CameraControlPIID.Flip         : 0,
                CameraControlPIID.NightVision  : 2,
                CameraControlPIID.OSDTimestamp : True,
                CameraControlPIID.WDR          : True,
            },
            CameraSIID.Misc: {
                CameraMiscPIID.LED          : True,
                CameraMiscPIID.LiveStream   : 0,
                CameraMiscPIID.Distortion   : True,
                CameraMiscPIID.BatteryLevel : 100,
                CameraMiscPIID.Resolution   : 0,
                CameraMiscPIID.RSSI         : -100,
                CameraMiscPIID.Online       : False,
                CameraMiscPIID.PowerFreq    : 50,
            },
            CameraSIID.DetectionMisc: {
                DetectionMiscPIID.RecordFreq  : 0,
                DetectionMiscPIID.RecordLimit : 10,
                DetectionMiscPIID.Enabled     : True,
            },
            CameraSIID.Detection: {
                DetectionPIID.Enabled           : True,
                DetectionPIID.RecordInterval    : 30,
                DetectionPIID.RecordSensitivity : 100,
            },
            CameraSIID.OTA: {
                OTAPIID.Progress : 100,
                OTAPIID.State    : 'idle',
            },
        }

class GatewayProperties(Properties):
    @cached_property
    def storage(self) -> dict[GatewaySIID, dict[PIID, Any]]:
        return {
            GatewaySIID.CameraControl: {
                CameraControlPIID.PowerSwitch  : True,
                CameraControlPIID.Flip         : 0,
                CameraControlPIID.NightVision  : 2,
                CameraControlPIID.OSDTimestamp : True,
                CameraControlPIID.WDR          : True,
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
                StorageControlPIID.StorageSwitch  : True,
                StorageControlPIID.Type           : 0,
                StorageControlPIID.LightIndicator : True,
            },
            GatewaySIID.OTA: {
                OTAPIID.Progress : 100,
                OTAPIID.State    : 'idle',
            },
        }

class KeyStore:
    @cached_property
    def static_keys(self) -> dict[int, str]:
        return {}

    def create_static_key(self) -> tuple[int, str]:
        kbuf = self.static_keys
        seed, = struct.unpack('I', os.urandom(4))

        # avoid seed confliction
        while seed in kbuf:
            seed, = struct.unpack('I', os.urandom(4))

        # calculate the static key and save to key store
        skey = hashlib.md5(b'XMITECH%x' % seed).hexdigest()[:16]
        kbuf[seed] = skey
        return seed, skey

class Settings:
    ap_ssid    : str   = 'XMCONFIG-0006262228000576'
    ap_passwd  : str   = '6bbca0049a'
    device_mac : str   = 'E0:A2:5A:0D:DC:1C'
    device_oob : bytes = b'9Zc3FlkRT5WydM0Sa57pew=='

class MiioApp(MiioApplication):
    did       : int
    log       : Logger
    rpc       : MiioRPC
    cfg       : Settings
    keys      : KeyStore
    uptime    : int
    gw_props  : GatewayProperties
    cam_props : dict[str, CameraProperties]

    def __init__(self, rpc: MiioRPC, cfg: MiioAppConfig):
        self.rpc       = rpc
        self.did       = cfg.security_provider.device_id
        self.log       = logging.getLogger('mwc10')
        self.cfg       = Settings()
        self.keys      = KeyStore()
        self.uptime    = cfg.uptime
        self.gw_props  = GatewayProperties()
        self.cam_props = {}

    @classmethod
    def device_model(cls) -> str:
        return DEVICE_MODEL

    def _send_reply(self, p: RPCRequest, *, data: Any = None, error: Optional[Exception] = None):
        if data is not None or error is not None:
            self.log.debug('RPC response: ' + str(RPCResponse(p.id, data = data, error = error)))
            self.rpc.reply_to(p, data = data, error = error)

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
                mac             = self.cfg.device_mac,
                fw_ver          = FW_VER,
                hw_ver          = HW_VER,
                miio_client_ver = MIIO_CLI_VER,
                VmPeak          = 0,
                VmRSS           = 0,
                MemFree         = 0,
                miio_times      = [0] * 4,
                ap              = {
                    'ssid'  : 'Wired Ethernet',
                    'bssid' : 'FF:FF:FF:FF:FF:FF',
                    'rssi'  : '0',
                    'freq'  : 2412,
                },
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
            self._send_reply(p, error = RPCError(-1, 'unknown RPC method'))
            return

        # attempt to handle the request
        try:
            resp = await func(self, p)
        except RPCError as e:
            self._send_reply(p, error = e)
        except Exception:
            self.log.exception('Exception when handling RPC request: ' + str(p))
            self._send_reply(p, error = RPCError(-1, 'unhandled exception'))
        else:
            self._send_reply(p, data = resp)

    async def _rpc_nop(self, _: RPCRequest):
        pass

    async def _rpc_get_gwinfo(self, p: RPCRequest):
        pkey = base64.b64decode(Payload.type_checked(p.args['app_pub_key'], str).encode('utf-8'))
        seed, mkey = self.keys.create_static_key()

        # compose the plain text
        data = json.dumps(
            separators = (',', ':'),
            obj        = {
                'ssid'           : self.cfg.ap_ssid,
                'passwd'         : self.cfg.ap_passwd,
                'static_key'     : mkey,
                'static_key_num' : seed,
            },
        )

        # generate a key pair, and derive the encryption key
        nkey = generate_private_key(SECP256R1())
        skey = nkey.exchange(ECDH(), EllipticCurvePublicKey.from_encoded_point(SECP256R1(), pkey))
        aesc = Cipher(AES128(HKDF(SHA256(), 16, Settings.device_oob, b'').derive(skey)), CBC(bytes(16))).encryptor()

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
        vals = []
        null = object()

        # fetch every property
        for item in p.args:
            try:
                did = Payload.type_checked(item['did'], str)
                siid = Payload.type_checked(item['siid'], int)
                piid = Payload.type_checked(item['piid'], int)
            except (KeyError, TypeError, ValueError) as e:
                self.log.error('Invalid RPC request: ' + str(e))
                raise RPCError(-1, 'invalid request') from None
            else:
                try:
                    if did == str(self.did):
                        vals.append((did, siid, piid, 0, self.gw_props.get(siid, piid)))
                    elif did in self.cam_props:
                        vals.append((did, siid, piid, 0, self.cam_props[did].get(siid, piid)))
                    else:
                        vals.append((did, siid, piid, RPCError.Code.NoSuchProperty, null))
                        self.log.warning('Cannot read property %s.%d.%d: device not found' % (did, siid, piid))
                except ValueError as e:
                    vals.append((did, siid, piid, RPCError.Code.NoSuchProperty, null))
                    self.log.warning('Cannot read property %s.%d.%d: %s' % (did, siid, piid, e))

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
            for did, siid, piid, code, value in vals
        ]

    __rpc_handlers__ = {
        'get_gwinfo'     : _rpc_get_gwinfo,
        'get_properties' : _rpc_get_properties,
    }

