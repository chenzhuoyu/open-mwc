#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import base64
import socket
import struct
import hashlib
import binascii

from typing import Any, Optional
from functools import cached_property

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from miot import Payload

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

class EventListener:
    def save_config(self, cfg: dict[str, Any]):
        raise NotImplementedError('save_config()', cfg)

class StaticKey(int):
    @cached_property
    def key(self) -> str:
        return hashlib.md5(b'XMITECH%x' % self).hexdigest()[:16]

class SessionKey(bytes):
    def encrypt(self, data: bytes) -> bytes:
        pad = (16 - len(data) % 16) % 16
        aes = Cipher(AES128(self), CBC(bytes(16))).encryptor()
        return aes.update(data) + aes.update(b'\x00' * pad) + aes.finalize()

    def decrypt(self, data: bytes, size: int) -> bytes:
        aes = Cipher(AES128(self), CBC(bytes(16))).decryptor()
        buf = aes.update(data) + aes.finalize()
        return buf[:size]

    def frame_token(self, addr: str, port: int) -> bytes:
        return hashlib.md5(self.encrypt(socket.inet_aton(addr) + port.to_bytes(2, 'little'))).digest()

class DeviceInfo:
    sn1: str
    sn2: str
    did: str
    mac: bytes
    oob: bytes
    psk: bytes

    def __init__(self, sn1: str, sn2: str, did: str, mac: bytes, oob: bytes, psk: bytes):
        self.sn1 = sn1
        self.sn2 = sn2
        self.did = did
        self.mac = mac
        self.oob = oob
        self.psk = psk

    def __str__(self) -> str:
        return '%s:%s:%s:%s|%s|%s' % (
            self.sn1,
            self.sn2,
            self.oob.decode('utf-8'),
            self.mac.hex(),
            self.did,
            self.psk.decode('utf-8'),
        )

    def __repr__(self) -> str:
        return '\n'.join([
            'DeviceInfo {',
            '    sn1 = ' + self.sn1,
            '    sn2 = ' + self.sn2,
            '    did = ' + self.did,
            '    mac = ' + self.mac.hex(),
            '    oob = ' + self.oob.decode('utf-8'),
            '    psk = ' + self.psk.decode('utf-8'),
            '}',
        ])

    @classmethod
    def parse(cls, info: str) -> 'DeviceInfo':
        try:
            val, did, psk = info.split('|')
            sn1, sn2, oob, mac = val.split(':')
            mac = MACAddress.parse(mac)
        except ValueError:
            raise ValueError('invalid info string ' + repr(info)) from None
        else:
            return cls(sn1, sn2, did, mac, oob.encode('utf-8'), psk.encode('utf-8'))

class ApConfiguration:
    ssid   : str
    passwd : str

    def __init__(self, ssid: str, passwd: str):
        self.ssid   = ssid
        self.passwd = passwd

    def __repr__(self) -> str:
        return '\n'.join([
            'ApConfiguration {',
            '    ssid   = ' + self.ssid,
            '    passwd = ' + self.passwd,
            '}',
        ])

    def to_dict(self) -> dict[str, Any]:
        return {
            'ssid'   : self.ssid,
            'passwd' : self.passwd,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ApConfiguration':
        return cls(
            ssid   = Payload.type_checked(data['ssid'], str),
            passwd = Payload.type_checked(data['passwd'], str),
        )

class DeviceConfiguration:
    info        : DeviceInfo
    model       : str
    auth_key    : bytes
    static_key  : StaticKey
    session_key : SessionKey

    def __init__(self, info: DeviceInfo, model: str, auth_key: bytes, static_key: StaticKey, session_key: SessionKey):
        self.info        = info
        self.model       = model
        self.auth_key    = auth_key
        self.static_key  = static_key
        self.session_key = session_key

    def __repr__(self) -> str:
        return '\n'.join([
            'DeviceConfiguration {',
            '    info        = %s' % self.info,
            '    model       = %s' % self.model,
            '    auth_key    = %s' % self.auth_key.hex(),
            '    static_key  = %d' % self.static_key,
            '    session_key = %s' % self.session_key.hex(),
            '}',
        ])

    def to_dict(self) -> dict[str, Any]:
        return {
            'info'        : str(self.info),
            'model'       : self.model,
            'auth_key'    : base64.b64encode(self.auth_key).decode('utf-8'),
            'static_key'  : self.static_key,
            'session_key' : base64.b64encode(self.session_key).decode('utf-8'),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'DeviceConfiguration':
        return cls(
            info        = DeviceInfo.parse(Payload.type_checked(data['info'], str)),
            model       = Payload.type_checked(data['model'], str),
            auth_key    = base64.b64decode(Payload.type_checked(data['auth_key'], str)),
            static_key  = StaticKey(Payload.type_checked(data['static_key'], int)),
            session_key = SessionKey(base64.b64decode(Payload.type_checked(data['session_key'], str))),
        )

class StationConfiguration:
    did      : int
    uid      : int
    mac      : bytes
    oob      : bytes
    token    : bytes
    bind_key : bytes

    def __init__(self, did: int, uid: int, mac: bytes, oob: bytes, token: bytes, bind_key: bytes):
        self.did      = did
        self.uid      = uid
        self.oob      = oob
        self.mac      = MACAddress.validated(mac)
        self.token    = token
        self.bind_key = bind_key

    def __repr__(self) -> str:
        return '\n'.join([
            'StationConfiguration {',
            '    did      = %d' % self.did,
            '    uid      = %d' % self.uid,
            '    mac      = %s' % self.mac.hex(':'),
            '    oob      = %s' % self.oob.decode('utf-8'),
            '    token    = %s' % self.token.decode('utf-8'),
            '    bind_key = %s' % self.bind_key.decode('utf-8'),
            '}',
        ])

    def to_dict(self) -> dict[str, Any]:
        return {
            'did'      : self.did,
            'uid'      : self.uid,
            'mac'      : self.mac.hex(':'),
            'oob'      : self.oob.decode('utf-8'),
            'token'    : self.token.decode('utf-8'),
            'bind_key' : self.bind_key.decode('utf-8'),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        return cls(
            Payload.type_checked(data['did'], int),
            Payload.type_checked(data['uid'], int),
            MACAddress.parse(Payload.type_checked(data['mac'], str)),
            Payload.type_checked(data['oob'], str).encode('utf-8'),
            Payload.type_checked(data['token'], str).encode('utf-8'),
            Payload.type_checked(data['bind_key'], str).encode('utf-8'),
        )

class Configuration:
    ap             : ApConfiguration
    station        : StationConfiguration
    devices        : dict[bytes, DeviceConfiguration]
    static_keys    : set[StaticKey]
    event_listener : Optional[EventListener]

    def __init__(self,
        ap             : ApConfiguration,
        station        : StationConfiguration,
        *,
        devices        : Optional[dict[bytes, DeviceConfiguration]] = None,
        event_listener : Optional[EventListener] = None,
    ):
        self.ap             = ap
        self.station        = station
        self.devices        = devices or {}
        self.static_keys    = set()
        self.event_listener = event_listener

    def __repr__(self) -> str:
        return '\n'.join([
            'Configuration {',
            '    ap      = ' + ('\n' + ' ' * 4).join(str(self.ap).splitlines()),
            '    station = ' + ('\n' + ' ' * 4).join(str(self.station).splitlines()),
            '    devices = {',
            *(
                ' ' * 8 + '%s = %s' % (k.hex(':'), ('\n' + ' ' * 8).join(str(v).splitlines()))
                for k, v in sorted(self.devices.items())
            ),
            '    }',
            '}',
        ])

    def save(self):
        if self.event_listener is not None:
            self.event_listener.save_config(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            'ap'      : self.ap.to_dict(),
            'station' : self.station.to_dict(),
            'devices' : {
                k.hex(':'): v.to_dict()
                for k, v in self.devices.items()
            }
        }

    def add_device(self, mac: bytes, dev: DeviceConfiguration):
        self.devices[mac] = dev
        self.save()

    def new_static_key(self) -> StaticKey:
        val = os.urandom(4)
        ret = StaticKey(struct.unpack('>I', val)[0])

        # avoid duplication
        while ret in self.static_keys:
            val = os.urandom(4)
            ret = StaticKey(struct.unpack('>I', val)[0])

        # add to static keys, and save the configuration
        self.static_keys.add(ret)
        return ret

    def remove_static_key(self, key: StaticKey):
        if key in self.static_keys:
            self.static_keys.remove(key)

    @classmethod
    def from_dict(cls, cfg: dict[str, Any], *, event_listener: Optional[EventListener] = None) -> 'Configuration':
        return cls(
            ap             = ApConfiguration.from_dict(Payload.type_checked(cfg['ap'], dict)),
            station        = StationConfiguration.from_dict(Payload.type_checked(cfg['station'], dict)),
            devices        = {
                MACAddress.parse(k): DeviceConfiguration.from_dict(v)
                for k, v in Payload.type_checked(cfg.get('devices', {}), dict).items()
            },
            event_listener = event_listener,
        )

class ConfigurationFile(EventListener):
    name: str

    def __init__(self, name: str = 'mwc1x.json'):
        self.name = name

    def save_config(self, cfg: dict[str, Any]):
        name = self.name
        data = json.dumps(cfg, indent = 4, sort_keys = True)

        # write to file after serializing to avoid destroying old config
        with open(name, 'w') as fp:
            fp.write(data)

    @classmethod
    def load(cls, name: str) -> 'Configuration':
        with open(name) as fp:
            return Configuration.from_dict(
                cfg            = Payload.type_checked(json.load(fp), dict),
                event_listener = cls(name),
            )
