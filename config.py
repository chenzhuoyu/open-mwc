#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import socket
import hashlib

from weakref import ReferenceType
from functools import cached_property

from typing import Any
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128

from miio import Payload
from miio import MACAddress

class EventListener:
    def on_config_changed(self):
        raise NotImplementedError('on_config_changed()')

class StaticKey(int):
    @cached_property
    def key(self) -> str:
        return hashlib.md5(b'XMITECH%x' % self).hexdigest()[:16]

class SessionKey(bytes):
    @classmethod
    def empty(cls) -> 'SessionKey':
        return cls(bytes(16))

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

class DeviceTag:
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
            'DeviceTag {',
            '    sn1 = ' + self.sn1,
            '    sn2 = ' + self.sn2,
            '    did = ' + self.did,
            '    mac = ' + self.mac.hex(),
            '    oob = ' + self.oob.decode('utf-8'),
            '    psk = ' + self.psk.decode('utf-8'),
            '}',
        ])

    @classmethod
    def parse(cls, info: str) -> 'DeviceTag':
        try:
            val, did, psk = info.split('|')
            sn1, sn2, oob, mac = val.split(':')
            mac = MACAddress.parse(mac)
        except ValueError:
            raise ValueError('invalid info string ' + repr(info)) from None
        else:
            return cls(sn1, sn2, did, mac, oob.encode('utf-8'), psk.encode('utf-8'))

    @classmethod
    def parse_opt(cls, info: str) -> Optional['DeviceTag']:
        if not info:
            return None
        else:
            return cls.parse(info)

class DeviceConfiguration:
    tag            : Optional[DeviceTag]
    model          : str
    auth_key       : bytes
    static_key     : StaticKey
    session_key    : SessionKey
    event_listener : Optional[EventListener]

    def __init__(self,
        *,
        tag            : Optional[DeviceTag]     = None,
        model          : str                     = '',
        auth_key       : bytes                   = b'',
        static_key     : StaticKey               = 0,
        session_key    : SessionKey              = b'',
        event_listener : Optional[EventListener] = None,
    ):
        self.tag            = tag
        self.model          = model
        self.auth_key       = auth_key
        self.static_key     = static_key
        self.session_key    = session_key
        self.event_listener = event_listener

    def __repr__(self) -> str:
        return '\n'.join([
            'DeviceConfiguration {',
            '    tag         = %s' % (self.tag or '(none)'),
            '    model       = %s' % (self.model or '(none)'),
            '    auth_key    = %s' % (self.auth_key.hex() or '(none)'),
            '    static_key  = %s' % (self.static_key or '(none)'),
            '    session_key = %s' % (self.session_key.hex() or '(none)'),
            '}',
        ])

    def save(self):
        if self.event_listener is not None:
            self.event_listener.on_config_changed()

    def to_dict(self) -> dict[str, Any]:
        return {
            k: v
            for k, v in (
                ('tag'         , str(self.tag or '')),
                ('model'       , self.model),
                ('auth_key'    , base64.b64encode(self.auth_key).decode('utf-8')),
                ('static_key'  , self.static_key),
                ('session_key' , base64.b64encode(self.session_key).decode('utf-8')),
            )
            if v
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, event_listener: Optional[EventListener] = None) -> 'DeviceConfiguration':
        return cls(
            tag            = DeviceTag.parse_opt(Payload.type_checked(data.get('tag', ''), str)),
            model          = Payload.type_checked(data.get('model', ''), str),
            auth_key       = base64.b64decode(Payload.type_checked(data.get('auth_key', ''), str)),
            static_key     = StaticKey(Payload.type_checked(data.get('static_key', 0), int)),
            session_key    = SessionKey(base64.b64decode(Payload.type_checked(data.get('session_key', ''), str))),
            event_listener = event_listener,
        )

class Configuration:
    devices        : dict[bytes, DeviceConfiguration]
    event_listener : Optional[EventListener]

    def __init__(self,
        *,
        devices        : Optional[dict[bytes, DeviceConfiguration]] = None,
        event_listener : Optional[EventListener] = None,
    ):
        self.devices        = devices or {}
        self.event_listener = event_listener

    def __repr__(self) -> str:
        return '\n'.join([
            'Configuration {',
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
            self.event_listener.on_config_changed()

    def to_dict(self) -> dict[str, Any]:
        return {
            'devices' : {
                k.hex(':'): v.to_dict()
                for k, v in self.devices.items()
            }
        }

    def add_device(self, mac: bytes, dev: DeviceConfiguration):
        dev.event_listener = self.event_listener
        self.devices[mac] = dev
        self.save()

    @classmethod
    def from_dict(cls, cfg: dict[str, Any], *, event_listener: Optional[EventListener] = None) -> 'Configuration':
        return cls(
            event_listener = event_listener,
            devices        = {
                MACAddress.parse(k): DeviceConfiguration.from_dict(v, event_listener = event_listener)
                for k, v in Payload.type_checked(cfg.get('devices', {}), dict).items()
            },
        )

class ConfigurationFile(EventListener):
    cfg  : Optional[ReferenceType[Configuration]]
    name : str

    def __init__(self, name: str = 'mwc1x.json'):
        self.cfg  = None
        self.name = name

    def on_config_changed(self):
        if self.cfg is not None:
            cfg = self.cfg().to_dict()
            data = json.dumps(cfg, indent = 4, sort_keys = True)

            # write to file after serializing to avoid destroying the old config
            with open(self.name, 'w') as fp:
                fp.write(data)

    @classmethod
    def load(cls, name: str) -> 'Configuration':
        with open(name) as fp:
            ret = cls(name)
            val = Payload.type_checked(json.load(fp), dict)
            cfg = Configuration.from_dict(val, event_listener = ret)
            ret.cfg = ReferenceType(cfg)
            return cfg

    @classmethod
    def create(cls, name: str) -> 'Configuration':
        ret = cls(name)
        cfg = Configuration(devices = {}, event_listener = ret)
        ret.cfg = ReferenceType(cfg)
        return cfg
