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

    def unbind_token(self,  addr: str, port: int) -> bytes:
        return hashlib.md5(self.encrypt(socket.inet_aton(addr) + port.to_bytes(2, 'little'))).digest()

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
    did      : int
    uid      : int
    mac      : bytes
    oob      : bytes
    token    : bytes
    bind_key : bytes

    def __init__(self, did: int, uid: int, mac: bytes, oob: bytes, token: bytes, bind_key: bytes):
        self.did      = did
        self.uid      = uid
        self.mac      = MACAddress.validated(mac)
        self.oob      = oob
        self.token    = token
        self.bind_key = bind_key

    def __repr__(self) -> str:
        return '\n'.join([
            'DeviceConfiguration {',
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
    device         : DeviceConfiguration
    static_keys    : set[StaticKey]
    session_keys   : dict[bytes, SessionKey]
    event_listener : Optional[EventListener]

    def __init__(self,
        ap             : ApConfiguration,
        device         : DeviceConfiguration,
        *,
        static_keys    : Optional[set[StaticKey]] = None,
        session_keys   : Optional[dict[bytes, SessionKey]] = None,
        event_listener : Optional[EventListener] = None,
    ):
        self.ap             = ap
        self.device         = device
        self.static_keys    = static_keys or set()
        self.session_keys   = session_keys or {}
        self.event_listener = event_listener

    def __repr__(self) -> str:
        return '\n'.join([
            'Configuration {',
            '    ap           = ' + ('\n' + ' ' * 4).join(str(self.ap).splitlines()),
            '    device       = ' + ('\n' + ' ' * 4).join(str(self.device).splitlines()),
            '    static_keys  = [',
            *(
                ' ' * 8 + str(v)
                for v in sorted(self.static_keys)
            ),
            '    ]',
            '    session_keys = {',
            *(
                ' ' * 8 + '%s = %s' % (k.hex(':'), ('\n' + ' ' * 12).join(str(v).splitlines()))
                for k, v in sorted(self.session_keys.items())
            ),
            '    }',
            '}',
        ])

    def save(self):
        if self.event_listener is not None:
            self.event_listener.save_config(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            'ap'           : self.ap.to_dict(),
            'device'       : self.device.to_dict(),
            'static_keys'  : sorted(self.static_keys),
            'session_keys' : {
                k.hex(':'): base64.b64encode(v).decode('utf-8')
                for k, v in self.session_keys.items()
            },
        }

    def new_static_key(self) -> StaticKey:
        val = os.urandom(4)
        ret = StaticKey(struct.unpack('>I', val)[0])

        # avoid duplication
        while ret in self.static_keys:
            val = os.urandom(4)
            ret = StaticKey(struct.unpack('>I', val)[0])

        # add to static keys, and save the configuration
        self.static_keys.add(ret)
        self.save()
        return ret

    def drop_static_key(self, key: StaticKey):
        if key in self.static_keys:
            self.static_keys.remove(key)
            self.save()

    def find_session_key(self, mac: bytes) -> Optional[SessionKey]:
        return self.session_keys.get(mac)

    def update_session_key(self, mac: bytes, key: SessionKey):
        self.session_keys[mac] = key
        self.save()

    @classmethod
    def from_dict(cls, cfg: dict[str, Any], *, event_listener: Optional[EventListener] = None) -> 'Configuration':
        return cls(
            ap             = ApConfiguration.from_dict(Payload.type_checked(cfg['ap'], dict)),
            device         = DeviceConfiguration.from_dict(Payload.type_checked(cfg['device'], dict)),
            static_keys    = set(
                StaticKey(Payload.type_checked(v, int))
                for v in Payload.type_checked(cfg.get('static_keys', []), list)
            ),
            session_keys   = {
                MACAddress.parse(k): SessionKey(base64.b64decode(Payload.type_checked(v, str)))
                for k, v in Payload.type_checked(cfg.get('session_keys', {}), dict).items()
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
