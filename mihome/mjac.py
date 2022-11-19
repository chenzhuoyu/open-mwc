#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import struct
import logging
import functools

from enum import IntEnum

from pyftdi.i2c import I2cPort
from pyftdi.i2c import I2cGpioPort
from pyftdi.i2c import I2cController

CMD_MAX_READ  = 507
CMD_PSK_SIZE  = 34
CMD_SIGN_SIZE = 68
CMD_HASH_SIZE = 34
CMD_PKEY_SIZE = 69

LEN_NIST_P256 = 8
ECC_NIST_P256 = b'\x2a\x86\x48\xce\x3d\x03\x01\x07'

class Crc16:
    __table__ = [
        0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
        0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
        0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
        0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
        0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
        0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
        0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
        0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
        0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
        0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
        0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
        0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
        0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
        0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
        0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
        0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
        0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
        0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
        0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
        0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
        0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
        0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
        0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
        0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
        0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
        0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
        0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
        0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
        0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
        0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
        0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
        0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
    ]

    @classmethod
    def sum(cls, data: bytes) -> int:
        return functools.reduce(lambda r, v: cls.__table__[(r ^ v) & 0xff] ^ (r >> 8), data, 0xffff) ^ 0xffff

    @classmethod
    def append(cls, data: bytes) -> bytes:
        return data + struct.pack('>H', cls.sum(data))

class Zone(IntEnum):
    DeviceCert  = 0
    VendorCert  = 1
    RootCert    = 2
    DeviceId    = 3
    UserData    = 4

class Command(IntEnum):
    Echo                = 0x00
    GenerateRandom      = 0x02
    Read                = 0x05
    Update              = 0x06
    Hibernate           = 0x0D
    PutAttribute        = 0x10
    GenerateKey         = 0x11
    Query               = 0x14
    GenerateSignature   = 0x16
    VerifySignature     = 0x17
    EstablishKey        = 0x18

    @staticmethod
    def _pack_req(cmd: 'Command', fmt: str, args: tuple, *extra: bytes) -> bytes:
        return Crc16.append(struct.pack('>B' + fmt, cmd, *args) + b''.join(extra))

    @classmethod
    def build_echo(cls, data: bytes) -> bytes:
        if len(data) > CMD_MAX_READ:
            raise ValueError('echo buffer size too large: %d' % len(data))
        else:
            return cls._pack_req(cls.Echo, '', (), data)

    @classmethod
    def build_read(cls, zone: Zone, offs: int, size: int) -> bytes:
        if size > CMD_MAX_READ:
            raise ValueError('read size too large: %d' % size)
        else:
            return cls._pack_req(cls.Read, 'xBHH', (zone, offs, size))

    @classmethod
    def build_query(cls) -> bytes:
        return cls._pack_req(cls.Query, 'B', (0x11,))

    @classmethod
    def build_hibernate(cls) -> bytes:
        return cls._pack_req(cls.Hibernate, 'B', (0x02,))

    @classmethod
    def build_generate_key(cls) -> bytes:
        return cls._pack_req(cls.GenerateKey, 'BBxBxxH', (0x13, 0xff, 0x01, LEN_NIST_P256), ECC_NIST_P256)

    @classmethod
    def build_establish_key(cls, pkey: bytes) -> bytes:
        if len(pkey) != CMD_PKEY_SIZE:
            raise ValueError('public key must be exactly %d bytes long' % CMD_PKEY_SIZE)
        else:
            return cls._pack_req(cls.EstablishKey, 'B', (0xff,), pkey)

    @classmethod
    def build_generate_random(cls, size: int) -> bytes:
        if size > CMD_MAX_READ:
            raise ValueError('random size too large: %d' % size)
        else:
            return cls._pack_req(cls.GenerateRandom, 'xB', (size,))

    @classmethod
    def build_verify_signature(cls, pkey: bytes, sign: bytes, data: bytes) -> bytes:
        if len(pkey) != CMD_PKEY_SIZE:
            raise ValueError('public key must be exactly %d bytes long' % CMD_PKEY_SIZE)
        elif len(sign) != CMD_SIGN_SIZE:
            raise ValueError('signature must be exactly %d bytes long' % CMD_SIGN_SIZE)
        elif len(data) != CMD_HASH_SIZE:
            raise ValueError('data must be exactly %d bytes long' % CMD_HASH_SIZE)
        else:
            return cls._pack_req(cls.VerifySignature, 'xH', (LEN_NIST_P256,), ECC_NIST_P256, pkey, sign, data)

    @classmethod
    def build_generate_signature(cls, data: bytes) -> bytes:
        if len(data) != CMD_HASH_SIZE:
            raise ValueError('data must be exactly %d bytes long' % CMD_HASH_SIZE)
        else:
            return cls._pack_req(cls.GenerateSignature, 'x', (), data)

class MJAC:
    _rst: int
    _dev: I2cPort
    _pin: I2cGpioPort

    def __init__(
        self,
        ftdi     : str = 'ftdi://ftdi:2232h/1',
        rst_pin  : int = 3,
        i2c_addr : int = 0x2a,
        i2c_freq : int = 1000000,
    ):
        i2c = I2cController()
        i2c.configure(ftdi, frequency = i2c_freq)
        i2c.log.setLevel(logging.ERROR)

        # initialize I2C device and GPIO port
        self._rst = 1 << rst_pin
        self._pin = i2c.get_gpio()
        self._dev = i2c.get_port(i2c_addr)

        # set the RST pin as output
        self._pin.set_direction(self._rst, self._rst)
        self._pin.log.setLevel(logging.ERROR)

    def _i2c_recv(self) -> bytes:
        while True:
            buf = self._dev.read(3)
            code, size = struct.unpack('>BH', buf)

            # check if the response is ready
            if code == 0xff:
                time.sleep(0.1)
                continue

            # read the payload
            buf = self._dev.read(size + 3)
            ret, crc = buf[:1] + buf[3:-2], struct.unpack('>H', buf[-2:])[0]

            # check CRC and return status
            if Crc16.sum(ret) != crc:
                raise OSError('checksum mismatch')
            elif ret[0] != 0:
                raise OSError('i2c command failed: %d' % ret[0])
            else:
                return ret[1:]

    def _i2c_hib_poll(self):
        while True:
            buf = self._dev.read(5)
            code, size, crc = struct.unpack('>BHH', buf)

            # check if the response is ready
            if code == 0xff:
                time.sleep(0.1)
            elif size != 2:
                raise OSError('unexpected i2c response')
            elif Crc16.sum(buf[:1] + buf[3:-2]) != crc:
                raise OSError('checksum mismatch')
            elif buf[0] != 0:
                raise OSError('i2c command failed: %d' % buf[0])
            else:
                break

    def echo(self, data: bytes) -> bytes:
        self._dev.write(Command.build_echo(data))
        return self._i2c_recv()

    def read(self, zone: Zone, offs: int, size: int) -> bytes:
        self._dev.write(Command.build_read(zone, offs, size))
        return self._i2c_recv()

    def read_cert(self, zone: Zone) -> bytes:
        if zone not in (Zone.RootCert, Zone.DeviceCert, Zone.VendorCert):
            raise ValueError('invalid zone type: ' + repr(zone))
        else:
            return self.read(zone, 0, struct.unpack('>H', self.read(zone, 2, 2))[0] + 4)

    def query(self) -> bytes:
        self._dev.write(Command.build_query())
        return self._i2c_recv()

    def reset(self):
        self._pin.write(0)
        time.sleep(0.001)
        self._pin.write(self._rst)
        time.sleep(0.001)

    def hibernate(self):
        self._dev.write(Command.build_hibernate())
        self._i2c_hib_poll()

    def generate_key(self) -> bytes:
        self._dev.write(Command.build_generate_key())
        return self._i2c_recv()

    def establish_key(self, pkey: bytes) -> bytes:
        self._dev.write(Command.build_establish_key(pkey))
        return self._i2c_recv()

    def generate_random(self, size: int) -> bytes:
        self._dev.write(Command.build_generate_random(size))
        return self._i2c_recv()

    def verify_signature(self, pkey: bytes, sign: bytes, data: bytes) -> bool:
        self._dev.write(Command.build_verify_signature(pkey, sign, data))
        return self._i2c_recv() == b'\x01'

    def generate_signature(self, data: bytes) -> bytes:
        self._dev.write(Command.build_generate_signature(data))
        return self._i2c_recv()
