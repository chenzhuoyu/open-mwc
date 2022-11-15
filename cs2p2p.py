#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class InitString(str):
    __key__ = bytes([
        0x49, 0x59, 0x43, 0x3d, 0xb5, 0xbf, 0x6d, 0xa3, 0x47, 0x53, 0x4f, 0x61, 0x65, 0xe3, 0x71, 0xe9,
        0x67, 0x7f, 0x02, 0x03, 0x0b, 0xad, 0xb3, 0x89, 0x2b, 0x2f, 0x35, 0xc1, 0x6b, 0x8b, 0x95, 0x97,
        0x11, 0xe5, 0xa7, 0x0d, 0xef, 0xf1, 0x05, 0x07, 0x83, 0xfb, 0x9d, 0x3b, 0xc5, 0xc7, 0x13, 0x17,
        0x1d, 0x1f, 0x25, 0x29, 0xd3, 0xdf,
    ])

    @classmethod
    def parse(cls, data: str) -> 'InitString':
        bv = ord('9')
        nb = len(data)
        buf = bytearray(nb // 2)

        # must have an even number of characters
        if nb & 1 != 0:
            raise ValueError('invalid encoded string')

        # decode every two characters
        for i in range(nb // 2):
            msb = ord(data[i * 2]) - 0x41
            lsb = ord(data[i * 2 + 1]) - 0x41
            val = ((msb << 4) | lsb) ^ cls.__key__[i % len(cls.__key__)] ^ bv

            # check for byte range
            if not (0 <= val <= 255):
                raise ValueError('invalid byte value')

            # add to the byte array
            bv ^= val
            buf[i] = val

        # attempt to decode the string
        try:
            return cls(buf.decode('utf-8'))
        except UnicodeDecodeError:
            raise ValueError('invalid encoded string') from None

print(InitString.parse(
    'EEGGFCBNKAJNGBJOEMGNFPEDHCMFHLJLHMAFBHHLBKIJLJPDGDBHHOPDGLKFNCLPB'
    'HIOKFCBKANBEIGGJKILIMEFNGLNFMHGAMDMHGAJIKLFANHEABFBLENHCLIGANHEEE'
))
