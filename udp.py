#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio

from asyncio import Queue
from asyncio import DatagramProtocol
from asyncio import DatagramTransport

class UdpProtocol(DatagramProtocol):
    rbuf: Queue[tuple[bytes, tuple[str, int]]]

    def __init__(self):
        self.rbuf = Queue()

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.rbuf.put_nowait((data, addr))

class UdpSocket:
    port   : DatagramTransport
    proto  : UdpProtocol
    closed : bool

    def __init__(self, port: DatagramTransport, proto: UdpProtocol) -> None:
        self.port   = port
        self.proto  = proto
        self.closed = False

    def close(self):
        if not self.closed:
            self.port.close()
            self.closed = True

    def sendto(self, buf: bytes, addr: tuple[str, int]):
        if self.closed:
            raise ConnectionError('send to closed socket')
        else:
            self.port.sendto(buf, addr)

    async def recvfrom(self) -> tuple[bytes, tuple[str, int]]:
        if self.closed:
            raise ConnectionError('receive from closed socket')
        else:
            return await self.proto.rbuf.get()

    @classmethod
    async def new(cls, *args, **kwargs) -> 'UdpSocket':
        port, proto = await asyncio.get_running_loop().create_datagram_endpoint(UdpProtocol, *args, **kwargs)
        return cls(port, proto)
