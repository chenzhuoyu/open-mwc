#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logs
import json
import asyncio

from yarl import URL
from logs import Logger
from http import HTTPStatus
from functools import cached_property

from typing import Callable
from typing import Coroutine
from typing import AsyncIterator

from asyncio import StreamReader
from asyncio import StreamWriter
from asyncio import AbstractEventLoop

SRV_PORT = 10554
SRV_HOST = '0.0.0.0'

class EmptyStreamReader(StreamReader):
    def __init__(self, loop: AbstractEventLoop | None = None) -> None:
        super().__init__(loop = loop)
        self.feed_eof()

class Headers:
    data: dict[str, tuple[str, object]]

    def __init__(self, data: dict[str, object] | None = None, **kwargs):
        self.data = { k.lower(): (k, v) for k, v in data or {} }
        self.data.update(**kwargs)

class Request:
    uri     : URL
    body    : StreamReader
    method  : str
    headers : dict[str, str]

    def __init__(self,
        method  : str,
        uri     : URL,
        *,
        body    : StreamReader | None = None,
        headers : dict[str, str] | None = None
    ):
        self.uri     = uri
        self.body    = body or EmptyStreamReader()
        self.method  = method
        self.headers = headers or {}

    @cached_property
    def cseq(self) -> int:
        return int(self.headers.get('CSeq', 1))

    def __repr__(self) -> str:
        return '\n'.join([
            '%s %s RTSP/1.0 {' % (self.method, self.uri.human_repr()),
            *(
                '    %s: %s' % (k, v)
                for k, v in sorted(self.headers.items())
            ),
            '}',
        ])

    def reply(self,
        *,
        status  : HTTPStatus               = HTTPStatus.OK,
        body    : object                   = b'',
        headers : dict[str, object] | None = None,
    ) -> 'Response':
        return Response(
            body    = body,
            status  = status,
            headers = { **(headers or {}), 'CSeq': self.cseq }
        )

class Response:
    body    : bytes
    status  : HTTPStatus
    headers : dict[str, object]

    def __init__(self,
        *,
        body    : object                   = b'',
        status  : HTTPStatus               = HTTPStatus.OK,
        headers : dict[str, object] | None = None,
    ):
        self.body    = self.to_bytes(body)
        self.status  = status
        self.headers = headers or {}

    @property
    def has_content_length(self) -> bool:
        return any(k.lower() == 'content-length' for k in self.headers)

    def __repr__(self) -> str:
        return '\n'.join([
            'RTSP/1.0 %d %s {' % (self.status.value, self.status.phrase),
            *(
                '    %s: %s' % (k, v)
                for k, v in sorted(self.headers.items())
            ),
            '}',
        ])

    @staticmethod
    def to_bytes(val: object) -> bytes:
        if val is None:
            return b''
        elif isinstance(val, bytes):
            return val
        elif isinstance(val, (bytearray, memoryview)):
            return bytes(val)
        else:
            return str(val).encode('utf-8')

    @classmethod
    def from_object(cls, val: object) -> 'Response':
        if isinstance(val, Response):
            return val
        else:
            return cls(body = val)

class RTSP:
    class Error(Exception):
        status  : HTTPStatus
        message : str

        def __init__(self, status: HTTPStatus, message: str = ''):
            self.status  = status
            self.message = message

        def __repr__(self) -> str:
            return 'RTSP Error: [%d %s] %s' % (
                self.status.value,
                self.status.phrase,
                self.message or self.status.description,
            )

        def to_response(self) -> Response:
            return Response(status = self.status, body = self.message.encode('utf-8'))

    @staticmethod
    async def skip(rd: StreamReader):
        while not rd.at_eof():
            if await rd.readuntil(b'\r\n') == b'\r\n':
                break

    @classmethod
    async def line(cls, rd: StreamReader) -> str:
        buf = await rd.readuntil(b'\r\n')
        ret = buf[:-2]

        # check for EOF
        if not buf:
            raise EOFError

        # decode the line
        try:
            return ret.decode('utf-8')
        except ValueError:
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid utf-8 string') from None

    @classmethod
    async def read(cls, rd: StreamReader) -> Request:
        line = await cls.line(rd)
        vals = line.split()

        # verify the first line
        if len(vals) != 3 or vals[2] != 'RTSP/1.0':
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid first line')

        # extract the path
        hdrs = {}
        path = vals[1]

        # parse the URL
        try:
            uri = URL(path)
        except ValueError:
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid URL') from None

        # check the URL
        if uri.scheme != 'rtsp':
            raise cls.Error(HTTPStatus.NOT_FOUND, 'invalid URL scheme')

        # parse the headers
        while not rd.at_eof():
            line = await cls.line(rd)
            item = line.split(':', 1)

            # check for the last line
            if not line:
                break

            # must have header name and value
            if len(item) != 2:
                raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid header')

            # add to headers
            key, value = item
            hdrs[key.strip().lower()] = value.strip()

        # construct the request
        method, _, _ = vals
        return Request(method, uri, body = rd, headers = hdrs)

    @classmethod
    async def iter(cls, rd: StreamReader) -> AsyncIterator[Error | Request]:
        while not rd.at_eof():
            try:
                yield await cls.read(rd)
            except (EOFError, ConnectionResetError):
                break
            except cls.Error as e:
                await cls.skip(rd)
                yield e

    @classmethod
    def write(cls, wr: StreamWriter, resp: Response):
        nb = False
        wb = [b'RTSP/1.0 %d %s\r\n' % (resp.status.value, resp.status.phrase.encode('utf-8'))]

        # add all the headers
        for k, v in resp.headers.items():
            nb |= k.lower() == 'content-length'
            wb.append(k.encode('utf-8'))
            wb.append(b': ')
            wb.append(Response.to_bytes(v))
            wb.append(b'\r\n')

        # add content length as needed
        if not nb and resp.body:
            wb.append(b'content-length: %d\r\n' % len(resp.body))

        # send the response to output
        wb.append(b'\r\n')
        wb.append(resp.body)
        wr.writelines(wb)

class StreamingServer:
    log  : Logger
    host : str
    port : int

    def __init__(self, *, host: str = SRV_HOST, port: int = SRV_PORT):
        self.log  = Logger.for_name('rtsp')
        self.host = host
        self.port = port

    async def _image_take(self, _: Request) -> Response:
        return Response(body = 'hello, world')

    async def _stream_play(self, req: Request) -> Response:
        print(req)
        return Response(body = 'hello, world')

    async def _stream_setup(self, req: Request) -> Response:
        print(req)
        return Response(body = 'hello, world')

    async def _stream_options(self, req: Request) -> Response:
        return req.reply(headers = { 'Public': 'DESCRIBE, SETUP, PLAY, TEARDOWN' })

    async def _stream_teardown(self, req: Request) -> Response:
        print(req)
        return Response(body = 'hello, world')

    async def _stream_describe(self, req: Request) -> Response:
        print(req)
        return Response(body = 'hello, world')

    __routes__: dict[tuple[str, str], Callable[['StreamingServer', Request], Coroutine[object, object, Response]]] = {
        ('GET'      , '/mwc11/snapshot'): _image_take,
        ('PLAY'     , '/mwc11/stream'  ): _stream_play,
        ('SETUP'    , '/mwc11/stream'  ): _stream_setup,
        ('OPTIONS'  , '/mwc11/stream'  ): _stream_options,
        ('TEARDOWN' , '/mwc11/stream'  ): _stream_teardown,
        ('DESCRIBE' , '/mwc11/stream'  ): _stream_describe,
    }

    def _log_request(self, req: Request | None, resp: Response, raddr: str):
        hline = '-'
        agent = '-'
        refer = '-'

        # dump request info if any
        if req is not None:
            refer = req.headers.get('referer', '-')
            agent = req.headers.get('user-agent', '-')
            hline = '%s %s RTSP/1.0' % (req.method, req.uri.human_repr())

        # log the request
        self.log.info('%(raddr)s - %(hline)s %(status)s %(size)d %(refer)s %(agent)s' % {
            'size'   : len(resp.body),
            'raddr'  : raddr,
            'hline'  : json.dumps(hline),
            'agent'  : json.dumps(agent),
            'refer'  : json.dumps(refer),
            'status' : resp.status.value,
        })

    async def _handle_request(self, req: Request) -> Response:
        uri = req.uri.path
        func = self.__routes__.get((req.method, uri))

        # check for handler
        if func is None:
            return req.reply(status = HTTPStatus.NOT_FOUND)

        # call the handler
        try:
            resp = await func(self, req)
        except RTSP.Error as e:
            return e.to_response()
        else:
            return Response.from_object(resp)

    async def _handle_requests(self, rd: StreamReader) -> AsyncIterator[tuple[Request | None, Response]]:
        try:
            async for msg in RTSP.iter(rd):
                if isinstance(msg, Request):
                    yield msg, await self._handle_request(msg)
                elif isinstance(msg, RTSP.Error):
                    yield None, msg.to_response()
                else:
                    raise SystemError('unreachable')
        except Exception:
            self.log.exception('Unhandled exception when handling requests:')
            yield None, Response(status = HTTPStatus.INTERNAL_SERVER_ERROR, body = 'internal error')

    async def _handle_connection(self, rd: StreamReader, wr: StreamWriter):
        try:
            async for req, resp in self._handle_requests(rd):
                self._log_request(req, resp, wr.transport.get_extra_info('peername')[0])
                RTSP.write(wr, resp)
        except (EOFError, ConnectionResetError):
            pass
        except Exception:
            self.log.exception('Unhandled exception:')
        finally:
            wr.close()

    async def run(self):
        srv = await asyncio.start_server(self._handle_connection, self.host, self.port)
        await srv.serve_forever()

async def main():
    await StreamingServer().run()

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
