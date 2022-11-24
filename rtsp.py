#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gzip
import logs
import json
import asyncio

from yarl import URL
from logs import Logger
from http import HTTPStatus

from itertools import chain
from functools import cached_property

from typing import overload
from typing import Callable
from typing import Iterator
from typing import Coroutine
from typing import AsyncIterator

from asyncio import StreamReader
from asyncio import StreamWriter
from asyncio import AbstractEventLoop

MAX_HDR  = 1024
MAX_REQ  = 65536
SRV_PORT = 10554
SRV_HOST = '0.0.0.0'

class EmptyStreamReader(StreamReader):
    def __init__(self, loop: AbstractEventLoop | None = None) -> None:
        super().__init__(loop = loop)
        self.feed_eof()

class Headers:
    data: dict[
        str,
        tuple[str, str],
    ]

    def __init__(self, data: 'Headers | dict[str, str] | None' = None, **kwargs):
        self.data = {
            k.lower(): (k, v)
            for k, v in chain((data or {}).items(), kwargs.items())
        }

    def __len__(self) -> int:
        return len(self.data)

    def __bool__(self) -> bool:
        return bool(self.data)

    def __iter__(self) -> Iterator[str]:
        return self.keys()

    def __delitem__(self, name: str):
        del self.data[name.lower()]

    def __getitem__(self, name: str) -> str:
        _, val = self.data[name.lower()]
        return val

    def __setitem__(self, name: str, value: str):
        self.data[name.lower()] = (name, value)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self.data

    @overload
    def get(self, name: str) -> str | None:
        ...

    @overload
    def get(self, name: str, default: str) -> str:
        ...

    def get(self, name: str, default: str | None = None) -> str | None:
        _, val = self.data.get(name.lower(), (None, default))
        return val

    @overload
    def pop(self, name: str) -> str | None:
        ...

    @overload
    def pop(self, name: str, default: str) -> str:
        ...

    def pop(self, name: str, default: str | None = None) -> str | None:
        _, val = self.data.pop(name.lower(), (None, default))
        return val

    def keys(self) -> Iterator[str]:
        for key, _ in self.data.values():
            yield key

    def items(self) -> Iterator[tuple[str, str]]:
        yield from self.data.values()

    def values(self) -> Iterator[str]:
        for _, val in self.data.values():
            yield val

class Request:
    uri     : URL
    body    : StreamReader
    method  : str
    headers : Headers

    def __init__(self,
        method  : str,
        uri     : URL,
        *,
        body    : StreamReader | None = None,
        headers : Headers | None = None
    ):
        self.uri     = uri
        self.body    = body or EmptyStreamReader()
        self.method  = method
        self.headers = headers or Headers()

    @cached_property
    def cseq(self) -> int:
        return int(self.headers.get('CSeq', '0'))

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
        status  : HTTPStatus            = HTTPStatus.OK,
        body    : object                = b'',
        headers : dict[str, str] | None = None,
    ) -> 'Response':
        return Response(
            body    = body,
            status  = status,
            headers = {
                **(headers or {}),
                'CSeq': str(self.cseq),
            }
        )

class Response:
    body    : bytes
    status  : HTTPStatus
    headers : Headers

    def __init__(self,
        *,
        body    : object                = b'',
        status  : HTTPStatus            = HTTPStatus.OK,
        headers : dict[str, str] | None = None,
    ):
        self.body    = self.to_bytes(body)
        self.status  = status
        self.headers = Headers(headers or {})

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

        # parse the URL
        try:
            uri = URL(vals[1])
        except ValueError:
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid URL') from None

        # check the URL
        if uri.scheme != 'rtsp':
            raise cls.Error(HTTPStatus.NOT_FOUND, 'invalid URL scheme')

        # header buffer
        nhdr = 0
        rlen = 0
        comp = False
        hdrs = Headers()

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

            # check for header sizes
            if nhdr >= MAX_HDR or len(line) > MAX_REQ:
                raise cls.Error(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)

            # add to headers
            nhdr += 1
            name, value = item
            hdrs[name.strip()] = value.strip()

            # parse the content length
            if name.lower() == 'content-length':
                try:
                    rlen = int(value)
                except ValueError:
                    raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid Content-Length') from None

            # save the content encoding
            if name.lower() == 'content-encoding':
                if value == 'gzip':
                    comp = True
                else:
                    raise cls.Error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'unsupported Content-Encoding')

        # no request body
        if not rlen:
            return Request(vals[0], uri, headers = hdrs)

        # limit the request length
        if rlen > MAX_REQ:
            raise cls.Error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, 'request too large')

        # read the body
        body = StreamReader()
        rbuf = await rd.readexactly(rlen)

        # feed into the reader, decompress as needed
        body.feed_data(gzip.decompress(rbuf) if comp else rbuf)
        body.feed_eof()

        # construct the request
        return Request(
            uri     = uri,
            body    = body,
            method  = vals[0],
            headers = hdrs,
        )

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
        ce = resp.headers.pop('Content-Encoding')
        wb = [b'RTSP/1.0 %d %s\r\n' % (resp.status.value, resp.status.phrase.encode('utf-8'))]

        # check for content encoding
        if ce is not None:
            if resp.body and ce == 'gzip':
                resp.body = gzip.compress(resp.body)
                resp.headers['Content-Encoding'] = 'gzip'

        # set the content length as needed
        if resp.body:
            resp.headers['Content-Length'] = str(len(resp.body))

        # add all the headers
        for k, v in resp.headers.items():
            wb.append(k.encode('utf-8'))
            wb.append(b': ')
            wb.append(Response.to_bytes(v))
            wb.append(b'\r\n')

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
        return req.reply(body = 'hello, world')

    async def _stream_setup(self, req: Request) -> Response:
        print(req)
        return req.reply(body = 'hello, world')

    async def _stream_options(self, req: Request) -> Response:
        return req.reply(headers = {
            'Public': ', '.join([
                'DESCRIBE',
                'SETUP',
                'PLAY',
                'TEARDOWN',
            ]),
        })

    async def _stream_teardown(self, req: Request) -> Response:
        print(req)
        return req.reply(body = 'hello, world')

    async def _stream_describe(self, req: Request) -> Response:
        print(req)
        return req.reply(body = 'hello, world')

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
        self.log.info('RTSP Server started at address %s:%d', self.host, self.port)
        await srv.serve_forever()

async def main():
    await StreamingServer().run()

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
