#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import gzip
import logs
import json
import base64
import hashlib
import asyncio

from yarl import URL
from logs import Logger
from http import HTTPStatus

from itertools import chain
from functools import cached_property

from udp import UdpSocket
from collections import OrderedDict

from enum import Enum
from enum import IntEnum

from typing import overload
from typing import runtime_checkable

from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Protocol
from typing import Awaitable
from typing import Coroutine
from typing import NamedTuple
from typing import AsyncIterator

from asyncio import StreamReader
from asyncio import StreamWriter
from asyncio import AbstractEventLoop

MAX_HDR = 1024
MAX_REQ = 65536

_KT = TypeVar('_KT', covariant = True)
_VT = TypeVar('_VT', covariant = True)

class EmptyStreamReader(StreamReader):
    def __init__(self, loop: AbstractEventLoop | None = None) -> None:
        super().__init__(loop = loop)
        self.feed_eof()

@runtime_checkable
class SupportsItems(Protocol[_KT, _VT]):
    def items(self) -> Iterable[tuple[_KT, _VT]]:
        ...

class Headers(SupportsItems):
    data: dict[
        str,
        tuple[str, str],
    ]

    def __init__(self, data: SupportsItems[str, str] | Iterable[tuple[str, str]] | None = None, **kwargs: str):
        self.data = {}
        self.update(data, **kwargs)

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

    def update(self, data: SupportsItems[str, str] | Iterable[tuple[str, str]] | None = None, **kwargs: str):
        if not data:
            self.data.update((k.lower(), (k, v)) for k, v in kwargs.items())
        elif not isinstance(data, SupportsItems):
            self.data.update((k.lower(), (k, v)) for k, v in chain(data, kwargs.items()))
        else:
            self.data.update((k.lower(), (k, v)) for k, v in chain(data.items(), kwargs.items()))

class Request:
    uri     : URL
    body    : StreamReader
    method  : str
    remote  : tuple[str, int]
    version : str
    headers : Headers

    def __init__(self,
        method  : str,
        uri     : URL,
        version : str,
        *,
        body    : StreamReader | None = None,
        remote  : tuple[str, int]     = ('', 0),
        headers : Headers | None      = None
    ):
        self.uri     = uri
        self.body    = body or EmptyStreamReader()
        self.method  = method
        self.remote  = remote
        self.version = version
        self.headers = headers or Headers()

    @cached_property
    def cseq(self) -> int:
        return int(self.headers.get('CSeq', '0'))

    def __repr__(self) -> str:
        return '\n'.join([
            '%s %s %s {' % (self.method, self.uri.human_repr(), self.version),
            *(
                '    %s: %s' % (k, v)
                for k, v in sorted(self.headers.items())
            ),
            '}',
        ])

    def reply(self,
        *,
        status  : HTTPStatus                      = HTTPStatus.OK,
        body    : object                          = b'',
        headers : Headers | dict[str, str] | None = None,
    ) -> 'Response':
        ver = self.version
        ret = Response(status = status, version = ver, body = body, headers = headers)

        # only RTSP uses CSeq headers
        if ver != 'RTSP/1.0' or 'CSeq' not in self.headers:
            return ret

        # copy the CSeq header
        ret.headers['CSeq'] = self.headers['CSeq']
        return ret

class Response:
    body    : bytes
    status  : HTTPStatus
    version : str
    headers : Headers

    class Serializable:
        def encode(self) -> bytes    : raise NotImplementedError('encode()')
        def headers(self) -> Headers : raise NotImplementedError('headers()')

    def __init__(self,
        *,
        status  : HTTPStatus                      = HTTPStatus.OK,
        version : str                             = 'HTTP/1.1',
        body    : object                          = b'',
        headers : Headers | dict[str, str] | None = None,
    ):
        self.body    = self.to_bytes(body)
        self.status  = status
        self.version = version
        self.headers = Headers()

        # add custom headers if any
        if isinstance(body, self.Serializable):
            self.headers.update(body.headers())

        # add override headers if any
        if headers is not None:
            self.headers.update(headers)

    def __repr__(self) -> str:
        return '\n'.join([
            '%s %d %s {' % (self.version, self.status.value, self.status.phrase),
            *(
                '    %s: %s' % (k, v)
                for k, v in sorted(self.headers.items())
            ),
            '}',
        ])

    @classmethod
    def to_bytes(cls, val: object) -> bytes:
        if val is None:
            return b''
        elif isinstance(val, bytes):
            return val
        elif isinstance(val, cls.Serializable):
            return val.encode()
        elif isinstance(val, (bytearray, memoryview)):
            return bytes(val)
        else:
            return str(val).encode('utf-8')

class SDP(Response.Serializable):
    fields       : list['Value']
    content_type : str = 'application/sdp'

    class Value:
        def to_string(self) -> str:
            raise NotImplementedError('to_string()')

    class Media(Value):
        fmt   : int
        port  : int
        count : int
        media : str
        proto : str

        def __init__(self, media: str, port: int, count: int, proto: str, fmt: int):
            self.fmt   = fmt
            self.port  = port
            self.count = count
            self.media = media
            self.proto = proto

        def to_string(self) -> str:
            if self.count == 1:
                return 'm=%s %d %s %d' % (self.media, self.port, self.proto, self.fmt)
            else:
                return 'm=%s %d/%d %s %d' % (self.media, self.port, self.count, self.proto, self.fmt)

    class Version(int, Value):
        def to_string(self) -> str:
            return 'v=%d' % self

    class Attribute(Value):
        name  : str
        value : str

        def __init__(self, name: str, value: str):
            self.name  = name
            self.value = value

        def to_string(self) -> str:
            return 'a=%s:%s' % (self.name, self.value)

        @classmethod
        def lit(cls, name: str, value: str) -> 'SDP.Attribute':
            return cls(name, value)

        @classmethod
        def int(cls, name: str, value: int) -> 'SDP.Attribute':
            return cls(name, 'integer;%d' % value)

        @classmethod
        def str(cls, name: str, value: str) -> 'SDP.Attribute':
            return cls(name, 'string;%s' % json.dumps(value))

    def __init__(self):
        self.fields  = []

    def add(self, item: Value):
        self.fields.append(item)

    def encode(self) -> bytes:
        return '\r\n'.join(v.to_string() for v in self.fields).encode('utf-8') + b'\r\n'

    def headers(self) -> Headers:
        return Headers({ 'Content-Type': self.content_type })

class RTSP:
    class Error(Response, Exception):
        def __init__(self,
            status  : HTTPStatus,
            message : str = '',
            *,
            version : str = 'HTTP/1.1',
            headers : Headers | dict[str, str] | None = None,
        ):
            super().__init__(
                status  = status,
                body    = message or status.description,
                version = version,
                headers = headers,
            )

        def __repr__(self) -> str:
            return 'Error: [%s %d %s] %s' % (
                self.version,
                self.status.value,
                self.status.phrase,
                self.body.decode('utf-8') if self.body else self.status.description
            )

    @staticmethod
    async def skip(rd: StreamReader):
        while not rd.at_eof():
            try:
                if await rd.readuntil(b'\r\n') == b'\r\n':
                    break
            except EOFError:
                break
            except asyncio.LimitOverrunError as e:
                await rd.read(e.consumed)

    @classmethod
    async def line(cls,
        rd      : StreamReader,
        *,
        status  : HTTPStatus = HTTPStatus.REQUEST_URI_TOO_LONG,
        version : str = 'HTTP/1.1',
    ) -> str:
        try:
            buf = await rd.readuntil(b'\r\n')
        except asyncio.LimitOverrunError:
            raise cls.Error(status, version = version) from None
        else:
            if not buf:
                raise EOFError
            else:
                try:
                    return buf[:-2].decode('utf-8')
                except ValueError:
                    raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid utf-8 string', version = version) from None

    @classmethod
    async def read(cls, rd: StreamReader, addr: tuple[str, int]) -> Request:
        line = await cls.line(rd)
        vals = line.split()

        # verify the first line
        if len(vals) != 3:
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid first line')

        # verify the protocol
        if vals[2] not in ('RTSP/1.0', 'HTTP/1.1'):
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid protocol', version = vals[2])

        # parse the URL
        try:
            uri = URL(vals[1])
        except ValueError:
            raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid URL', version = vals[2]) from None

        # header buffer
        nhdr = 0
        rlen = 0
        name = None
        comp = False
        hdrs = Headers()

        # parse the headers
        while not rd.at_eof():
            line = await cls.line(rd, status = HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, version = vals[2])
            data = line.strip()

            # check for the last line
            if not line:
                break

            # check for header sizes
            if len(line) > MAX_REQ:
                raise cls.Error(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, version = vals[2])

            # header line folding
            if line[0].isspace():
                if not name:
                    raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid header line', version = vals[2])
                elif len(hdrs[name]) + len(data) > MAX_REQ:
                    raise cls.Error(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, version = vals[2])
                else:
                    hdrs[name] += data
                    continue

            # check for header size
            if nhdr >= MAX_HDR:
                raise cls.Error(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, version = vals[2])

            # get the name and value
            try:
                name, value = map(str.strip, data.split(':', 1))
            except TypeError:
                raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid header', version = vals[2]) from None

            # check the header name:
            if not name:
                raise cls.Error(HTTPStatus.BAD_REQUEST, 'empty header name', version = vals[2])

            # add to headers
            nhdr += 1
            hdrs[name] = value

            # parse the content length
            if name.lower() == 'content-length':
                try:
                    rlen = int(value)
                except ValueError:
                    raise cls.Error(HTTPStatus.BAD_REQUEST, 'invalid Content-Length', version = vals[2]) from None

            # save the content encoding
            if name.lower() == 'content-encoding':
                if value == 'gzip':
                    comp = True
                else:
                    raise cls.Error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'unsupported Content-Encoding', version = vals[2])

        # no request body
        if not rlen:
            return Request(vals[0], uri, vals[2], remote = addr, headers = hdrs)

        # limit the request length
        if rlen > MAX_REQ:
            raise cls.Error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, version = vals[2])

        # read the body
        body = StreamReader()
        rbuf = await rd.readexactly(rlen)

        # feed into the reader, decompress as needed
        body.feed_data(gzip.decompress(rbuf) if comp else rbuf)
        body.feed_eof()

        # construct the request
        return Request(
            method  = vals[0],
            uri     = uri,
            version = vals[2],
            body    = body,
            remote  = addr,
            headers = hdrs,
        )

    @classmethod
    async def iter(cls, rd: StreamReader, addr: tuple[str, int]) -> AsyncIterator[Error | Request]:
        while not rd.at_eof():
            try:
                yield await cls.read(rd, addr)
            except (EOFError, ConnectionResetError):
                break
            except cls.Error as e:
                await cls.skip(rd)
                yield e

    @classmethod
    def write(cls, wr: StreamWriter, resp: Response):
        payload = resp.body
        encoding = resp.headers.pop('Content-Encoding')

        # the first line
        wb = [
            resp.version.encode('utf-8'),
            b' %d ' % resp.status.value,
            resp.status.phrase.encode('utf-8'),
            b'\r\n',
        ]

        # check for content encoding
        if encoding is not None:
            if payload and encoding == 'gzip':
                payload = gzip.compress(payload)
                resp.headers['Content-Encoding'] = 'gzip'

        # set the content length as needed
        if payload:
            resp.headers['Content-Length'] = str(len(payload))

        # add all the headers
        for k, v in resp.headers.items():
            wb.append(k.encode('utf-8'))
            wb.append(b': ')
            wb.append(Response.to_bytes(v))
            wb.append(b'\r\n')

        # send the response to output
        wb.append(b'\r\n')
        wb.append(payload)
        wr.writelines(wb)

class TransportInfo:
    proto: str
    attrs: OrderedDict[str, str | None]

    def __init__(self, proto: str, attrs: OrderedDict[str, str | None] | None = None):
        self.proto = proto
        self.attrs = attrs or OrderedDict()

    def __str__(self) -> str:
        return '%s;%s' % (self.proto, ';'.join(
            k if v is None else '%s=%s' % (k, v)
            for k, v in self.attrs.items()
        ))

    def __repr__(self) -> str:
        return '\n'.join([
            'Transport %s {' % self.proto,
            *(
                '    ' + k if v is None else '    %s = %s' % (k, v)
                for k, v in self.attrs.items()
            ),
            '}',
        ])

    @classmethod
    def parse(cls, src: str) -> 'TransportInfo':
        args = OrderedDict()
        proto, *vals = src.split(';')

        # parse every item
        for item in vals:
            if '=' not in item:
                args[item] = None
            else:
                key, val = item.split('=', 1)
                args[key] = val

        # construct the result
        return cls(
            attrs = args,
            proto = proto,
        )

class SetupSession(Response.Serializable):
    session   : str
    transport : TransportInfo

    def __init__(self, session: str, transport: TransportInfo):
        self.session   = session
        self.transport = transport

    def encode(self) -> bytes:
        return b''

    def headers(self) -> Headers:
        return Headers(
            Session   = self.session,
            Transport = str(self.transport),
        )

class Authentication:
    kind   : 'Kind'
    fields : OrderedDict[str, 'Field']

    class Kind(Enum):
        Basic  = 'Basic'
        Digest = 'Digest'

    class Field:
        name  : str
        value : str
        quote : bool

        def __init__(self, name: str, value: str, *, quote: bool = True):
            self.name  = name
            self.value = value
            self.quote = quote

        def __repr__(self) -> str:
            return '%s = %s' % (self.name, self.value)

        def __str__(self) -> str:
            if not self.quote:
                return '%s=%s' % (self.name, self.value)
            else:
                return '%s=%s' % (self.name, json.dumps(self.value))

        @classmethod
        def parse(cls, val: str, i: int = 0) -> tuple['Authentication.Field', int]:
            n = len(val)
            p = val.find('=', i)

            # '=' must exists
            if p < 0:
                raise ValueError('invalid authentication field')

            # extract the name
            j = p + 1
            name = val[i:p].strip()

            # name cannot be empty
            if not name:
                raise ValueError('empty authentication field name')

            # skip all the spaces
            while j < n and val[j].isspace():
                j += 1

            # end of string
            if j >= n:
               return cls(name, ''), n

            # quoted string value, parse with JSON
            if val[j] == '"':
                val, i = json.JSONDecoder().raw_decode(val, j)
                return cls(name, val), i

            # plain text, find the next ','
            try:
                k = val.index(',', j)
            except ValueError:
                return cls(name, val[j:], quote = False), n
            else:
                return cls(name, val[j:k], quote = False), k

    def __init__(self, kind: Kind, *fields: Field):
        self.kind   = kind
        self.fields = OrderedDict((f.name, f) for f in fields)

    def __repr__(self) -> str:
        return '\n'.join([
            'Authentication {',
            '    %s' % self.kind.value,
            *('    %r' % v for v in self.fields.values()),
            '}',
        ])

    def __str__(self) -> str:
        return '%s %s' % (self.kind.value, ', '.join(map(str, self.fields.values())))

    @classmethod
    def parse(cls, val: str) -> 'Authentication':
        pos = 0
        vals = val.split(None, 1)

        # must have arguments
        if len(vals) != 2:
            raise ValueError('missing fields')

        # parse the authentication kind
        val = vals[1]
        ret = cls(cls.Kind(vals[0]))

        # parse every field
        while pos < len(val):
            fv, pos = cls.Field.parse(val, pos)
            ret.fields[fv.name] = fv

            # skip the spaces
            while pos < len(val) and val[pos].isspace():
                pos += 1

            # should be either ',' or EOF
            if pos >= len(val) or val[pos] == ',':
                pos += 1
            else:
                raise ValueError('invalid authentication fields')

        # parsed successfully
        return ret

class SupportsHexDigest(Protocol):
    def __init__(self, buf: bytes) : ...
    def hexdigest(self) -> str     : ...

class DigestAlgorithm(Enum):
    ident  : str
    hashfn : Callable[[bytes], SupportsHexDigest]

    MD5    = 'MD5'     , hashlib.md5
    SHA256 = 'SHA-256' , hashlib.sha256

    def __new__(cls, ident: str, hashfn: Callable[[bytes], SupportsHexDigest]):
        ret = object.__new__(cls)
        ret.ident = ident
        ret.hashfn = hashfn
        ret._value_ = (ident, hashfn)
        return ret

    def digest(self, val: str) -> str:
        return self.hashfn(val.encode('utf-8')).hexdigest()

    @classmethod
    def for_name(cls, name: str) -> 'DigestAlgorithm':
        for alg in cls:
            if name.lower() in (alg.name.lower(), alg.ident.lower()):
                return alg
        else:
            raise ValueError('invalid algorithm name or identifier')

class AuthenticationMethod:
    async def authenticate(self, srv: 'StreamingServer', req: Request):
        raise NotImplementedError('auth()', srv, req)

class AuthenticationContext(NamedTuple):
    realm     : str
    username  : str
    password  : str
    algorithm : DigestAlgorithm

@runtime_checkable
class SupportsAuthenticationContext(Protocol):
    def authentication_context(self) -> AuthenticationContext:
        ...

class DefaultAuthenticationContext(SupportsAuthenticationContext):
    realm     : str             = os.getenv('RTSP_AUTH_REALM') or 'default'
    username  : str             = os.getenv('RTSP_AUTH_USERNAME') or 'rtsp'
    password  : str             = os.getenv('RTSP_AUTH_PASSWORD') or '12345678'
    algorithm : DigestAlgorithm = DigestAlgorithm.for_name(os.getenv('RTSP_AUTH_ALG') or 'SHA-256')

    def authentication_context(self) -> AuthenticationContext:
        return AuthenticationContext(
            realm     = self.realm,
            username  = self.username,
            password  = self.password,
            algorithm = self.algorithm,
        )

class DigestAuthenticationMethod(AuthenticationMethod):
    def _auth_ctx(self, srv: 'StreamingServer') -> AuthenticationContext:
        if not isinstance(srv, SupportsAuthenticationContext):
            raise TypeError('%s does not implement AuthenticationContext' % type(srv).__name__)
        else:
            return srv.authentication_context()

    def _hash_rand(self, ctx: AuthenticationContext, rnd: bytes) -> str:
        return hashlib.sha256(rnd + ctx.password.encode('utf-8')).hexdigest()

    def _make_auth(self, ctx: AuthenticationContext, rnd: bytes) -> RTSP.Error:
        return RTSP.Error(
            status  = HTTPStatus.UNAUTHORIZED,
            message = 'unauthorized',
            headers = {
                'Content-Type'     : 'text/plain',
                'WWW-Authenticate' : str(Authentication(
                    Authentication.Kind.Digest,
                    Authentication.Field('realm'     , ctx.realm),
                    Authentication.Field('qop'       , 'auth'),
                    Authentication.Field('algorithm' , ctx.algorithm.ident, quote = False),
                    Authentication.Field('nonce'     , rnd.hex()),
                    Authentication.Field('opaque'    , self._hash_rand(ctx, rnd)),
                ))
            },
        )

    async def authenticate(self, srv: 'StreamingServer', req: Request):
        rnd = os.urandom(16)
        ctx = self._auth_ctx(srv)

        # parse the authentication header
        try:
            auth = Authentication.parse(req.headers['Authorization'])
        except (KeyError, ValueError):
            raise self._make_auth(ctx, rnd) from None

        # must be digest authentication
        if auth.kind != Authentication.Kind.Digest:
            raise self._make_auth(ctx, rnd)

        # extract all required fields
        try:
            nc        = auth.fields['nc'].value
            qop       = auth.fields['qop'].value
            uri       = auth.fields['uri'].value
            realm     = auth.fields['realm'].value
            nonce     = auth.fields['nonce'].value
            cnonce    = auth.fields['cnonce'].value
            opaque    = auth.fields['opaque'].value
            username  = auth.fields['username'].value
            response  = auth.fields['response'].value
            algorithm = auth.fields['algorithm'].value
        except KeyError:
            raise self._make_auth(ctx, rnd) from None

        # validate some basic fields
        if qop != 'auth'                    : raise self._make_auth(ctx, rnd)
        if realm != ctx.realm               : raise self._make_auth(ctx, rnd)
        if username != ctx.username         : raise self._make_auth(ctx, rnd)
        if algorithm != ctx.algorithm.ident : raise self._make_auth(ctx, rnd)

        # parse the URI
        try:
            url = URL(uri)
        except ValueError:
            raise self._make_auth(ctx, rnd) from None

        # verify the query path
        if url.path_qs != req.uri.path_qs:
            raise self._make_auth(ctx, rnd)

        # calculate the signature of nonce
        try:
            sign = self._hash_rand(ctx, bytes.fromhex(nonce))
        except ValueError:
            raise self._make_auth(ctx, rnd) from None

        # verify the nonce
        if sign != opaque:
            raise self._make_auth(ctx, rnd)

        # generate the hashes
        ha2 = ctx.algorithm.digest(f'{req.method}:{uri}')
        ha1 = ctx.algorithm.digest(f'{username}:{realm}:{ctx.password}')
        sig = ctx.algorithm.digest(f'{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}')

        # check the signature
        if sig != response:
            raise self._make_auth(ctx, rnd)

class Authenticator:
    auth: 'AuthenticationMethod'
    func: Callable[['StreamingServer', Request], Awaitable[object]]

    def __init__(self, auth: AuthenticationMethod, func: Callable[['StreamingServer', Request], Awaitable[object]]):
        self.auth = auth
        self.func = func

    async def __call__(self, srv: 'StreamingServer', req: Request) -> object:
        await self.auth.authenticate(srv, req)
        return await self.func(srv, req)

    @classmethod
    def digest(cls, func: Callable[['StreamingServer', Request], Awaitable[object]]) -> 'Authenticator':
        return cls(DigestAuthenticationMethod(), func)

class StreamKind(IntEnum):
    Audio = 0
    Video = 1

    @classmethod
    def for_name(cls, name: str) -> 'StreamKind':
        match name:
            case 'audio' : return cls.Audio
            case 'video' : return cls.Video
            case _       : raise ValueError('invalid stream kind name: ' + name)

class StreamSink:
    log       : Logger
    addr      : str
    ssid      : str
    kind      : StreamKind
    rtp_port  : int
    rtcp_port : int

    def __init__(self,
        kind      : StreamKind,
        addr      : str,
        ssid      : str,
        rtp_port  : int,
        rtcp_port : int,
    ):
        self.log       = Logger.for_name('rtsp.sink.%s.%s' % (kind.name.lower(), ssid))
        self.addr      = addr
        self.kind      = kind
        self.ssid      = ssid
        self.rtp_port  = rtp_port
        self.rtcp_port = rtcp_port

    def start(self):
        self.log.debug('Stream sink started.', )

    async def stop(self):
        self.log.debug('Stopping stream sink ...')

class StreamingServer(SupportsAuthenticationContext):
    log  : Logger
    ctx  : SupportsAuthenticationContext
    host : str
    port : int
    ssrc : int
    sink : dict[str, StreamSink]
    link : dict[tuple[str, int], StreamSink]
    conn : dict[tuple[str, int], list[StreamSink]]

    def __init__(self,
        host     : str = '0.0.0.0',
        port     : int = 10554,
        ssrc     : int = 0x00000000,
        *,
        auth_ctx : SupportsAuthenticationContext | None = None,
    ):
        self.log  = Logger.for_name('rtsp')
        self.ctx  = auth_ctx or DefaultAuthenticationContext()
        self.sink = {}
        self.link = {}
        self.conn = {}
        self.host = host
        self.port = port
        self.ssrc = ssrc

    def authentication_context(self) -> AuthenticationContext:
        return self.ctx.authentication_context()

    @Authenticator.digest
    async def _image_take(self, _: Request) -> object:
        return 'hello, world'

    async def _stream_play(self, req: Request) -> object:
        ssid = req.headers.get('Session', '')
        pair = self.sink.get(ssid)

        # check for session ID
        if pair is None:
            raise RTSP.Error(HTTPStatus.UNAUTHORIZED, 'invalid session id')

        # TODO: start the stream and construct the response
        return req.reply(headers = { 'Session': ssid })

    async def _stream_pause(self, req: Request) -> object:
        ssid = req.headers.get('Session', '')
        pair = self.sink.get(ssid)

        # check for session ID
        if pair is None:
            raise RTSP.Error(HTTPStatus.UNAUTHORIZED, 'invalid session id')

        # TODO: pause the stream and construct the response
        return req.reply(headers = { 'Session': ssid })

    async def _stream_setup(self, req: Request) -> object:
        addr = req.remote[0]
        desc = req.headers.get('Transport')
        mode = req.uri.query.get('m', '')

        # check for transport header
        if not desc:
            raise RTSP.Error(HTTPStatus.BAD_REQUEST, 'missing Transport header')

        # parse the stream kind
        try:
            kind = StreamKind.for_name(mode)
        except ValueError:
            raise RTSP.Error(HTTPStatus.BAD_REQUEST, 'invalid stream kind') from None

        # parse the transport header
        try:
            info = TransportInfo.parse(desc)
        except ValueError:
            raise RTSP.Error(HTTPStatus.BAD_REQUEST, 'invalid Transport header')

        # check for protocol
        if info.proto != 'RTP/AVP/UDP':
            raise RTSP.Error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'unsupported protocol')

        # currently unicast only
        if info.attrs.get('unicast', 0) is not None:
            raise RTSP.Error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'unicast only')

        # parse the port range
        try:
            attr = info.attrs.get('client_port') or ''
            rtp_port, rtcp_port = (int(v) for v in attr.split('-'))
        except (KeyError, TypeError, ValueError):
            raise RTSP.Error(HTTPStatus.BAD_REQUEST, 'invalid port range')

        # check the port range, typically RTP will be sent on an even-numbered UDP
        # port, with RTCP messages being sent over the next higher odd-numbered port
        if rtcp_port != rtp_port + 1:
            raise RTSP.Error(HTTPStatus.BAD_REQUEST, 'invalid port range')

        # generate a new session ID
        sidv = os.urandom(12)
        ssid = base64.urlsafe_b64encode(sidv).decode('utf-8')

        # avoid Session ID confliction
        while ssid in self.sink:
            sidv = os.urandom(12)
            ssid = base64.urlsafe_b64encode(sidv).decode('utf-8')

        # create and start a new stream sink
        sink = StreamSink(kind, addr, ssid, rtp_port, rtcp_port)
        sink.start()

        # record the two-way relationship
        self.sink[ssid] = sink
        self.link[addr, rtp_port] = sink
        self.link[addr, rtcp_port] = sink
        self.conn[req.remote].append(sink)

        # reply the request
        return req.reply(body = SetupSession(
            session   = ssid,
            transport = TransportInfo(info.proto, OrderedDict(
                unicast     = None,
                client_port = '%d-%d' % (rtp_port, rtcp_port),
                server_port = '%d-%d' % (self.port, self.port + 1),
                ssrc        = '%08x' % self.ssrc,
                mode        = 'play',
            )),
        ))

    async def _stream_options(self, req: Request) -> object:
        return req.reply(headers = {
            'Public': ', '.join([
                'DESCRIBE',
                'SETUP',
                'PLAY',
                'PAUSE',
                'TEARDOWN',
            ]),
        })

    async def _stream_teardown(self, req: Request) -> object:
        print(req)
        return req.reply(body = 'hello, world')

    async def _stream_describe(self, req: Request) -> object:
        sdp = SDP()
        ctype = SDP.content_type

        # check accepted content type
        if req.headers.get('accept', ctype) != ctype:
            raise RTSP.Error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'invalid Accept header')

        # construct the SDP object
        sdp.add(SDP.Version(0))
        sdp.add(SDP.Media('video', self.port, 1, 'RTP/AVP', 96))
        sdp.add(SDP.Attribute.lit('rtcp', str(self.port + 1)))
        sdp.add(SDP.Attribute.lit('rtpmap', '96 H265/90000'))
        sdp.add(SDP.Attribute.lit('control', '?m=video'))
        sdp.add(SDP.Attribute.lit('framerate', '16.67'))
        sdp.add(SDP.Media('audio', self.port, 1, 'RTP/AVP', 97))
        sdp.add(SDP.Attribute.lit('rtcp', str(self.port + 1)))
        sdp.add(SDP.Attribute.lit('rtpmap', '97 PCMA-WB/16000'))
        sdp.add(SDP.Attribute.lit('control', '?m=audio'))
        return sdp

    __routes__: dict[tuple[str, str], Callable[['StreamingServer', Request], Coroutine[object, object, object]]] = {
        ('GET'      , '/snapshot'): _image_take,
        ('PLAY'     , '/stream'  ): _stream_play,
        ('PAUSE'    , '/stream'  ): _stream_pause,
        ('SETUP'    , '/stream'  ): _stream_setup,
        ('OPTIONS'  , '/stream'  ): _stream_options,
        ('TEARDOWN' , '/stream'  ): _stream_teardown,
        ('DESCRIBE' , '/stream'  ): _stream_describe,
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
        path = req.uri.path
        func = self.__routes__.get((req.method, path))

        # not found, remove the trailing slash (if possible), and try again
        if func is None:
            if path != '/' and path.endswith('/'):
                func = self.__routes__.get((req.method, path.rstrip('/')))

        # still not found, report 404 Not Found
        if func is None:
            return req.reply(status = HTTPStatus.NOT_FOUND, body = 'not found')

        # call the handler
        try:
            resp = await func(self, req)
        except RTSP.Error as e:
            resp = req.reply(status = e.status, body = e.body, headers = e.headers)

        # ensure it's a valid response
        if isinstance(resp, Response):
            return resp
        else:
            return req.reply(body = resp)

    async def _handle_requests(self, rd: StreamReader, addr: tuple[str, int]) -> AsyncIterator[tuple[Request | None, Response]]:
        try:
            async for msg in RTSP.iter(rd, addr):
                if isinstance(msg, Request):
                    yield msg, await self._handle_request(msg)
                elif isinstance(msg, RTSP.Error):
                    yield None, msg
                else:
                    raise SystemError('unreachable')
        except Exception:
            self.log.exception('Unhandled exception when handling requests:')
            yield None, Response(status = HTTPStatus.INTERNAL_SERVER_ERROR, body = 'internal error')

    async def _handle_connection(self, rd: StreamReader, wr: StreamWriter):
        addr = wr.transport.get_extra_info('peername')
        host, _ = addr

        # connection address should be unique
        if addr in self.conn:
            raise SystemError('connection address confliction')

        # log the connection
        self.log.debug('New connection from %s:%d.', *addr)
        self.conn[addr] = []

        # handle every request
        try:
            async for req, resp in self._handle_requests(rd, addr):
                self._log_request(req, resp, host)
                RTSP.write(wr, resp)
        except (EOFError, ConnectionResetError):
            pass
        except Exception:
            self.log.exception('Unhandled exception:')

        # kill all the stream sink associated with this connection
        for sink in self.conn.pop(addr):
            self.sink.pop(sink.ssid)
            self.link.pop((sink.addr, sink.rtp_port))
            self.link.pop((sink.addr, sink.rtcp_port))
            await sink.stop()

        # close the writer
        self.log.debug('Connection from %s:%d closed.', *addr)
        wr.close()

    async def _handle_rtp(self, rtp: UdpSocket):
        while True:
            print('RTP', await rtp.recvfrom())

    async def _handle_rtcp(self, rtcp: UdpSocket):
        while True:
            print('RTCP', await rtcp.recvfrom())

    async def run(self):
        rtp  = await UdpSocket.new(local_addr = (self.host, self.port))
        rtcp = await UdpSocket.new(local_addr = (self.host, self.port + 1))
        rtsp = await asyncio.start_server(self._handle_connection, self.host, self.port)

        # start the RTSP server
        futs = [
            asyncio.get_running_loop().create_task(rtsp.serve_forever()),
            asyncio.get_running_loop().create_task(self._handle_rtp(rtp)),
            asyncio.get_running_loop().create_task(self._handle_rtcp(rtcp)),
        ]

        # wait for it to terminate
        self.log.info('HTTP Server at %s:%d', self.host, self.port)
        await asyncio.gather(*futs)

async def main():
    await StreamingServer().run()

if __name__ == '__main__':
    logs.setup()
    asyncio.run(main())
