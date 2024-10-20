import asyncio
import base64
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, is_dataclass
import datetime
import enum
import hashlib
import inspect
import io
import json
from pathlib import Path
import re
import struct
import tempfile
import time
from typing import Any, AsyncGenerator, AsyncIterable, AsyncIterator, Coroutine, Generator, Iterable, Iterator, Optional, Union, Callable, get_args, get_type_hints
import uuid

from bson import ObjectId

from const import const
from logger import logger
import scheduler
import units
import urllib.parse as urlparse
from utils import decimal_to_base36
from web import filetype
from web.compresstor import compress

STATUS_CODE = {
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    207: 'Multi-Status',
    208: 'Already Reported',
    226: 'IM Used',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Payload Too Large',
    414: 'URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Range Not Satisfiable',
    417: 'Expectation Failed',
    418: 'I\'m a teapot',
    421: 'Misdirected Request',
    422: 'Unprocessable Entity',
    423: 'Locked',
    424: 'Failed Dependency',
    426: 'Upgrade Required',
    428: 'Precondition Required',
    429: 'Too Many Requests',
    431: 'Request Header Fields Too Large',
    451: 'Unavailable For Legal Reasons',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
    506: 'Variant Also Negotiates',
    507: 'Insufficient Storage',
    508: 'Loop Detected',
    510: 'Not Extended',
    511: 'Network Authentication Required',
    101: 'Switching Protocols',
    102: 'Processing',
    103: 'Early Hints',
}

CONTENT_TYPES = Union[
    str, 
    
    int,
    bool,
    float,

    list,
    tuple,
    dict,
    set,
    
    Generator[bytes | str, None, None],
    Iterable [bytes | str],
    Iterator [bytes | str],

    AsyncGenerator[bytes | str, None],
    AsyncIterable [bytes | str],
    AsyncIterator [bytes | str],


    bytes, 
    bytearray, 
    memoryview,
    Callable,
    Coroutine,

    'Response',
    Path,
    None
]

@dataclass
class Client:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    _peername: Optional[tuple[str, int]] = None
    tls: bool = False
    _closed: bool = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.writer.close()

    def write(self, data: bytes):
        self.writer.write(data)
    
    async def drain(self):
        await self.writer.drain()
    
    async def read(self, size: int = 1024) -> bytes:
        return await self.reader.read(size)
    
    async def read_until(self, separator: bytes) -> bytes:
        return await self.reader.readuntil(separator)
    
    async def read_exactly(self, size: int) -> bytes:
        return await self.reader.readexactly(size)
    
    async def read_line(self) -> bytes:
        return await self.reader.readline()
    
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            self.close()
        except:
            ...

    @property
    def closed(self):
        return self._closed

    @property
    def peername(self):
        if self._peername is None:
            self._peername = self.writer.get_extra_info('peername')
        return self._peername or ("", 0)

@dataclass
class ProxyClient:
    origin: Client
    target: Client
    buffer: bytes = b''

    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        try:
            self.origin.close()
            self.target.close()
        except:
            ...
    
    def is_closing(self):
        return self.origin.writer.is_closing() or self.target.writer.is_closing()

    async def forward(self, c: Client, s: Client):
        while not self.is_closing():
            data = await c.read(const.io_buffer)
            if not data:
                break
            s.write(data)
            await s.drain()
        c.close()
        s.close()

    async def forward_all(self):
        self.target.write(self.buffer)
        await self.target.drain()
        self.buffer = b''
        try:
            await asyncio.gather(*[
                self.forward(self.origin, self.target),
                self.forward(self.target, self.origin)
            ])
        except:
            ...

class RequestTiming:
    def start(self):
        self.start_time = time.monotonic_ns()

    def __enter__(self):
        self.start()
        return self

    def stop(self):
        if hasattr(self, "end"):
            return
        self.end = time.monotonic_ns()
        self.duration = self.end - self.start_time

    def print(self, request: 'Request', response: 'Response'):
        if not hasattr(self, "end"):
            return
        logger.info(
            request.host,
            "|",
            self.get_format_time(4).rjust(14),
            "|",
            request.method.ljust(9),
            str(response.status).rjust(3),
            "|",
            request.address,
            "|",
            request.raw_path,
            "-",
            request.user_agent
        )

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    def get_time(self):
        return self.duration
    
    def get_format_time(self, round: int = 2):
        return units.format_count_time(self.duration, round)

class Application:
    def __init__(self, root_hostname: str, subdomains: list[str], port: int) -> None:
        self.root_hostname = root_hostname
        self.subdomains = subdomains
        self.port = port
        self._routers: deque[Router] = deque(
            [
                Router()
            ]
        )
        self.before_middles: list[RouteFunction] = []
        self.after_middles: list[RouteFunction] = []
    
    def get_route(self, request: 'Request'):
        method = request.method
        path = request.path
        if request.is_websocket:
            method = "WEBSOCKET"
        for router in self._routers:
            match_route = router.get_route(method, path)
            if match_route is not None:
                return match_route
        if request.is_websocket:
            method = "GET"
        for router in self._routers:
            match_route = router.get_route(method, path)
            if match_route is not None:
                return match_route
    
    def get_mount(self, path: str):
        for router in self._routers:
            match_route = router.get_mount(path)
            if match_route is not None:
                return match_route

    async def handle(self, request: 'Request'):
        with RequestTiming() as timing:
            result = inspect._empty
            match_route = self.get_route(request)
            if match_route is not None:
                result = await self.handle_route(request, match_route, timing)
            if match_route is None or result is None:
                match_route = True
                result = self.get_mount(request.path)
            if result == inspect._empty:
                result = None
            result = Response(result)
            await result(request, timing)

    async def handle_route(self, request: 'Request', match_route: 'RouteResult', timing: RequestTiming):
        matched, route = match_route.matched, match_route.route
        parameters = {}
        args = route.parameters.route_handler_args
        url_parameters = matched.groupdict()
        query_parameters = request.query
        handler = route.func
        json_parameters = None
        for arg in args:
            name, types = arg.name, arg.type_annotation
            for type in types:
                if name in parameters:
                    break
                if type == Request:
                    parameters[name] = request
                elif type == RequestTiming:
                    parameters[name] = timing
                elif type == Form and request.method == 'POST' and request.is_form:
                    request.form = await Form.parse(request)
                    parameters[name] = request.form
                elif type == WebSocket and request.method == "GET":
                    parameters[name] = request.ws
                    await request.ws.handshake()(request, timing)
                    request.ws.start()
                else:
                    if name in url_parameters:
                        parameters[name] = url_parameters[name]
                    elif name in query_parameters:
                        parameters[name] = query_parameters[name]
                        if list not in types:
                            parameters[name] = parameters[name][0]
                    elif name not in parameters:
                        if json_parameters is None and request.is_json:
                            json_parameters = await request.json()
                        if json_parameters is not None and name in json_parameters:
                            parameters[name] = json_parameters[name]
                    elif arg.default != inspect._empty:
                        parameters[name] = arg.default
                    
                    if name in parameters:
                        parameters[name] = fix_value(parameters[name], types)
        if request.is_websocket:
            ...
        if asyncio.iscoroutinefunction(handler):
            result = await handler(**parameters)
        else:
            result = await asyncio.get_event_loop().run_in_executor(None, lambda: handler(**parameters))
        return result

    def get(self, path: str):
        return self.add_route('GET', path)
    
    def post(self, path: str):
        return self.add_route('POST', path)

    def head(self, path: str):
        return self.add_route('HEAD', path)
    
    def websocket(self, path: str):
        return self.add_route('WEBSOCKET', path)
    
    def patch(self, path: str):
        return self.add_route('PATCH', path)
    
    def put(self, path: str):
        return self.add_route('PUT', path)
    
    def delete(self, path: str):
        return self.add_route('DELETE', path)

    def options(self, path: str):
        return self.add_route('OPTIONS', path)

    def mount(self, url: str, path: Path):
        return self._routers[0].mount(url, path)

    def add_route(self, method: str, path: str):
        return self._routers[0]._route(method, path)

    def add_router(self, router: 'Router'):
        self._routers.append(router)
        return router

class Response:
    def __init__(
        self, 
        content: CONTENT_TYPES = None,
        content_type: Optional[str] = None,
        headers: Optional['Header'] = None,
        cookies: Optional[list['Cookie']] = None,
        status: int = 200,
    ):
        self.content: CONTENT_TYPES = content
        self.content_type = content_type
        self.cookies = cookies or []
        self.headers = headers or Header({})
        self.status = status

    def __repr__(self) -> str:
        return f'<Response {self.status} {self.headers}>'
    
    async def get_content(self):
        if self.content is None:
            return memoryview(b'')
        if isinstance(self.content, Response):
            t = self.content
            for k in (param.name for param in inspect.signature(Response).parameters.values()
                    if not param.default == inspect.Parameter.empty 
                    and not inspect.isbuiltin(param.default)
            ):
                setattr(self, k, getattr(t, k))
            self.content = t.content
            return await self.get_content()
        if isinstance(self.content, Path):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'application/octet-stream'
            return self.content
        if isinstance(self.content, str):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'text/plain'
            return memoryview(self.content.encode('utf-8'))
        if isinstance(self.content, bytes):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'application/octet-stream'
            return memoryview(self.content)
        if isinstance(self.content, ObjectId):
            self.content_type = self.content_type or 'application/json'
            return memoryview(json_dumps(self.content).encode('utf-8'))
        if isinstance(self.content, memoryview):
            self.content_type = self.content_type or filetype.guess_mime(self.content.tobytes()) or 'application/octet-stream'
            return memoryview(self.content.tobytes())
        if isinstance(self.content, (list, set, tuple, dict, bool, int, float)) or is_dataclass(self.content):
            self.content_type = self.content_type or 'application/json'
            return memoryview(json_dumps(self.content).encode('utf-8'))
        if isinstance(self.content, (AsyncGenerator, AsyncIterable, AsyncIterator, Generator, Iterable, Iterator)):
            self.content_type = self.content_type or 'application/octet-stream'
            return self.content
        if isinstance(self.content, bytearray):
            self.content_type = self.content_type or 'application/octet-stream'
            return memoryview(self.content)
        if asyncio.iscoroutine(self.content):
            self.content = await self.content
            return await self.get_content()
        if isinstance(self.content, Callable):
            self.content = await asyncio.get_event_loop().run_in_executor(None, self.content)
            return await self.get_content()
        if inspect.isgenerator(self.content):
            self.content = async_generator(self.content)
            return await self.get_content()
        return self.content
    
    async def __call__(self, request: 'Request', timing: RequestTiming):
        content = await self.get_content()
        # if content instanceof Any, warning
        extra_headers = Header({})
        length = None
        if isinstance(content, Path):
            stat = content.stat()
            length = stat.st_size
            if self.content_type is None or ("text/" not in self.content_type and "application/json" not in self.content_type):
                extra_headers['Content-Disposition'] = f'attachment; filename="{content.name}"'
            etag = f'"{hashlib.md5(f"{content.name};{stat.st_mtime_ns};{stat.st_ctime_ns};{stat.st_size}".encode()).hexdigest()}"'
            if request.headers.get("If-None-Match", "") == etag and self.status == 200:
                self.status = 304
                content = memoryview(b'')
            extra_headers["ETag"] = etag
            extra_headers["Last-Modified"] = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%a, %d %b %Y %H:%M:%S GMT')
            #extra_headers["Cache-Control"] = "public, max-age=31536000"
        elif isinstance(content, memoryview):
            length = len(content)
        elif Any in type(content).__mro__:
            logger.debug(f'content is Any, {content}')
        
        # headers, to response headers
        headers = self.headers.copy()
        headers.update(extra_headers)
        headers.update({
            "Server": "TTB-Network",
            "Date": datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
        })
        start_bytes, end_bytes = request.range
        if length is not None:
            if end_bytes is not None:
                headers["Content-Range"] = f"bytes {start_bytes}-{end_bytes}/{length}"
                headers["Accept-Ranges"] = "bytes"
                length = end_bytes - start_bytes + 1
            else:
                headers["Content-Length"] = length
            if isinstance(content, memoryview):
                compression = compress(content.tobytes(), request.accept_encoding)
                if compression.compressed:
                    headers["Content-Encoding"] = compression.compression
                    headers["Content-Length"] = compression.length
                    content = memoryview(compression.data)
                content = memoryview(content.tobytes())[start_bytes:start_bytes + length]
            headers["Content-Type"] = self.content_type
        else:
            headers["Transfer-Encoding"] = "chunked"
    
        byte_header = f'{request.http_protocol} {self.status} {(STATUS_CODE[self.status] if self.status in STATUS_CODE else STATUS_CODE[int(self.status / 100) * 100])}\r\n'
        self.add_content_type_encoding(headers)
        for k, v in headers.items():
            if v is None:
                continue
            byte_header += f'{k}: {v}\r\n'
        byte_header += '\r\n'
        # cookie
        if self.cookies:
            byte_header += '\r\n'.join([cookie.to_response_header() for cookie in self.cookies]) + '\r\n'
        request.client.write(byte_header.encode('utf-8'))
        if isinstance(content, memoryview):
            request.client.write(content)
            await request.client.drain()
        elif inspect.isasyncgen(content) or inspect.isgenerator(content):
            if inspect.isgenerator(content):
                content = async_generator(content)
            async for chunk in content:
                request.client.write(send_chunk(chunk))
            request.client.write(send_chunk(b''))
            await request.client.drain()
        elif isinstance(content, Path):
            with content.open("rb") as f:
                await asyncio.get_event_loop().sendfile(
                    request.client.writer.transport,
                    f,
                    start_bytes,
                    end_bytes
                )
        else:
            logger.debug(content)
        if not hasattr(timing, "end"):
            timing.stop()
            timing.print(request, self)
        return self
    
    def add_content_type_encoding(self, headers: 'Header'):
        if 'Content-Type' not in headers:
            return 
        content_type = headers['Content-Type'] or ""
        if 'charset=' in content_type:
            return
        if 'text/' in content_type or 'application/json' in content_type:
            headers['Content-Type'] += '; charset=utf-8'

class LocationResponse(Response):
    def __init__(self, location: str, status: int = 302):
        super().__init__(status=status)
        self.headers['Location'] = location


@dataclass
class Cookie:
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[int] = None
    secure: Optional[bool] = None
    http_only: Optional[bool] = None
    same_site: Optional[str] = None

    def to_response_header(self):
        return f'{self.name}={self.value};' + \
            (f' domain={self.domain};' if self.domain else '') + \
            (f' path={self.path};' if self.path else '') + \
            (f' expires={self.expires};' if self.expires else '') + \
            (f' max-age={self.max_age};' if self.max_age else '') + \
            (f' secure;' if self.secure else '') + \
            (f' httponly;' if self.http_only else '') + \
            (f' samesite={self.same_site};' if self.same_site else '')

class Header:
    def __init__(self, data: Any):
        self._data = self.parse(data)
    def parse(self, data: Any):
        if isinstance(data, bytes):
            values = {}
            for line in data.split(b'\r\n'):
                if not line:
                    break
                k, v = line.split(b': ', 1)
                values[k.decode('utf-8')] = v.decode('utf-8')
            return values
        elif isinstance(data, dict):
            return data
        elif isinstance(data, Header):
            return data._data.copy()
        else:
            raise TypeError('Header must be bytes or dict')

    def __repr__(self) -> str:
        return f'<Header {self._data}>'

    def _get_key(self, key: str) -> str:
        keys = {
            k.lower(): k
            for k in self._data.keys()
        }
        return keys.get(key.lower(), key)

    def __getitem__(self, key: str) -> str:
        return self._data[self._get_key(key)]

    def __setitem__(self, key: str, value: Any) -> None:
        return self.set(key, value)

    def __delitem__(self, key: str) -> None:
        del self._data[self._get_key(key)]

    def __contains__(self, key: str) -> bool:
        return self._get_key(key) in self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(self._get_key(key), default)

    def set(self, key: str, value: Any) -> None:
        origin_key = self._get_key(key)
        if origin_key in self._data:
            del self._data[self._get_key(key)]
        self._data[key] = value

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()
    
    def values(self):
        return self._data.values()
    
    def copy(self):
        return Header(self._data.copy())
    
    def update(self, object: Any):
        if isinstance(object, Header):
            object = object._data
        if isinstance(object, dict):
            for k, v in object.items():
                self.set(k, v)
        else:
            raise TypeError('Header must be bytes or dict')

@dataclass
class Request:
    client: Client
    method: str
    raw_path: str
    http_protocol: str
    headers: Header
    body: bytes
    _peername: str
    form: Optional['Form'] = None

    def __post_init__(self):
        self._parse_path()
        self._current_length = 0
        if self.is_form:
            self.form = None
        if self.is_websocket:
            self.ws = WebSocket(
                self
            )

    @property
    def address(self):
        return self._peername

    @property
    def host(self) -> str:
        return self.headers.get("Host")
    
    @property
    def hostname(self):
        return self.host.rsplit(":", 1)[0]

    @property
    def user_agent(self):
        return self.headers.get('User-Agent')
    
    @property
    def range(self):
        start_bytes, end_bytes = 0, None
        if not self.headers.get('Range'):
            return start_bytes, end_bytes
        range = self.headers.get('Range').split('=')[1]
        if '-' in range:
            start_bytes, end_bytes = map(int, range.split('-'))
        else:
            start_bytes = int(range)
        return start_bytes, end_bytes
    
    @property
    def accept_encoding(self):
        return self.headers.get('Accept-Encoding', "")

    @property
    def length(self):
        return int(self.headers.get("Content-Length", 0))

    @property
    def path(self):
        return self._path
    
    @property
    def query(self):
        return self._query

    def _parse_path(self):
        if not hasattr(self, "_path") or not hasattr(self, "_query"):
            parsed = urlparse.urlparse(self.raw_path)
            self._path = urlparse.unquote(parsed.path)
            self._query = urlparse.parse_qs(parsed.query)

    @property
    def is_websocket(self):
        return self.headers.get('Upgrade', '').lower() == 'websocket' and self.headers.get('Connection', '').lower() == 'upgrade'

    @property
    def is_form(self):
        return self.headers.get('Content-Type', '').lower().startswith('multipart/form-data')

    @property
    def is_json(self):
        return self.headers.get('Content-Type', '').lower() in ('application/json', 'application/x-www-form-urlencoded')
    
    @property
    def is_www_form(self):
        return self.headers.get('Content-Type', '').lower().startswith('application/x-www-form-urlencoded')

    async def json(self):
        content = await self.read()
        if self.is_www_form:
            return dict(urlparse.parse_qsl(content.decode('utf-8')))
        return json.loads(content)

    async def read(self, size: int = -1):
        if size == -1:
            size = self.length
        size = min(size, self.length - self._current_length)
        data = b''
        if self.body:
            data, self.body = self.body[:size], self.body[size:]
        else:
            data = await self.client.reader.read(size)
        self._current_length += len(data)
        return data


class WebSocketOPCode(enum.Enum):
    TEXT = 1
    BINARY = 2
    CLOSE = 8
    PING = 9
    PONG = 10
    CONTINUATION = 0

@dataclass
class WebSocketReadFrame:
    opcode: WebSocketOPCode
    data: bytes

class WebSocket:
    def __init__(self, request: 'Request'):
        self.request = request
        self.client = request.client
        self.frames: defaultdict[WebSocketOPCode, deque[WebSocketReadFrame]] = defaultdict(deque)
        self.keepalive = None

    def handshake(self):
        return Response(
            "",
            status=101,
            headers=Header({
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Accept": base64.b64encode(
                    hashlib.sha1(
                        (self.request.headers.get('Sec-WebSocket-Key') + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")
                    ).digest()
                ).decode(),
            })
        )
    
    def start(self):
        self.request.method = "WEBSOCKET"
        self.keepalive = asyncio.create_task(self._keepalive())
    
    async def _keepalive(self):
        while True:
            await asyncio.sleep(10)
            await self.raw_send(
                WebSocketOPCode.PING,
                f"{decimal_to_base36(int(time.time() * 1000.0))}".encode("utf-8")
            )

    def __del__(self):
        if self.keepalive is not None and not self.keepalive.cancelled():
            self.keepalive.cancel()

    def _build_frame(
        self, content: memoryview, opcode: WebSocketOPCode, status: int = 0
    ):
        data = io.BytesIO()
        close = opcode == WebSocketOPCode.CLOSE
        payload = len(content)
        head1 = 0b10000000 | opcode.value
        head2 = 0
        if not close:
            first = True
            cur = 0
            while cur < payload:
                header = 0b10000000 if payload <= cur + 65535 else 0
                if first:
                    head1 = header | opcode.value
                    first = False
                else:
                    head1 = header | WebSocketOPCode.CONTINUATION.value
                length = min(payload - cur, 65535)
                if length < 126:
                    data.write(struct.pack("!BB", head1, head2 | length))
                elif length < 65536:
                    data.write(struct.pack("!BBH", head1, head2 | 126, length))
                else:
                    data.write(struct.pack("!BBQ", head1, head2 | 127, length))
                data.write(content[cur : length + cur])
                cur += length
        else:
            if payload > 123:
                content = content[:123]
                payload = len(content)
            data.write(struct.pack("!BB", 0b10000000 | opcode.value, 0 | payload + 2))
            data.write(struct.pack("!H", status))
            data.write(content)
        return data

    async def raw_send(self, opcode: WebSocketOPCode, data: bytes):
        if self.client.closed:
            return
        self.client.write(self._build_frame(memoryview(data), opcode).getbuffer())
        await self.client.drain()

    async def send_text(self, data: str):
        await self.raw_send(WebSocketOPCode.TEXT, data.encode('utf-8'))
    
    async def send_binary(self, data: bytes):
        await self.raw_send(WebSocketOPCode.BINARY, data)

    async def send_json(self, data: Any):
        await self.send_text(json.dumps(data))
    
    async def close(self, status: int = 1000, reason: str = ""):
        await self.raw_send(WebSocketOPCode.CLOSE, struct.pack("!H", status) + reason.encode('utf-8'))
        await self.client.drain()

    async def _read_frame(self):
        try:
            head1, head2 = struct.unpack("!BB", await self.client.read_exactly(2))
            fin = bool(head1 & 0b10000000)
            mask = bool((head1 & 0x80) >> 7)
            opcode = head1 & 0b00001111
            length = head2 & 0b01111111
            mask_bits = b""
            if length == 126:
                length, = struct.unpack("!H", await self.client.read_exactly(2))
            elif length == 127:
                length, = struct.unpack("!Q", await self.client.read_exactly(8))
            if mask:
                mask_bits = await self.client.read_exactly(4)
            data = await self.client.read_exactly(length)
            content = io.BytesIO()
            if (mask and mask_bits is None) or (
                mask and mask_bits and len(mask_bits) != 4
            ):
                raise ValueError("mask must contain 4 bytes")
            if mask and mask_bits is not None:
                content.write(
                    b"".join(
                        (
                            (data[i] ^ mask_bits[i % 4]).to_bytes()
                            for i in range(len(data))
                        )
                    )
                )
            else:
                content.write(data)
            if opcode == WebSocketOPCode.CLOSE.value:
                self.client.close()
            if not fin:
                frame = await self._read_frame()
                if (
                    not frame
                    or frame.opcode != WebSocketOPCode.CONTINUATION
                    and len(content.getbuffer()) + len(frame.data) != length
                ):
                    raise ValueError(
                        "opcode doesn't match {} {}".format(opcode, length)
                    )
                content.write(frame.data)
            return WebSocketReadFrame(
                WebSocketOPCode(
                    opcode
                ),
                content.getvalue(),
            )
        except:
            await self.close()
            return None
        
    async def read_frame(self):
        frame = await self._read_frame()
        if frame is None:
            return None
        if frame.opcode == WebSocketOPCode.PING:
            await self.raw_send(WebSocketOPCode.PONG, frame.data)
            return await self.read_frame()
        if frame.opcode == WebSocketOPCode.PONG:
            return await self.read_frame()
        return frame
    
    async def read(self, opcode: Optional[WebSocketOPCode] = None):
        frame = await self.read_frame()
        if frame is None:
            return
        if opcode is None:
            return frame
        self.frames[frame.opcode].append(frame)
        if len(self.frames[opcode]) >= 1:
            return self.frames[opcode].popleft().data
        return await self.read(opcode)
    
    async def read_text(self):
        return (await self.read(WebSocketOPCode.TEXT)).decode('utf-8') # type: ignore

    async def read_bytes(self):
        return await self.read(WebSocketOPCode.BINARY)
    
    async def read_json(self):
        return json.loads(await self.read_text()) # type: ignore
    
    async def __aiter__(self):
        while not self.client.closed:
            yield await self.read()

@dataclass
class Form:
    boundary: str
    files: dict[str, list[tempfile._TemporaryFileWrapper | io.BytesIO]]
    fields: dict[str, list[tempfile._TemporaryFileWrapper | io.BytesIO]]

    @staticmethod
    async def parse(
        request: Request,
        io_buffer = 256
    ):
        async def read_chunks() -> AsyncGenerator[bytes, None]:
            yield b"\r\n"
            while (data := await request.read(io_buffer)):
                if not data:
                    break
                yield data
        
        def process_part(
            part: bytes,
        ):
            nonlocal temp_file
            if b"\r\n\r\n" not in part:
                if temp_file is not None:
                    temp_file.write(part.rstrip(b))
                return
            headers, body = part.split(b"\r\n\r\n", 1)
            headers = {
                key: value
                for key, value in (
                    (
                        urlparse.unquote(a.groupdict()["key"]),
                        urlparse.unquote(a.groupdict()["value"]),
                    )
                    for a in re.finditer(
                        r'(?P<key>\w+)="(?P<value>[^"\\]*(\\.[^"\\]*)*)"',
                        headers.decode("utf-8"),
                    )
                )
            }
            if temp_file is None:
                if "filename" in headers:
                    temp_file = tempfile.TemporaryFile()
                else:
                    temp_file = io.BytesIO()
            temp_file.write(body)
            if "filename" in headers:
                files[headers["filename"]].append(temp_file)
            else:
                fields[headers["name"]].append(temp_file)
        files: defaultdict[str, list[tempfile._TemporaryFileWrapper | io.BytesIO]] = defaultdict(list)
        fields: defaultdict[str, list[tempfile._TemporaryFileWrapper | io.BytesIO]] = defaultdict(list)
                
        boundary: str = request.headers.get("Content-Type").split("=")[1]
        b = b"\r\n--" + boundary.encode("utf-8")
        buffer: list[bytes] = []
        temp_file = None
        async for chunk in read_chunks():
            buffer.append(chunk)
            while b in b"".join(buffer):
                t = [t for t in (b"".join(buffer)).split(b) if t]
                if temp_file is not None:
                    process_part(t[0])
                    temp_file.seek(0)
                    temp_file = None
                    t = t[1:]
                part, tm = t[0], b"" if len(t) == 1 else b.join(t[1:])
                buffer = [tm]
                process_part(part)
            while len(buffer) >= 2 and temp_file is not None:
                temp_file.write(b"".join(buffer[:-1]))
                buffer = buffer[-1:]
            await asyncio.sleep(0.001)
        if temp_file is not None:
            process_part(b"".join(buffer))
            temp_file.seek(0)
            temp_file = None
        return Form(boundary, files, fields)


@dataclass  
class RouteHandlerArg:  
    name: str  
    type_annotation: list[Any]
    default: Any = inspect._empty 
  
class RouteHandlerArgs:  
    def __init__(self, handler) -> None:  
        self.handler = handler
        self.handler_args = inspect.getfullargspec(handler)  
        annotations_params = get_type_hints(handler)  
        defaults = self.handler_args.defaults or ()
        offset = len(self.handler_args.args) - len(defaults)
        self.route_handler_args = [  
            RouteHandlerArg(name=param, type_annotation=self._get_annotations(annotations_params.get(param, Any)), default=defaults[i - offset] if i - offset >= 0 else inspect._empty)  
            for i, param in enumerate(self.handler_args.args)  
        ]  
        self.return_annotation = self.handler_args.annotations.get("return", Any)

    def _get_annotations(self, value: Any):
        if hasattr(value, "__origin__") and value.__origin__ is Union:
            return list(get_args(value))
        return [value]

    def __str__(self) -> str:
        return f"<{self.handler}: {self.route_handler_args}>"
    
@dataclass
class RouteFunction:
    path: str
    func: Callable

    def __post_init__(self):
        self.parameters = RouteHandlerArgs(self.func)
        self.path = self.path.strip("/")
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        self.is_url_params = self.path.count("{") == self.path.count("}") >= 1
        self.re_path = re.compile("^" + self._replace_path(self.path) + "[/]?$")

    def _replace_path(self, path: str):
        # if {:url:} in path, replace it and not [^/]*
        if path.endswith("/{:url:}"):
            path = path.replace("/{:url:}", r"/(?P<url>.*)")
        elif path.endswith("{:url:}"):
            path = path.replace("{:url:}", r"(?P<url>.*)")
        return path.replace("{", "(?P<").replace("}", ">[^/]*)")
            

    def __repr__(self) -> str:
        return f"RouteFunction(path={self.path}, func={self.func.__name__}, is_url_params={self.is_url_params}, re_path={self.re_path})"

@dataclass
class RouteResult:
    matched: re.Match
    route: RouteFunction

class Router:
    def __init__(self, prefix: str = "/"):
        self.prefix = prefix
        self.routes: defaultdict[str, list[RouteFunction]] = defaultdict(list)
        self.mounts: defaultdict[str, Path] = defaultdict(Path)

    def _route(self, method: str, path: str):
        def decorator(func: Callable):
            self.routes[method.upper()].append(RouteFunction(
                path=path,
                func=func
            ))
            self.routes[method.upper()].sort(key=lambda x: len(x.path))
            self.routes[method.upper()].sort(key=lambda x: x.is_url_params)
            return func
        return decorator
    
    def get(self, path: str):
        return self._route("GET", path)

    def post(self, path: str):
        return self._route("POST", path)
    
    def put(self, path: str):
        return self._route("PUT", path)
    
    def delete(self, path: str):
        return self._route("DELETE", path)
    
    def options(self, path: str):
        return self._route("OPTIONS", path)
    
    def head(self, path: str):
        return self._route("HEAD", path)
    
    def patch(self, path: str):
        return self._route("PATCH", path)
    
    def trace(self, path: str):
        return self._route("TRACE", path)
    
    def websocket(self, path: str):
        return self._route("WEBSOCKET", path)
        
    def get_route(self, method: str, path: str) -> Optional[RouteResult]:
        if self.prefix and path.startswith(self.prefix):
            path = path[len(self.prefix):]
            if not path.startswith("/"):
                path = "/" + path
        for route in self.routes[method.upper()]:
            m = route.re_path.match(path)
            if m is not None:
                return RouteResult(
                    m,
                    route
                )
        return None
    
    def mount(self, path: str, root: Path):
        self.mounts[path] = root

    def get_mount(self, path: str) -> Any:
        if self.prefix and path.startswith(self.prefix):
            path = path[len(self.prefix):]
            if not path.startswith("/"):
                path = "/" + path
        root = None
        for mount_path, mount_root in sorted(self.mounts.items(), key=lambda x: len(x[0]), reverse=True):
            if path.startswith(mount_path):
                root = mount_root
                path = path[len(mount_path):].lstrip("/")
                break
        if root is None:
            return Response(
                status=404,
                content="Not Found",
            )
        file = root / path
        if not str(file).startswith(str(root)):
            return Response(
                status=403,
                content="Forbidden",
            )
        if file.is_file():
            return file
        return Response(
            status=404,
            content="Not Found",
        )

class Protocol(enum.Enum):
    HTTP = 'HTTP'
    UNKNOWN = 'UNKNOWN'

def get_protocol(buffer: bytes):
    try:
        if b"HTTP/1." in buffer.split(b"\r\n", 1)[0].split(b" ")[2]:
            return Protocol.HTTP
    except:
        ...
    return Protocol.UNKNOWN

def parse_request(client: Client, buffer: bytes):
    protocol = get_protocol(buffer)
    if protocol == Protocol.UNKNOWN:
        return None
    else:
        try:
            bytes_header, bytes_body = buffer.split(b"\r\n\r\n", 1)
            first_header, bytes_header = bytes_header.split(b"\r\n", 1)
            method, raw_path, http_protocol = first_header.decode("utf-8").split(" ", 2)
            headers = Header(bytes_header)
            return Request(client, method, raw_path, http_protocol, headers, bytes_body, client.peername[0])
        except:
            logger.traceback(f"parse request error: {buffer}")
            return None
        
class HTTPResponseJSONEncoder(json.JSONEncoder):
    def default(self, o):  
        if isinstance(o, datetime.datetime):  
            return o.isoformat()  
        if isinstance(o, uuid.UUID):
            return str(o)
        if is_dataclass(o):
            return asdict(o) # type: ignore
        if isinstance(o, (tuple, set, Generator)):
            return list(o)
        if isinstance(o, Callable):
            return o()
        if asyncio.iscoroutinefunction(o) or asyncio.iscoroutine(o):
            return asyncio.run_coroutine_threadsafe(o, asyncio.get_event_loop())
        if isinstance(o, ObjectId):
            return str(o)
        try:
            return json.JSONEncoder.default(self, o)
        except:
            logger.traceback(f"json encode error: {o}", type(o))
            return str(o)
        
json_encoder = HTTPResponseJSONEncoder(separators=(",", ":"))

def json_dumps(obj: Any):
    return json_encoder.encode(obj)

def send_chunk(data: bytes | str):
    if isinstance(data, str):
        data = data.encode("utf-8")
    # length (16) + data
    return b'\r\n'.join((f"{len(data):x}".encode("utf-8"), data, b""))

def fix_value(value: Any, type: list[type]):
    if bool in type:
        if value == "true":
            return True
        elif value == "false":
            return False
    if int in type:
        return int(value)
    if float in type:
        return float(value)
    if str in type:
        return value
    return value

async def async_generator(sync_generator: Generator):
    for item in sync_generator:
        await asyncio.sleep(0)
        yield item