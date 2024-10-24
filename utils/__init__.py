import asyncio
import base64
from collections import deque
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import re
import socket
import time
from typing import Any, Callable, Optional

from core import logger


class CountLock:
    def __init__(self):
        self.count = 0
        self.fut: deque[asyncio.Future] = deque()
    
    async def wait(self):
        if self.count >= 1:
            fut = asyncio.get_running_loop().create_future()
            self.fut.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self.fut:
                    self.fut.remove(fut)
    
    def acquire(self):
        self.count += 1
    
    def release(self):
        self.count -= 1
        if self.count == 0 and self.fut:
            self._wake()

    def _wake(self):
        if self.fut:
            for fut in self.fut:
                try:
                    fut.set_result(None)
                except asyncio.InvalidStateError:
                    pass
            self.fut.clear()

    @property
    def locked(self):
        return self.count > 0
    
class SemaphoreLock:
    def __init__(self, value: int):
        self._value = value
        self.count = 0
        self.fut: deque[asyncio.Future] = deque()
    
    async def wait(self):
        if self.count >= 1:
            fut = asyncio.get_running_loop().create_future()
            self.fut.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self.fut:
                    self.fut.remove(fut)
    
    async def acquire(self):
        if self.count >= self._value:
            await self.wait()
        self.count += 1
    
    def release(self):
        self.count -= 1
        if self.count == 0 and self.fut:
            self._wake()

    def _wake(self):
        if self.fut:
            for fut in self.fut:
                try:
                    fut.set_result(None)
                except asyncio.InvalidStateError:
                    pass
            self.fut.clear()

    @property
    def locked(self):
        return self.count > 0
    
    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False
    
    def set_value(self, value: int):
        self._value = value
    
                    
    

class FileStream:
    def __init__(self, data: bytes) -> None:
        self.data = io.BytesIO(data)
    
    def read_long(self): 
        result, shift = 0, 0
        while True:
            byte = ord(self.data.read(1))
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return (result >> 1) ^ -(result & 1)
    def read_string(self):
        return self.data.read(self.read_long()).decode('utf-8')
    
def check_sign(hash: str, secret: str, s: str, e: str) -> bool:
    if not s or not e:
        return False
    sign = (
        base64.urlsafe_b64encode(
            hashlib.sha1(f"{secret}{hash}{e}".encode()).digest()
        )
        .decode()
        .rstrip("=")
    )
    return sign == s and time.time() - 300 < int(e, 36)

def equals_hash(origin: str, content: bytes):
    return get_hash_hexdigest(origin, content) == origin

def get_hash_hexdigest(origin: str, content: bytes):
    h = hashlib.sha1
    if len(origin) == 32:
        h = hashlib.md5
    return h(content).hexdigest()

def pause():
    try:
        input("Press Enter to continue...")
    except KeyboardInterrupt:
        exit()
        pass

def get_runtime():
    from core import _START_RUNTIME
    return time.monotonic() - _START_RUNTIME

def parse_isotime_to_timestamp(iso_format: str) -> float:
    return datetime.fromisoformat(iso_format).timestamp()

def is_service_error(body: Any) -> bool:
    if isinstance(body, (bytes, str)):
        try:
            body = json.loads(body)
        except:
            return False
    return isinstance(body, dict) and "$isServiceError" in body and body["$isServiceError"]

def parse_service_error(body: Any) -> Optional['ServiceError']:
    if isinstance(body, (bytes, str)):
        try:
            body = json.loads(body)
        except:
            return None
    if not isinstance(body, dict) or "$isServiceError" not in body or not body["$isServiceError"]:
        return None
    return ServiceError(
        body["code"],
        body["httpCode"],
        body["message"],
        body["name"]
    )

def raise_service_error(body: Any, key: str = "utils.error.service_error", **kwargs) -> bool:
    service = parse_service_error(body)
    if service is None:
        return False
    logger.terror(key, code=service.code, httpCode=service.httpCode, message=service.message, name=service.name, **kwargs)
    return True



@dataclass
class ServiceError:
    code: str
    httpCode: int
    message: str
    name: str

SSL_PROTOCOLS = {
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
} # SSL ?

@dataclass
class ClientHandshakeInfo:
    version: int
    sni: Optional[str]

    @property
    def version_name(self):
        return SSL_PROTOCOLS.get(self.version, "Unknown")
    
    def __str__(self):
        return f"ClientHandshakeInfo(version={self.version_name}, sni={self.sni})"
    def __repr__(self):
        return str(self)

def get_client_handshake_info(data: bytes):
    info = ClientHandshakeInfo(-1, None)
    try:
        buffer = io.BytesIO(data)
        if not buffer.read(1):
            raise
        info.version = int.from_bytes(buffer.read(2), 'big')
        if not buffer.read(40):
            raise
        buffer.read(buffer.read(1)[0])
        buffer.read(int.from_bytes(buffer.read(2), 'big'))
        buffer.read(buffer.read(1)[0])
        extensions_length = int.from_bytes(buffer.read(2), 'big')
        current_extension_cur = 0
        extensions = []
        while current_extension_cur < extensions_length:
            extension_type = int.from_bytes(buffer.read(2), 'big')
            extension_length = int.from_bytes(buffer.read(2), 'big')
            extension_data = buffer.read(extension_length)
            if extension_type == 0x00: # SNI
                info.sni = extension_data[5:].decode("utf-8")
            extensions.append((extension_type, extension_data))
            current_extension_cur += extension_length + 4
    except:
        ...
    return info

def decimal_to_base36(decimal_number):
    if decimal_number == 0:
        return '0'
    base36_digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    base36 = ""
    while decimal_number > 0:
        decimal_number, remainder = divmod(decimal_number, 36)
        base36 = base36_digits[remainder] + base36
    return base36

IPV6_COMPILE = re.compile(r"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$")
IPV4_COMPILE = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def is_ipv4(ip: str) -> bool:
    return IPV4_COMPILE.match(ip) is not None


def retry(max_retries=3, delay=1):
    def decorator(func):
        async def wrapper_retry(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return asyncio.get_event_loop().run_in_executor(None, lambda: func(*args, **kwargs))
                except Exception as e:
                    retries += 1
                    await asyncio.sleep(delay)
            raise Exception(f"Function {func.__name__} failed after {max_retries} retries.")
        return wrapper_retry
    return decorator


@dataclass
class ServiceData:
    causedBy: str
    httpCode: Optional[int] = None
    data: Optional[Any] = None
    cause: Optional[Exception] = None

class ServiceException(Exception):
    def __init__(
        self,
        code: int,
        httpCode: int = 500,
        data: Optional[ServiceData] = None,
        name: str = "ServiceError",
        isServiceError: bool = True
    ):
        super().__init__(
            f"cause: {data.causedBy}" if data is not None else self.__class__.__name__
        )
        self.cause = self 
        self.code = code
        self.data = data
        self.httpCode = httpCode
        self.name = name
        self.isServiceError = isServiceError
        if data is not None:
            self.httpCode = self.httpCode or data.httpCode
            self.cause = self.cause or data.cause

    @property
    def message(self):
        return str(self.cause)

    
    def to_json(self): 
        return {
            "$isServiceError": self.isServiceError,
            "code": self.code,
            "message": self.message,
            "name": self.name.upper(),
            "data": self.data,
            "httpCode": self.httpCode,
            "cause": str(self.cause)
        }