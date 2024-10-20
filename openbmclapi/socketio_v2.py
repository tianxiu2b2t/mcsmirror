import asyncio
import base64
from dataclasses import dataclass
import enum
import json
import random
import time
from typing import Any, Callable, Optional
from logger import logger
import web

sysrand = random.SystemRandom()

class SocketIOType(enum.Enum):
    CONNECT = 0
    DISCONNECT = 1
    PING = 2
    PONG = 3
    MESSAGE = 4
    UPGRADE = 5
    NOOP = 6
    ERROR = 7

class SocketIOPacketType(enum.Enum):
    AUTH = 0
    EVENT = 2
    ACK = 3

@dataclass
class Packet:
    type: SocketIOType = SocketIOType.MESSAGE
    ptype: Optional[SocketIOPacketType] = None
    namespace: Optional[str] = None
    data: Optional[str | Any] = None
    id: Optional[int] = None
    attachments: Optional[int] = None
    binary: Optional[bytes] = None

    def encode(self) -> str:
        resp = str(self.type.value)
        if self.namespace is not None and self.namespace != '/':
            resp += self.namespace + ","
        if self.type == SocketIOType.MESSAGE and self.ptype is not None:
            resp += str(self.ptype.value)
        if self.id is not None:
            resp += str(self.id)
        resp += json.dumps(self.data, separators=(',', ':'))
        return resp
                

    @staticmethod
    def decode(data: str) -> 'Packet':
        packet = Packet()
        packet.type = SocketIOType(int(data[0]))
        data = data[1:]
        if len(data) >= 1 and data[0] == '/':
            packet.namespace, data = data[1:].split(',', 1)
        if len(data) >= 2 and data[0:2].isdigit():
            packet.ptype = SocketIOPacketType(int(data[0:1]))
            data = data[1:]
        if len(data) >= 1 and data[0].isdigit():
            str_num = ""
            for i, s in enumerate(data):
                if s.isdigit():
                    str_num += s
                else:
                    packet.id = int(str_num)
                    data = data[i:]
                    break
        try:
            packet.data = json.loads(data) if data else None
        except:
            packet.data = data
            logger.debug(data)
        return packet
@dataclass
class SocketIOData:
    event: str
    sid: str
    data: Any
    address: str

class SocketIOServer:
    sequence_number = 0
    def __init__(self, 
        app: web.Application, 
        transports: list[str] = [
            "websocket"
        ],
        ping_interval: float = 25,
        ping_timeout: float = 20
    ):
        self.app = app
        self.transports = transports
        self.handlers: dict[str, Callable[[SocketIOData], Any]] = {}
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.sid_ws: dict[str, web.WebSocket] = {}

        @app.get("/socket.io")
        async def _(request: web.Request, transport: list[str], timing: web.RequestTiming):
            if transport not in self.transports:
                return web.Response(
                    status=403,
                )
            if transport == "websocket" and request.is_websocket:
                await request.ws.handshake()(request, timing)
                request.ws.start()
                sid = await self.accept_ws(request)
                frame: web.WebSocketReadFrame
                self.sid_ws[sid] = request.ws
                task = asyncio.create_task(self.ping(sid))
                try:
                    async for frame in request.ws:
                        if frame is None:
                            break
                        if frame.opcode == web.WebSocketOPCode.CLOSE:
                            break
                        await self.recvive_packet(sid, request, frame)
                except:
                    logger.traceback()
                del self.sid_ws[sid]
                try:
                    task.cancel()
                except:
                    ...

    async def ping(self, sid: str):
        while sid in self.sid_ws:
            await self.send_packet(sid, Packet(SocketIOType.PING))
            await asyncio.sleep(self.ping_interval)

    def generate_sid(self):
        id = base64.b64encode(
            sysrand.randbytes(16) + self.sequence_number.to_bytes(3, 'big'))
        self.sequence_number = (self.sequence_number + 1) & 0xffffff
        return id.decode('utf-8').replace('/', '_').replace('+', '-')

    def connect_configuration(self, sid: str):
        return Packet(
            SocketIOType.CONNECT,
            data={
                "sid": sid,
                "upgrades": [],
                "pingInterval": int(self.ping_interval * 1000),
                "pingTimeout": int(self.ping_timeout * 1000)
            }
        )
    
    async def send_packet(self, sid: str, packet: Packet):
        if sid in self.sid_ws:
            await self.ws_send_packet(self.sid_ws[sid], packet)

    async def ws_send_packet(self, ws: web.WebSocket, packet: Packet):
        pkt = packet.encode()
        if isinstance(pkt, str):
            pkt = [pkt]
        for pk in pkt:
            if isinstance(pk, str):
                await ws.send_text(pk)
            else:
                await ws.send_binary(pk)
    
    async def recvive_packet(self, sid: str, request: web.Request, data: web.WebSocketReadFrame):
        packet = Packet.decode(data.data.decode("utf-8"))
        await self.handle(sid, request, packet)

    async def handle(self, sid: str, request: web.Request, packet: Packet):
        event = None
        packet_data = packet.data
        if packet.type == SocketIOType.CONNECT:
            event = "disconnect"
        elif packet.type == SocketIOType.MESSAGE:
            if isinstance(packet_data, dict):
                event = "connect"
            elif isinstance(packet_data, list):
                if len(packet_data) == 0:
                    logger.debug(packet_data)
                elif len(packet_data) == 1:
                    event = packet_data[0]
                elif len(packet_data) >= 2:
                    if len(packet_data) >= 3:
                        logger.debug(packet_data)
                    event, packet_data = packet_data[0], packet_data[1]
        elif packet.type == SocketIOType.PONG:
            return
        if event is None or event not in self.handlers:
            logger.debug(event, packet)
            return
        
        handler = self.handlers[event]
        data = SocketIOData(
            event,
            sid, 
            packet_data, 
            request.address
        )
        if asyncio.iscoroutinefunction(handler):
            res = await handler(data)
        else:
            res = handler(data)
        if packet.type == SocketIOType.MESSAGE:
            if res is not None:
                ack_packet = Packet(SocketIOType.MESSAGE, data=res, id=packet.id)
                if event != "connect":
                    ack_packet.ptype = SocketIOPacketType.ACK
                    ack_packet.data = [ack_packet.data]
                await self.ws_send_packet(request.ws, ack_packet)
        

    async def accept_ws(self, request: web.Request) -> str:
        sid = self.generate_sid()
        await self.ws_send_packet(request.ws, self.connect_configuration(sid))
        return sid
        

    def on(self, event: str):
        def decorator(func: Callable[[SocketIOData], Any]):
            self.handlers[event] = func
            return func
        return decorator