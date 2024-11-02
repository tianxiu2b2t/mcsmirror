import asyncio
import base64
from collections import defaultdict
from dataclasses import dataclass
import datetime
import enum
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import random
import re
import tempfile
import time
from typing import Any, Optional

import aiohttp
import bson
import database
import env
from logger import logger
import service
import units
import utils
import web
from .socketio_v2 import SocketIOData, SocketIOServer
import pyzstd as zstd

@dataclass
class ClusterInfo:
    id: bson.ObjectId
    name: str
    endpoint_host: Optional[str] = None
    endpoint_port: Optional[int] = None
    endpoint_proto: Optional[str] = None
    endpoint_byoc: Optional[bool] = None
    bandwidth: Optional[int] = 0
    measure: Optional[int] = 0
    downReason: Optional[str] = None
    downTime: Optional[int] = None
    flavor_runtime: Optional[str] = None
    flavor_storage: Optional[str] = None
    fullSize: Optional[bool] = False
    shared: Optional[int] = None
    

    @property
    def createAt(self):
        return self.id.generation_time
    
@dataclass
class ClusterToken:
    clusterId: str
    iat: int

    @property
    def id(self):
        return bson.ObjectId(self.clusterId)
    
    @property
    def expiredAt(self):
        return self.iat / 1000.0 + TOKEN_TTL
    
    @property
    def expired(self):
        return self.expiredAt < time.time()
    
    @property
    def valid(self):
        return not self.expired

@dataclass
class StorageFile:
    id: bson.ObjectId
    hash: str
    size: int
    path: str
        
class WrapperTempFile:
    def __init__(self, dir: Any):
        self.tmp = tempfile.NamedTemporaryFile(
            dir=dir,
            suffix=utils.decimal_to_base36(time.monotonic_ns()) + "_" + utils.decimal_to_base36(time.perf_counter_ns()),
            delete=False
        )
        self.path = Path(self.tmp.name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tmp.close()
        if self.path.exists():
            self.path.unlink()

    @property
    def origin(self):
        return self.tmp

class Storage:
    def __init__(self):
        self.files_collection = db.get_collection("files")
        self.root = Path(os.environ["OPENBMCLAPI_STORAGE_ROOT"])
        self.root.mkdir(parents=True, exist_ok=True)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.hash_type = hashlib.md5
        self.cache: dict[str, StorageFile | None] = {}


    async def upload(self, path: str, reader: asyncio.StreamReader):
        hash = self.hash_type()
        with WrapperTempFile(
            dir=self.tmp
        ) as tmp:
            tmp_path = tmp.path
            f = tmp.origin
            length: int = 0
            while True:
                chunk = await reader.read(UPLOAD_BUFFER)
                if not chunk:
                    break
                f.write(chunk)
                hash.update(chunk)
                length += len(chunk)
                await asyncio.sleep(0)
            f.flush()
            f.seek(0)
            file_path = self.get_hash_path(hash.hexdigest())
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if not file_path.exists():
                f.close()
                tmp_path.rename(self.get_hash_path(hash.hexdigest())) # type: ignore
            q = await self.files_collection.find_one({
                "hash": hash.hexdigest(),
                "path": path
            })
            if q is not None:
                return StorageFile(
                    id=q["_id"],
                    hash=hash.hexdigest(),
                    size=q["size"],
                    path=path
                )
            r = await self.files_collection.insert_one({
                "path": path,
                "hash": hash.hexdigest(),
                "size": length,
            })
            file = StorageFile(
                id=r.inserted_id,
                hash=hash.hexdigest(),
                size=length,
                path=path
            )
            self.cache[path] = file
            return file
        
    async def upload_from_bytes(self, path: str, data: bytes | memoryview | bytearray):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await self.upload(path, reader)
    
    async def upload_from_bytes_io(self, path: str, data: io.BytesIO):
        return await self.upload_from_bytes(path, data.getbuffer())
    
    async def upload_from_file(self, path: str, origin: Path):
        reader = asyncio.StreamReader()
        async def task_read():
            with open(origin, "rb") as f:
                while True:
                    chunk = f.read(UPLOAD_BUFFER)
                    if not chunk:
                        break
                    reader.feed_data(chunk)
                    await asyncio.sleep(0)
            reader.feed_eof()
        tasks = [
            asyncio.create_task(task_read()),
            asyncio.create_task(self.upload(path, reader))
        ]
        return (await asyncio.gather(*tasks))[1]
    
    async def get_files_generator(self, paths: list[str]):
        paths = [Storage.fix_path(p) for p in paths]
        async for i in self.files_collection.find({
            "path": {"$in": paths}
        }):
            yield StorageFile(
                id=i["_id"],
                hash=i["hash"],
                size=i["size"],
                path=i["path"]
            )

    async def get_files(self, paths: list[str]):
        return [i async for i in self.get_files_generator(paths)]

    async def get_file(self, path: str):
        path = Storage.fix_path(path)
        if path in self.cache:
            return self.cache[path]
        r = await self.files_collection.find_one({
            "path": path
        })
        if r is None:
            self.cache[path] = None
            return None
        return StorageFile(
            id=r["_id"],
            hash=r["hash"],
            size=r["size"],
            path=r["path"]
        )

    @staticmethod
    def fix_path(path: str):
        return path.replace("\\", "/")
    
    def get_hash_path(self, hash: str):
        return self.root / hash[:2] / hash

    async def delete(self, path: str):
        path = Storage.fix_path(path)
        file_hash = await self.get_file(path)
        file_hash = file_hash.hash if file_hash is not None else None
        if file_hash is not None:
            c = await self.files_collection.count_documents({
                "hash": file_hash
            })
            print(path, c)
            if c == 1:
                file_path = self.get_hash_path(file_hash)
                if file_path.exists():
                    file_path.unlink()
        await self.files_collection.delete_one({
            "path": path
        })
        self.cache[path] = None

@dataclass
class DownloadLink:
    createdAt: float
    valid: bool
    cluster: Optional[str] = None
    hash: Optional[str] = None
    secret: Optional[str] = None
    endpoint: Optional['ClusterEndpoint'] = None

    @property
    def origin(self):
        return self.endpoint.url # type: ignore
    
    @property
    def url(self):
        sign = self.sign
        return f"{self.origin}{self.path}?s={sign.sign}&e={sign.expires}"
    
    def url_params(self, name: str):
        return self.url + "&name=" + name

    @property
    def path(self):
        return f"/download/{self.hash}"
    
    @property
    def sign(self):
        return get_sign(
            self.hash, # type: ignore
            self.secret # type: ignore
        )

class AvroBuffer:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

class AvroOutput(AvroBuffer):
    def __init__(self):
        self.buffer = io.BytesIO()
    
    def write_long(self, value: int):
        value = (value << 1) ^ (value >> 63)
        while True:
            byte = value & 0x7F
            value >>= 7
            if value == 0:
                self.buffer.write(byte.to_bytes())
                break
            else:
                self.buffer.write((byte | 0x80).to_bytes())

    def write_string(self, value: str):
        data = value.encode("utf-8")
        self.write_long(len(data))
        self.buffer.write(data)

    def getbuffer(self):
        return self.buffer.getbuffer()
    
    def getvalue(self):
        return self.buffer.getvalue()

@dataclass
class ClusterMeasureResult:
    results: list['ClusterMeasure']

    def __post_init__(self):
        if len(self.results) > 1:
            self.results = self.results[1:]

    @property
    def high_speed(self):
        return max(self.results, key=lambda x: x.speed_mbps).speed_mbps

    @property
    def low_speed(self):
        return min(self.results, key=lambda x: x.speed_mbps).speed_mbps

    @property
    def avg_speed(self):
        return sum(x.speed_mbps for x in self.results) / len(self.results)
    
@dataclass
class ClusterMeasure:
    duration: float
    bytes: int

    @property
    def speed(self):
        if self.duration == 0:
            return 0
        return self.bytes * 8 / self.duration
    
    @property
    def speed_mbps(self):
        return self.speed / 1000000

@dataclass
class FileListShared:
    expireAt: float
    files: list[StorageFile]

class ClusterLoggerAction(enum.Enum):
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    MEASURE = "MEASURE"
    FILE_CHECK = "FILE_CHECK"
    WARDEN = "WARDEN"

@dataclass
class ClusterEndpoint:
    host: str
    port: int
    real_host: Optional[str] = None

    @property
    def url(self):
        return f"https://{self.real_host or self.host}:{self.port}"

@dataclass
class CheckFileResult:
    origin_hash: str
    origin_size: int
    target_hash: str
    target_size: int

    @property
    def hash(self):
        return self.target_hash == self.origin_hash
    
    @property
    def size(self):
        return self.target_size == self.origin_size

@dataclass
class CheckFile:
    file_hash: str
    content_hash: str
    end: int
    start: int = 0
    partial: bool = False

    @property
    def size(self):
        return self.end - self.start + 1

class ClusterManager:
    def __init__(self) -> None:
        self.cluster_collection = db.get_collection("clusters")
        self.statistics_collection = db.get_collection("statistics")
        self.logger_collection = db.get_collection("logger")
        self.clusters_secret: dict[str, str] = {}
        self.files_shared: dict[int, FileListShared] = {}
        self.socketio_clusters: dict[str, str] = {}
        self.clusters_endpoint: dict[str, ClusterEndpoint] = {}

    def start(self):
        asyncio.create_task(self.task_warden())

    async def get_cluster_endpoint(self, id: str):
        if id in self.clusters_endpoint:
            return self.clusters_endpoint[id]
        r = await self.cluster_collection.find_one({
            "_id": bson.ObjectId(id)
        })
        if r is None:
            return None
        self.clusters_endpoint[id] = ClusterEndpoint(
            host=r.get("endpoint_host"),
            port=r.get("endpoint_port"),
        )
        if not r["endpoint_byoc"]:
            self.clusters_endpoint[id].real_host = f"{id}.openbmclapi.{env.get_env('OPENBMCLAPI_DOMAIN')}"
        return self.clusters_endpoint[id]

    async def create_cluster(self, name: str):
        secret = hashlib.md5(random.getrandbits(128).to_bytes(16, "big")).hexdigest()
        r = await self.cluster_collection.insert_one({
            "name": name,
            "secret": secret
        })
        return {
            "id": r.inserted_id,
            "secret": secret,
            "name": name
        }
    
    async def get_cluster_secret(self, id: str):
        if id in self.clusters_secret:
            return self.clusters_secret[id]
        r = await self.cluster_collection.find_one({
            "_id": bson.ObjectId(id)
        })
        if r is None:
            return None
        self.clusters_secret[id] = r["secret"]
        return r["secret"]
    
    async def get_cluster_info(self, id: str):
        r = await self.cluster_collection.find_one({
            "_id": bson.ObjectId(id)
        })
        if r is None:
            return None
        return ClusterInfo(
            id=r["_id"],
            name=r["name"],
            endpoint_host=r.get("endpoint_host"),
            endpoint_port=r.get("endpoint_port"),
            endpoint_byoc=r.get("endpoint_byoc"),
            endpoint_proto="https",
            bandwidth=r.get("bandwidth"),
            measure=r.get("measure"),
            downReason=r.get("downReason"),
            downTime=r.get("downTime"),
            flavor_runtime=r.get("flavor_runtime"),
            flavor_storage=r.get("flavor_storage"),
            fullSize=r.get("shared", -1) == -1,
            shared=r.get("shared")
        )
    
    async def get_file(self, hash: str):
        ...

    async def get_files(self, shared: int = -1, last_modified: float = 0):
        size = 0
        files = []
        # reverse id
        async for r in storage.files_collection.find().sort({
            "_id": -1
        }):
            file = StorageFile(
                id=r["_id"],
                hash=r["hash"],
                size=r["size"],
                path=r["path"]
            )
            if shared == -1 or shared * SHARED > size + file.size:
                size += file.size
                if last_modified > file.id.generation_time.timestamp():
                    continue
                files.append(file)
        
        self.files_shared[shared] = FileListShared(
            expireAt=time.time() + 600,
            files=files
        )

        return self.files_shared[shared]
    
    async def setup_route(self, app: web.Application):
        agent = web.Router(
            "/openbmclapi-agent"
        )
        clusters = web.Router(
            "/openbmclapi"
        )
        download = web.Router(
            "/"
        )
        @agent.get("/challenge")
        async def _(clusterId: str):
            return {
                "challenge": hashlib.md5(random.getrandbits(128).to_bytes(16, "big")).hexdigest(),
            }
        
        @agent.post("/token")
        async def _(clusterId: str, challenge: str, signature: str):
            cluster_secret = await self.get_cluster_secret(clusterId)
            if cluster_secret is None:
                return web.Response(
                    status=404,
                )
            if hmac.new(cluster_secret.encode("utf-8"), challenge.encode("utf-8"), hashlib.sha256).hexdigest() != signature:
                return web.Response(
                    status=403,
                )
            return {
                "token": JWT({
                    "clusterId": clusterId,
                    "iat": timestamp(),
                }, cluster_secret).encode(),
                "ttl": TOKEN_TTL * 1000
            }
        
        @clusters.get("/files")
        async def _(request: web.Request, lastModified: float = 0):
            last_modified = lastModified / 1000.0
            token = get_cluster_info_from_jwt(request.headers.get("Authorization", "").removeprefix("Bearer "))
            if token is None or token.expired:
                return web.Response(
                    status=401
                )
            cluster = await self.get_cluster_info(str(token.id))
            if cluster is None:
                return web.Response(
                    status=404
                )
            files = await self.get_files(
                -1 if cluster.fullSize else cluster.shared or -1, last_modified
            )
            buffer = AvroOutput()
            count = 0
            size = 0
            for file in files.files:
                count += 1
                size += file.size
                buffer.write_string(file.path)
                buffer.write_string(file.hash)
                buffer.write_long(file.size)
                buffer.write_long(int(file.id.generation_time.timestamp() * 1000))

            logger.debug(f"Cluster [{cluster.id}] Files Count [{count}] Size [{units.format_bytes(size)}] lastModified [{last_modified}]")
            output = AvroOutput()
            output.write_long(count)
            output.buffer.write(buffer.getvalue())
            return web.Response(
                status=204 if count == 0 else 200,
                content=zstd.compress(output.getbuffer()) if count != 0 else b'',
            )

        @clusters.get("/configuration")
        async def _():
            return {
                "sync": {
                    "source": "center",
                    "concurrency": 50
                }
            }
        
        @clusters.get("/download/{hash}")
        async def _(hash: str):
            # all letters and number
            if re.match(r"^[a-fA-F0-9]+$", hash) is None:
                return web.Response(
                    status=400
                )
            return storage.get_hash_path(hash)

        @download.get("/{:url:}")
        async def _(url: str):
            path = f"/{url}"
            link = await downloads.get_download_link(path)
            if link.valid:
                return web.LocationResponse(
                    link.url
                )
            file = await storage.get_file(path)
            if file is None:
                return web.Response(
                    status=404
                )
            local_path = storage.get_hash_path(file.hash)
            return local_path
        


        app.add_router(clusters)
        app.add_router(agent)
        app.add_router(download)

    async def logger_cluster(self, clusterId: str, action: ClusterLoggerAction, reason: dict[str, Any] | str, trust: int = 0):
        collection = db.get_collection("logger")
        await collection.insert_one({
            "clusterId": bson.ObjectId(clusterId),
            "action": action.value,
            "reason": reason,
            "trust": trust
        })
        if trust != 0:
            cluster: Any = await self.cluster_collection.find_one({
                "_id": bson.ObjectId(clusterId)
            })
            cluster_trust = 0
            if "trust" in cluster:
                cluster_trust = cluster["trust"]
            final_trust = min(TRUST_MAX, cluster_trust + trust)
            await self.cluster_collection.update_one({
                "_id": bson.ObjectId(clusterId)
            }, {
                "$set": {
                    "trust": final_trust
                }
            })

    async def task_warden(self):
        while True:
            s = random.randint(WARDEN_INTERVAL_MIN, WARDEN_INTERVAL_MAX)
            await asyncio.sleep(s)
            # get online clusters
            clusters = [
                cluster["_id"] async for cluster in self.cluster_collection.find({
                    "status": True,
                    "keep-alive": {
                        "$gte": datetime.datetime.now() - datetime.timedelta(seconds=KEEPALIVE * 2)
                    }
                })
            ]
            choiced = random.sample(clusters, min(len(clusters), WARDEN_COUNT))
            for cluster in choiced:
                results = await self.check_files(cluster, 2, "bmclapi-warden/1.0.0")
                not_matched = [
                    file for file in results if not file.size or not file.hash
                ]
                if len(not_matched) > 0:
                    await self.cluster_collection.update_one({
                        "_id": bson.ObjectId(cluster)
                    }, {
                        "$set": {
                            "status": False,
                            "downReason": "WARDEN"
                        }
                    })
                    await self.logger_cluster(cluster, ClusterLoggerAction.WARDEN, "WARDEN")
                else:
                    cls: Any = await self.cluster_collection.find_one({
                        "_id": bson.ObjectId(cluster)
                    })
                    trust = min(TRUST_MAX, cls.get("trust", 0) + 1)
                    await self.cluster_collection.update_one({
                        "_id": bson.ObjectId(cluster)
                    }, {
                        "$set": {
                            "trust": trust
                        }
                    })    

    async def measure_cluster(self, clusterId: str, endpoint: ClusterEndpoint, force: bool = False) -> list[ClusterMeasureResult]:
        results = [ClusterMeasureResult(
            [
                ClusterMeasure(0, 0)
            ]
        )]
        async def read_response(resp: aiohttp.ClientResponse):
            start = time.time()
            res = 0
            while time.time() - start < 1:
                data = await resp.content.read(1048576)
                res += len(data)
                if not data:
                    break
            return res, time.time() - start
    
        async with aiohttp.ClientSession(
            headers={
                "User-Agent": USER_AGENT
            },
            base_url=endpoint.url
        ) as session:
            for size in MEASURE_SIZE[0 : len(MEASURE_SIZE) if force else 1]:
                url = f"/measure/{size}"
                sign = get_sign(url, await self.get_cluster_secret(clusterId)) # type: ignore
                try:
                    real_length = size * 1048576
                    current_length = 0
                    res: defaultdict[int, list[ClusterMeasure]] = defaultdict(list)
                    async with session.get(
                        url,
                        params={
                            "s": sign.sign,
                            "e": sign.expires
                        },
                        headers={
                            "Accept-Encoding": ""
                        },
                    ) as resp:
                        while True:
                            length, dur = await read_response(resp)
                            if length == 0:
                                break
                            t = int(time.time())
                            res[t].append(ClusterMeasure(
                                dur, length
                            ))
                            current_length += length
                            if current_length >= real_length:
                                break
                        if current_length < real_length:
                            continue
                        merge = ClusterMeasureResult(
                            [
                                ClusterMeasure(
                                    sum([x.duration for x in t]),
                                    sum([x.bytes for x in t])
                                ) for t in res.values()
                            ]
                        )
                        last_speed = results[-1].high_speed
                        # 0.1% +-, if in 0.1% skip next measure
                        if last_speed == 0:
                            results.append(merge)
                            continue
                        if abs(merge.high_speed - last_speed) / last_speed > 0.01 and not force:
                            break
                        results.append(merge)
                except Exception as e:
                    logger.traceback(e)
                    ...
        return sorted(results, key=lambda x: x.high_speed, reverse=True)
                
    def get_cluster_id_from_socketio(self, sid: str):
        for cluster, session in self.socketio_clusters.items():
            if session == sid:
                return cluster
        return None

    async def setup_socketio(self, app: web.Application):
        self.sio = SocketIOServer(app)
        
        @self.sio.on("connect")
        async def _(client: SocketIOData):
            token = client.data["token"]
            cluster = get_cluster_info_from_jwt(token)
            if cluster is None or cluster.expired:
                return
            self.socketio_clusters[str(cluster.id)] = client.sid
            return {
                "sid": client.sid
            }
        @self.sio.on("request-cert")
        async def _(client: SocketIOData):
            clusterId = self.get_cluster_id_from_socketio(client.sid)
            if clusterId is None:
                return [
                    "无法找到节点",
                    None
                ]
            host = f"{clusterId}.openbmclapi.{env.get_env('OPENBMCLAPI_DOMAIN')}"
            async with service.acme_zerossl_v2.get_zerossl_instance(env.get_env("ZEROSSL_EMAIL"), env.get_env("OPENBMCLAPI_DOMAIN"), service.acme_zerossl_v2.TencentDNSRecord(
                env.get_env("TENCENT_KEY"),
                env.get_env("TENCENT_SECRET"),
            )) as instance:
                certificate = await instance.get_certificate([
                    host
                ])
                if certificate is None or not certificate.valid: # cert is not None and cert.valid
                    return [
                        "无法签发证书",
                        None
                    ]
                with open(certificate.ca, "r") as ca, open(certificate.key, "r") as key:
                    return [
                        None,
                        {
                            "_id": str(clusterId),
                            "clusterId": str(clusterId),
                            "cert": ca.read(),
                            "key": key.read(),
                            "expires": datetime.datetime.fromtimestamp(instance.get_certificate_expires([host])).isoformat()
                        }
                    ]
        @self.sio.on("enable")
        async def _(client: SocketIOData):
            clusterId = self.get_cluster_id_from_socketio(client.sid)
            if clusterId is None:
                return [
                    {
                        "message": "无法找到节点",
                    },
                    None
                ]
            data = client.data

            endpoint = ClusterEndpoint(
                data["host"],
                data["port"]
            )

            if not data["byoc"]:
                try:
                    await service.tencent.dnspod_add_record(
                        env.get_env("OPENBMCLAPI_DOMAIN"),
                        f"{clusterId}.openbmclapi",
                        "A" if utils.is_ipv4(endpoint.host) else "CNAME",
                        endpoint.host
                    )
                except:
                    ...
                finally:
                    endpoint.real_host = f"{clusterId}.openbmclapi.{env.get_env('OPENBMCLAPI_DOMAIN')}"
                await wait_domain(endpoint.real_host)

            await self.cluster_collection.update_one({
                "_id": bson.ObjectId(clusterId)
            }, {
                "$set": {
                    "endpoint_host": data["host"],
                    "endpoint_port": data["port"],
                    "endpoint_byoc": data["byoc"],
                    "version": data["version"],
                    "noFastEnable": data["noFastEnable"],
                    "flavor_storage": data["flavor"]["storage"],
                    "flavor_runtime": data["flavor"]["runtime"]
                }
            })

            measures = await self.measure_cluster(clusterId, endpoint)
            measure = measures[0]
            if measure.high_speed < MEASURE_LIMIT:
                await self.logger_cluster(
                    clusterId,
                    ClusterLoggerAction.MEASURE,
                    f"当前节点测速：{measure.high_speed} Mbps，低于 {MEASURE_LIMIT} Mbps",
                    -10
                )
                return [
                    {
                        "message": f"当前节点测速：{measure.high_speed} Mbps，低于 {MEASURE_LIMIT} Mbps",
                    },
                    None
                ]

            logger.info(f"Cluster [{clusterId}] Measure [{measure.high_speed}/{measure.avg_speed}/{measure.low_speed}]")

            results = await self.check_files(clusterId, 12)
            not_matched = [
                file for file in results if not file.size or not file.hash
            ]
            if len(not_matched) > 0:
                await self.logger_cluster(
                    clusterId,
                    ClusterLoggerAction.FILE_CHECK,
                    f"文件校验失败：{len(not_matched)} 个文件校验失败",
                    -10
                )
                return [
                    {
                        "message": f"文件校验失败：{len(not_matched)} 个文件校验失败，第一个是希望的是 [{not_matched[0].origin_hash}]，得到的是 [{not_matched[0].target_hash}]",
                    },
                    None
                ]

            await self.logger_cluster(
                clusterId,
                ClusterLoggerAction.ENABLE,
                f"节点启用成功，测速 {measure.high_speed} Mbps",
                0
            )

            await self.cluster_collection.update_one({
                "_id": bson.ObjectId(clusterId)
            }, {
                "$set": {
                    "status": True,
                    "uptime": datetime.datetime.now(),
                    "keep-alive": datetime.datetime.now(),
                    "endpoint_host": data["host"],
                    "endpoint_port": data["port"],
                    "endpoint_byoc": data["byoc"],
                    "version": data["version"],
                    "noFastEnable": data["noFastEnable"],
                    "flavor_storage": data["flavor"]["storage"],
                    "flavor_runtime": data["flavor"]["runtime"]
                }
            })
            return [
                None,
                True
            ]
        
        @self.sio.on("keep-alive")
        async def _(client: SocketIOData):
            clusterId = self.get_cluster_id_from_socketio(client.sid)
            if clusterId is None:
                return [
                    {
                        "message": "无法找到节点",
                    },
                    None
                ]
            
            data = client.data
            isotimestamp = datetime.datetime.now()
            hits, bytes = data["hits"], data["bytes"]
            hourtimestamp = datetime.datetime(isotimestamp.year, isotimestamp.month, isotimestamp.day, isotimestamp.hour)
            r = await self.cluster_collection.find_one({
                "_id": bson.ObjectId(clusterId),
                "status": True,
                "keep-alive": {
                    "$lte": isotimestamp + datetime.timedelta(seconds=KEEPALIVE_THRESHOLD),
                    "$gte": isotimestamp - datetime.timedelta(seconds=KEEPALIVE_THRESHOLD)
                }
            })
            if r is None:
                return [
                    False,
                    None
                ]
            await self.cluster_collection.update_one({
                "_id": bson.ObjectId(clusterId)
            }, {
                "$set": {
                    "keep-alive": datetime.datetime.now() + datetime.timedelta(seconds=KEEPALIVE)
                }
            })
            r = await self.statistics_collection.find_one({
                "date": hourtimestamp,
            })
            if r is None:
                await self.statistics_collection.insert_one({
                    "date": hourtimestamp,
                })
            await self.statistics_collection.update_one({
                "date": hourtimestamp,
            }, {
                "$inc": {
                    "hits": hits,
                    "bytes": bytes
                }
            })
            return [
                None,
                str(datetime.datetime.fromtimestamp(client.data["time"] / 1000.0))
            ]
        
        @self.sio.on("disable")
        async def _(client: SocketIOData):
            clusterId = self.get_cluster_id_from_socketio(client.sid)
            if clusterId is None:
                return [
                    {
                        "message": "无法找到节点",
                    },
                    None
                ]
            r: Any = await self.cluster_collection.find_one({
                "_id": bson.ObjectId(clusterId),
            })
            trust = 0
            if r["status"] and r["uptime"] + datetime.timedelta(seconds=ABORT_DOWN) >= datetime.datetime.now():
                trust = -50

            await self.logger_cluster(
                clusterId,
                ClusterLoggerAction.DISABLE,
                "节点下线",
                trust
            )
            await self.cluster_collection.update_one({
                "_id": bson.ObjectId(clusterId)
            }, {
                "$set": {
                    "status": False,
                    "downtime": datetime.datetime.now()
                }
            })
            return [
                None,
                True
            ]
            
    async def check_files(self, clusterId: str, limit: int = 1, ua: Optional[str] = None):
        ua = ua or USER_AGENT
        cluster = await self.cluster_collection.find_one({
            "_id": bson.ObjectId(clusterId),
        })
        if cluster is None:
            return []
        secret = cluster["secret"]
        endpoint = ClusterEndpoint(
            cluster["endpoint_host"],
            cluster["endpoint_port"]
        )
        if not cluster["endpoint_byoc"]:
            endpoint.real_host = f"{clusterId}.openbmclapi.{env.get_env('OPENBMCLAPI_DOMAIN')}"
        files = await self.get_files(-1 if cluster.get("fullSize") else cluster.get("shared") or -1)
        if len(files.files) == 0:
            return []
        choose = await asyncio.gather(*[asyncio.get_event_loop().run_in_executor(None, self.get_check_file_hash, file) for file in random.sample(files.files, limit)])
        
        async with aiohttp.ClientSession(
            endpoint.url
        ) as session:
            return await asyncio.gather(
                *(self.check_file(file, secret, session, ua) for file in choose)
            )

    def get_check_file_hash(self, file: StorageFile) -> CheckFile:
        partial = bool(random.randint(0, 1))
        path = storage.get_hash_path(file.hash)
        hash = hashlib.md5()
        start, end = 0, file.size - 1
        if partial:
            start = random.randint(0, file.size - 1)
            end = random.randint(start, file.size - 1)
        total_length = end - start + 1
        current_length = 0
        # start, end is http range
        # hash total_length
        with open(path, "rb") as f:
            f.seek(start)
            while current_length < total_length:
                chunk = f.read(min(1024, total_length - current_length))
                current_length += len(chunk)
                hash.update(chunk)
        return CheckFile(
            file.hash,
            hash.hexdigest(),
            end, start,
            partial
        )

    async def check_file(self, file: CheckFile, secret: str, session: aiohttp.ClientSession, ua: str):
        sign = get_sign(file.file_hash, secret)
        headers = {
            "User-Agent": ua,
        }
        total_length = file.size
        if file.partial:
            headers["Range"] = f"bytes={file.start}-{file.end}"
        async with session.get(f"/download/{file.file_hash}", 
            params={
                "s": sign.sign,
                "e": sign.expires,
            },
            headers=headers
        ) as resp:
            length = 0
            hash = hashlib.md5()
            async for chunk in resp.content.iter_chunked(1024):
                length += len(chunk)
                hash.update(chunk)
            return CheckFileResult(
                file.content_hash,
                total_length,
                hash.hexdigest(),
                length
            )
            

class ClusterDownload:
    def __init__(self):
        self.files: dict[str, DownloadLink] = {}

    async def get_download_link(self, path: str):
        file = self.files.get(path)
        if file is None:
            file = DownloadLink(
                0,
                False
            )
            self.files[path] = file
        elif file.valid and file.createdAt + 60 < time.time():
            file.valid = False
        if not file.valid and file.createdAt + 10 < time.time():
            file_hash = (await storage.get_file(path))
            if file_hash is None:
                file.createdAt = time.time()
                return file
            clusters = [
                cluster async for cluster in cluster_manager.cluster_collection.find({
                    "status": True,
                    "keep-alive": {"$gte": datetime.datetime.now() - datetime.timedelta(minutes=2)}
                })
            ]
            if len(clusters) == 0:
                file.createdAt = time.time()
                return file
            cluster = random.choice(clusters)
            endpoint = ClusterEndpoint(
                cluster["endpoint_host"],
                cluster["endpoint_port"]
            )
            if not cluster["endpoint_byoc"]:
                endpoint.real_host = f"{cluster['_id']}.openbmclapi.{env.get_env('OPENBMCLAPI_DOMAIN')}"
            file.cluster = str(cluster["_id"])
            file.valid = True
            file.hash = file_hash.hash
            file.secret = cluster["secret"]
            file.endpoint = endpoint
        return file

@dataclass
class ClusterSign:
    sign: str
    expires: str

class JWT:
    def __init__(self, 
            payload: Any, 
            secret: str,
            headers: dict[str, Any] = {
                "alg": "HS256",
                "typ": "JWT"
            }) -> None:
        self.secret = secret
        self.random_key = random.getrandbits(128).to_bytes(16, "big")
        self.headers = json.dumps(headers)
        self.signature_secret = hashlib.md5(self.random_key).hexdigest() + self.secret
        self.payload = json.dumps({
            "rk": hashlib.md5(self.random_key).hexdigest(),
            "payload": payload
        })

    def encode(self):
        header = base64.urlsafe_b64encode(self.headers.encode("utf-8")).decode("utf-8")
        payload = base64.urlsafe_b64encode(self.payload.encode("utf-8")).decode("utf-8")
        signature = base64.urlsafe_b64encode(hashlib.sha256((header + "." + payload).encode("utf-8") + self.signature_secret.encode("utf-8")).digest()).decode("utf-8")
        return header + "." + payload + "." + signature
    
    @staticmethod
    def decode(jwt: str):
        try:
            header, payload, signature = jwt.split(".")
            payload = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
            random_key = payload["rk"]
            return payload["payload"]
        except:
            return None
        
    @staticmethod
    def verify(jwt: str, secret: str):
        try:
            header, payload, signature = jwt.split(".")
            payload = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
            random_key = payload["rk"]
            signature_secret = hashlib.md5(random_key.encode("utf-8")).hexdigest() + secret
            return hashlib.sha256((header + "." + payload).encode("utf-8") + signature_secret.encode("utf-8")).hexdigest() == signature
        except:
            return False

db = database.client.get_database("mcsmirror_openbmclapi")
cluster_manager = ClusterManager()
storage = Storage()
CLUSTER_NAME_LIMIT = 16
TOKEN_TTL = 86400
UPLOAD_BUFFER = 1024 * 1024 * 10
SHARED = 1024 * 1024 * 1024
KEEPALIVE_THRESHOLD = 5
KEEPALIVE = 60
TRUST_MAX = 1000
USER_AGENT = "bmclapi-ctrl/1.0.0"
MEASURE_SIZE = [10, 20, 40, 60, 80, 100]
MEASURE_LIMIT = 5
ABORT_DOWN = 600
WARDEN_INTERVAL_MIN = 60
WARDEN_INTERVAL_MAX = 600
WARDEN_COUNT = 5
DOMAIN = env.get_env("DOMAIN")
HOST = f"openbmclapi.{DOMAIN}"
downloads = ClusterDownload()


async def init():
    app = await web.start_server(
        DOMAIN,
        [
            HOST
        ],
        9394,
        True
    )

    await cluster_manager.setup_route(app)
    await cluster_manager.setup_socketio(app)

    cluster_manager.start()

    @app.get("/backend/cluster/create")
    async def _(name: str, shared: Optional[int] = None):
        return await cluster_manager.create_cluster(name)

def timestamp():
    return int(time.time() * 1000)

def get_cluster_info_from_jwt(jwt: str):
    token = JWT.decode(jwt)
    if token is None:
        return None
    return ClusterToken(
        clusterId=token["clusterId"],
        iat=token["iat"]
    )

def get_sign(hash: str, secret: str):
    e = utils.decimal_to_base36(timestamp() + 300)
    s = base64.urlsafe_b64encode(
        hashlib.sha1(f"{secret}{hash}{e}".encode()).digest()
    ).decode().rstrip("=")
    return ClusterSign(
        sign=s,
        expires=e
    )

async def wait_domain(domain: str):
    value = service.dns.query_domain(domain)
    while not value:
        await asyncio.sleep(10)
        value = service.dns.query_domain(domain)
    return value