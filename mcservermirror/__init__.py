from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
import time
from typing import Any, Optional
import env
from logger import logger
import openbmclapi
import sync
import utils
import web
import urllib.parse as urlparse

@dataclass
class QueryCache[T]:
    data: T
    expire: float
    
    @property
    def expired(self):
        return time.monotonic() > self.expire

DOMAIN = env.get_env("DOMAIN")
HOST = f"sync-api.{DOMAIN}"
CACHE_TIMEOUT = 600
CACHE: defaultdict[str, QueryCache[Any]] = defaultdict(lambda: QueryCache(None, 0))

@dataclass
class Response:
    data: dict[str, Any] = field(default_factory=dict)
    message: str = "ok"
    code: int = 200

@dataclass
class Checksum:
    mode: str
    checksum: str

@dataclass
class CoreBuildInfo:
    name: str
    url: str
    syncTime: Optional[datetime] = None
    checksum: Optional[Checksum] = None

@dataclass
class CoreVersionInfo:
    name: str
    builds: list[CoreBuildInfo] = field(default_factory=list)

@dataclass
class CoreInfo:
    name: str
    versions: list[CoreVersionInfo] = field(default_factory=list)

@dataclass
class BuildInfo:
    name: str
    url: str
    hash: Optional[str] = None
    size: Optional[int] = None
    mtime: Optional[datetime] = None

@dataclass
class FileInfo:
    size: int
    downloaded: int
    total: int

def pop_id(data: dict):
    if "_id" in data:
        data.pop("_id")
    return data

async def query(
    core: Optional[str] = None,
    version: Optional[str] = None,
    build: Optional[str] = None
):
    query_data = {}
    cache_tag = ""
    for key, value in {
        "core": core,
        "version": version,
        "build": build
    }.items():
        if value is not None:
            cache_tag += urlparse.quote(f"{key}:{value}") + ";"
            query_data[key] = value
    cache = CACHE[cache_tag]
    
    if cache.expired:
        result = [
            i#pop_id(i)
            async for i in sync.cores_collection.find(query_data)
        ]
        cache.expire = time.monotonic() + CACHE_TIMEOUT
        cache.data = result
    
    return cache.data

async def setup_v2(app: web.Application):
    apiv2 = web.Router(
        "/api/v2"
    )

    @apiv2.get("/")
    async def _():
        if len(sync.sync_sources) == 0:
            return utils.ServiceException(404, "NoSyncSourceError").to_json()
        return {
            "version": "2.0",
            "sources": len(sync.sync_sources),
            "cores": [
                core.core for core in sync.sync_sources
            ]
        }

    @apiv2.get("/{core}")
    async def _(core: str):
        cache = CACHE[f"core_{core}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query(core=core)
            if len(q) == 0:
                cache.data = utils.ServiceException(404, "NoCoreError").to_json()
            else:
                cache.data = {
                    "core": core,
                    "versions": sorted(
                        set(
                            i["version"]
                            for i in q
                        ),
                        reverse=True
                    )
                }
        return cache.data

    @apiv2.get("/{core}/{version}")
    async def _(core: str, version: str):
        cache = CACHE[f"core_versions_{core}:{version}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query(core=core, version=version)
            if len(q) == 0:
                cache.data = utils.ServiceException(404, "NoVersionError").to_json()
            else:
                cache.data = {
                    "core": core,
                    "version": version,
                    "builds": sorted(set(
                        [
                            i["build"]
                            for i in q
                        ]
                    ), reverse=True)
                }
        return cache.data

    @apiv2.get("/{core}/{version}/{build}")
    async def _(core: str, version: str, build: str):
        cache = CACHE[f"core_versions_builds_{core}:{version}:{build}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query(core=core, version=version, build=build)
            if len(q) == 0:
                cache.data = utils.ServiceException(404, "NoBuildError").to_json()
            else:
                cache.data = {
                    "core": core,
                    "version": version,
                    "build": build,
                    "date": q[0]["date"],
                    "assets": [
                        i["name"]
                        for i in q[0]["assets"]
                    ]
                }
        return cache.data

    @apiv2.get("/{core}/{version}/{build}/{asset}")
    async def _(request: web.Request, core: str, version: str, build: str, asset: str):
        cache = CACHE[f"core_versions_builds_assets_{core}:{version}:{build}:{asset}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query(core=core, version=version, build=build)
            if len(q) == 0:
                cache.data = utils.ServiceException(404, "NoBuildError").to_json()
            else:
                assets = [
                ]
                for i in q:
                    for q_asset in i["assets"]:
                        if q_asset["name"] == asset:
                            assets.append(q_asset)
                if len(assets) == 0:
                    cache.data = utils.ServiceException(404, "NoAssetError").to_json()
                else:
                    cache.data = {
                        "core": core,
                        "version": version,
                        "build": build,
                        "asset": asset,
                        "origin_url": assets[0]["url"],
                        "download": f"{request.scheme}://{request.host}/download/{core}/{version}/{build}/{asset}"
                    }
        return cache.data

    app.add_router(apiv2)

async def setup(app: web.Application):
    api = web.Router(
        "/api"
    )

    @api.get("/")
    async def _():
        return {
            "status": "ok"
        }

    @api.get("/cores")
    async def _():
        cache = CACHE["resp_api_cores"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query()
            if not q:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
                return cache.data
            cache.data = Response(
                {
                    "cores": sorted(
                        set(
                            [
                                i["core"]
                                for i in q
                            ]
                        )
                    )
                }
            )
        return cache.data
    
    @api.get("/cores/all")
    async def cores_all(request: web.Request):
        cache = CACHE["resp_api_cores_detail"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query()
            if not q:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
                return cache.data
            cores_version: defaultdict[tuple[str, str], list[CoreBuildInfo]] = defaultdict(list)
            for item in q:
                if not isinstance(item["assets"], list):
                    item["assets"] = [item["assets"]]
                    logger.warning(f"[{item["_id"]}] Invalid assets: {item['assets']}")
                    await sync.cores_collection.update_one(
                        {"_id": item["_id"]},
                        {"$set": {"assets": item["assets"]}}
                    )
                for asset in item["assets"]:
                    originCheckSum = None
                    if "hash" in asset:
                        originCheckSum = Checksum(
                            "md5",
                            asset["hash"]
                        )

                    cores_version[(item["core"], item["version"])].append(
                        CoreBuildInfo(
                            item["build"],
                            f"{request.scheme}://{request.host}/api/download/{item["core"]}/{item["version"]}/{item["build"]}/{asset["name"]}",
                            asset.get("mtime"),
                            originCheckSum
                        )
                    )
            res: defaultdict[str, list[CoreVersionInfo]] = defaultdict(list)
            for cores, build in cores_version.items():
                core, version = cores
                res[core].append(CoreVersionInfo(
                    version,
                    build
                ))
            cache.data = Response(
                {
                    "cores": [
                        CoreInfo(
                            core,
                            info
                        )
                        for core, info in res.items()
                    ]
                }
            )
        return cache.data
    
    @api.get("/core/{core}/all")
    async def _(request: web.Request, core: str):
        cache = CACHE[f"resp_api_core_{core}_all"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            try:
                res: Response = await cores_all(request)
                cores: list[CoreInfo] = res.data["cores"]
                info = next(filter(lambda x: x.name == core, cores), None)
                if info is None:
                    raise
                cache.data = Response(
                    asdict(info),
                )
            except:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
        return cache.data
    
    @api.get("/core/{core}")
    async def _(request: web.Request, core: str):
        cache = CACHE[f"resp_api_core_{core}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            try:
                res: Response = await cores_all(request)
                cores: list[CoreInfo] = res.data["cores"]
                info = next(filter(lambda x: x.name == core, cores), None)
                if info is None:
                    raise
                cache.data = Response(
                    {
                        "versions": sorted(set(
                            version.name
                            for version in info.versions
                        ), reverse=True)
                    },
                )
            except:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
        return cache.data
        
    @api.get("/core/{core}/{version}")
    async def _(request: web.Request, core: str, version: str):
        cache = CACHE[f"resp_api_core_version_{core}_{version}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            try:
                res: Response = await cores_all(request)
                cores: list[CoreInfo] = res.data["cores"]
                info = next(filter(lambda x: x.name == core, cores), None)
                if info is None:
                    raise
                info = next(filter(lambda x: x.name == version, info.versions), None)
                if info is None:
                    raise
                cache.data = Response(
                    {
                        "builds": sorted(set(
                            build.name
                            for build in info.builds
                        ), reverse=True)
                    }
                )
            except:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
        return cache.data
    
    @api.get("/core/{core}/{version}/{build}")
    async def _(request: web.Request, core: str, version: str, build: str):
        cache = CACHE[f"resp_api_core_version_build_{core}_{version}_{build}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            try:
                res: Response = await cores_all(request)
                cores: list[CoreInfo] = res.data["cores"]
                info = next(filter(lambda x: x.name == core, cores), None)
                if info is None:
                    raise
                info = next(filter(lambda x: x.name == version, info.versions), None)
                if info is None:
                    raise

                info = next(filter(lambda x: x.name == build, info.builds), None)
                if info is None:
                    raise

                cache.data = Response(
                    asdict(info)
                )
            except:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
        return cache.data
    

    @api.get("/download/{core}/{version}/{build}/{name}")
    async def _(request: web.Request, core: str, version: str, build: str, name: str):
        cache = CACHE[f"resp_api_download_{core}_{version}_{build}_{name}"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            q = await query(
                core,
                version,
                build
            )
            if not q:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
                return cache.data
            assets: list[BuildInfo] = []
            for item in q:
                for asset in item["assets"]:
                    assets.append(
                        BuildInfo(**asset)
                    )
            info = next(filter(lambda x: x.name == name, assets), None)
            if not info:
                cache.data = Response(
                    message="No Found",
                    code=404
                )
                return cache.data
            
            if info.hash is None:
                cache.data = web.LocationResponse(
                    info.url,
                    headers=web.common.Header({
                        "Content-Disposition": f"attachment; filename={urlparse.quote(info.name)}"
                    })
                )
                return cache.data
            link = await openbmclapi.downloads.get_download_link(f"/{core}/{version}/{build}/{name}")
            if link.valid:
                cache.data = web.LocationResponse(
                    link.url,
                    headers=web.common.Header({
                        "Content-Disposition": f"attachment; filename={urlparse.quote(info.name)}",
                        "X-BMCLAPI-Hash": info.hash,
                        "X-BMCLAPI-Last-Modified": info.mtime,
                        "X-BMCLAPI-Size": info.size
                    })
                )
            else:
                cache.data = web.Response(
                    openbmclapi.storage.get_hash_path(info.hash),
                    headers=web.common.Header({
                        "Content-Disposition": f"attachment; filename={urlparse.quote(info.name)}",
                        "X-BMCLAPI-Hash": info.hash,
                        "X-BMCLAPI-Last-Modified": info.mtime,
                        "X-BMCLAPI-Size": info.size
                    })
                )
        return cache.data


    app.add_router(api)

async def init():
    app = await web.start_server(
        DOMAIN,
        [
            HOST
        ],
        7454,
        True
    )

    @app.get("/")
    async def _():
        cache = CACHE["resp_info"]
        if cache.expired:
            cache.expire = time.monotonic() + CACHE_TIMEOUT
            data = FileInfo(0, 0, 0)
            async for i in sync.cores_collection.find({}):
                for asset in i["assets"]:
                    data.total += 1
                    data.size += asset.get("size", 0)
                    if "hash" in asset:
                        data.downloaded += 1
            cache.data = data

            
        return {
            "version": "1.0",
            "files": cache.data
        }
    
    await setup(app)

    await sync.init()