from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests


@dataclass
class Cache[T]:
    data: T
    expire: datetime

    @property
    def expired(self):
        return datetime.now() >= self.expire

class Source(CoreSource):
    def __init__(self):
        super().__init__("Fabric")
        self.resp_cache: dict[str, Any] = {}
        self.expire = datetime.now()
        self.cache: defaultdict[str, Cache] = defaultdict(lambda: Cache(None, datetime.now()))
    
    async def fetch(self):
        if datetime.now() > self.expire:
            self.resp_cache = await requests.request(BASEURL, get_path(f"/versions"))
            self.expire = datetime.now() + timedelta(seconds=requests.REQUEST_CACHE_TIMEOUT)
        return self.resp_cache
    async def get_versions(self) -> list[str]:
        cache = self.cache["versions"]
        if cache.expired:
            resp = await self.fetch()
            versions = [version["version"] for version in resp["game"] if version.get("stable", False)]
            cache.data = versions
            cache.expire = datetime.now() + timedelta(seconds=requests.REQUEST_CACHE_TIMEOUT)
        return cache.data
    
    async def get_builds(self, version: str) -> list[str]:
        cache = self.cache[f"builds"]
        if cache.expired:
            resp = await self.fetch()
            loaders = [item["version"] for item in resp["loader"]]
            installers = [item["version"] for item in resp["installer"]]
            cache.data = [
                f"{loader}-{installer}"
                for loader, installer in zip(loaders, installers)
            ]
            cache.expire = datetime.now() + timedelta(seconds=requests.REQUEST_CACHE_TIMEOUT)
        return cache.data
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            datetime.now(),
            [
                BuildAsset(
                    f"fabric-installer-{info.version.version}-{info.build}.jar",
                    f"https://meta.fabricmc.net/v2/versions/loader/{info.version.version}/{info.build.replace("-", "/")}/server/jar"
                )
            ]
        )


    
BASEURL = "https://meta.fabricmc.net/"
PATH = "/v2"

async def init():
    return Source()


def get_path(path: str):
    return f"{PATH}{path}"