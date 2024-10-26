from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests


INSTALLER = (0, 8)

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
            installers = [item["version"] for item in resp["installer"] if is_version_greater_or_equal(item["version"])]
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

def is_version_greater_or_equal(version_str):
    version_tuple = tuple(map(int, version_str.split('.')))
    target_version = INSTALLER
    min_length = min(len(version_tuple), len(target_version))
    for i in range(min_length):
        if version_tuple[i] > target_version[i]:
            return True
        elif version_tuple[i] < target_version[i]:
            return False
    return len(version_tuple) >= len(target_version)

def get_path(path: str):
    return f"{PATH}{path}"