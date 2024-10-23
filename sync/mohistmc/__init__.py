from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests

@dataclass
class VersionBuildCache[T]:
    data: Any
    expired: datetime

class Source(CoreSource):
    def __init__(self, core: str):
        super().__init__(
            core
        )
        self.lower_core = core.lower()
        self.cache: defaultdict[str, VersionBuildCache] = defaultdict(lambda: VersionBuildCache(None, datetime.now() - timedelta(days=1)))
    
    async def fetch_build(self, version: str):
        cache = self.cache[version]
        if cache.expired < datetime.now():
            resp = await requests.request(BASEURL, get_path(f"/projects/{self.lower_core}/{version}/builds"))
            cache.data = resp["builds"]
            cache.expired = datetime.now() + timedelta(seconds=requests.REQUEST_CACHE_TIMEOUT)
        return cache.data

    async def get_versions(self) -> list[str]:
        resp = await requests.request(BASEURL, get_path("/projects"))
        project = next(
            item
            for item in resp
            if item["project"].lower() == self.lower_core
        )
        return project["versions"]

    async def get_builds(self, version: str) -> list[str]:
        resp = await self.fetch_build(version)
        return [build["number"] for build in resp]
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        builds = await self.fetch_build(info.version.version)
        build = next(
            build
            for build in builds
            if str(build["number"]) == str(info.build)
        )
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            datetime.fromtimestamp(build["createdAt"] / 1000.0),
            [
                BuildAsset(
                    f"{info.core.core}-{info.version.version}-{info.build}.jar",
                    build["url"]
                ),
                BuildAsset(
                    f"{info.core.core}-{info.version.version}-{info.build}.jar",
                    build["originUrl"]
                )    
            ]
        )

BASEURL = "https://mohistmc.com"
PATH = "/api/v2"

async def get_projects():
    resp = await requests.request(BASEURL, get_path("/projects"))
    return [
        item["project"].capitalize()
        for item in resp
    ]

async def init():
    return [
        Source(core)
        for core in await get_projects()
    ]


def get_path(path: str):
    return f"{PATH}{path}"