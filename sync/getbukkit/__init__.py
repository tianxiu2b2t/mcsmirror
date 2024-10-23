from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

import aiohttp
from const import const
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests
from lxml import html

@dataclass
class Response:
    version: str
    date: datetime
    link: str

@dataclass
class Cache[T]:
    data: T
    expire: datetime

    @property
    def expired(self):
        return datetime.now() >= self.expire

class Source(CoreSource):
    def __init__(self, core: str):
        super().__init__(core)
        self.resp_cache: list[Response] = []
        self.expire = datetime.now()
        self.cache: defaultdict[str, Cache] = defaultdict(lambda: Cache(None, datetime.now()))
    
    async def fetch(self):
        if datetime.now() > self.expire:
            async with aiohttp.ClientSession(
                BASEURL,
                headers = {
                    "User-Agent": const.user_agent
                }
            ) as session:
                async with session.get(f"/download/{self.core.lower()}") as resp:
                    root = html.fromstring(await resp.text())
            results = []
            for pane in root.xpath('//div[@class="download-pane"]'):
                version = pane.xpath(".//h2/text()")[0]
                date = datetime.strptime(pane.xpath(".//h3/text()")[1], "%A, %B %d %Y")
                link = pane.xpath('.//a[@class="btn btn-download"]/@href')[0]
                results.append(
                    Response(
                        version,
                        date,
                        link
                    )
                )
            self.resp_cache = results
            self.expire = datetime.now() + timedelta(seconds=requests.REQUEST_CACHE_TIMEOUT)
        return self.resp_cache
    async def get_versions(self) -> list[str]:
        resp = await self.fetch()
        return [
            r.version
            for r in resp
        ]
    
    async def get_builds(self, version: str) -> list[str]:
        return [
            "latest"
        ]
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        resp = await self.fetch()
        version_build = next((r for r in resp if r.version == info.version.version), None)
        if not version_build:
            return None
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            version_build.date,
            [
                BuildAsset(
                    f"{info.core.core}-{info.version.version}-latest.jar",
                    version_build.link
                )
            ]
        )


    
BASEURL = "https://getbukkit.org/"

async def init():
    return [
        Source(core)
        for core in [
            'Craftbukkit',
            "Spigot",
            "Vanilla"
        ]
    ]