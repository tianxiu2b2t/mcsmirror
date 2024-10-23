from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests

class Source(CoreSource):
    def __init__(self, core: str):
        super().__init__(
            core
        )
        self.lower_core = core.lower()

    async def get_versions(self) -> list[str]:
        resp = await requests.request(BASEURL, get_path(f"/{self.lower_core}"))
        return resp["versions"]

    async def get_builds(self, version: str) -> list[str]:
        resp = await requests.request(BASEURL, get_path(f"/{self.lower_core}/{version}"))
        return resp["builds"]["all"]
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        resp = await requests.request(
            BASEURL,
            get_path(f"/{self.lower_core}/{info.version.version}/{info.build}")
        )
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            datetime.fromtimestamp(resp["timestamp"] / 1000.0),
            [
                BuildAsset(
                    f"{info.core.core}-{info.version.version}-{info.build}.jar",
                    f"{BASEURL}{PATH}/{self.lower_core}/{info.version.version}/{info.build}/download"
                )
            ]
        )

BASEURL = "https://api.purpurmc.org"
PATH = "/v2"

async def get_projects():
    resp = await requests.request(BASEURL, get_path("/"))
    return [
        item.capitalize()
        for item in resp["projects"]
    ]

async def init():
    return [
        Source(core)
        for core in await get_projects()
    ]


def get_path(path: str):
    return f"{PATH}{path}"