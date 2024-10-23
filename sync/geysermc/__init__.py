from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests

class Source(CoreSource):
    def __init__(self, core: str):
        super().__init__(core)
        self.lower_core = core.lower()
    
    async def get_versions(self) -> list[str]:
        return (
            await requests.request(BASEURL, get_path(f"/projects/{self.lower_core}"))
        )['versions']
    
    async def get_builds(self, version: str) -> list[str]:
        resp = await requests.request(BASEURL, get_path(f"/projects/{self.lower_core}/versions/{version}"))
        return resp['builds']
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        resp = await requests.request(BASEURL, get_path(f"/projects/{self.lower_core}/versions/{info.version.version}/builds/{info.build}"))
        assets = []
        for item in resp["downloads"].values():
            assets.append(
                BuildAsset(
                    item["name"],
                    f"{BASEURL}{PATH}/projects/{self.lower_core}/versions/{info.version.version}/builds/{info.build}/{item["name"]}",
                )
            )
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            datetime.fromisoformat(resp["time"]),
            assets
        )

    
FILTER = [
    "geyserconnect",
    "geyseroptionalpack",
    "hydraulic",
    "geyserpreview",
    "thirdpartycosmetics",
    "erosion"
]

BASEURL = "https://download.geysermc.org"
PATH = "/v2"

async def get_projects() -> list[str]:
    projects = (await requests.request(BASEURL, get_path("/projects")))['projects']
    return [project.capitalize() for project in projects if project.lower() not in FILTER]


async def init():
    return [
        Source(core)
        for core in await get_projects()
    ]


def get_path(path: str):
    return f"{PATH}{path}"