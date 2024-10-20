import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import aiohttp
from const import const
from sync import requests
from sync.types import VersionBuildInfo


@dataclass
class VersionInfo:
    project: str
    version: str
    build: int
    time: datetime
    downloads: list['VersionDownload']

@dataclass
class VersionDownload:
    prop: str
    name: str
    sha256: str

@dataclass
class DownloadInfo:
    project: str
    version: str
    build: int
    time: datetime
    name: str
    sha256: str

    def __hash__(self) -> int:
        return hash((self.project, self.version, self.build, self.time, self.name, self.sha256))


__CORES__ = [
    'Mohist'
]

BASEURL = "https://mohistmc.com"
PATH = "/api/v2/"
USER_AGENT = const.user_agent


# build version: https://download.geysermc.org/v2/projects/geyser/versions/2.1.0/builds/latest
# versions: https://download.geysermc.org/v2/projects/{project}

async def get_version_build_infos() -> set[VersionBuildInfo]:
    results: set[VersionBuildInfo] = set()
    async with aiohttp.ClientSession(
        BASEURL,
        headers = {
            "User-Agent": USER_AGENT
        }
    ) as session:
        projects = await get_projects(session)
        versions: dict[str, str] = {
            project: version
            for project, version in zip(
                projects,
                await asyncio.gather(*(
                    get_project_version(session, project)
                    for project in projects
                ))
            )
        }
        print(versions)
    return results

async def request(
    session: aiohttp.ClientSession,
    path: str
) -> dict:
    return await requests.request(
        BASEURL,
        f"{PATH}/{path}",
        session=session
    )

async def get_projects(session: aiohttp.ClientSession) -> list[str]:
    return (await request(session, "projects"))['projects']

async def get_project_version(session: aiohttp.ClientSession, project: str) -> str:
    return (await request(session, f"projects/{project}"))['versions'][-1]



async def init():
    ...