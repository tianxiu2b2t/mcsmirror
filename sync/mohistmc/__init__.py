import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import aiohttp
from const import const
from sync import requests
from sync.types import VersionBuildInfo


@dataclass
class BuildInfo:
    project: str
    version: str
    build: int
    time: datetime


__CORES__ = [
    'Mohist'
]

BASEURL = "https://mohistmc.com"
PATH = "/api/v2"
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
        projects = await get_project_versions(session)
        builds: list[BuildInfo] = await asyncio.gather(
            *[get_version_build(session, project, version) for project, versions in projects.items() for version in versions]
        )
    
    for build in builds:
        results.add(
            VersionBuildInfo(
                build.project,
                str(build.build),
                build.version,
                f"https://mohistmc.com/api/v2/projects/{build.project}/{build.version}/builds/{build.build}/download",
                f"{build.project}-{build.version}-{build.build}.jar"
            )
        )

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

async def get_project_versions(session: aiohttp.ClientSession) -> dict[str, list[str]]:
    resp = await request(session, "projects")
    return {
        item["project"]: item["versions"]
        for item in resp
    }


async def get_version_build(session: aiohttp.ClientSession, project: str, version: str) -> BuildInfo:
    resp = await request(session, f"projects/{project}/{version}/builds")
    build = resp["builds"][-1]
    return BuildInfo(
        project=project,
        version=version,
        build=build["number"],
        time=datetime.fromtimestamp(build["createdAt"] / 1000.0)
    )




async def init():
    ...