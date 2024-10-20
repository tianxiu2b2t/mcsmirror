import asyncio
from dataclasses import dataclass
import aiohttp
from const import const
from sync import requests
from sync.types import VersionBuildInfo

@dataclass
class BuildInfo:
    project: str
    version: str
    build: str

__CORES__ = [
    'Purpur'
]

BASEURL = "https://api.purpurmc.org"
PATH = "/v2"
USER_AGENT = const.user_agent

# Final URL: /v2/versions/loader/:game_version/:loader_version/:installer_version/server/jar

async def get_version_build_infos() -> set[VersionBuildInfo]:
    async with aiohttp.ClientSession(
        BASEURL,
        headers = {
            "User-Agent": USER_AGENT
        }
    ) as session:
        projects = await get_projects(session)
        versions: dict[str, list[str]] = {
            project: results
            for project, results in zip(projects, await asyncio.gather(*(
                get_versions(session, project) for project in projects
            )))
        }
        builds: list[BuildInfo] = await asyncio.gather(*(
            get_build(session, project, version)
            for project, versions in versions.items()
            for version in versions
        ))
    results: set[VersionBuildInfo] = set()
    for build in builds:
        results.add(VersionBuildInfo(
            build.project, 
            build.build, 
            build.version,
            f"{BASEURL}{PATH}/{build.project}/{build.version}/{build.build}/download",
            f"{build.project}-{build.version}-{build.build}.jar"
        ))
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

async def get_projects(session: aiohttp.ClientSession):
    return (await request(session, ""))["projects"]

async def get_versions(session: aiohttp.ClientSession, project: str) -> list[str]:
    return (await request(session, f"{project}"))["versions"]

async def get_build(session: aiohttp.ClientSession, project: str, version: str) -> BuildInfo:
    return BuildInfo(
        project,
        version,
        (await request(session, f"{project}/{version}"))["builds"]["latest"]
    )


async def init():
    ...