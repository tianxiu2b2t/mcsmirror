import asyncio
from dataclasses import dataclass
from datetime import datetime
import aiohttp

from const import const
from logger import logger
from sync import requests
from sync.types import VersionBuildInfo

@dataclass
class Project:
    name: str
    versions: set[str]

    def __hash__(self) -> int:
        return hash((self.name, tuple(self.versions)))
    
@dataclass
class ProjectVersion:
    project: str
    version: str

    def __hash__(self) -> int:
        return hash((self.project, self.version))
    
@dataclass
class ProjectBuild:
    project: str
    version: str
    build: int

    def __hash__(self) -> int:
        return hash((self.project, self.version, self.build))

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

BASEURL = "https://api.papermc.io"
PATH = "/v2"
USER_AGENT = const.user_agent

__CORES__ = [
    "Paper",
    "Travertine",
    "Waterfall",
    "Velocity",
    "Folia"
]
async def get_version_build_infos() -> set[VersionBuildInfo]:
    async with aiohttp.ClientSession(
        BASEURL,
        headers = {
            "User-Agent": USER_AGENT
        }
    ) as session:
        projects = await get_projects(session)
        project_versions: list[Project] = []
        for project, versions in zip(projects,
            await asyncio.gather(
                *[
                    get_project_versions(session, project)
                    for project in projects
                ]
            )
        ):
            project_versions.append(Project(project, set(versions)))
        project_last_builds = {
            ProjectVersion(project.name, version): last_build 
            for ((project, version), last_build) in zip(
                [(project, version) for project in project_versions for version in project.versions], 
                await asyncio.gather(*[
                    get_project_last_build(session, project.name, version) for project in project_versions for version in project.versions
                ])
            )
        }
        # async
        project_last_build_infos = {
            ProjectVersion(project.name, version): info
            for ((project, version), info) in zip(
                [(project, version) for project in project_versions for version in project.versions], 
                await asyncio.gather(*[
                    get_project_build(session, project.project, project.version, last_build) for project, last_build in project_last_builds.items()
                ])
            )
        }
        urls: set[DownloadInfo] = set()
        for project_version, version_info in project_last_build_infos.items():
            for download in version_info.downloads:
                urls.add(DownloadInfo(
                    project_version.project,
                    project_version.version,
                    version_info.build,
                    version_info.time,
                    download.name,
                    download.sha256
                ))
        return set(
            VersionBuildInfo(
                url.project,
                str(url.build),
                url.version,
                f"{BASEURL}{PATH}/projects/{url.project}/versions/{url.version}/builds/{url.build}/{url.name}",
                url.name
            ) for url in urls
        )
    # asyncio gather


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
    return (await request(session, "projects"))["projects"]
        
async def get_project_versions(session: aiohttp.ClientSession, project_name: str) -> list[str]:
    return (await request(session, f"projects/{project_name}"))["versions"]

async def get_project_last_build(session: aiohttp.ClientSession, project_name: str, project_version: str) -> int:
    return max(*(await request(session, f"projects/{project_name}/versions/{project_version}"))["builds"], -1)

async def get_project_build(session: aiohttp.ClientSession, project: str, version: str, build: int) -> VersionInfo:
    resp = (await request(session, f"projects/{project}/versions/{version}/builds/{build}"))
    return VersionInfo(
        project,
        version,
        build,
        datetime.fromisoformat(resp["time"]),
        [VersionDownload(prop, download["name"], download["sha256"]) for prop, download in resp["downloads"].items()]
    )

    
async def init():
    ...