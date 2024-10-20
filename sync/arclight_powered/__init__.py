__CORES__ = [
    "Arclight",
    "Lightfall",
    "LightfallClient"
]

import asyncio
from sync.requests import GithubRelease
from sync.types import VersionBuildInfo

async def get_version_build_infos() -> set[VersionBuildInfo]:
    return set().union(*(await asyncio.gather(
        GithubRelease("IzzelAliz", "Arclight").get_version_build_infos(
            "Arclight",
            lambda x: x.tag_name.split('/')[0],
            lambda x: x.tag_name.split('/')[1],
            filter=lambda x: '/' in x.tag_name
        ),
        GithubRelease("ArclightPowered", "lightfall").get_version_build_infos(
            "Lightfall",
            lambda x: x.tag_name.split('-')[0],
            lambda x: x.tag_name.split('-')[1],
        ),
        GithubRelease("ArclightPowered", "lightfall-client").get_version_build_infos(
            "LightfallClient",
            lambda x: x.tag_name.split('-')[0],
            lambda x: x.tag_name.split('-')[1],
        ),
    )))

async def init():
    ...