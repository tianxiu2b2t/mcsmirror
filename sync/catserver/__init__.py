__CORES__ = [
    'Akarin'
]

from sync.requests import GithubRelease
from sync.types import VersionBuildInfo


async def get_version_build_infos() -> set[VersionBuildInfo]:
    return await GithubRelease("Luohuayu", "CatServer").get_version_build_infos(
        "Lightfall",
        lambda x: x.target_commitish,
        lambda x: x.tag_name,
    )

async def init():
    ...