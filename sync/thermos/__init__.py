__CORES__ = [
    'Thermos'
]

from sync.requests import GithubRelease
from sync.types import VersionBuildInfo


async def get_version_build_infos() -> set[VersionBuildInfo]:
    github = GithubRelease("CyberdyneCC", "Thermos")
    return await GithubRelease("CyberdyneCC", "Thermos").get_version_build_infos(
        "Thermos",
        lambda x: "1.7.10",
        lambda x: x.tag_name,
        lambda x: x.name.endswith("stable.jar")
    )

async def init():
    ...