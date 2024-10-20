__CORES__ = [
    'Contigo'
]

from sync.requests import GithubRelease
from sync.types import VersionBuildInfo


async def get_version_build_infos() -> set[VersionBuildInfo]:
    return await GithubRelease("djoveryde", "Contigo").get_version_build_infos(
        "Contigo",
        lambda x: x.tag_name.split("-")[0],
        lambda x: x.tag_name.split("-")[1],
    )

async def init():
    ...