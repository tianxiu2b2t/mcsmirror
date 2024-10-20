__CORES__ = [
    'Luminol'
]

from sync.requests import GithubRelease
from sync.types import VersionBuildInfo


async def get_version_build_infos() -> set[VersionBuildInfo]:
    return await GithubRelease("LuminolMC", "Luminol").get_version_build_infos(
        "Luminol",
        lambda x: x.tag_name.split("-")[0],
        lambda x: x.tag_name.split("-")[1],
    )

async def init():
    ...