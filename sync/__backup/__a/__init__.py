__CORES__ = [
    'Akarin'
]

from sync.types import VersionBuildInfo


async def get_version_build_infos() -> set[VersionBuildInfo]:
    ...

async def init():
    ...