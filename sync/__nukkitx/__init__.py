__CORES__ = [
    'NukkitX'
]

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import aiohttp
from const import const
from sync.requests import Jenkins
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
    jenkins = Jenkins("https://ci.opencollab.dev/job/NukkitX/job/Nukkit")
    await jenkins.get_jobs()

    return set()


async def init():
    ...