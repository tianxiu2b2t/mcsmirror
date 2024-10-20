import asyncio
from datetime import datetime
from typing import Any
import aiohttp
from const import const
from sync import requests
from sync.types import VersionBuildInfo
from lxml import html

__CORES__ = [
    'craftbukkit',
    "spigot",
    "vanilla"
]

BASEURL = "https://getbukkit.org/"
USER_AGENT = const.user_agent

# Final URL: /v2/versions/loader/:game_version/:loader_version/:installer_version/server/jar

async def get_version_build_infos() -> set[VersionBuildInfo]:
    async with aiohttp.ClientSession(
        BASEURL,
        headers = {
            "User-Agent": USER_AGENT
        }
    ) as session:
        versions: dict[str, str] = {
            k: v
            for k, v in zip(__CORES__, await asyncio.gather(
                *[request(
                    session,
                    f"/download/{core}"
                ) for core in __CORES__]
            ))
        }
    results: set[VersionBuildInfo] = set()
    for core, text in versions.items():
        root = html.fromstring(text)
        for pane in root.xpath('//div[@class="download-pane"]'):
            version = pane.xpath(".//h2/text()")[0]
            sync_time = pane.xpath(".//h3/text()")[1]
            date = parse_time(sync_time)
            link = pane.xpath('.//a[@class="btn btn-download"]/@href')[0]
            results.add(VersionBuildInfo(
                core,
                "latest",
                version,
                link,
                f"{core}-{version}-latest.jar",
            ))
    return results

async def request(
    session: aiohttp.ClientSession,
    path: str
) -> str:
    async with session.get(
        path
    ) as resp:
        return await resp.text()

def parse_time(date: str):
    return datetime.strptime(date, "%A, %B %d %Y")

async def init():
    ...