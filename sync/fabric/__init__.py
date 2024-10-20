import aiohttp
from const import const
from sync import requests
from sync.types import VersionBuildInfo

__CORES__ = [
    'Fabric'
]

BASEURL = "https://meta.fabricmc.net/"
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
        resp = await request(session, "versions")
    results: set[VersionBuildInfo] = set()
    versions = [
        resp['version'] for resp in resp['game'] if resp.get("stable")
    ]
    loader = resp["loader"][0]["version"]
    installer = resp["installer"][0]["version"]
    for version in versions:
        results.add(
            VersionBuildInfo(
                "Fabric",
                f"{loader}-{installer}",
                version,
                f"https://meta.fabricmc.net/v2/versions/loader/{version}/{loader}/{installer}/server/jar",
                f"fabric-installer-{version}-{loader}-{installer}.jar"
            )
        )
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


async def init():
    ...