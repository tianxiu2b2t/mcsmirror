from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any, Callable, Optional
import aiohttp

import const
import env
from logger import logger
from sync.types import VersionBuildInfo


async def request(
    baseurl: str,
    path: str,
    params: dict = {},
    headers: dict = {},
    session: Optional[aiohttp.ClientSession] = None
) -> dict:
    local_session = session
    if local_session is None:
        local_session = aiohttp.ClientSession(
            baseurl,
            headers={
                "User-Agent": const.const.user_agent
            } | headers
        )
    try:
        return await _request(local_session, path, params)
    except:
        raise
    finally:
        if session is None:
            await local_session.close()
        
async def _request(
    session: aiohttp.ClientSession,
    path: str,
    params: dict = {},
):
    async with session.get(
        path,
        params=params
    ) as resp:
        data = await resp.json()
        return data
    


GITHUB_TOKEN = env.get_env("GITHUB_TOKEN")
GITHUB_BASEURL = "https://api.github.com/"
GITHUB_HEADERS: dict[str, str] = {
    "User-Agent": const.const.user_agent
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

GITHUB_PER_PAGE = 100

@dataclass
class Release:
    tag_name: str
    target_commitish: str
    name: str
    time: datetime
    assets: list['ReleaseAsset']

@dataclass
class ReleaseAsset:
    name: str
    size: int
    time: datetime
    url: str

class GithubRelease:
    def __init__(self, owner: str, repo: str):
        self.base_url = f"/repos/{owner}/{repo}"


    async def request(self, path: str, params: dict[str, Any] = {}):
        async with aiohttp.ClientSession(
            GITHUB_BASEURL,
            headers=GITHUB_HEADERS
        ) as session:
            async with session.get(f"{self.base_url}/{path}", params=params) as resp:
                logger.debug(f"Github: {self.base_url}/{path}")
                data = await resp.json()
                #logger.debug(data)
                #with open("test.json", "w") as f:
                #    json.dump(data, f, indent=4)
                return data
            
    async def get_releases(self):
        releases = await self.request(
            "releases",
            {
                "per_page": GITHUB_PER_PAGE
            }
        )
        results: list[Release] = []
        for release in releases:
            results.append(
                Release(
                    tag_name=release["tag_name"],
                    target_commitish=release["target_commitish"],
                    name=release["name"],
                    time=datetime.fromisoformat(release["published_at"]),
                    assets=[
                        ReleaseAsset(
                            name=asset["name"],
                            size=asset["size"],
                            time=datetime.fromisoformat(asset["updated_at"]),
                            url=asset["browser_download_url"]
                        )
                        for asset in release["assets"]
                    ]
                )
            )
        return list(filter(lambda x: x.assets, results))
    
    async def get_version_build_infos(self, core: str, mc_version_handler: Callable[[Release], str], build_handler: Callable[[Release], str], name_handler: Callable[[ReleaseAsset], bool] = lambda x: True, filter: Callable[[Release], bool] = lambda x: True) -> set[VersionBuildInfo]:
        results: set[VersionBuildInfo] = set()
        for release in await self.get_releases():
            if not filter(release):
                continue
            mc_version = mc_version_handler(release)
            build = build_handler(release)
            asset = max(release.assets, key=lambda x: x.time)
            results.add(
                VersionBuildInfo(
                    core,
                    build,
                    mc_version,
                    asset.url,
                    asset.name
                )
            )
        return results