from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional
import aiohttp

import const
import env
from logger import logger
import urllib.parse as urlparse

from sync.types import GithubVersionBuildInfo, Release, ReleaseAsset

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
    
    async def get_version_build_infos(self, core: str, version_handler: Callable[[Release], str], build_handler: Callable[[Release], str], name_handler: Callable[[ReleaseAsset], bool] = lambda x: True, filter: Callable[[Release], bool] = lambda x: True) -> list[GithubVersionBuildInfo]:
        results: list[GithubVersionBuildInfo] = []
        for release in await self.get_releases():
            if not filter(release):
                continue
            version = version_handler(release)
            build = build_handler(release)
            asset = max(release.assets, key=lambda x: x.time)
            results.append(
                GithubVersionBuildInfo(
                    core,
                    build,
                    version,
                    asset.url,
                    asset.name,
                    release
                )
            )
        return results

class Jenkins:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint + "/"

    async def request(self, path: str, params: dict[str, Any] = {}):
        async with aiohttp.ClientSession(
            headers=GITHUB_HEADERS
        ) as session:
            async with session.get(urlparse.urljoin(self.endpoint, path), params=params) as resp:
                logger.debug(f"Jenkins: {resp.request_info.real_url}")
                data = await resp.json()
                #logger.debug(data)
                #with open("test.json", "w") as f:
                #    json.dump(data, f, indent=4)
                return data
    
    async def get_jobs(self):
        resp = await self.request("api/json?tree=[name,url]")
        print(resp)

class aiohttpClientSessionManager:
    def __init__(self):
        self.default_session: aiohttp.ClientSession = aiohttp.ClientSession(
            headers={
                "User-Agent": const.const.user_agent
            }
        )
        self.current_session: Optional[aiohttp.ClientSession] = None

    async def __aclose__(self):
        await self.default_session.close()

    def get_session(self) -> aiohttp.ClientSession:
        return self.current_session or self.default_session
    
    def set_session(self, session: aiohttp.ClientSession):
        self.current_session = session
    
    def clear_session(self):
        self.current_session = None

GITHUB_TOKEN = env.get_env("GITHUB_TOKEN")
GITHUB_BASEURL = "https://api.github.com/"
GITHUB_HEADERS: dict[str, str] = {
    "User-Agent": const.const.user_agent
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

GITHUB_PER_PAGE = 100
REQUEST_CACHE_TIMEOUT = 3600

session_manager = aiohttpClientSessionManager()

async def request(
    baseurl: str,
    path: str,
    params: dict = {},
    headers: dict = {},
    session: Optional[aiohttp.ClientSession] = None
) -> dict:
    session = session or session_manager.get_session()
    path = urlparse.urljoin(baseurl, path)
    try:
        return await _request(session, path, params, headers)
    except:
        raise
        
async def _request(
    session: aiohttp.ClientSession,
    path: str,
    params: dict = {},
    headers: dict = {}
):
    async with session.get(
        path,
        params=params,
        headers=headers
    ) as resp:
        data = await resp.json()
        return data