import asyncio
from dataclasses import dataclass
from datetime import datetime
import inspect
import traceback
from typing import Any, Callable, Optional
import aiohttp
import bson
from tqdm import tqdm

import const
import env
from logger import logger
import urllib.parse as urlparse

import openbmclapi
from sync.types import DownloadHistory, DownloadStatusError, GithubVersionBuildInfo, Release, ReleaseAsset
from sync.database import cores_collection
import units
import utils

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

@dataclass
class DownloadFile:
    _id: bson.ObjectId
    hash: str
    url: str
    size: int
    name: str
    mtime: datetime

    def __hash__(self):
        return hash(self.hash)
    
@dataclass
class DownloadFileResult:
    _result: Optional[DownloadFile | type[inspect._empty]] = inspect._empty

    def __post_init__(self):
        self.lock = utils.CountLock()
        self.lock.acquire()
    
    async def set_result(self, result: Optional[DownloadFile]):
        self._result = result
        self.lock.release()
        if result is None:
            return
        query = [
            i async for i in cores_collection.aggregate([
                {
                  "$match": { 'assets.url': result.url } 
                }
            ])
        ]
        updated = await asyncio.gather(*(
            cores_collection.update_one(
                {
                    "_id": i["_id"]
                },
                {
                    "$set": {
                        "assets": [
                            ({
                                "hash": result.hash,
                                "url": j["url"],
                                "size": result.size,
                                "name": j["name"],
                                "mtime": result.mtime
                            } if j["url"] == result.url else j) for j in i["assets"]
                        ]
                    }
                }
            ) for i in query
        ))
        logger.info(f"Downloaded [{result.name} ({result.hash}, {units.format_bytes(result.size)})] from {result.url}, updated [{len(updated)}]")

    @property
    def result(self) -> Optional[DownloadFile]:
        if self._result == inspect._empty:
            raise Exception("DownloadFileResult not set")
        return self._result # type: ignore

    async def wait(self):
        return await self.lock.wait()
    
@dataclass
class DownloadQueue:
    _id: bson.ObjectId
    url: str
    path: str
    name: str
    result: DownloadFileResult

class Downloader:
    def __init__(
        self
    ):
        self.task_queues: asyncio.Queue[DownloadQueue] = asyncio.Queue()
        self.task: Optional[asyncio.Task] = None
        self.tqdm: Optional[DownloadTqdm] = None
    
    @property
    def download_count(self):
        return int(env.get_env("DOWNLOAD_THREADS")) or 32
    
    @property
    def download_per_sessions(self):
        return min(self.download_count, int(env.get_env("DOWNLOAD_SESSIONS_PER_THREAD")) or 1)

    async def _download(self, session: aiohttp.ClientSession):
        while not self.task_queues.empty():
            file = await self.task_queues.get()
            fileinfo = await openbmclapi.storage.get_file(file.path)
            if fileinfo is not None:
                await file.result.set_result(
                    DownloadFile(
                        file._id,
                        fileinfo.hash,
                        file.url,
                        fileinfo.size,
                        file.name,
                        fileinfo.id.generation_time
                    )
                )
                self.tqdm.success() # type: ignore
            try:
                async with session.get(file.url, cookies=None) as resp:
                    if resp.status != 200:
                        if resp.status == 404:
                            await file.result.set_result(None)
                            continue
                        raise DownloadStatusError(
                            f"Status: {resp.status}"
                        )
                    reader = asyncio.StreamReader()
                    async def copy():
                        async for data in resp.content.iter_any():
                            reader.feed_data(data)
                        reader.feed_eof()
                    res = await asyncio.gather(
                        copy(),
                        openbmclapi.storage.upload(file.path, reader)
                    )
                    upload_res = res[1]
                    await file.result.set_result(
                        DownloadFile(
                            file._id,
                            upload_res.hash,
                            file.url,
                            upload_res.size,
                            file.name,
                            upload_res.id.generation_time
                        )
                    )
                    self.tqdm.success() # type: ignore
            except Exception as e:
                self.show_error(file, locals().get("resp", None), e, traceback.format_exc())
                await self.task_queues.put(file)
                ...
                
    def show_error(self, file: DownloadQueue, resp: Optional[aiohttp.ClientResponse], e: Exception, tb):
        history: list[DownloadHistory] = []
        if resp is not None:
            # current resp
            # history: resp.history
            for res in resp.history:
                history.append(DownloadHistory(
                    str(res.real_url),
                    res.status
                    )
                )
            history.append(DownloadHistory(
                str(resp.url),
                resp.status
                )
            )
        history_text = "\n".join(
            f"{h.status} | {h.url}" for h in history
        )
            
        logger.error(f"Failed to [{file.name}({file.url})] Error [{e}] Response Redirects: \n{history_text}\n{tb}")
        self.tqdm.failed() # type: ignore

    async def _download_task(self):
        sessions: list[aiohttp.ClientSession] = []
        tasks = []
        try:
            for i in range(0, self.download_count, self.download_per_sessions):
                session = aiohttp.ClientSession(
                    headers={
                        "User-Agent": const.const.user_agent
                    }
                )
                for j in range(min(self.download_per_sessions, self.download_count - i)):
                    tasks.append(asyncio.create_task(self._download(session)))
            await asyncio.gather(*tasks)
        except:
            ...
        finally:
            del self.tqdm
            self.tqdm = None
            for session in sessions:
                await session.close()
            self.task_queues.task_done()
            if self.task is not None:
                self.task.cancel()
            self.task = None

    async def download(self, _id: bson.ObjectId, url: str, path: str, name: str):
        result = DownloadFileResult()
        await self.task_queues.put(DownloadQueue(_id, url, path, name, result))
        if self.tqdm is None:
            self.tqdm = DownloadTqdm()
        self.tqdm.add()
        if self.task is None:
            self.task = asyncio.create_task(self._download_task())
        return result

class DownloadTqdm:
    def __init__(
        self,
    ) -> None:
        self.tqdm = tqdm(
            total=0,
            unit="file",
            unit_scale=True,
            desc="Downloading",
        )
        self._failed = 0
        self.tqdm.set_postfix_str(
            f"{self._failed} failed"
        )
    
    def add(self):
        self.tqdm.total += 1
        self.tqdm.refresh()

    def success(self):
        self.tqdm.update(1)

    def failed(self):
        self._failed += 1
        self.tqdm.set_postfix_str(
            f"{self._failed} failed"
        )

    def __del__(self):
        self.tqdm.close()
    


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
downloader = Downloader()

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