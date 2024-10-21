import abc
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

class CoreSource(metaclass=abc.ABCMeta):
    def __init__(self, core: str) -> None:
        self.core = core

    @abc.abstractmethod
    async def get_versions(self) -> list[str]:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_builds(self, version: str) -> list[str]:
        raise NotImplementedError
    
    @abc.abstractmethod
    async def get_build_info(self, info: 'CoreVersionBuild') -> Optional['CoreVersionBuildInfo']:
        raise NotImplementedError
    
    def __hash__(self) -> int:
        return hash(self.core)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.core})"
    
class GithubSource(CoreSource):
    cache_timeout: int = 60 * 60 * 24 * 7  # 7 days
    def __init__(
            self, 
            core: str, 
            owner: str, 
            repo: str,
            version_handler: Callable[['Release'], str],
            build_handler: Callable[['Release'], str], 
            name_handler: Callable[['ReleaseAsset'], bool] = lambda x: True, 
            filter: Callable[['Release'], bool] = lambda x: True
        ):
        super().__init__(core)

        from sync.requests import GithubRelease
        
        self.owner = owner
        self.repo = repo
        self.github = GithubRelease(self.owner, self.repo)
        self.cache: list[GithubVersionBuildInfo] = []
        self.expires = datetime.now()
        self.lock = asyncio.Lock()
        self.version_handler = version_handler
        self.build_handler = build_handler
        self.name_handler = name_handler
        self.filter = filter


    async def fetch_data(self):
        async with self.lock:
            if datetime.now() > self.expires:
                self.cache = await self.github.get_version_build_infos(
                    self.core,
                    self.version_handler,
                    self.build_handler,
                    self.name_handler,
                    self.filter
                )
                self.expires = datetime.now() + timedelta(seconds=self.cache_timeout)
            return self.cache
    
    async def _fetch_data(self) -> list['GithubVersionBuildInfo']:
        raise NotImplementedError

    async def get_versions(self) -> list[str]:
        builds = await self.fetch_data()
        return [
            build.version for build in builds
        ]
    
    async def get_builds(self, version: str) -> list[str]:
        builds = await self.fetch_data()
        return [
            build.build for build in builds if build.version == version
        ]
    
    async def get_build_info(self, info: 'CoreVersionBuild') -> Optional['CoreVersionBuildInfo']:
        builds = await self.fetch_data()
        build = next((build for build in builds if build.version == info.version.version and build.build == info.build), None)
        if build is None:
            return None
        return CoreVersionBuildInfo(
            info.core,
            info.version,
            info,
            max(build.release.assets, key=lambda x: x.time).time,
            [
                BuildAsset(
                    asset.name,
                    asset.url,
                ) for asset in build.release.assets
            ]
        )

@dataclass
class CoreVersion:
    core: CoreSource
    version: str

    def __hash__(self) -> int:
        return hash((self.core, self.version))
    
@dataclass
class CoreVersionBuild:
    core: CoreSource
    version: CoreVersion
    build: str

    def __hash__(self) -> int:
        return hash((self.core, self.version, self.build))
    
@dataclass
class BuildAsset:
    name: str
    url: str

    def __hash__(self) -> int:
        return hash((self.name, self.url))

@dataclass
class CoreVersionBuildInfo:
    core: CoreSource
    version: CoreVersion
    build: CoreVersionBuild
    date: datetime
    assets: list['BuildAsset']

    def __hash__(self) -> int:
        return hash((self.core, self.version, self.build, self.date))

@dataclass
class Release:
    tag_name: str
    target_commitish: str
    name: str
    time: datetime
    assets: list['ReleaseAsset']

    def __hash__(self) -> int:
        return hash((self.tag_name, self.target_commitish, self.name, self.time))

@dataclass
class ReleaseAsset:
    name: str
    size: int
    time: datetime
    url: str

    def __hash__(self) -> int:
        return hash((self.name, self.size, self.time, self.url))

@dataclass
class GithubVersionBuildInfo:
    core: str
    build: str
    version: str
    url: str
    name: str
    release: Release

    def __hash__(self) -> int:
        return hash((
            self.core, self.build, self.version, self.name, self.release
        ))