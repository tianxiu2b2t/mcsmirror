import asyncio
from collections import defaultdict
from dataclasses import dataclass
import importlib
from pathlib import Path
from types import ModuleType
from typing import Callable

import database
import env
from logger import logger
from sync.types import CoreSource, CoreVersion, CoreVersionBuild, CoreVersionBuildInfo, FileInfo, URLFileInfo, URLInfo
from sync.database import (
    cores_collection
)

@dataclass
class Source:
    m: ModuleType

    def __post_init__(self):
        self._init = self.m.init

    def __repr__(self) -> str:
        return f'{self.package}'
    
    @property
    def package(self) -> str:
        return self.m.__name__

    @property
    def init(self) -> Callable:
        return self._init
    
    def __hash__(self) -> int:
        return hash(self.package)
    
sync_sources: list[CoreSource] = []
sources: list[Source] = []

def import_sources():
    results = []
    current_path = Path(
        __file__
    ).parent
    # only search current path dir or other file
    for file in current_path.iterdir():
        # if __ xxx __ skip it
        if file.name.startswith('__'):
            continue
        try:
            m = importlib.import_module(f'sync.{file.stem}')
            if not hasattr(m, "init"):
                del m
                continue
            init = getattr(m, "init")
            if not (asyncio.iscoroutinefunction(init) or callable(init)):
                del m
                continue
            results.append(Source(m))
        except Exception as e:
            logger.traceback(f'import {file.stem}')
    return results

async def load(source: Source) -> list[CoreSource]:
    result = None
    try:
        if asyncio.iscoroutinefunction(source.init):
            result = await source.init()
        else:
            result = await asyncio.get_event_loop().run_in_executor(None, source.init)
    except Exception as e:
        logger.traceback(f'load {source.package} error: {e}')
    if result is None:
        return []
    if isinstance(result, CoreSource):
        return [
            result
        ]
    return result
        
async def init():
    for module in import_sources():
        logger.success(f'Loaded Package [{module.package}]')
        sources.append(module)

    core_sources: dict[Source, list[CoreSource]] = {
        module: result
        for module, result in zip(
            sources,
            await asyncio.gather(*[load(module) for module in sources])
        )
    }

    for module, csources in core_sources.items():
        for source in csources:
            sync_sources.append(source)
            logger.success(f'Loaded Source [{source.core}] [{module}]')

    await asyncio.create_task(sync())

async def get_sync_version_from_source(sync_source: CoreSource):
    return [
        CoreVersion(
            sync_source,
            version
        ) for version in await sync_source.get_versions()
    ]

async def get_sync_builds_from_source(versions: list[CoreVersion]) -> dict[CoreVersion, list[str]]:
    return {
        core_version: result
        for core_version, result in zip(
            versions,
            await asyncio.gather(*[core_version.core.get_builds(core_version.version) for core_version in versions])
        )
    }

async def get_core_version_builds_from_database(core_version: CoreVersion) -> list[str]:
    return [
        i["build"] async for i in cores_collection.find({
            "core": core_version.core.core,
            "version": core_version.version,
        })
    ]

async def get_sync_build_infos_from_source(builds: list[CoreVersionBuild]):
    return {
        core_version_build: result
        for core_version_build, result in zip(
            builds,
            await asyncio.gather(*[core_version_build.core.get_build_info(core_version_build) for core_version_build in builds])
        ) if result is not None
    }


async def sync_from_source(sync_source: CoreSource):
    versions = await get_sync_version_from_source(sync_source)
    builds: dict[CoreVersion, list[str]] = await get_sync_builds_from_source(versions)
    newer_builds: dict[CoreVersion, list[str]] = {
        core_version: list(
            set(builds[core_version]) - set(result)
        )
        for core_version, result in zip(
            builds.keys(),
            await asyncio.gather(*[get_core_version_builds_from_database(core_version) for core_version in builds.keys()])
        )
    }
    newer_build_count = sum(len(r) for r in newer_builds.values())
    logger.success(f'Fetch {len(versions)} versions, {sum(len(r) for r in builds.values())}. Newer {newer_build_count} builds from {sync_source.core}')
    
    core_versions_builds: list[CoreVersionBuild] = list(
        CoreVersionBuild(
            core_version.core,
            core_version,
            build
        ) for core_version, builds in newer_builds.items() for build in builds
    )

    sync_source_build_infos: dict[CoreVersionBuild, CoreVersionBuildInfo] = await get_sync_build_infos_from_source(core_versions_builds)
    sync_build_count = len(sync_source_build_infos)
    if sync_build_count == 0 and newer_build_count != 0:
        logger.warning(f'No fetch newer builds from {sync_source.core}, but {newer_build_count} newer builds')
        return
    if sync_build_count == 0:
        return
    
    await cores_collection.insert_many([
        {
            "core": build.core.core,
            "version": build.version.version,
            "build": build.build.build,
            "date": build.date,
            "assets": [
                {
                    "name": asset.name,
                    "url": asset.url,
                } for asset in build.assets
            ],
        } for build in sync_source_build_infos.values()
    ])


async def get_no_files_builds():
    urls: defaultdict[str, set[URLFileInfo]] = defaultdict(set)

    async for i in cores_collection.aggregate([
        { "$sort": { "build": -1 } },
        {
            "$group": {
              "_id": { "core": "$core", "version": "$version" },
              "documents": { "$push": "$$ROOT" }
            }
        },
        {
            "$project": {
              "documents": { "$slice": ["$documents", int(env.get_env("SYNC_DOWNLOAD_BUILD")) or 1] }
            }
        },
        { "$unwind": "$documents" },
        { "$replaceRoot": { "newRoot": "$documents" } },
        {
            "$match": {
                  "$or": [
                      { "assets.hash": { "$exists": False } },
                      { "assets.size": { "$exists": False } },
                      { "assets.mtime": { "$exists": False } }
                  ]
            }
        }
    ]):
        for asset in i["assets"]:
            url = urls[asset["url"]]
            url.add(URLFileInfo(i["_id"], i["core"], i["version"], i["build"], asset["name"]))
    

    return urls

async def sync():
    from .requests import downloader
    await asyncio.gather(*(
        sync_from_source(source) for source in sync_sources
    ))
    logger.success("Synced all sources")

    logger.info("Get no downloaded files builds")
    no_files_builds = await get_no_files_builds()
    logger.success(f"Get {len(no_files_builds.keys())} no files builds")

    results: dict[str, requests.DownloadFileResult] = {
        build: result
        for build, result in zip(
            list(no_files_builds.keys()),
            await asyncio.gather(*[downloader.download(build._id, url, f"/{build.core}/{build.version}/{build.build}/{build.name}", build.name) for url, builds in no_files_builds.items() for build in builds])
        )
    }
    wait = asyncio.gather(*[
        res.wait()
        for res in results.values()
    ])
    await wait