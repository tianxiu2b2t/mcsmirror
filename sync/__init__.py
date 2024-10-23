import asyncio
from dataclasses import dataclass
import importlib
from pathlib import Path
from types import ModuleType
from typing import Callable

import database
from logger import logger
from sync.types import CoreSource, CoreVersion, CoreVersionBuild, CoreVersionBuildInfo

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
db = database.client.get_database("mcsmirror")
versions_collection = db.get_collection("versions")

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

async def sync_from_source(sync_source: CoreSource):
    core_versions: list[CoreVersion] = list(
        CoreVersion(
            sync_source,
            version
        ) for version in await sync_source.get_versions()
    )
    sync_source_builds: dict[CoreVersion, list[str]] = {
        core_version: result
        for core_version, result in zip(
            core_versions,
            await asyncio.gather(*[core_version.core.get_builds(core_version.version) for core_version in core_versions])
        )
    }
    core_versions_builds: list[CoreVersionBuild] = list(
        CoreVersionBuild(
            core_version.core,
            core_version,
            build
        ) for core_version, builds in sync_source_builds.items() for build in builds
    )
    sync_source_build_infos: dict[CoreVersionBuild, CoreVersionBuildInfo] = {
        core_version_build: result
        for core_version_build, result in zip(
            core_versions_builds,
            await asyncio.gather(*[core_version_build.core.get_build_info(core_version_build) for core_version_build in core_versions_builds])
        ) if result is not None
    }
    if sync_source_build_infos:
        logger.success(f'Synced {len(sync_source_build_infos)} builds from {sync_source.core}')
    return sync_source_build_infos
async def sync():
    results = await asyncio.gather(*(
        sync_from_source(source) for source in sync_sources
    ))
    logger.success("Synced all sources")
    logger.success(f'Synced {sum(len(result) for result in results)} builds')
        #for asset in core_version_build_info.assets:
        #    print(f'  {asset.name}: {asset.url}')
    #version_infos: set[VersionBuildInfo] = await get_version_build_infos()
    #for info in sorted(sorted(sorted(version_infos, key=lambda x: x.build, reverse=True), key=lambda x: x.mc_version), key=lambda x: x.core):
    #    print(f"[{info.core} {info.mc_version} {info.build}] {info.name}: {info.url}")
    ...