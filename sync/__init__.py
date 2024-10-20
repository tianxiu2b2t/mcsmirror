import asyncio
from dataclasses import dataclass
import importlib
from pathlib import Path
from types import ModuleType
from typing import Callable

import database
from logger import logger
from sync.types import VersionBuildInfo

@dataclass
class Source:
    m: ModuleType

    def __post_init__(self):
        self._init = self.m.init

    def __repr__(self) -> str:
        return f'{self.package}({self.cores})'
    
    @property
    def package(self) -> str:
        return self.m.__name__

    @property
    def cores(self) -> list:
        return self.m.__CORES__

    @property
    def version_build_info(self) -> Callable:
        return self.m.get_version_build_infos

    @property
    def init(self) -> Callable:
        return self._init
    


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
            if not hasattr(m, "__CORES__") or not hasattr(m, "get_version_build_infos") or not hasattr(m, "init"):
                del m
                continue
            cores = getattr(m, "__CORES__")
            init = getattr(m, "init")
            get_version_build_infos = getattr(m, "get_version_build_infos")
            if not isinstance(cores, (tuple, set, list)) or not (asyncio.iscoroutinefunction(get_version_build_infos) or callable(get_version_build_infos)) or not (asyncio.iscoroutinefunction(init) or callable(init)):
                del m
                continue
            results.append(Source(m))
        except Exception as e:
            logger.traceback(f'import {file.stem}')
    return results


async def load(source: Source):
    try:
        if asyncio.iscoroutinefunction(source.init):
            await source.init()
        else:
            await asyncio.get_event_loop().run_in_executor(None, source.init)
    except Exception as e:
        logger.traceback(f'load {source.package} error: {e}')

async def get_version_build_infos_from_source(source: Source) -> set[VersionBuildInfo]: # type: ignore
    try:
        if asyncio.iscoroutinefunction(source.version_build_info):
            return await source.version_build_info()
        else:
            return await asyncio.get_event_loop().run_in_executor(None, source.version_build_info)
    except Exception as e:
        logger.traceback(f'load {source.package} error: {e}')
        
async def init():
    for module in import_sources():
        logger.success(f'Loaded [{module.package}] Cores: [{', '.join(module.cores)}]')
        sources.append(module)

    asyncio.create_task(sync())

async def sync():
    version_infos: set[VersionBuildInfo] = await get_version_build_infos()
    for info in sorted(sorted(sorted(version_infos, key=lambda x: x.build, reverse=True), key=lambda x: x.mc_version), key=lambda x: x.core):
        print(f"[{info.core} {info.mc_version} {info.build}] {info.name}: {info.url}")

async def get_version_build_infos() -> set[VersionBuildInfo]:
    return set().union(*(
        await asyncio.gather(*[
            get_version_build_infos_from_source(source) for source in sources
        ])
    ))