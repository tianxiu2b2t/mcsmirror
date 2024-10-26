from datetime import datetime
from typing import Optional
from sync.types import BuildAsset, CoreSource, CoreVersionBuild, CoreVersionBuildInfo
from sync import requests


class Source(CoreSource):
    def __init__(self, core: str):
        super().__init__(core)
        self.lower_core = core.lower()

    async def get_versions(self) -> list[str]:
        resp = await requests.request(BASEURL, f"{PATH}/projects/{self.lower_core}")
        return resp["versions"]
    
    async def get_builds(self, version: str) -> list[str]:
        resp = await requests.request(BASEURL, f"{PATH}/projects/{self.lower_core}/versions/{version}")
        return list(map(str, resp["builds"]))
    
    async def get_build_info(self, info: CoreVersionBuild) -> Optional[CoreVersionBuildInfo]:
        resp = await requests.request(BASEURL, f"{PATH}/projects/{self.lower_core}/versions/{info.version.version}/builds/{info.build}")
        assets = []
        for item in resp["downloads"].values():
            assets.append(
                BuildAsset(
                    name=item["name"],
                    url=f"{BASEURL}{PATH}/projects/{self.lower_core}/versions/{info.version.version}/builds/{info.build}/downloads/{item["name"]}"
                )
            )
        return CoreVersionBuildInfo(
            core=self,
            version=info.version,
            build=info,
            date=datetime.fromisoformat(resp["time"]),
            assets=assets
        )
    
BASEURL = "https://api.papermc.io"
PATH = "/v2"

async def get_projects():
    resp = (await requests.request(BASEURL, get_path("/projects")))['projects']
    return [project.capitalize() for project in resp]

async def init():
    return [
        Source(project) for project in await get_projects()
    ]


def get_path(path: str):
    return f"{PATH}{path}"