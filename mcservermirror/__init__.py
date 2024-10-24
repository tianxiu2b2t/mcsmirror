import env
import sync
import utils
import web

DOMAIN = env.get_env("DOMAIN")
HOST = f"sync-api.{DOMAIN}"

async def init():
    app = await web.start_server(
        DOMAIN,
        [
            HOST
        ],
        7456,
        True
    )

    api = web.Router(
        "/api/v2"
    )

    @api.get("/")
    async def _():
        if len(sync.sync_sources) == 0:
            return utils.ServiceException(404, 404, name="NoSyncSourceError").to_json()
        return {
            "version": "2.0",
            "sources": len(sync.sync_sources),
            "cores": [
                core.core for core in sync.sync_sources
            ]
        }
    
    
    @api.get("/{core}")
    async def _(core: str):
        ...

    @api.get("/{core}/{version}")
    async def _(core: str, version: str):
        ...

    @api.get("/{core}/{version}/{build}")
    async def _(core: str, version: str, build: str):
        ...

    @api.get("/{core}/{version}/{build}/download")
    async def _(core: str, version: str, build: str):
        ...

    app.add_router(api)

    await sync.init()