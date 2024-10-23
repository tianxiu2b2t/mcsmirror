import env
import sync
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
    @app.get("/api/v2")
    async def _():
        return {
            "version": "2.0",
            "sources": len(sync.sync_sources)
        }
    
    await sync.init()