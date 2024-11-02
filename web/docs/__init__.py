from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import web

RENDER_ROOT = Path(__file__).parent / "render"

@dataclass
class DocsRouteParameters:
    name: str
    type: list[str]
    required: bool

@dataclass
class DocsRoute:
    method: str
    path: str
    parameters: list[DocsRouteParameters]

@dataclass
class DocsRouter:
    prefix: str
    mount: list[str]
    routes: list[DocsRoute]

filter_types = [
    web.common.Request,
    web.common.RequestTiming,
    web.common.WebSocket,
    web.common.Form
]

def get_parameter(item: web.common.RouteHandlerArg) -> Optional[DocsRouteParameters]:
    args = list(
        filter(
            lambda x: x not in filter_types,
            item.type_annotation
        )
    )
    if not args:
        return None
    return DocsRouteParameters(
        args[0].__name__,
        [item.__name__ for item in args],
        item.required
    )

def get_parameters(item: web.common.RouteHandlerArgs) -> list[DocsRouteParameters]:
    return [
        item for item in (
            get_parameter(arg) for arg in item.route_handler_args
        ) if item is not None
    ]



def get_routers(router: web.Router) -> list[DocsRoute]:
    results = []
    for method, route in router.routes.items():
        for item in route:
            results.append(
                DocsRoute(
                    method,
                    item.path,
                    get_parameters(item.parameters)
                )
            )
    return results

async def setup(
    app: web.Application,
    path: str = "/docs",
):
    def get_docs(app: web.Application) -> list[DocsRouter]:
        results = []
        for router in app.routers:
            if router is doc_router:
                continue
            results.append(
                DocsRouter(
                    router.prefix,
                    list(router.mounts.keys()),
                    get_routers(router)
                )
            )
        return results


    doc_router = web.Router(
        path
    )
    @doc_router.get("/")
    def _(request: web.Request):
        if request.headers.get("Content-Type", "") == "application/json":
            return get_docs(app)
        index = RENDER_ROOT / "index.html"
        etag = web.common.get_etag(index)
        if request.headers.get("If-None-Match") == etag:
            return web.Response(status=304)
        return web.Response(
            content=index.read_bytes().replace(b"<<prefix>>", doc_router.prefix.encode("utf-8")),
            headers=web.common.Header(
                {
                    "ETag": etag
                }
            ),
            content_type="text/html"
        )
    
    @doc_router.get("/index.js")
    def _():
        return RENDER_ROOT / "index.js"
    
    doc_router.mount(
        "/assets",
        RENDER_ROOT / "assets"
    )
    
    app.add_router(doc_router)