import asyncio
import hashlib
from typing import Optional

import env
from logger import logger
import scheduler
import utils
from . import common
import ssl
import service

REQUEST_BUFFER = int(env.get_env("REQUEST_BUFFER", def_=8192))
PUBLIC_SERVER: dict[int, asyncio.Server] = {}
SSL_SERVER: dict[Optional[str], asyncio.Server] = {}
EMPTY_SSL_SERVER: asyncio.Server = None # type: ignore
SUBDOMAINS_VALUES: dict[tuple[str, ...], str] = {   
}
PROXY_TABLES: dict[tuple[str, int], tuple[str, int]] = {
}
APPLICATIONS: dict[str, common.Application] = {}
LOCK = asyncio.Lock()

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    async with common.Client(reader, writer) as client:
        try:
            buffer = await client.read(REQUEST_BUFFER)
            if not buffer:
                return
            sni = utils.get_client_handshake_info(buffer)
            if sni.version != -1 and sni.sni is not None:
                ssl_server = EMPTY_SSL_SERVER
                subdomain = get_key_by_subdomain(sni.sni)
                if subdomain is not None and subdomain in SSL_SERVER:
                    ssl_server = SSL_SERVER[subdomain]
                port = ssl_server.sockets[0].getsockname()[1]
                target = common.Client(
                    *(await asyncio.open_connection(
                        ssl_server.sockets[0].getsockname()[0],
                        port,
                    ))
                )
                PROXY_TABLES[target.writer.get_extra_info("sockname")] = client.writer.get_extra_info("peername")
                async with common.ProxyClient(client, target, buffer) as proxy_client:
                    await proxy_client.forward_all()
            else:
                while not client.closed and (request := common.parse_request(client, buffer)):
                    await handle_application(client, request)
                    if request is not None and request.http_protocol == "HTTP/1.0":
                        break
                    buffer = await client.read(REQUEST_BUFFER)
        except (GeneratorExit, asyncio.CancelledError, OSError, ConnectionAbortedError):
            ...
        except:
            logger.traceback("Error while handling request")
    client.close()

async def ssl_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    async with common.Client(reader, writer) as client:
        try:
            client.tls = True
            peername = client.writer.get_extra_info("peername")
            if peername in PROXY_TABLES:
                peername = PROXY_TABLES[peername]
            client._peername = peername
            buffer = await client.read(REQUEST_BUFFER)
            while not client.closed and (request := common.parse_request(client, buffer)):
                await handle_application(client, request)
                if request is not None and request.http_protocol == "HTTP/1.0":
                    break
                buffer = await client.read(REQUEST_BUFFER)
        except (GeneratorExit, asyncio.CancelledError, ssl.SSLError, OSError, ConnectionAbortedError):
            ...
        except:
            logger.traceback("Error while handling request")
    client.close()

async def handle_application(client: common.Client, request: Optional[common.Request]):
    if request is None:
        logger.twarning("web.warning.request.invalid", address=client.peername)
        return
    key = get_key_by_subdomain(request.hostname)
    if key is None:
        logger.twarning("web.warning.request.no_application", host=request.host, address=request.address)
        return
    if key not in APPLICATIONS:
        logger.twarning("web.warning.request.no_application", host=request.host, address=request.address)
        return
    app = APPLICATIONS[key]
    await app.handle(request)
    ...

async def start_server(root_hostname: str, subdomains: list[str], port: int, ssl: bool = False) -> common.Application:
    await _start_empty_ssl()
    await _start_public_server(port)
    key = service.acme_zerossl_v2.get_subdomains_hash(subdomains)
    SUBDOMAINS_VALUES[tuple(subdomains)] = key
    if key not in APPLICATIONS:
        APPLICATIONS[key] = common.Application(root_hostname, subdomains, port, ssl)
    if ssl:
        scheduler.run_later(_start_ssl_server, 1, args=(root_hostname, subdomains))
    return APPLICATIONS[key]

async def _start_public_server(port: int, force: bool = False):
    if port in PUBLIC_SERVER and not force:
        return
    async with LOCK:
        old_server = PUBLIC_SERVER.get(port)
        if old_server:
            old_server.close()
            await old_server.wait_closed()
        server = await asyncio.start_server(handle, "0.0.0.0", port)
        PUBLIC_SERVER[port] = server
        await server.start_serving()
        logger.tsuccess("web.success.server.start_port.public", port=server.sockets[0].getsockname()[1])

async def _get_certificate(root_hostname: Optional[str], subdomains: list[str] = []):
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH
    )
    if root_hostname is not None:
        async with service.acme_zerossl_v2.get_zerossl_instance(env.get_env("ZEROSSL_EMAIL"), root_hostname, service.acme_zerossl_v2.TencentDNSRecord(
            env.get_env("TENCENT_KEY"),
            env.get_env("TENCENT_SECRET"),
        )) as instance:
            cert = await instance.get_certificate(subdomains or [root_hostname])
            if cert is not None and cert.valid:
                context.load_cert_chain(cert.ca, cert.key)
                logger.debug(f"load cert chain from zerossl v2 instance for {root_hostname} {subdomains}")
    else:
        context.post_handshake_auth = False

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.hostname_checks_common_name = False
    return context

async def _start_empty_ssl(force: bool = False):
    global EMPTY_SSL_SERVER
    if EMPTY_SSL_SERVER and not force:
        return
    old_server = EMPTY_SSL_SERVER
    if old_server:
        old_server.close()
        await old_server.wait_closed()
    context = await _get_certificate(None)
    server = await asyncio.start_server(ssl_handle, "127.0.0.1", 0, ssl=context)
    await server.start_serving()
    EMPTY_SSL_SERVER = server
    logger.tsuccess("web.success.server.start_port.ssl.empty", port=server.sockets[0].getsockname()[1])

async def _start_ssl_server(root_hostname: str, subdomains: list[str], force: bool = False):
    key = service.acme_zerossl_v2.get_subdomains_hash(subdomains)
    SUBDOMAINS_VALUES[tuple(subdomains)] = key
    if key in SSL_SERVER and not force:
        return
    old_server = SSL_SERVER.get(key)
    if old_server:
        old_server.close()
        await old_server.wait_closed()
    context = await _get_certificate(root_hostname, subdomains)
    server = await asyncio.start_server(ssl_handle, "127.0.0.1", 0, ssl=context)
    await server.start_serving()
    SSL_SERVER[key] = server
    logger.tsuccess("web.success.server.start_port.ssl", port=server.sockets[0].getsockname()[1], root_hostname=root_hostname, subdomains=', '.join(subdomains))

def get_key_by_subdomain(subdomain: str) -> Optional[str]:
    for subdomains, key in SUBDOMAINS_VALUES.items():
        if subdomain in subdomains:
            return key
    return None