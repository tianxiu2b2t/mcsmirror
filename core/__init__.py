import asyncio
import os
from pathlib import Path
import time
from logger import logger
import service
import utils
import atexit
import scheduler
import mcservermirror

_WAITLOCK = utils.CountLock()
_START_RUNTIME = time.monotonic()

def init_env():
    tmp = os.getenv("TMPDIR")
    if tmp is None:
        return
    Path(tmp).mkdir(parents=True, exist_ok=True)

async def load(module):
    try:
        init = getattr(module, "init")
        if asyncio.iscoroutinefunction(init):
            await init()
        else:
            await asyncio.get_event_loop().run_in_executor(None, init)
    except:
        logger.traceback()

async def main():
    start = time.monotonic_ns()
    await asyncio.gather(*[
        load(module) for module in [
            scheduler,
            service,
            mcservermirror
        ]
    ])
    _WAITLOCK.acquire()
    end = time.monotonic_ns()
    logger.tsuccess("main.success.start_service_done", time=f"{((end-start) / 1e9):.2f}")
    try:
        await _WAITLOCK.wait()
    except:
        logger.tdebug("main.debug.service_unfinish")
    finally:
        await scheduler.unload()

def init():
    atexit.register(main_exit)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("KeyboardInterrupt")
    finally:
        atexit.unregister(main_exit)
    logger.tsuccess("main.success.service_exit")

def main_exit():
    _WAITLOCK.release()