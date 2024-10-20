from . import tencent
from . import acme_zerossl_v2
from . import dns

async def init():
    await tencent.init()