from sync.types import GithubSource

async def init():
    return GithubSource(
        "CatServer",
        "Luohuayu",
        "CatServer",
        lambda x: x.target_commitish,
        lambda x: x.tag_name,
    )