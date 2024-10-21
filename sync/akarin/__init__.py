from sync.types import GithubSource

async def init():
    return GithubSource(
        "Akarin",
        "Akarin-project",
        "Akarin",
        lambda x: x.tag_name.split('-')[0],
        lambda x: x.tag_name.split('-')[1],
    )