from sync.types import GithubSource


async def init():
    return [
        GithubSource(
            "Arclight",
            "IzzelAliz",
            "Arclight",
            lambda x: x.tag_name.split('/')[0],
            lambda x: x.tag_name.split('/')[1],
            filter=lambda x: '/' in x.tag_name
        ),
        GithubSource(
            "Lightfall",
            "ArclightPowered",
            "lightfall",
            lambda x: x.tag_name.split('-')[0],
            lambda x: x.tag_name.split('-')[1],
        ),
        GithubSource(
            "LightfallClient",
            "ArclightPowered",
            "lightfall-client",
            lambda x: x.tag_name.split('-')[0],
            lambda x: x.tag_name.split('-')[1],
        )
    ]