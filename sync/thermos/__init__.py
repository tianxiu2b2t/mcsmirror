from sync.types import GithubSource


async def init():
    return GithubSource(
        "Thermos",
        "CyberdyneCC", 
        "Thermos",
        lambda x: "1.7.10",
        lambda x: x.tag_name,
        lambda x: x.name.endswith("stable.jar")
    )