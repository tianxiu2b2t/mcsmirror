from dataclasses import dataclass


@dataclass
class VersionBuildInfo:
    core: str
    build: str
    mc_version: str
    url: str
    name: str

    def __hash__(self) -> int:
        return hash((
            self.name, self.url,
            self.build, self.core
        ))