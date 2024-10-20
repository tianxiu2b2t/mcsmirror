from dataclasses import dataclass
import time
from typing import TypeVar

T = TypeVar("T")

@dataclass
class Cache[T]:
    data: T
    expires: int

    def __post_init__(self):
        self.createdAt = int(time.time())
        self.expires = self.createdAt + self.expires

    @property
    def expired(self):
        return self.expires <= int(time.time())