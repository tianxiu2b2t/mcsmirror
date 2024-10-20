import sys


class Const:
    @property
    def debug(self) -> bool:
        return True
    @property
    def user_agent(self) -> str:
        return f"MinecraftServerMirror/1.0 Python/{const.python_version}"

    @property
    def python_version(self) -> str:
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    @property
    def request_buffer(self) -> int:
        return 8192
    
    @property
    def io_buffer(self) -> int:
        return 16777216

    
const = Const()