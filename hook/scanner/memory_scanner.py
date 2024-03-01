from typing import Generator

from .pattern import Pattern, _Pattern
from .pattern_scanner import IPatternScanner


class MemoryPatternScanner(IPatternScanner):
    def __init__(self, process: "Process", region_address, region_size):
        self.process = process
        self.region_address = region_address
        self.region_size = region_size

    def get_raw(self):
        return self.process.read(self.region_address, self.region_size)

    def search(self, pattern: str | Pattern) -> Generator[tuple[int, list[int]], None, None]:
        if isinstance(pattern, str):
            pattern = _Pattern.compile_pattern(pattern)
        for offset, args in pattern.finditer(self.get_raw()):
            yield self.region_address + offset, [
                a + self.region_address if r else a for a, r in zip(args, pattern.res_is_ref)
            ]


class CachedRawMemoryPatternScanner(MemoryPatternScanner):
    def __init__(self, *a):
        super().__init__(*a)
        self._cached_raw = None

    def get_raw(self):
        if self._cached_raw is None:
            self._cached_raw = super().get_raw()
        return self._cached_raw
