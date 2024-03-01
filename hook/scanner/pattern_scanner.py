from typing import Generator

from hook.scanner.pattern import Pattern


class IPatternScanner:
    def search(self, pattern: str | Pattern) -> Generator[tuple[int, list[int]], None, None]:
        raise NotImplementedError

    def search_unique(self, pattern: str | Pattern) -> tuple[int, list[int]]:
        s = self.search(pattern)
        try:
            res = next(s)
        except StopIteration:
            raise KeyError("pattern not found")
        try:
            next(s)
        except StopIteration:
            return res
        raise KeyError("pattern is not unique, at least 2 is found")

    def find_addresses(self, pattern: str | Pattern):
        for address, _ in self.search(pattern):
            yield address

    def find_vals(self, pattern: str | Pattern):
        for address, args in self.search(pattern):
            yield args

    def find_address(self, pattern: str | Pattern):
        return self.search_unique(pattern)[0]

    def find_val(self, pattern: str | Pattern):
        return self.search_unique(pattern)[1]
