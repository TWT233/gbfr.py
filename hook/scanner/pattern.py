import io
import re


class _Pattern:
    fl_is_ref = 1 << 0
    fl_is_byes = 1 << 1
    fl_store = 1 << 2

    hex_chars = set(b"0123456789abcdefABCDEF")
    dec_chars = set(b"0123456789")

    special_chars_map = {i for i in b"()[]{}?*+-|^$\\.&~# \t\n\r\v\f"}

    @classmethod
    def take_dec_number(cls, pattern: str, i: int):
        assert i < len(pattern) and ord(pattern[i]) in cls.dec_chars
        j = i + 1
        while j < len(pattern) and ord(pattern[j]) in cls.dec_chars:
            j += 1
        return int(pattern[i:j]), j

    @classmethod
    def take_cnt(cls, pattern: str, i: int, regex_pattern: bytearray):
        if i < len(pattern) and pattern[i] == "{":
            regex_pattern.append(123)  # {
            n1, i = cls.take_dec_number(pattern, i + 1)
            regex_pattern.extend(str(n1).encode())
            if pattern[i] == ":":
                n2, i = cls.take_dec_number(pattern, i + 1)
                assert n1 <= n2
                regex_pattern.append(44)  # ,
                regex_pattern.extend(str(n2).encode())
            assert pattern[i] == "}"
            regex_pattern.append(125)  # }
            i += 1
        return i

    @classmethod
    def take_byte(cls, pattern: str, i: int, regex_pattern: bytearray):
        assert i + 2 <= len(pattern)
        next_byte = int(pattern[i : i + 2], 16)
        if next_byte in cls.special_chars_map:
            regex_pattern.append(92)  # \
        regex_pattern.append(next_byte)
        return i + 2

    @classmethod
    def _take_unk(cls, pattern: str, i: int):
        start_chr = pattern[i]
        assert start_chr in ("?", "*", "^")
        if i + 1 < len(pattern) and pattern[i + 1] == start_chr:
            i += 1
        return start_chr, i + 1

    @classmethod
    def take_unk(cls, pattern: str, i: int, regex_pattern: bytearray):
        start_unk, i = cls._take_unk(pattern, i)
        regex_pattern.append(46)
        i = cls.take_cnt(pattern, i, regex_pattern)
        while i < len(pattern):
            match pattern[i]:
                case " ":
                    i += 1
                case c if c == start_unk:
                    start_unk, i = cls._take_unk(pattern, i)
                    regex_pattern.append(46)
                    i = cls.take_cnt(pattern, i, regex_pattern)
                case _:
                    break
        return start_unk, i

    @classmethod
    def _compile_pattern(cls, pattern: str, i=0, ret_at=None):
        _i = i
        regex_pattern = bytearray()
        sub_matches = []
        group_flags = []
        while i < len(pattern):
            match pattern[i]:
                case " ":
                    i += 1
                case "[":
                    regex_pattern.append(91)  # [
                    i += 1
                    i = cls.take_byte(pattern, i, regex_pattern)
                    while True:
                        match pattern[i]:
                            case " ":
                                i += 1
                            case "]":
                                regex_pattern.append(93)  # ]
                                i += 1
                                break
                            case "|":
                                i = cls.take_byte(pattern, i + 1, regex_pattern)
                            case ":":
                                regex_pattern.append(45)  # -
                                i = cls.take_byte(pattern, i + 1, regex_pattern)
                            case c:
                                raise ValueError(f"Invalid character {c} in pattern {pattern!r} at {i}")

                case "(":
                    base_flag = 0  # not fl_store
                    regex_pattern.append(40)  # (
                    unk_type, i = cls.take_unk(pattern, i + 1, regex_pattern)
                    if unk_type == "*":
                        base_flag |= cls.fl_is_ref
                    elif unk_type == "^":
                        base_flag |= cls.fl_is_byes
                    sub_pattern = None
                    while True:
                        match pattern[i]:
                            case " ":
                                i += 1
                            case ")":
                                regex_pattern.append(41)  # )
                                i += 1
                                break
                            case ":":
                                sub_pattern, i = cls._compile_pattern(pattern, i + 1, ret_at=")")
                                assert pattern[i] == ")", f"Expected ) get {pattern[i]} at {i} in pattern {pattern!r}"
                                regex_pattern.append(41)
                                i += 1
                                break
                            case c:
                                raise ValueError(f"Invalid character {c} in pattern {pattern!r} at {i}")
                    group_flags.append(base_flag)
                    sub_matches.append(sub_pattern)
                case "<":
                    base_flag = cls.fl_store
                    regex_pattern.append(40)
                    unk_type, i = cls.take_unk(pattern, i + 1, regex_pattern)
                    if unk_type == "*":
                        base_flag |= cls.fl_is_ref
                    elif unk_type == "^":
                        base_flag |= cls.fl_is_byes
                    sub_pattern = None
                    while True:
                        match pattern[i]:
                            case " ":
                                i += 1
                            case ">":
                                regex_pattern.append(41)
                                i += 1
                                break
                            case ":":
                                sub_pattern, i = cls._compile_pattern(pattern, i + 1, ret_at=">")
                                assert pattern[i] == ">", f"Expected > get {pattern[i]} at {i} in pattern {pattern!r}"
                                regex_pattern.append(41)
                                i += 1
                                break
                            case c:
                                raise ValueError(f"Invalid character {c} in pattern {pattern!r} at {i}")
                    group_flags.append(base_flag)
                    sub_matches.append(sub_pattern)
                case "?" | "*" | "^" as c:
                    regex_pattern.append(40)
                    unk_type, i = cls.take_unk(pattern, i, regex_pattern)
                    regex_pattern.append(41)
                    if c == "?":
                        group_flags.append(0)
                    elif c == "*":
                        group_flags.append(cls.fl_is_ref | cls.fl_store)
                    elif c == "^":
                        group_flags.append(cls.fl_is_byes | cls.fl_store)
                    else:
                        raise ValueError(f"Invalid character {c} in pattern {pattern!r} at {i}")
                    sub_matches.append(None)
                case c if ord(c) in cls.hex_chars:
                    i = cls.take_byte(pattern, i, regex_pattern)
                    i = cls.take_cnt(pattern, i, regex_pattern)
                case c if c == ret_at:
                    break
                case c:
                    fmt_pattern = pattern[:i] + "_" + pattern[i] + "_" + pattern[i + 1 :]
                    raise ValueError(f"Invalid character {c} in pattern {fmt_pattern!r} at {i} (ret_at={ret_at})")
        try:
            regex = re.compile(bytes(regex_pattern), re.DOTALL)
        except re.error as e:
            raise ValueError(f"{e}: ({pattern!r}, {_i}, {ret_at!r}) -> {bytes(regex_pattern)}")
        return Pattern(regex, sub_matches, group_flags, pattern), i

    @classmethod
    def compile_pattern(cls, pattern: str):
        return cls._compile_pattern(pattern)[0]

    @classmethod
    def fmt_bytes_regex_pattern(cls, pat: bytes):
        s = ""
        is_escape = False
        is_in_bracket = 0
        for b in pat:
            if is_escape:
                is_escape = False
                s += f"\\x{b:02x}"
            elif b == 92:  # \
                is_escape = True
            elif b in cls.special_chars_map:
                if b == 123:  # {
                    is_in_bracket += 1
                elif b == 125:  # }
                    is_in_bracket -= 1
                s += chr(b)
            elif is_in_bracket:
                s += chr(b)
            else:
                s += f"\\x{b:02x}"
        return s


class Pattern:
    def __init__(self, regex: re.Pattern, sub_matches: "typing.List[None | Pattern]", group_flags, pattern: str):
        self.regex = regex
        self.sub_matches = sub_matches
        self.group_flags = group_flags
        self.pattern = pattern
        self.res_is_ref = []
        for i, (sub, flag) in enumerate(zip(sub_matches, group_flags)):
            if flag & _Pattern.fl_store:
                self.res_is_ref.append(flag & _Pattern.fl_is_ref)
            if sub is not None:
                self.res_is_ref.extend(sub.res_is_ref)

    def finditer(self, _data: bytes | bytearray | memoryview, ref_base=0):
        data = _data if isinstance(_data, memoryview) else memoryview(_data)
        for match in self.regex.finditer(data):
            res = []
            if self._parse_match(data, match, res, ref_base):
                yield match.start(0), res

    def _parse_match(self, data: memoryview, match: re.Match, res: list, ref_base=0):
        for i, (sub_match, flag) in enumerate(zip(self.sub_matches, self.group_flags)):
            if flag & _Pattern.fl_is_byes:
                res.append(match.group(i + 1))
            else:
                val = int.from_bytes(match.group(i + 1), "little", signed=True)
                if flag & _Pattern.fl_is_ref:
                    val += match.end(i + 1)
                if flag & _Pattern.fl_store:
                    res.append(val)
                if sub_match is not None:
                    start = val if flag & _Pattern.fl_is_ref else val - ref_base
                    if start < 0 or start >= len(data):
                        return False
                    if not sub_match._match(data, start, res, ref_base):
                        return False
        return True

    def _match(self, _data: memoryview, start_at: int, res: list, ref_base=0):
        if not (match := self.regex.match(_data, start_at)):
            return False
        return self._parse_match(_data, match, res, ref_base)

    def fmt(self, ind: str | int = " ", _ind=0):
        if isinstance(ind, int):
            ind = " " * ind
        s = io.StringIO()
        s.write(ind * _ind)
        s.write(_Pattern.fmt_bytes_regex_pattern(self.regex.pattern))
        s.write("\n")
        s.write(ind * _ind)
        s.write("res is ref:")
        for flag in self.res_is_ref:
            s.write(" ref" if flag else " val")
        s.write("\n")
        for i, (sub, flag) in enumerate(zip(self.sub_matches, self.group_flags)):
            s.write(ind * _ind)
            s.write(
                f'{i}:{"ref" if flag & _Pattern.fl_is_ref else "val"}{" store" if flag & _Pattern.fl_store else ""}\n'
            )
            if sub is not None:
                s.write(sub.fmt(ind, _ind + 1))
                s.write("\n")
        return s.getvalue().rstrip()
