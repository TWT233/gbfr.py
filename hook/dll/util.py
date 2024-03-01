import ctypes
from typing import Any

_NULL = type('NULL', (), {})


def _win_api(func, res_type: Any = ctypes.c_void_p, arg_types=(), error_zero=False, error_nonzero=False,
             error_val: Any = _NULL):
    func.argtypes = arg_types
    func.restype = res_type
    if error_zero and error_nonzero:  # pragma: no cover
        raise ValueError("Cannot raise on both zero and non-zero")

    if error_zero:
        def wrapper(*args, **kwargs):

            res = func(*args, **kwargs)
            if not res:
                raise ctypes.WinError()
            return res

        return wrapper
    if error_nonzero:
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            if res: raise ctypes.WinError()
            return res

        return wrapper

    if error_val is not _NULL:
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            if res == error_val: raise ctypes.WinError()
            return res

        return wrapper
    return func
