import ctypes

from .util import _win_api


class NT:
    dll = ctypes.WinDLL("ntdll.dll")
    NtQueryInformationProcess = _win_api(
        dll.NtQueryInformationProcess,
        ctypes.c_long,
        (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p),
        error_nonzero=True,
    )
