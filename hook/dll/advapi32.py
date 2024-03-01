import ctypes

from .util import _win_api


class ADVApi32:
    dll = ctypes.WinDLL("advapi32.dll")
    OpenProcessToken = _win_api(
        dll.OpenProcessToken, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p), error_zero=True
    )
    LookupPrivilegeName = _win_api(
        dll.LookupPrivilegeNameW,
        ctypes.c_long,
        (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p),
        error_zero=True,
    )
    LookupPrivilegeValue = _win_api(
        dll.LookupPrivilegeValueW, ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p), error_zero=True
    )
    AdjustTokenPrivileges = _win_api(
        dll.AdjustTokenPrivileges,
        ctypes.c_long,
        (ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p),
        error_zero=True,
    )
