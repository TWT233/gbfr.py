import ctypes

from .util import _win_api

INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF


class Kernel32:
    dll = ctypes.WinDLL("kernel32.dll")
    GetCurrentProcess = _win_api(dll.GetCurrentProcess, ctypes.c_void_p, (), error_zero=True)
    CreateToolhelp32Snapshot = _win_api(
        dll.CreateToolhelp32Snapshot, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_ulong), error_val=INVALID_HANDLE_VALUE
    )
    Process32First = _win_api(dll.Process32First, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    Process32Next = _win_api(dll.Process32Next, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
    CloseHandle = _win_api(dll.CloseHandle, ctypes.c_bool, (ctypes.c_void_p,), error_zero=True)
    OpenProcess = _win_api(
        dll.OpenProcess, ctypes.c_void_p, (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong), error_zero=True
    )
    CreateRemoteThread = _win_api(
        dll.CreateRemoteThread,
        ctypes.c_void_p,
        (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ),
        error_zero=True,
    )
    ReadProcessMemory = _win_api(
        dll.ReadProcessMemory,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p),
        error_zero=True,
    )
    WriteProcessMemory = _win_api(
        dll.WriteProcessMemory,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p),
        error_zero=True,
    )
    VirtualAllocEx = _win_api(
        dll.VirtualAllocEx,
        ctypes.c_void_p,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong),
        error_val=0,
    )
    VirtualFreeEx = _win_api(
        dll.VirtualFreeEx,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong),
        error_zero=True,
    )
    VirtualProtectEx = _win_api(
        dll.VirtualProtectEx,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p),
        error_zero=True,
    )
    VirtualQueryEx = _win_api(
        dll.VirtualQueryEx,
        ctypes.c_size_t,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t),
        error_zero=True,
    )
    GetProcAddress = _win_api(dll.GetProcAddress, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_char_p), error_zero=True)
    GetModuleHandle = _win_api(dll.GetModuleHandleW, ctypes.c_size_t, (ctypes.c_wchar_p,), error_val=0)
    GetCurrentProcessId = _win_api(dll.GetCurrentProcessId, ctypes.c_ulong, (), error_zero=True)
    WaitForSingleObject = _win_api(
        dll.WaitForSingleObject, ctypes.c_ulong, (ctypes.c_void_p, ctypes.c_ulong), error_val=0xFFFFFFFF
    )
    CreateEvent = _win_api(
        dll.CreateEventW,
        ctypes.c_void_p,
        (ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_wchar_p),
        error_val=INVALID_HANDLE_VALUE,
    )
    WriteFile = _win_api(
        dll.WriteFile,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p),
        error_zero=True,
    )
    ReadFile = _win_api(
        dll.ReadFile,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p),
        error_zero=True,
    )
    GetOverlappedResult = _win_api(
        dll.GetOverlappedResult,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool),
        error_zero=True,
    )
    CreateNamedPipe = _win_api(
        dll.CreateNamedPipeW,
        ctypes.c_void_p,
        (
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ),
        error_val=INVALID_HANDLE_VALUE,
    )
    ConnectNamedPipe = _win_api(
        dll.ConnectNamedPipe, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_void_p), error_zero=True
    )
    CreateFile = _win_api(
        dll.CreateFileW,
        ctypes.c_void_p,
        (
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ),
        error_val=INVALID_HANDLE_VALUE,
    )
    SetNamedPipeHandleState = _win_api(
        dll.SetNamedPipeHandleState,
        ctypes.c_bool,
        (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p),
        error_zero=True,
    )
