import ctypes
import locale
import sys

from .dll import Kernel32, ADVApi32
from .process_entry_32 import ProcessEntry32


def align4(v):
    return (v + 0x3) & (~0x3)


def align16(v):
    return (v + 0xF) & (~0xF)


def run_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except:
        pass
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    raise PermissionError(
        "Need admin permission, a new process should be started, if not, please run it as admin manually"
    )


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("count", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


def enable_privilege():
    p = ctypes.c_void_p(Kernel32.GetCurrentProcess())
    if ADVApi32.OpenProcessToken(p, 32, ctypes.byref(p)):
        tp = TOKEN_PRIVILEGES()
        ADVApi32.LookupPrivilegeValue(None, "SeDebugPrivilege", ctypes.byref(tp.Privileges[0].Luid))
        tp.count = 1
        tp.Privileges[0].Attributes = 2
        ADVApi32.AdjustTokenPrivileges(p, 0, ctypes.byref(tp), 0, None, None)


DEFAULT_CODING = locale.getpreferredencoding()


def pid_by_executable(executable_name: bytes | str):
    if isinstance(executable_name, str):
        executable_name = executable_name.encode(DEFAULT_CODING)

    def _iter_processes():
        snapshot = Kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # SNAPPROCESS
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        Kernel32.Process32First(snapshot, ctypes.byref(entry))
        try:
            yield entry
            while 1:
                yield entry
                Kernel32.Process32Next(snapshot, ctypes.byref(entry))
        except WindowsError as e:
            if e.winerror != 18:
                raise
        finally:
            Kernel32.CloseHandle(snapshot)

    for process in _iter_processes():
        if process.szExeFile == executable_name:
            yield process.th32ProcessID
