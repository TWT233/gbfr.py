import ctypes
import threading
import typing

from ..dll import Kernel32

try:
    import win32file, win32pipe, win32event
except ImportError:
    has_win32 = False
else:
    has_win32 = True

_T = typing.TypeVar("_T")


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p),
    ]


class PipeHandlerBase:
    active_pipe_handler = {}
    buf_size = 64 * 1024
    handle = None
    period = 0.001

    def __init__(self):
        self.serve_thread = threading.Thread(target=self.serve, daemon=True)
        self.work = False
        self.is_connected = threading.Event()

    if has_win32:

        def send(self, s: bytes):
            win32file.WriteFile(self.handle, s, win32file.OVERLAPPED())

        def _serve(self):
            tid = threading.get_ident()
            PipeHandlerBase.active_pipe_handler[tid] = self
            try:
                self.is_connected.set()
                self.work = True
                overlapped = win32file.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
                while self.work:
                    err, buf = win32file.ReadFile(self.handle, self.buf_size, overlapped)
                    num_read = win32file.GetOverlappedResult(self.handle, overlapped, True)
                    self.on_data_received(bytes(buf[:num_read]))
            finally:
                if PipeHandlerBase.active_pipe_handler[tid] is self:
                    PipeHandlerBase.active_pipe_handler.pop(tid, None)

    else:

        def send(self, s: bytes):
            Kernel32.WriteFile(self.handle, s, len(s), None, ctypes.byref(OVERLAPPED()))

        def _serve(self):
            tid = threading.get_ident()
            PipeHandlerBase.active_pipe_handler[tid] = self
            try:
                self.is_connected.set()
                self.work = True
                buf = ctypes.create_string_buffer(self.buf_size + 0x10)
                size = ctypes.c_ulong()
                overlapped = OVERLAPPED()
                overlapped.hEvent = Kernel32.CreateEvent(None, True, False, None)
                while self.work:
                    try:
                        Kernel32.ReadFile(self.handle, buf, self.buf_size, 0, ctypes.byref(overlapped))
                    except WindowsError as e:
                        if e.winerror != 997:
                            raise
                        Kernel32.WaitForSingleObject(overlapped.hEvent, -1)
                    Kernel32.GetOverlappedResult(self.handle, ctypes.byref(overlapped), ctypes.byref(size), True)
                    self.on_data_received(bytes(buf[: size.value]))
            finally:
                if PipeHandlerBase.active_pipe_handler[tid] is self:
                    PipeHandlerBase.active_pipe_handler.pop(tid, None)

    def serve(self):
        try:
            self.on_connect()
            self._serve()
        except Exception as e:
            self.on_close(e)
        else:
            self.on_close(None)
        finally:
            try:
                Kernel32.CloseHandle(self.handle)
            except Exception:
                pass

    def close(self, block=True):
        self.work = False
        Kernel32.CloseHandle(self.handle)
        if block:
            self.serve_thread.join()

    def on_connect(self):
        pass

    def on_close(self, e: Exception | None):
        pass

    def on_data_received(self, data: bytes):
        pass
