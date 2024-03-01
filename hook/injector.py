import logging
import os
import pathlib
import sys
import threading
import time

from .client.rpc import RpcClient
from .mutex import Mutex


def get_server() -> RpcServer:
    return getattr(sys, "__inject_server__")


def wait_until(func, timeout=-1, interval=0.1, *args, **kwargs):
    start = time.perf_counter()
    while not func(*args, **kwargs):
        if 0 < timeout < time.perf_counter() - start:
            raise TimeoutError
        time.sleep(interval)


class Injector:
    logger = logging.getLogger("Injector")

    def __init__(self, process: "Process"):
        self.process = process
        self.pipe_name = rf"\\.\\pipe\\NyLibInjectPipe-pid-{self.process.process_id}"
        tmp_dir = pathlib.Path(os.environ["TEMP"])
        self.exc_file = tmp_dir / f"NyLibInjectErr{self.process.process_id}-{time.time()}.txt"
        self.lock_file = Mutex(tmp_dir / f"NyLibInjectLock-{self.process.process_id}.lck")
        self.client = RpcClient(self.pipe_name)
        self.is_starting_server = False
        self.paths = []

    def reg_std_out(self, func):
        self.client.subscribe("__std_out__", func)

    def unreg_std_out(self, func):
        self.client.unsubscribe("__std_out__", func)

    def reg_std_err(self, func):
        self.client.subscribe("__std_err__", func)

    def unreg_std_err(self, func):
        self.client.unsubscribe("__std_err__", func)

    def is_active(self):
        return self.lock_file.is_lock()

    def is_python_load(self):
        try:
            self.process.get_python_base()
        except KeyError:
            return False
        return True

    def start_server(self):
        assert not self.is_active()
        self.is_starting_server = True
        shell_code = f"""
def run_rpc_server_main():
    import threading
    import injector

    res_id_counter = injector.Counter()
    pipe_name = {repr(self.pipe_name)}
    lock_file_name = {repr(str(self.lock_file.name))}
    def run_call(code, args, res_key='res', filename="<rpc>"):
        exec(compile(code, filename, 'exec'), namespace := {{'inject_server': server, 'args': args, '__file__': filename}})
        return namespace.get(res_key)

    server = injector.RpcServer(pipe_name, {{"run": run_call}})
    sys.stdout = type('_rpc_stdout', (), {{'write': lambda _, data: server.push_event('__std_out__', data), 'flush': lambda *_: None}})()
    sys.stderr = type('_rpc_stderr', (), {{'write': lambda _, data: server.push_event('__std_err__', data), 'flush': lambda *_: None}})()
    import logging
    for handler in logging.root.handlers[:]:
        handler.stream = sys.stdout
    mutex = injector.Mutex(lock_file_name)
    if not mutex.is_lock():
        setattr(sys, '__inject_server__', server)
        with mutex: server.serve()
import traceback
import ctypes
try:
    import sys
    sys.path = {repr(sys.path + self.paths)} + sys.path
    run_rpc_server_main()
except:
    ctypes.windll.user32.MessageBoxW(0, 'error:\\n'+traceback.format_exc() ,'error' , 0x40010)
    with open({repr(str(self.exc_file))},'w',encoding='utf-8') as f:
        f.write(traceback.format_exc())
"""
        compile(shell_code, "s", "exec")
        self.process.exec_shell_code(shell_code, auto_inject=True)
        if self.exc_file.exists():
            self.logger.error("error occurred in injection:\n" + self.exc_file.read_text("utf-8"))
            self.exc_file.unlink(missing_ok=True)
        self.is_starting_server = False

    def wait_inject(self):
        if not self.is_active():
            self.logger.debug(f"python base {self.process.get_python_base(True):#x}")
            if not self.is_starting_server:
                threading.Thread(target=self.start_server, daemon=True).start()
            time.sleep(0.1)
            wait_until(self.is_active, timeout=10)

        if not self.client.is_connected.is_set():
            self.client.connect()

    def add_path(self, path):
        path = str(path)
        if self.is_active():
            self.run(f"import sys;\nif {path!r} not in sys.path:\n  sys.path.append({path!r})")
        else:
            self.paths.append(path)
        return self

    def run(self, code, *args, res_key="res", filename="<rpc>"):
        self.wait_inject()
        return self.client.rpc.run(code, args, res_key, filename)
