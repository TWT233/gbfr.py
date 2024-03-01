from hook.process import Process
from hook.util import run_admin, enable_privilege


def main(exe_name):
    run_admin()
    enable_privilege()
    process = Process.from_name(exe_name)
    process.injector.wait_inject()
    process.injector.reg_std_out(lambda _, s: print(s, end=""))
    process.injector.reg_std_err(lambda _, s: print(s, end=""))
    process.injector.run("import importlib;import injector;importlib.reload(injector).injected_main()")
