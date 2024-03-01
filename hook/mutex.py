import pathlib
import msvcrt


class Mutex:
    fp = None

    def __init__(self, name):
        self.name = pathlib.Path(name).absolute()

    def is_lock(self):
        if not self.name.exists():
            return False
        with open(self.name, "wb") as tmp:
            tmp.seek(0)
            try:
                msvcrt.locking(tmp.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                return True
            else:
                msvcrt.locking(tmp.fileno(), msvcrt.LK_UNLCK, 1)
                return False

    def acquire(self):
        self.fp = open(self.name, "wb")
        self.fp.seek(0)
        msvcrt.locking(self.fp.fileno(), msvcrt.LK_LOCK, 1)

    def release(self):
        self.fp.seek(0)
        msvcrt.locking(self.fp.fileno(), msvcrt.LK_UNLCK, 1)
        self.fp.close()
        self.name.unlink()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, _type, value, tb):
        self.release()
