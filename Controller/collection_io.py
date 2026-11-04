"""One OS-managed lease shared by collection and offline readers."""

from contextlib import contextmanager
import os
from pathlib import Path


@contextmanager
def collection_lease(directory, create=True):
    """Nonblocking exclusive lease. Closing releases it after crashes as well."""
    path = Path(directory) / ".collection.lock"
    if not create and not path.exists():
        yield False
        return
    with path.open("a+b" if create else "r+b") as handle:
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                if path.stat().st_size == 0:
                    if not create:
                        raise OSError("Empty Windows lease cannot be checked read-only")
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise BlockingIOError("Collection lease unavailable; stop other collector/readers") from error
        yield True
