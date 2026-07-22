from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

__all__ = ["SandboxBackend", "SubprocessBackend"]


def get_backend(name: str = "seccomp"):
    if name == "landlock":
        from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

        backend = LandlockBackend()
        if backend.is_available():
            return backend
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        return SeccompBackend()
    if name == "seccomp":
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        return SeccompBackend()
    if name == "subprocess":
        return SubprocessBackend()
    raise ValueError(f"unknown sandbox backend: {name}")
