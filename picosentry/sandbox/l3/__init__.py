from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.sandbox.l3.engine import SandboxEngine, sandbox_run
    from picosentry.sandbox.l3.models import Policy, SandboxEvent, SandboxResult
    from picosentry.sandbox.l3.policy import default_policy, load_policy
    from picosentry.sandbox.l3.session import SandboxSession

# ponytail: l3/__init__ is a pure re-export layer; importing any l3 submodule
# no longer pays for engine+policy+session. Submodule names are in the map so
# attribute access keeps working. Upgrade path: none — dict lookup after first load.
_LAZY = {
    "engine": "engine",
    "SandboxEngine": "engine",
    "sandbox_run": "engine",
    "models": "models",
    "Policy": "models",
    "SandboxEvent": "models",
    "SandboxResult": "models",
    "policy": "policy",
    "default_policy": "policy",
    "load_policy": "policy",
    "session": "session",
    "SandboxSession": "session",
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY.get(name)
    if submodule is not None:
        from importlib import import_module

        return getattr(import_module(f"picosentry.sandbox.l3.{submodule}"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Policy",
    "SandboxEngine",
    "SandboxEvent",
    "SandboxResult",
    "SandboxSession",
    "default_policy",
    "load_policy",
    "sandbox_run",
]
