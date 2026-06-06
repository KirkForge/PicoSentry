"""A clean Python library with no install-time execution."""


def hello(name: str) -> str:
    return f"hello, {name}"


__all__ = ["hello"]
