from __future__ import annotations

from contextlib import nullcontext
from typing import Any


class NoOpSpan:
    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass

    def set_status(self, status: Any, description: str = "") -> None:
        pass

    def record_exception(self, exception: Exception, attributes: dict[str, Any] | None = None) -> None:
        pass

    def end(self) -> None:
        pass


class NoOpTracer:
    def start_as_current_span(self, name: str, **kwargs: Any):  # noqa: ARG002
        return nullcontext(NoOpSpan())

    def start_span(self, name: str, **kwargs: Any) -> NoOpSpan:  # noqa: ARG002
        return NoOpSpan()


class NoOpMeter:
    def create_counter(self, name: str, **kwargs: Any):  # noqa: ARG002
        return NoOpInstrument()

    def create_histogram(self, name: str, **kwargs: Any):  # noqa: ARG002
        return NoOpInstrument()

    def create_gauge(self, name: str, **kwargs: Any):  # noqa: ARG002
        return NoOpInstrument()

    def create_up_down_counter(self, name: str, **kwargs: Any):  # noqa: ARG002
        return NoOpInstrument()


class NoOpInstrument:
    def add(self, amount: Any, attributes: dict[str, Any] | None = None) -> None:
        pass

    def record(self, amount: Any, attributes: dict[str, Any] | None = None) -> None:
        pass

    def set(self, amount: Any, attributes: dict[str, Any] | None = None) -> None:
        pass
