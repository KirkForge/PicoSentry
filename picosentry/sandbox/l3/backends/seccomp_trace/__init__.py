"""Seccomp-bpf trace backend (v2.1.0 refactor).

This subpackage replaces the monolithic ``seccomp_trace_backend.py``
file. The class itself lives in ``orchestrator.py``; the rest of the
modules split the implementation along clear seams:

- ``_audit`` — audit-message constants and the x86_64 number→name table
- ``filter_builder`` — pure functions that build the seccomp-bpf filter
- ``event_parser`` — classify syscalls, parse audit text, compute verdict
- ``process_manager`` — fork+exec, /proc/seccomp reads, timeouts
- ``orchestrator`` — ``SeccompTraceBackend`` class

The public import path
``picosentry.sandbox.l3.backends.seccomp_trace.SeccompTraceBackend``
is the canonical one starting in v2.1.0. The old single-file path
(``picosentry.sandbox.l3.backends.seccomp_trace_backend``) is kept as
a thin re-export shim for back-compat through v2.1.x.
"""
from __future__ import annotations

from .orchestrator import SeccompTraceBackend

__all__ = ["SeccompTraceBackend"]
