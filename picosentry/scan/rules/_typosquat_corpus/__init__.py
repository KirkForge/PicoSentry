from __future__ import annotations

from picosentry.scan.rules._typosquat_corpus.cargo import BUILTIN_CARGO_TOP_100
from picosentry.scan.rules._typosquat_corpus.go import BUILTIN_GO_TOP_100
from picosentry.scan.rules._typosquat_corpus.maven import BUILTIN_MAVEN_TOP_100
from picosentry.scan.rules._typosquat_corpus.npm import BUILTIN_TOP_100
from picosentry.scan.rules._typosquat_corpus.nuget import BUILTIN_NUGET_TOP_100
from picosentry.scan.rules._typosquat_corpus.pypi import BUILTIN_PYPI_TOP_100
from picosentry.scan.rules._typosquat_corpus.rubygems import BUILTIN_RUBYGEMS_TOP_100

__all__: list[str] = [
    "BUILTIN_CARGO_TOP_100",
    "BUILTIN_GO_TOP_100",
    "BUILTIN_MAVEN_TOP_100",
    "BUILTIN_NUGET_TOP_100",
    "BUILTIN_PYPI_TOP_100",
    "BUILTIN_RUBYGEMS_TOP_100",
    "BUILTIN_TOP_100",
]
