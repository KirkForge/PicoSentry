#!/usr/bin/env python3
"""Normalize an sdist for byte-reproducible builds.

setuptools ignores SOURCE_DATE_EPOCH for the tar container itself: directory
entries and PKG-INFO keep build-time mtimes/uids/unames, and the gzip wrapper
embeds the compression timestamp — so two sdist builds of the same commit
hash differently even with SOURCE_DATE_EPOCH set. Wheels need no such help.

This rewrites an sdist with every member mtime clamped to the epoch, uid/gid
0 (uname/gname "root"), member order preserved, and a fixed gzip header
(mtime 0, no embedded filename). release.yml runs it after `python -m build`;
the push-tier reproducible-build job runs it on two builds and compares.

Usage: python scripts/normalize_sdist.py <src.tar.gz> <dst.tar.gz> <epoch>
"""

from __future__ import annotations

import gzip
import io
import sys
import tarfile
from pathlib import Path


def normalize_sdist(src: Path, dst: Path, epoch: int) -> None:
    with tarfile.open(src) as tar:
        members = tar.getmembers()
        contents = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}

    # Plain TarFile (not tarfile.open) — no compression sniffing; the gzip
    # wrapping below is applied once, with a pinned header.
    out = tarfile.TarFile(dst, "w", format=tarfile.GNU_FORMAT)
    try:
        for member in members:
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            out.addfile(member, io.BytesIO(contents[member.name]) if member.isfile() else None)
    finally:
        out.close()

    raw = dst.read_bytes()
    with dst.open("wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as gz:
        gz.write(raw)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {sys.argv[0]} <src.tar.gz> <dst.tar.gz> <source-date-epoch>", file=sys.stderr)
        return 2
    normalize_sdist(Path(argv[0]), Path(argv[1]), int(argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
