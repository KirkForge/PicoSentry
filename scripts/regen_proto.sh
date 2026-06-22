#!/usr/bin/env bash
# Regenerate the committed gRPC stubs from picosentry/sandbox/grpc_transport/proto/picodome.proto.
#
# The generated *_pb2.py and *_pb2_grpc.py files are committed to the
# repo (see picosentry/sandbox/grpc_transport/proto/) so a stock
# `pip install picosentry[grpc]` works without grpcio-tools on the
# target host.  Run this script after editing picodome.proto.
#
# Tries, in order:
#   1. $PYTHON_BIN (if set and can import grpc_tools)
#   2. python3 / python on PATH that has grpc_tools
#   3. `uv run --with grpcio-tools python` (auto-installs grpcio-tools
#      into a throwaway environment — slowest, but works without any
#      pre-install)

set -euo pipefail

# Resolve repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$REPO_ROOT/picosentry/sandbox/grpc_transport/proto"

# Choose a strategy that can run `python -m grpc_tools.protoc`.
RUN_PROTOC=()
if [ -n "${PYTHON_BIN:-}" ]; then
    if "$PYTHON_BIN" -c "import grpc_tools.protoc" >/dev/null 2>&1; then
        RUN_PROTOC=("$PYTHON_BIN")
    else
        echo "error: PYTHON_BIN=$PYTHON_BIN was set but cannot import grpc_tools" >&2
        exit 1
    fi
elif command -v python3 >/dev/null 2>&1 && python3 -c "import grpc_tools.protoc" >/dev/null 2>&1; then
    RUN_PROTOC=(python3)
elif command -v python >/dev/null 2>&1 && python -c "import grpc_tools.protoc" >/dev/null 2>&1; then
    RUN_PROTOC=(python)
elif command -v uv >/dev/null 2>&1; then
    # uv run --with installs into a throwaway env, so this always works
    # if uv is on PATH (it just takes a few seconds the first time).
    RUN_PROTOC=(uv run --with grpcio-tools python)
else
    echo "error: need python, python3, or uv on PATH" >&2
    echo "       (and either needs grpc_tools, or set PYTHON_BIN explicitly)" >&2
    exit 1
fi

echo "running protoc via: ${RUN_PROTOC[*]}"

cd "$PROTO_DIR"
"${RUN_PROTOC[@]}" -m grpc_tools.protoc \
    -I . \
    --python_out=. \
    --grpc_python_out=. \
    picodome.proto

# Patch the grpc_python_out's flat import.  grpc_tools.protoc emits
#   ``import picodome_pb2 as picodome__pb2``
# at the top of picodome_pb2_grpc.py, which only works if the package
# directory is on sys.path.  In a regular Python package with
# __init__.py, that's not how imports resolve — the relative form
# ``from . import picodome_pb2 as picodome__pb2`` does.  Re-apply the
# patch on every regen so the committed stubs stay loadable.
"${RUN_PROTOC[@]}" - "$PROTO_DIR/picodome_pb2_grpc.py" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
src = path.read_text()
needle = "import picodome_pb2 as picodome__pb2"
replacement = "from . import picodome_pb2 as picodome__pb2"
if needle in src and replacement not in src:
    path.write_text(src.replace(needle, replacement))
    print(f"patched flat-import in {path}")
elif replacement in src:
    print(f"already relative-imported: {path}")
else:
    print(f"warning: could not find flat import in {path}", file=sys.stderr)
PY

# Touch the file mtimes so the .py outputs are no older than the .proto.
# (Otherwise the .proto will look "newer" than the .py on a clean checkout
# and grpcio will warn that the stubs need regenerating.)
touch -r picodome.proto picodome_pb2.py picodome_pb2_grpc.py

echo "regenerated: $PROTO_DIR/picodome_pb2.py"
echo "regenerated: $PROTO_DIR/picodome_pb2_grpc.py"
