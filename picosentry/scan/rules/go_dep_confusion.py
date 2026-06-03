"""
L2-GO-DEPC-001: Go module dependency confusion detection.

Flags private/internal Go module paths that could be squatted on the public
Go module proxy. Attackers register internal-looking module paths on the
Go proxy to inject malicious code when ``go get`` resolves the public module.

Pure function: (target_path, corpus_dir) -> List[Finding]

Go-specific considerations:
- The Go module proxy (proxy.golang.org) serves as the default registry
- ``GOPRIVATE``, ``GONOSUMDB``, ``GONOSUMCHECK`` env vars control private module access
- ``replace`` directives in go.mod pin local/alternative module sources
- Internal modules often follow ``company.com/internal/*`` patterns
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .go_utils import (
    detect_go_project,
    detect_goproxy_private,
    get_go_dep_names,
    parse_go_mod,
)

logger = logging.getLogger("picosentry.go_dep_confusion")

__all__ = ["detect_go_dep_confusion"]

# Horisontal patterns indicating internal/private module paths
_DEFAULT_INTERNAL_PATTERNS = [
    r"^internal-",
    r"^private-",
    r"^my-",
    r"^acme-",
    r"^company-",
    r"^org-",
    r"^corp-",
    r"/internal/",       # Go convention for internal packages
    r"/internal-",       # Internal in module path
]

# Patterns for known public module sources (safe prefixes)
_PUBLIC_MODULE_PREFIXES = {
    "github.com",
    "golang.org",
    "google.golang.org",
    "cloud.google.com",
    "go.uber.org",
    "k8s.io",
    "gopkg.in",
    "pkg.go.dev",
    "bitbucket.org",
    "gitlab.com",
    "go.opentelemetry.io",
    "go.etcd.io",
    "go.mongodb.org",
    "go.elastic.co",
    "go.redis.io",
    "go.opencensus.io",
    "gocloud.dev",
    "sigs.k8s.io",
    "knative.dev",
    "istio.io",
    "go.chromium.org",
    "google.golang.org",
    "go.uber.org",
    "go.mercari.go",
    "go.starlark.net",
}


def _looks_internal(module_path: str) -> bool:
    """Heuristic check if a module path looks like an internal/private name.

    Checks:
    - Matches known internal prefixes (internal-, private-, my-, etc.)
    - Is NOT from a known public module source
    - Contains /internal/ or /internal- segments
    """
    # Skip known public sources
    for prefix in _PUBLIC_MODULE_PREFIXES:
        if module_path.startswith(prefix + "/") or module_path == prefix:
            return False

    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.search(pattern, module_path, re.IGNORECASE):
            return True

    # Single-segment names that aren't on public sources are suspicious
    if "/" not in module_path:
        return True

    # Custom domain-like paths that aren't public: e.g. company.com/pkg
    return False


def detect_go_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Go module dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_go_project(target):
        return findings

    # Collect all dependency module paths from go.mod
    all_deps: set[str] = set()

    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        all_deps.update(get_go_dep_names(go_mod_data))

    if not all_deps:
        return findings

    has_private = detect_goproxy_private(target)

    # Check if replace directives exist for specific modules
    replaced_modules: set[str] = set()
    if go_mod_data:
        replaced_modules = set(go_mod_data.get("replace", {}).keys())

    for dep_path in sorted(all_deps):
        is_internal = _looks_internal(dep_path)
        is_replaced = dep_path in replaced_modules

        # If replaced by a replace directive, it's deliberately pinned
        if is_replaced:
            continue

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-GO-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=dep_path,
                    file=str(target / "go.mod") if (target / "go.mod").exists() else str(target),
                    message=(
                        f"Internal-looking dependency '{dep_path}' declared "
                        "without private Go proxy configuration"
                    ),
                    evidence=f"dependency: {dep_path}",
                    remediation=(
                        f"Set GOPRIVATE or GONOSUMDB for '{dep_path}' to prevent "
                        "go get from resolving it from the public Go module proxy."
                        " Alternatively, add a replace directive in go.mod."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://go.dev/ref/mod#private-modules",
                    ],
                    ecosystem="go",
                )
            )

    return findings