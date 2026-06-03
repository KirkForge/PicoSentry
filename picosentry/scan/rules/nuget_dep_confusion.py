"""
L2-NUGET-DEPC-001: NuGet dependency confusion detection.

Flags private/internal package IDs that could be squatted on nuget.org.
Attackers register internal-looking package IDs on the public registry
to inject malicious code when ``dotnet restore`` resolves the package.

Pure function: (target_path, corpus_dir) -> List[Finding]

NuGet-specific considerations:
- nuget.org is the default public package source
- Private sources are configured via nuget.config <packageSources>
- Package IDs often follow org.Project pattern (e.g. Company.Library)
- Internal packages often have Company. prefix without a private source
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .nuget_utils import (
    collect_nuget_deps,
    detect_nuget_project,
    detect_private_nuget_source,
    get_nuget_dep_names,
    parse_csproj_file,
    parse_packages_config,
)

logger = logging.getLogger("picosentry.nuget_dep_confusion")

__all__ = ["detect_nuget_dep_confusion"]

# Patterns indicating internal/private package IDs
_DEFAULT_INTERNAL_PATTERNS = [
    r"^Internal\.",
    r"^Private\.",
    r"^My\.",
    r"^Company\.",
    r"^Acme\.",
    r"^Org\.",
    r"^Corp\.",
    r"-internal$",
    r"-private$",
    r"-local$",
]

# Public NuGet owner/org prefixes — packages starting with these are public
_PUBLIC_NUGET_PREFIXES: frozenset[str] = frozenset({
    "Microsoft.", "System.", "Newtonsoft.", "Serilog.", "AutoMapper.",
    "FluentValidation.", "EntityFramework.", "NUnit.", "xunit.",
    "Moq.", "Castle.Core", "log4net.", "NLog.", "StackExchange.",
    "Dapper.", "Hangfire.", "Swashbuckle.", "AWSSDK.", "Google.",
    "Amazon.", "Azure.", "RestSharp.", "Refit.", "Polly.",
    "MediatR.", "FluentAssertions.", "Shouldly.", "BenchmarkDotNet.",
    "coverlet.", "SonarAnalyzer.", "StyleCop.", "Roslynator.",
    "MongoDB.", "Elastic.", "CsvHelper.", "ClosedXML.", "EPPlus.",
    "SixLabors.", "SkiaSharp.", "MailKit.", "MimeKit.", "Quartz.",
    "MassTransit.", "RabbitMQ.", "Confluent.", "Npgsql.",
    "MySql.", "EntityFramework.",
})

# Well-known safe package suffixes/names
_KNOWN_SAFE_NUGET: frozenset[str] = frozenset({
    "NETCore.App", "AspNetCore.App", "Runtime", "Collections",
    "Linq", "Threading.Tasks", "Text.Json", "IO", "Net.Http",
    "ComponentModel", "Data", "Xml", "Reflection", "Diagnostics",
    "xunit", "Serilog", "NLog", "Moq", "Polly", "Dapper", "Refit",
    "MediatR", "Hangfire", "Quartz", "RestSharp", "AutoMapper",
    "NSubstitute", "Bogus", "Shouldly", "CsvHelper", "MailKit",
})


def _looks_internal(package_id: str) -> bool:
    """Heuristic check if a NuGet package ID looks like an internal/private package.

    Checks:
    - Package ID matches known internal prefixes (Internal., Private., Company., etc.)
    - Package ID does NOT start with a known public prefix
    - Package ID matches internal suffix patterns
    """
    for prefix in _PUBLIC_NUGET_PREFIXES:
        if package_id.startswith(prefix):
            return False

    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.search(pattern, package_id, re.IGNORECASE):
            return True

    # Single-segment package IDs (no dots) are unusual in NuGet
    # but known-safe packages should not be flagged
    if package_id in _KNOWN_SAFE_NUGET:
        return False

    if "." not in package_id and re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", package_id):
        return True

    return False


def detect_nuget_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect NuGet dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_nuget_project(target):
        return findings

    # Collect all dependencies
    deps = collect_nuget_deps(target)

    if not deps:
        return findings

    has_private = detect_private_nuget_source(target)

    for pkg_id, version, source in deps:
        if not pkg_id:
            continue

        is_internal = _looks_internal(pkg_id)

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-NUGET-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=pkg_id,
                    file=str(target / "test.csproj") if (target / "test.csproj").exists() else str(target),
                    message=(
                        f"Internal-looking package '{pkg_id}' declared "
                        "without private NuGet source configuration"
                    ),
                    evidence=f"dependency: {pkg_id}",
                    remediation=(
                        f"Configure a private NuGet source for '{pkg_id}' via "
                        "<packageSources> in nuget.config to prevent "
                        "dotnet restore from resolving it from nuget.org."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://docs.microsoft.com/en-us/nuget/consume-packages/configuring-nuget-behavior",
                    ],
                    ecosystem="nuget",
                )
            )

    return findings