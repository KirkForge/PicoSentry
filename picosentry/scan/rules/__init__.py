from .advisory_check import detect_all_advisory_vulnerabilities
from .bundled_shadow import detect_bundled_shadows
from .credential_read import detect_credential_reading
from .dangerous_build_hooks import detect_dangerous_build_hooks
from .dep_confusion import detect_all_dep_confusion
from .engine import detect_engine_issues
from .fork_drift import detect_fork_drift
from .license import detect_license_issues
from .lockfile_drift import detect_lockfile_drift
from .maintainer_change import detect_maintainer_changes
from .manifest import detect_manifest_issues
from .network_exfil import detect_network_exfiltration
from .obfuscation import detect_obfuscation
from .pnpm_config import detect_pnpm_config
from .post_install import detect_post_install_scripts
from .provenance import detect_provenance_issues
from .pypi_obfuscation import detect_pypi_obfuscation
from .pypi_post_install import detect_pypi_post_install
from .sideloading import detect_sideloading
from .typosquat import detect_all_typosquat
from .worm_propagation import detect_worm_propagation

__all__ = [
    "RULE_COUNT",
    "RULE_ID_ALIASES",
    "RULE_INFO",
    "all_rule_ids",
    "detect_all_advisory_vulnerabilities",
    "detect_all_dep_confusion",
    "detect_all_typosquat",
    "detect_bundled_shadows",
    "detect_credential_reading",
    "detect_dangerous_build_hooks",
    "detect_engine_issues",
    "detect_fork_drift",
    "detect_license_issues",
    "detect_lockfile_drift",
    "detect_maintainer_changes",
    "detect_manifest_issues",
    "detect_network_exfiltration",
    "detect_obfuscation",
    "detect_pnpm_config",
    "detect_post_install_scripts",
    "detect_provenance_issues",
    "detect_pypi_obfuscation",
    "detect_pypi_post_install",
    "detect_sideloading",
    "detect_worm_propagation",
]


_DOCS_BASE = "https://github.com/KirkForge/PicoSentry/blob/main/picosentry/docs/rules"


RULE_INFO = {
    "L2-POST-001": {
        "name": "post_install",
        "description": "Install scripts with network/credential access",
        "severity": "CRITICAL",
        "category": "execution",
        "helpUri": f"{_DOCS_BASE}/L2-POST-001.md",
    },
    "L2-OBFS-001": {
        "name": "obfuscation_eval",
        "description": "eval() calls in install scripts",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-OBFS-001.md",
    },
    "L2-OBFS-002": {
        "name": "obfuscation_hex",
        "description": "Hex-encoded strings in install scripts",
        "severity": "HIGH",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-OBFS-002.md",
    },
    "L2-OBFS-003": {
        "name": "obfuscation_base64",
        "description": "Base64 + exec patterns in install scripts",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-OBFS-003.md",
    },
    "L2-OBFS-004": {
        "name": "obfuscation_unicode",
        "description": "Unicode escape sequences in install scripts",
        "severity": "HIGH",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-OBFS-004.md",
    },
    "L2-DEPC-001": {
        "name": "dep_confusion",
        "description": "Internal dependencies without private registry configuration",
        "severity": "HIGH",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-DEPC-001.md",
    },
    "L2-TYPO-001": {
        "name": "typosquat",
        "description": "Package names within edit distance ≤2 of top-327 npm packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-TYPO-001.md",
    },
    "L2-MANI-001": {
        "name": "manifest_version_range",
        "description": "Dangerous version ranges (*, latest, x ranges)",
        "severity": "MEDIUM",
        "category": "manifest",
        "helpUri": f"{_DOCS_BASE}/L2-MANI-001.md",
    },
    "L2-MANI-002": {
        "name": "manifest_optional_scripts",
        "description": "Optional dependencies with install scripts",
        "severity": "HIGH",
        "category": "manifest",
        "helpUri": f"{_DOCS_BASE}/L2-MANI-002.md",
    },
    "L2-FORK-001": {
        "name": "fork_drift",
        "description": "Missing repository URL or fork indicators",
        "severity": "MEDIUM",
        "category": "provenance",
        "helpUri": f"{_DOCS_BASE}/L2-FORK-001.md",
    },
    "L2-CRED-001": {
        "name": "credential_read",
        "description": "Install scripts reading .npmrc, .aws/, .ssh/, env vars",
        "severity": "HIGH",
        "category": "credential",
        "helpUri": f"{_DOCS_BASE}/L2-CRED-001.md",
    },
    "L2-LOCK-001": {
        "name": "lockfile_drift",
        "description": "Missing lockfile, missing deps, pnpm dangerouslyAllowAllBuilds",
        "severity": "MEDIUM",
        "category": "lockfile",
        "helpUri": f"{_DOCS_BASE}/L2-LOCK-001.md",
    },
    "L2-BUND-001": {
        "name": "bundled_shadow",
        "description": "bundledDependencies shadows (event-stream attack vector)",
        "severity": "HIGH",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-BUND-001.md",
    },
    "L2-PROV-001": {
        "name": "provenance",
        "description": "Missing repo, no integrity hash, scripts without provenance",
        "severity": "LOW",
        "category": "provenance",
        "helpUri": f"{_DOCS_BASE}/L2-PROV-001.md",
    },
    "L2-MAINT-001": {
        "name": "maintainer_change",
        "description": "Publisher/author mismatch, anonymous scripts, bus factor, domain transfer",
        "severity": "MEDIUM",
        "category": "maintainer",
        "helpUri": f"{_DOCS_BASE}/L2-MAINT-001.md",
    },
    "L2-PNPM-001": {
        "name": "pnpm_config",
        "description": "dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies",
        "severity": "MEDIUM",
        "category": "lockfile",
        "helpUri": f"{_DOCS_BASE}/L2-PNPM-001.md",
    },
    "L2-LICENSE-001": {
        "name": "license",
        "description": "Missing, unlicensed, copyleft (GPL/AGPL/LGPL), or unrecognized license fields",
        "severity": "MEDIUM",
        "category": "compliance",
        "helpUri": f"{_DOCS_BASE}/L2-LICENSE-001.md",
    },
    "L2-ENGIN-001": {
        "name": "engine_constraints",
        "description": "Missing, overly permissive, or suspicious Node.js engine constraints",
        "severity": "MEDIUM",
        "category": "compatibility",
        "helpUri": f"{_DOCS_BASE}/L2-ENGIN-001.md",
    },
    "L2-SIDELOAD-001": {
        "name": "protocol_sideloading",
        "description": "Dependencies using git://, file:, link:, github: protocols that bypass registry integrity",
        "severity": "HIGH",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-SIDELOAD-001.md",
    },
    "L2-IOC-001": {
        "name": "custom_ioc_detection",
        "description": "Checks installed packages against user-registered custom IoC indicators",
        "severity": "HIGH",
        "category": "supply-chain",
        "helpUri": f"{_DOCS_BASE}/L2-IOC-001.md",
    },
    "L2-ADV-001": {
        "name": "advisory_vulnerability",
        "description": "Checks installed packages against OSV/GHSA/npm advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-ADV-001.md",
    },
    "L2-WORM-001": {
        "name": "worm_propagation",
        "description": "Self-propagating worm patterns (npm publish, curl|sh, self-modifying packages)",
        "severity": "CRITICAL",
        "category": "supply-chain",
        "helpUri": f"{_DOCS_BASE}/L2-WORM-001.md",
    },
    "L2-NETEX-001": {
        "name": "network_exfiltration",
        "description": "C2 domains, cloud metadata access, phishing domains, credential exfiltration",
        "severity": "CRITICAL",
        "category": "supply-chain",
        "helpUri": f"{_DOCS_BASE}/L2-NETEX-001.md",
    },
    "L2-GO-TYPO-001": {
        "name": "go_typosquat",
        "description": "Go module short names within edit distance <=2 of top Go packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-GO-TYPO-001.md",
    },
    "L2-GO-DEPC-001": {
        "name": "go_dep_confusion",
        "description": "Internal Go modules without private proxy configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-GO-DEPC-001.md",
    },
    "L2-GO-ADV-001": {
        "name": "go_advisory_vulnerability",
        "description": "Checks Go modules against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-GO-ADV-001.md",
    },
    "L2-CARGO-TYPO-001": {
        "name": "cargo_typosquat",
        "description": "Crate names within edit distance <=2 of top Rust crates",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-CARGO-TYPO-001.md",
    },
    "L2-CARGO-DEPC-001": {
        "name": "cargo_dep_confusion",
        "description": "Internal crates without private registry configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-CARGO-DEPC-001.md",
    },
    "L2-CARGO-ADV-001": {
        "name": "cargo_advisory_vulnerability",
        "description": "Checks Rust crates against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-CARGO-ADV-001.md",
    },
    "L2-PYPI-TYPO-001": {
        "name": "pypi_typosquat",
        "description": "Package names within edit distance <=2 of top PyPI packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-TYPO-001.md",
    },
    "L2-PYPI-DEPC-001": {
        "name": "pypi_dep_confusion",
        "description": "Internal PyPI dependencies without private index configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-DEPC-001.md",
    },
    "L2-PYPI-POST-001": {
        "name": "pypi_post_install",
        "description": "setup.py/pyproject.toml with install-time code execution",
        "severity": "CRITICAL",
        "category": "execution",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-POST-001.md",
    },
    "L2-PYPI-OBFS-001": {
        "name": "pypi_obfuscation_eval",
        "description": "exec/eval calls in Python packages",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-001.md",
    },
    "L2-PYPI-OBFS-002": {
        "name": "pypi_obfuscation_base64",
        "description": "Base64-decoded strings in Python packages",
        "severity": "HIGH",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-002.md",
    },
    "L2-PYPI-OBFS-003": {
        "name": "pypi_obfuscation_hex",
        "description": "Hex-encoded strings in Python packages",
        "severity": "HIGH",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-003.md",
    },
    "L2-PYPI-OBFS-004": {
        "name": "pypi_obfuscation_unicode",
        "description": "Unicode character arithmetic obfuscation in Python packages",
        "severity": "HIGH",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-004.md",
    },
    "L2-PYPI-OBFS-005": {
        "name": "pypi_obfuscation_zlib",
        "description": "Compressed (zlib) payload imported for execution",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-005.md",
    },
    "L2-PYPI-OBFS-006": {
        "name": "pypi_obfuscation_marshal",
        "description": "Marshal deserialization (arbitrary code execution)",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-006.md",
    },
    "L2-PYPI-OBFS-007": {
        "name": "pypi_obfuscation_b64_exec",
        "description": "Base64 decode followed by exec/eval",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-OBFS-007.md",
    },
    "L2-PYPI-ADV-001": {
        "name": "pypi_advisory_vulnerability",
        "description": "Checks installed Python packages against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-PYPI-ADV-001.md",
    },
    "L2-MAVEN-TYPO-001": {
        "name": "maven_typosquat",
        "description": "Artifact IDs within edit distance <=2 of top Maven packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-MAVEN-TYPO-001.md",
    },
    "L2-MAVEN-DEPC-001": {
        "name": "maven_dep_confusion",
        "description": "Internal Maven artifacts without private repository configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-MAVEN-DEPC-001.md",
    },
    "L2-MAVEN-ADV-001": {
        "name": "maven_advisory_vulnerability",
        "description": "Checks Maven artifacts against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-MAVEN-ADV-001.md",
    },
    "L2-RUBYGEMS-TYPO-001": {
        "name": "rubygems_typosquat",
        "description": "Gem names within edit distance <=2 of top RubyGems packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-RUBYGEMS-TYPO-001.md",
    },
    "L2-RUBYGEMS-DEPC-001": {
        "name": "rubygems_dep_confusion",
        "description": "Internal gems without private gem server configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-RUBYGEMS-DEPC-001.md",
    },
    "L2-RUBYGEMS-ADV-001": {
        "name": "rubygems_advisory_vulnerability",
        "description": "Checks Ruby gems against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-RUBYGEMS-ADV-001.md",
    },
    "L2-NUGET-TYPO-001": {
        "name": "nuget_typosquat",
        "description": "Package IDs within edit distance <=2 of top NuGet packages",
        "severity": "HIGH",
        "category": "typosquat",
        "helpUri": f"{_DOCS_BASE}/L2-NUGET-TYPO-001.md",
    },
    "L2-NUGET-DEPC-001": {
        "name": "nuget_dep_confusion",
        "description": "Internal NuGet packages without private package source configuration",
        "severity": "CRITICAL",
        "category": "dependency",
        "helpUri": f"{_DOCS_BASE}/L2-NUGET-DEPC-001.md",
    },
    "L2-NUGET-ADV-001": {
        "name": "nuget_advisory_vulnerability",
        "description": "Checks .NET packages against OSV advisory database for known CVEs",
        "severity": "HIGH",
        "category": "vulnerability",
        "helpUri": f"{_DOCS_BASE}/L2-NUGET-ADV-001.md",
    },
    "L2-BUILD-001": {
        "name": "dangerous_build_hooks",
        "description": (
            "Build scripts (Cargo, Go, RubyGems, Maven, NuGet) that spawn processes, "
            "download code, or read credentials during install"
        ),
        "severity": "CRITICAL",
        "category": "execution",
        "helpUri": f"{_DOCS_BASE}/L2-BUILD-001.md",
    },
}


RULE_COUNT = len(RULE_INFO)


RULE_ID_ALIASES: dict[str, list[str]] = {
    "detect_obfuscation": [
        "L2-OBFS-001",  # primary: general obfuscation (eval, dynamic exec)
        "L2-OBFS-002",  # sub: hex-encoded strings
        "L2-OBFS-003",  # sub: base64+exec patterns
        "L2-OBFS-004",  # sub: unicode escape sequences
    ],
    "detect_manifest_issues": [
        "L2-MANI-001",  # primary: dangerous version ranges (*, latest, x)
        "L2-MANI-002",  # sub: optional dependencies with install scripts
    ],
    "detect_pypi_obfuscation": [
        "L2-PYPI-OBFS-001",  # exec/eval
        "L2-PYPI-OBFS-002",  # base64-decoded strings
        "L2-PYPI-OBFS-003",  # hex-encoded strings
        "L2-PYPI-OBFS-004",  # unicode arithmetic
        "L2-PYPI-OBFS-005",  # zlib-compressed payloads
        "L2-PYPI-OBFS-006",  # marshal deserialization
        "L2-PYPI-OBFS-007",  # base64 decode followed by exec/eval
    ],
}


def all_rule_ids() -> set[str]:
    ids: set[str] = set(RULE_INFO.keys())
    for alias_list in RULE_ID_ALIASES.values():
        ids.update(alias_list)
    return ids
