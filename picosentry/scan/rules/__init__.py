"""Scanner rules — deterministic, offline, pure-function detectors.

Each rule is a pure function: (target_path, corpus_dir) → List[Finding]
No HTTP. No global state. No randomness. Same input = same output.
"""

from .bundled_shadow import detect_bundled_shadows
from .credential_read import detect_credential_reading
from .dep_confusion import detect_dep_confusion
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
from .sideloading import detect_sideloading
from .typosquat import detect_typosquat
from .worm_propagation import detect_worm_propagation

__all__ = [
    "detect_post_install_scripts",
    "detect_obfuscation",
    "detect_dep_confusion",
    "detect_typosquat",
    "detect_manifest_issues",
    "detect_fork_drift",
    "detect_credential_reading",
    "detect_lockfile_drift",
    "detect_bundled_shadows",
    "detect_provenance_issues",
    "detect_maintainer_changes",
    "detect_pnpm_config",
    "detect_license_issues",
    "detect_engine_issues",
    "detect_sideloading",
    "detect_worm_propagation",
    "detect_network_exfiltration",
]

# Base documentation URL for PicoSentry rules
_DOCS_BASE = "https://github.com/KirkForge/PicoSentry/blob/main/picosentry/docs/rules"

# Rule metadata registry — description, default severity, category, helpUri
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
}

# Total detector rules
RULE_COUNT = len(RULE_INFO)
