"""Default policy template and organization-specific starters.

Extracted in v2.1.0 (refactor) from ``picosentry/scan/policy.py``.
"""
from __future__ import annotations

import logging

from picosentry.scan.policy_pkg.engine import Policy

logger = logging.getLogger("picosentry.policy")


def default_policy_template() -> str:
    """Return a YAML template for .picosentry-policy.yml."""
    return """# PicoSentry Enterprise Policy
# Place alongside .picosentry.yml in your project root.
# See docs for full schema reference.

version: 1

# Minimum severity to fail CI on (critical, high, medium, low, info)
fail_on:
  severity: high
  # Specific rules that always fail CI regardless of severity
  rules:
    # - L2-POST-001
    # - L2-CRED-001

# License compliance: allow-list or deny-list
# Use SPDX identifiers: MIT, Apache-2.0, GPL-3.0, etc.
allow_licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC

# deny_licenses takes precedence over allow_licenses
# deny_licenses:
#   - GPL-3.0
#   - AGPL-3.0

# Block specific packages (exact name or name@version)
# deny_packages:
#   - event-stream@3.3.6
#   - left-pad
#   - malicious-package

# Environmental requirements
require:
  lockfile: true       # Require lockfile
  integrity: true      # Require integrity hashes
  provenance: false    # Require SLSA provenance (future)

# Waivers: time-bound exceptions with ownership
waivers: []
# Example:
# waivers:
#   - id: WAIVER-001
#     rule_id: L2-PROV-001
#     package: internal-tool
#     reason: "Private package with internal provenance"
#     owner: security@example.com
#     expires: "2026-09-01"
#     ticket: "https://github.com/org/repo/issues/123"
"""


def policy_from_org(org_name: str) -> Policy:
    """Create a recommended default policy for common organization types.

    Args:
        org_name: One of 'startup', 'enterprise', 'oss', 'government'.

    Returns:
        A pre-configured Policy with sensible defaults.
    """
    defaults = {
        "startup": Policy(
            fail_on_severity="high",
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"],
            require_lockfile=True,
            require_integrity=True,
        ),
        "enterprise": Policy(
            fail_on_severity="medium",
            fail_on_rules=["L2-POST-001", "L2-CRED-001", "L2-OBFS-001", "L2-OBFS-003"],
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"],
            deny_licenses=["GPL-3.0", "AGPL-3.0"],
            require_lockfile=True,
            require_integrity=True,
            require_provenance=False,
        ),
        "oss": Policy(
            fail_on_severity="critical",
            allow_licenses=[
                "MIT",
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "GPL-2.0",
                "GPL-3.0",
                "AGPL-3.0",
                "LGPL-2.1",
                "LGPL-3.0",
                "MPL-2.0",
                "0BSD",
                "Unlicense",
                "CC0-1.0",
            ],
            require_lockfile=True,
            require_integrity=False,
        ),
        "government": Policy(
            fail_on_severity="low",
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"],
            deny_licenses=["GPL-3.0", "AGPL-3.0", "UNLICENSED"],
            require_lockfile=True,
            require_integrity=True,
            require_provenance=True,
        ),
    }

    if org_name.lower() not in defaults:
        logger.warning("Unknown org type '%s'; using permissive default Policy", org_name)
    return defaults.get(org_name.lower(), Policy())


__all__ = ["default_policy_template", "policy_from_org"]
