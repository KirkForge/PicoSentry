"""Enterprise policy-as-code subpackage for PicoSentry.

Split in v2.1.0 (refactor) from the monolithic ``picosentry/scan/policy.py``.

Submodules:
- ``models``   — Policy dataclasses + helpers (Waiver, PolicyViolation,
                 PolicyResult, _parse_npm_label, constants)
- ``engine``   — Policy class with all evaluation methods
- ``bundle``   — export_signed_policy, import_policy_bundle (signed bundles)
- ``template`` — default_policy_template, policy_from_org (org templates)

The public API is re-exported here for ``from picosentry.scan.policy_pkg import ...``
"""
from picosentry.scan.policy_pkg.models import (
    KNOWN_POLICY_KEYS,
    POLICY_VERSION,
    VALID_LICENSES,
    PolicyResult,
    PolicyViolation,
    Waiver,
    _parse_npm_label,
)
from picosentry.scan.policy_pkg.engine import Policy
from picosentry.scan.policy_pkg.bundle import (
    export_signed_policy,
    import_policy_bundle,
)
from picosentry.scan.policy_pkg.template import (
    default_policy_template,
    policy_from_org,
)

__all__ = [
    "KNOWN_POLICY_KEYS",
    "POLICY_VERSION",
    "VALID_LICENSES",
    "Policy",
    "PolicyResult",
    "PolicyViolation",
    "Waiver",
    "_parse_npm_label",
    "default_policy_template",
    "export_signed_policy",
    "import_policy_bundle",
    "policy_from_org",
]
