"""PicoSentry enterprise policy-as-code — v2.1.0 back-compat shim.

The original ``picosentry/scan/policy.py`` was 836 lines. v2.1.0 splits it
into a subpackage:

- ``picosentry.scan.policy_pkg.models``   — ``Waiver``, ``PolicyViolation``,
  ``PolicyResult``, ``_parse_npm_label``, ``POLICY_VERSION``,
  ``KNOWN_POLICY_KEYS``, ``VALID_LICENSES``
- ``picosentry.scan.policy_pkg.engine``   — ``Policy`` class (with all
  evaluation methods: ``apply``, ``check_licenses``, ``check_packages``,
  ``check_requirements``, ``is_finding_waived``, ``from_file``)
- ``picosentry.scan.policy_pkg.bundle``   — ``export_signed_policy``,
  ``import_policy_bundle``
- ``picosentry.scan.policy_pkg.template`` — ``default_policy_template``,
  ``policy_from_org``

This file is a thin re-export shim so callers that import from
``picosentry.scan.policy`` keep working unchanged:

- All public classes (``Policy``, ``Waiver``, ``PolicyViolation``,
  ``PolicyResult``) are re-exported.
- All module-level functions (``default_policy_template``,
  ``export_signed_policy``, ``import_policy_bundle``, ``policy_from_org``)
  are re-exported.
- Module constants (``POLICY_VERSION``, ``KNOWN_POLICY_KEYS``,
  ``VALID_LICENSES``) and the private ``_parse_npm_label`` are re-exported.

The shim is on the deprecation path for v2.2.0: new code should import from
``picosentry.scan.policy_pkg`` directly.

.. note::

   ``picosentry.scan.crypto.sign_content`` is intentionally **not** re-exported
   from this module. The pre-refactor policy code imported ``sign_content``
   directly from :mod:`picosentry.scan.crypto`; if a test patches
   ``picosentry.scan.policy.sign_content`` after the refactor, it will only
   see the shim's local binding. Patch the source module
   (``picosentry.scan.crypto.sign_content``) or the actual call site
   (``picosentry.scan.policy_pkg.bundle.sign_content``) instead.
"""
from __future__ import annotations

# Re-export the public API. New code should import from policy_pkg directly.
from picosentry.scan.policy_pkg import (
    KNOWN_POLICY_KEYS,
    POLICY_VERSION,
    VALID_LICENSES,
    Policy,
    PolicyResult,
    PolicyViolation,
    Waiver,
    _parse_npm_label,
    default_policy_template,
    export_signed_policy,
    import_policy_bundle,
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
