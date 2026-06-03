"""Versioned policy store — track who changed what and when.

Wraps the existing Policy model with versioning metadata (author,
timestamp, change description) and provides diff, rollback, and
signing capabilities.
"""

from __future__ import annotations

from picosentry.sandbox.policy_versioned.signing import (
    PolicySignature,
    VerifyResult,
    generate_key,
    key_to_hex,
    load_key,
    load_policy_with_companion_verification,
    load_policy_with_verification,
    sign_policy,
    sign_policy_companion,
    sign_policy_file,
    strip_signature,
    verify_policy,
    verify_policy_companion,
    verify_policy_file,
)
from picosentry.sandbox.policy_versioned.store import (
    PolicyVersion,
    VersionedPolicyStore,
    get_policy_store,
)

__all__ = [
    "PolicySignature",
    "VerifyResult",
    "VersionedPolicyStore",
    "PolicyVersion",
    "generate_key",
    "get_policy_store",
    "key_to_hex",
    "load_key",
    "load_policy_with_companion_verification",
    "load_policy_with_verification",
    "sign_policy",
    "sign_policy_companion",
    "sign_policy_file",
    "strip_signature",
    "verify_policy",
    "verify_policy_companion",
    "verify_policy_file",
]
