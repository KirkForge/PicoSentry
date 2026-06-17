
from __future__ import annotations

import json
import logging
from pathlib import Path

from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction

logger = logging.getLogger("picodome.l3.policy")


DEFAULT_RULES: list = [

    {
        "rule_id": "L3-FILE-R-001",
        "target": "file_read",
        "action": "allow",
        "paths": ["/usr/lib/**", "/lib/**", "/usr/share/**", "/etc/ld.so.cache", "/etc/localtime", "/proc/self/**"],
        "description": "Read system libraries and locale info",
    },

    {
        "rule_id": "L3-FILE-R-002",
        "target": "file_read",
        "action": "allow",
        "paths": ["/usr/lib/python3*/**", "**/site-packages/**"],
        "description": "Read Python packages",
    },

    {
        "rule_id": "L3-FILE-R-003",
        "target": "file_read",
        "action": "allow",
        "paths": ["./**", "/tmp/**"],
        "description": "Read project and temp files only",
    },

    {
        "rule_id": "L3-FILE-R-004",
        "target": "file_read",
        "action": "allow",
        "paths": [
            "**/package.json",
            "**/package-lock.json",
            "**/requirements.txt",
            "**/pyproject.toml",
            "**/setup.cfg",
            "**/setup.py",
            "**/Cargo.toml",
            "**/go.mod",
            "**/go.sum",
            "**/.npmrc",
            "**/Makefile",
            "**/CMakeLists.txt",
        ],
        "description": "Read project configuration files",
    },

    {
        "rule_id": "L3-FILE-W-001",
        "target": "file_write",
        "action": "allow",
        "paths": ["/tmp/**", "/dev/null", "/dev/stdout", "/dev/stderr"],
        "description": "Write to temp and stdio only",
    },

    {
        "rule_id": "L3-NET-OUT-001",
        "target": "network_out",
        "action": "deny",
        "description": "Block all outbound network",
    },

    {"rule_id": "L3-DNS-001", "target": "dns_query", "action": "allow", "description": "Allow DNS resolution"},

    {"rule_id": "L3-PROC-001", "target": "process_spawn", "action": "deny", "description": "Block process spawning"},

    {
        "rule_id": "L3-NET-BIND-001",
        "target": "network_bind",
        "action": "deny",
        "description": "Block network bind/listen",
    },
]


STRICT_RULES: list = [
    {"rule_id": "L3-STRICT-001", "target": "file_read", "action": "deny", "description": "Deny all file reads"},
    {"rule_id": "L3-STRICT-002", "target": "file_write", "action": "deny", "description": "Deny all file writes"},
    {"rule_id": "L3-STRICT-003", "target": "network_out", "action": "deny", "description": "Deny all outbound network"},
    {"rule_id": "L3-STRICT-004", "target": "network_in", "action": "deny", "description": "Deny all inbound network"},
    {"rule_id": "L3-STRICT-005", "target": "network_bind", "action": "deny", "description": "Deny all network binding"},
    {
        "rule_id": "L3-STRICT-006",
        "target": "process_spawn",
        "action": "deny",
        "description": "Deny all process spawning",
    },
    {"rule_id": "L3-STRICT-007", "target": "dns_query", "action": "deny", "description": "Deny all DNS queries"},
    {"rule_id": "L3-STRICT-008", "target": "file_exec", "action": "deny", "description": "Deny all file execution"},
    {"rule_id": "L3-STRICT-009", "target": "signal_send", "action": "deny", "description": "Deny all signal sending"},
]


NODE_RULES: list = [
    {
        "rule_id": "L3-NODE-R-001",
        "target": "file_read",
        "action": "allow",
        "paths": [
            "/usr/lib/**",
            "/lib/**",
            "/usr/share/**",
            "/etc/localtime",
            "/proc/self/**",
            "**/node_modules/**",
            "**/package.json",
            "**/package-lock.json",
            "**/.npm/**",
        ],
        "description": "Read Node.js system and project files",
    },
    {
        "rule_id": "L3-NODE-R-002",
        "target": "file_write",
        "action": "allow",
        "paths": [
            "/tmp/**",
            "/dev/null",
            "/dev/stdout",
            "/dev/stderr",
            "**/node_modules/**",
            "**/package-lock.json",
            "**/.npm/**",
        ],
        "description": "Write to node_modules and npm cache",
    },
    {
        "rule_id": "L3-NODE-NET-001",
        "target": "network_out",
        "action": "allow",
        "description": "Allow outbound network (npm registry)",
    },
    {"rule_id": "L3-NODE-DNS-001", "target": "dns_query", "action": "allow", "description": "Allow DNS resolution"},
    {
        "rule_id": "L3-NODE-PROC-001",
        "target": "process_spawn",
        "action": "allow",
        "description": "Allow process spawning (node, npm)",
    },
    {"rule_id": "L3-NODE-BIND-001", "target": "network_bind", "action": "allow", "description": "Allow network binding (npm needs NETLINK bind for DNS)"},
    {
        "rule_id": "L3-NODE-EXEC-001",
        "target": "file_exec",
        "action": "allow",
        "paths": [
            "/usr/bin/node",
            "/usr/local/bin/node",
            "/usr/bin/npm",
            "/usr/local/bin/npm",
            "/usr/bin/npx",
            "/usr/local/bin/npx",
        ],
        "description": "Allow node/npm execution",
    },
]


PYTHON_RULES: list = [
    {
        "rule_id": "L3-PY-R-001",
        "target": "file_read",
        "action": "allow",
        "paths": [
            "/usr/lib/**",
            "/lib/**",
            "/usr/share/**",
            "/etc/localtime",
            "/proc/self/**",
            "**/site-packages/**",
            "**/*.py",
            "**/pyproject.toml",
            "**/setup.py",
            "**/requirements.txt",
            "**/pip.conf",
            "**/.pip/**",
        ],
        "description": "Read Python system and project files",
    },
    {
        "rule_id": "L3-PY-R-002",
        "target": "file_write",
        "action": "allow",
        "paths": [
            "/tmp/**",
            "/dev/null",
            "/dev/stdout",
            "/dev/stderr",
            "**/site-packages/**",
            "**/__pycache__/**",
            "**/*.pyc",
        ],
        "description": "Write to site-packages and cache",
    },
    {
        "rule_id": "L3-PY-NET-001",
        "target": "network_out",
        "action": "allow",
        "description": "Allow outbound network (PyPI)",
    },
    {"rule_id": "L3-PY-DNS-001", "target": "dns_query", "action": "allow", "description": "Allow DNS resolution"},
    {
        "rule_id": "L3-PY-PROC-001",
        "target": "process_spawn",
        "action": "allow",
        "description": "Allow process spawning (python, pip)",
    },
    {"rule_id": "L3-PY-BIND-001", "target": "network_bind", "action": "allow", "description": "Allow network binding (pip needs NETLINK bind for DNS)"},
    {
        "rule_id": "L3-PY-EXEC-001",
        "target": "file_exec",
        "action": "allow",
        "paths": ["/usr/bin/python*", "/usr/local/bin/python*", "/usr/bin/pip*", "/usr/local/bin/pip*"],
        "description": "Allow python/pip execution",
    },
]


NAMED_POLICIES: dict[str, list[dict]] = {
    "default": DEFAULT_RULES,
    "strict": STRICT_RULES,
    "node": NODE_RULES,
    "python": PYTHON_RULES,
}


def _rules_from_list(rules_data: list) -> list[PolicyRule]:
    rules = []
    for r in rules_data:
        rules.append(
            PolicyRule(
                rule_id=r["rule_id"],
                target=RuleTarget(r["target"]),
                action=SyscallAction(r["action"]),
                paths=r.get("paths", []),
                addresses=r.get("addresses", []),
                syscalls=r.get("syscalls", []),
                description=r.get("description", ""),
            )
        )
    return rules


def load_policy(
    path: Path | None = None,
    name: str | None = None,
    verify_signature: bool = False,
) -> Policy:

    if path is not None:
        path = Path(path).resolve()
    if name is not None and ("/" in name or "\\" in name or ".." in name):
        raise ValueError(f"Invalid policy name: {name!r}")


    if name is not None and name in NAMED_POLICIES:
        logger.info("Loading named policy: %s", name)
        rules_data = NAMED_POLICIES[name]
        default_action = SyscallAction.DENY
        return Policy(
            name=f"picodome-{name}",
            version="1.0",
            default_action=default_action,
            rules=_rules_from_list(rules_data),
        )


    if path is not None:
        if verify_signature:
            from picosentry.sandbox.policy_versioned.signing import (
                load_policy_with_companion_verification,
            )

            content, result = load_policy_with_companion_verification(path)
            if not content and result and not result.valid:
                raise ValueError(f"Policy signature verification failed for {path}: {result.error}")
            data = json.loads(content)
        else:
            with open(path) as f:
                data = json.load(f)
        return _policy_from_dict(data)

    return default_policy()


def default_policy() -> Policy:
    return Policy(
        name="picodome-default",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=_rules_from_list(DEFAULT_RULES),
    )


def strict_policy() -> Policy:
    return Policy(
        name="picodome-strict",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=_rules_from_list(STRICT_RULES),
    )


def node_policy() -> Policy:
    return Policy(
        name="picodome-node",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=_rules_from_list(NODE_RULES),
    )


def python_policy() -> Policy:
    return Policy(
        name="picodome-python",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=_rules_from_list(PYTHON_RULES),
    )


def export_policy(policy: Policy, path: Path) -> None:
    data = policy.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    logger.info("Exported policy '%s' to %s", policy.name, path)


def import_policy(path: Path) -> Policy:
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    policy = _policy_from_dict(data)


    errors = validate_policy(policy)
    if errors:
        raise ValueError(
            f"Policy validation failed with {len(errors)} error(s):\n" + "\n".join(f"  - {e}" for e in errors)
        )

    logger.info("Imported and validated policy '%s' from %s", policy.name, path)
    return policy


def validate_policy(policy: Policy) -> list[str]:
    errors: list[str] = []


    if not policy.rules:
        errors.append("Policy has no rules")


    seen_ids: set[str] = set()
    for rule in policy.rules:
        if rule.rule_id in seen_ids:
            errors.append(f"Duplicate rule ID: {rule.rule_id}")
        seen_ids.add(rule.rule_id)


    valid_targets = {t.value for t in RuleTarget}
    for rule in policy.rules:
        if rule.target.value not in valid_targets:
            errors.append(f"Invalid target '{rule.target.value}' in rule {rule.rule_id}")


    valid_actions = {a.value for a in SyscallAction}
    for rule in policy.rules:
        if rule.action.value not in valid_actions:
            errors.append(f"Invalid action '{rule.action.value}' in rule {rule.rule_id}")


    for rule in policy.rules:
        if rule.target in (RuleTarget.FILE_READ, RuleTarget.FILE_WRITE, RuleTarget.FILE_EXEC) and not rule.paths and rule.action == SyscallAction.ALLOW:
            pass


    if policy.default_action.value not in valid_actions:
        errors.append(f"Invalid default_action: {policy.default_action.value}")

    return errors


def _policy_from_dict(data: dict) -> Policy:
    rules = []
    for r in data.get("rules", []):
        rules.append(
            PolicyRule(
                rule_id=r["rule_id"],
                target=RuleTarget(r["target"]),
                action=SyscallAction(r["action"]),
                paths=r.get("paths", []),
                addresses=r.get("addresses", []),
                syscalls=r.get("syscalls", []),
                description=r.get("description", ""),
            )
        )
    return Policy(
        name=data.get("name", "custom"),
        version=data.get("version", "1.0"),
        default_action=SyscallAction(data.get("default_action", "deny")),
        fail_closed=data.get("fail_closed", True),
        rules=rules,
    )
