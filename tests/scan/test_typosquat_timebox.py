"""WO5.0.0-028 — L2-TYPO-001 rule-timebox regression.

On dev (c64619de), a dependency-heavy tree (400+ realistic package names)
made the pure-Python banded DP exceed the 5s per-rule timebox: the engine
skipped L2-TYPO-001 and silently dropped its findings.  The SymSpell
delete-index acceleration plus the scan-start prewarm must keep the rule
inside its timebox and return the typosquat findings.
"""

from __future__ import annotations

import json

from picosentry.scan.engine import create_default_engine
from picosentry.scan.rules._typosquat_corpus import BUILTIN_TOP_100


def _make_tree(root, packages: int = 420) -> None:
    deps = {}
    for i in range(packages):
        base = BUILTIN_TOP_100[i % len(BUILTIN_TOP_100)]
        name = f"{base}-alt{i:04d}"
        deps[name] = "^1.0.0"
        d = root / "node_modules" / name
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    # Names within edit distance 1-2 of popular packages: must be flagged.
    for i, base in enumerate(BUILTIN_TOP_100[:20]):
        pos = 2 + (i % max(1, len(base) - 4))
        squatted = base[:pos] + "q" + base[pos + 1 :]
        deps[squatted] = "^1.0.0"
    (root / "package.json").write_text(json.dumps({"name": "bench-root", "version": "1.0.0", "dependencies": deps}))


def test_typosquat_rule_completes_on_dep_heavy_tree(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    _make_tree(root)

    engine = create_default_engine()
    result = engine.scan(str(root))

    typo = [f for f in result.findings if f.rule_id == "L2-TYPO-001"]
    assert typo, "L2-TYPO-001 returned no findings on a tree seeded with 1-edit typosquats"

    executions = {e.rule_id: e for e in result.rule_executions}
    assert executions["L2-TYPO-001"].status == "ok", (
        f"L2-TYPO-001 status={executions['L2-TYPO-001'].status} — rule timeboxed out and "
        "findings were dropped (the WO5.0.0-028 regression)"
    )
