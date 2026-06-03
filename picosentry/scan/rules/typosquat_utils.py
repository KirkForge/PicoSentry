"""
Shared typosquatting detection utilities — ecosystem-agnostic.

Provides Levenshtein distance, keyboard adjacency distance, homoglyph detection,
and combined scoring. Used by npm, PyPI, and all future ecosystem typosquat rules.

Pure functions only — no global state, no network calls.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("picosentry.typosquat_utils")

# ── QWERTY keyboard adjacency map ───────────────────────────────────────
# For keyboard_distance(): adjacent keys on a standard US QWERTY layout.
# Defined manually to preserve column alignment (alphabetical sort doesn't).
_KEYBOARD_ADJ: dict[str, set[str]] = {
    "q": {"w", "a"},
    "w": {"q", "e", "a", "s"},
    "e": {"w", "r", "s", "d"},
    "r": {"e", "t", "d", "f"},
    "t": {"r", "y", "f", "g"},
    "y": {"t", "u", "g", "h"},
    "u": {"y", "i", "h", "j"},
    "i": {"u", "o", "j", "k"},
    "o": {"i", "p", "k", "l"},
    "p": {"o", "l"},
    "a": {"q", "w", "s", "z"},
    "s": {"w", "e", "a", "d", "z", "x"},
    "d": {"e", "r", "s", "f", "x", "c"},
    "f": {"r", "t", "d", "g", "c", "v"},
    "g": {"t", "y", "f", "h", "v", "b"},
    "h": {"y", "u", "g", "j", "b", "n"},
    "j": {"u", "i", "h", "k", "n", "m"},
    "k": {"i", "o", "j", "l", "m"},
    "l": {"o", "p", "k"},
    "z": {"a", "s", "x"},
    "x": {"s", "d", "z", "c"},
    "c": {"d", "f", "x", "v"},
    "v": {"f", "g", "c", "b"},
    "b": {"g", "h", "v", "n"},
    "n": {"h", "j", "b", "m"},
    "m": {"j", "k", "n"},
}

# ── Common homoglyph pairs ──────────────────────────────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "0": "o",
    "1": "l",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "p",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}


def edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings — O(len(a)*len(b)).

    Public version of the original _edit_distance utility.
    """
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def keyboard_distance(a: str, b: str) -> float:
    """QWERTY keyboard adjacency cost between two strings.

    Like Levenshtein distance, but a substitution between adjacent keys
    costs 0.5 instead of 1.0. Returns float so keyboard-adjacent
    substitutions score lower than full substitutions.

    Example: ``reqct`` → ``react`` costs 0.5 instead of 1.0 because
    'q' is keyboard-adjacent to 'a'.
    """
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return float(len(a))

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertion = prev[j + 1] + 1
            deletion = curr[j] + 1
            if ca == cb:
                substitution = prev[j]
            elif _is_keyboard_adjacent(ca, cb):
                substitution = prev[j] + 0.5
            else:
                substitution = prev[j] + 1
            curr.append(min(insertion, deletion, substitution))
        prev = curr
    return prev[-1]


def _is_keyboard_adjacent(a: str, b: str) -> bool:
    """Check if two characters are adjacent on a QWERTY keyboard.

    Does NOT count equal characters as adjacent — the caller handles equality.
    """
    al = a.lower()
    bl = b.lower()
    if al == bl:
        return False
    return bl in _KEYBOARD_ADJ.get(al, set()) or al in _KEYBOARD_ADJ.get(bl, set())


def homoglyph_score(name: str) -> float:
    """Score a name for homoglyph substitution patterns.

    Returns a float 0.0–1.0 where higher means more likely a homoglyph attack.
    Counts characters that are common Unicode homoglyphs of ASCII letters.
    """
    if not name:
        return 0.0

    suspicious_count = 0
    for ch in name:
        if ch in _HOMOGLYPHS:
            suspicious_count += 1
        # Non-ASCII letters are suspicious
        if ord(ch) > 127 and ch.isalpha():
            suspicious_count += 2  # Heavier weight for non-ASCII

    return min(suspicious_count / max(len(name), 1), 1.0)


def scope_confusion_score(name: str) -> float:
    """Score a package name for scope-confusion patterns.

    npm-style scoped packages (@org/pkg) can be typosquatted as
    org-pkg or org_pkg in unscoped ecosystems (PyPI, Go).

    Returns 1.0 if the name matches an org-pkg pattern that could be
    confused with a scoped package name, 0.0 otherwise.
    """
    if name.startswith("@"):
        return 0.0  # Already scoped, not a confusion vector

    # Check for org-pkg or org_pkg or org.pkg patterns
    for sep in ("-", "_", "."):
        parts = name.split(sep)
        if len(parts) >= 2 and len(parts[0]) <= 20 and all(c.isalnum() for c in parts[0]):
            return 0.5

    return 0.0


def check_typosquat(
    dep_name: str,
    corpus: set[str],
    max_distance: float = 2.0,
    use_keyboard: bool = False,
) -> list[tuple[str, float]]:
    """Return list of (popular_package, distance) tuples for typosquat matches.

    Optimised with length filter: edit distance >= |len(a) - len(b)|,
    so entries differing by > max_distance in length can't match and are skipped.

    When use_keyboard=True, uses keyboard_distance instead of edit_distance
    for more lenient QWERTY typo detection.

    Args:
        dep_name: Package name to check.
        corpus: Set of known popular package names.
        max_distance: Maximum edit distance for a match (default 2).
        use_keyboard: Use keyboard-aware distance instead of pure Levenshtein.

    Returns:
        List of (match_name, distance) tuples, sorted by distance ascending.
    """
    # Skip scoped packages — typosquatting targets unscoped names
    if dep_name.startswith("@"):
        return []

    distance_fn = keyboard_distance if use_keyboard else edit_distance

    name_len = len(dep_name)
    matches: list[tuple[str, float]] = []
    for popular in sorted(corpus):  # sorted for determinism
        if popular == dep_name:
            continue
        # Length filter: edit distance >= |len(a) - len(b)|
        if abs(name_len - len(popular)) > max_distance:
            continue
        dist = distance_fn(dep_name, popular)
        if dist <= max_distance:
            matches.append((popular, dist))

    # Sort by distance ascending, then alphabetically for determinism
    matches.sort(key=lambda m: (m[1], m[0]))
    return matches


def typosquat_severity_confidence(
    dep_name: str,
    match_name: str,
    distance: float,
) -> tuple:
    """Determine severity and confidence for a typosquat match.

    Short names (<=4 chars) are extremely prone to false positives because
    almost any 3-4 char string is within edit distance 2 of some other
    short name. We cap these at LOW/MEDIUM to avoid noisy HIGH-severity
    findings that break CI with --fail-on high.

    For normal-length names, edit distance <=1 is HIGH (likely real squat),
    edit distance ~2 is MEDIUM (could be coincidence).
    """
    from ..models import Confidence, Severity

    min_len = min(len(dep_name), len(match_name))
    length_ratio = min_len / max(len(dep_name), len(match_name), 1)

    if min_len <= 4:
        # Short names: edit distance >= 2 at LOW, distance <= 1 at MEDIUM
        if distance >= 2:
            return Severity.LOW, Confidence.LOW
        return Severity.MEDIUM, Confidence.MEDIUM

    if distance <= 1 and length_ratio >= 0.8:
        return Severity.HIGH, Confidence.HIGH
    if distance <= 2 and length_ratio >= 0.6:
        return Severity.MEDIUM, Confidence.MEDIUM
    return Severity.LOW, Confidence.LOW


def load_corpus_for_ecosystem(
    corpus_dir: Path,
    ecosystem: str,
    builtin_list: list[str] | None = None,
) -> set[str]:
    """Load package corpus for a given ecosystem from file.

    Looks for ``{ecosystem}_top_packages.json`` in the corpus directory.
    Falls back to builtin_list if the corpus file is missing or corrupt.

    Args:
        corpus_dir: Path to the corpus directory.
        ecosystem: Ecosystem name (``npm``, ``pypi``, etc.).
        builtin_list: Fallback list of popular packages if file is missing.

    Returns:
        Set of popular package names.
    """
    corpus_file = corpus_dir / f"{ecosystem}_top_packages.json"
    if corpus_file.is_file():
        try:
            data = json.loads(corpus_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Corpus file %s is corrupt (%s), falling back to built-in list.",
                corpus_file,
                e,
            )
    else:
        logger.info(
            "No corpus file at %s, using built-in fallback. Run 'picosentry update' to download.",
            corpus_file,
        )

    if builtin_list:
        return set(builtin_list)
    return set()


# ── NPM built-in fallback corpus (top-100 npm packages) ─────────────────
BUILTIN_TOP_100: list[str] = sorted([
    "react", "react-dom", "next", "typescript", "eslint",
    "lodash", "axios", "express", "vue", "angular",
    "webpack", "babel-core", "jest", "mocha", "chalk",
    "commander", "inquirer", "dotenv", "nodemon", "npm",
    "yarn", "gulp", "grunt", "bower", "babel-loader",
    "core-js", "rxjs", "tslib", "prop-types", "styled-components",
    "material-ui", "emotion", "tailwindcss", "postcss", "sass",
    "prettier", "eslint-config-airbnb", "eslint-plugin-react",
    "babel-preset-env", "babel-preset-react", "webpack-dev-server",
    "copy-webpack-plugin", "html-webpack-plugin", "mini-css-extract-plugin",
    "terser-webpack-plugin", "fork-ts-checker-webpack-plugin",
    "css-loader", "style-loader", "file-loader", "url-loader",
    "uuid", "moment", "dayjs", "date-fns", "date-fns-tz",
    "jquery", "bootstrap", "popper.js", "d3", "chart.js",
    "three", "phaser", "pixi.js", "gsap", "hammerjs",
    "socket.io", "ws", "mqtt", "kafkajs", "amqplib",
    "mongoose", "pg", "mysql2", "redis", "ioredis",
    "prisma", "sequelize", "typeorm", "knex", "sqlite3",
    "passport", "jsonwebtoken", "bcrypt", "crypto-js",
    "helmet", "cors", "morgan", "winston", "pino",
    "debug", "bluebird", "q", "zod", "joi", "ajv",
    "class-validator", "yup", "io-ts", "runtypes",
])

# ── PyPI built-in fallback corpus (top-100 PyPI packages) ────────────────
BUILTIN_PYPI_TOP_100: list[str] = sorted([
    "pip", "setuptools", "wheel", "requests", "urllib3",
    "botocore", "boto3", "s3transfer", "certifi", "idna",
    "charset-normalizer", "cryptography", "pyyaml", "six", "python-dateutil",
    "numpy", "pandas", "scipy", "matplotlib", "scikit-learn",
    "jinja2", "markupsafe", "click", "flask", "django",
    "sqlalchemy", "alembic", "pydantic", "typing-extensions", "pydantic-core",
    "fastapi", "uvicorn", "starlette", "httpx", "anyio",
    "pytest", "coverage", "pluggy", "tomli", "iniconfig",
    "packaging", "importlib-metadata", "zipp", "more-itertools", "attrs",
    "bcrypt", "passlib", "jwcrypto", "pyjwt", "oauthlib",
    "redis", "celery", "kombu", "vine", "billiard",
    "psycopg2-binary", "asyncpg", "aiosqlite", "aioredis", "motor",
    "pillow", "opencv-python", "imageio", "scikit-image", "plotly",
    "dash", "streamlit", "gradio", "tqdm", "rich",
    "colorama", "loguru", "structlog", "python-dotenv", "environs",
    "pydantic-settings", "pydantic-extra-types", "email-validator", "dnspython", "aiosmtplib",
    "orjson", "ujson", "msgpack", "protobuf", "grpcio",
    "mypy", "ruff", "black", "isort", "flake8",
    "pre-commit", "poetry-core", "poetry", "virtualenv", "filelock",
    "platformdirs", "distlib", "pipenv", "tox", "nox",
])

# ── Go built-in fallback corpus (top-100 Go modules) ─────────────────────
BUILTIN_GO_TOP_100: list[str] = sorted([
    "kubernetes", "kubectl", "helm", "etcd", "prometheus",
    "grafana", "alertmanager", "thanos", "cadvisor", "node-exporter",
    "traefik", "caddy", "nginx-ingress", "envoy", "istio",
    "linkerd", "consul", "vault", "nomad", "terraform",
    "packer", "vagrant", "pulumi", "crossplane", "argo",
    "hugo", "syncthing", "rclone", "restic", "docker-slim",
    "minio", "cockroachdb", "tidb", "influxdb", "timescaledb",
    "mongo-go", "redis-go", "dgraph", "badger", "bolt",
    "gin", "echo", "fiber", "chi", "mux",
    "gorilla", "negroni", "revel", "buffalo", "kit",
    "cobra", "viper", "pflag", "mapstructure", "cast",
    "zap", "logrus", "zerolog", "slog", "apex",
    "gorm", "ent", "sqlx", "go-pg", "migrate",
    "pgx", "pq", "mysql", "sqlite3", "mongo-driver",
    "grpc", "protobuf", "connect-go", "twirp", "go-restful",
    "zeromq", "nats", "kafka-go", "amqp", "paho",
    "jwt-go", "bcrypt-go", "oauth2", "saml", "casbin",
    "testify", "gomega", "ginkgo", "mock", "httptest",
    "vegeta", "hey", "wrk", "pprof", "trace",
    "crypto", "net", "sys", "text", "time",
])

# ── Cargo built-in fallback corpus (top-100 Rust crates) ──────────────────
BUILTIN_CARGO_TOP_100: list[str] = sorted([
    "serde", "tokio", "rand", "reqwest", "clap",
    "serde_json", "regex", "syn", "quote", "proc-macro2",
    "axum", "actix-web", "rocket", "tide", "warp",
    "hyper", "http", "tower", "tonic", "grpc",
    "log", "env_logger", "tracing", "tracing-subscriber",
    "anyhow", "thiserror", "eyre", "color-eyre",
    "rustls", "native-tls", "openssl", "ring", "jsonwebtoken",
    "bcrypt", "argon2", "sha2", "uuid", "chrono",
    "time", "chrono-tz", "sqlx", "diesel", "sea-orm",
    "rusqlite", "sqlite", "mongodb", "redis",
    "lazy_static", "once_cell", "parking_lot", "dashmap",
    "crossbeam", "rayon", "futures", "futures-util",
    "async-trait", "async-std", "smol",
    "indicatif", "console", "dialoguer", "inquire",
    "crossterm", "ratatui", "tui",
    "yew", "leptos", "dioxus", "wasm-bindgen", "wasmer",
    "js-sys", "web-sys",
    "image", "imageproc", "piston", "ggez", "bevy",
    "macroquad", "minifb", "winit", "wgpu",
    "glam", "nalgebra", "cgmath",
    "serde_yaml", "toml", "csv", "json", "xml-rs",
    "quick-xml", "roxmltree", "pest", "nom", "combine",
    "pulldown-cmark", "comrak", "tera", "askama", "maud",
    "handlebars", "minijinja", "html2md",
])

# ── Maven built-in fallback corpus (top-100 Java/Maven artifacts) ─────────────
BUILTIN_MAVEN_TOP_100: list[str] = sorted([
    "junit-jupiter", "junit-jupiter-api", "junit-jupiter-engine", "mockito-core",
    "mockito-junit-jupiter", "assertj-core", "hamcrest", "byte-buddy",
    "spring-boot-starter-web", "spring-boot-starter", "spring-boot-starter-test",
    "spring-boot-autoconfigure", "spring-boot", "spring-core", "spring-context",
    "spring-beans", "spring-aop", "spring-expression", "spring-web",
    "spring-webmvc", "spring-boot-starter-data-jpa", "spring-security",
    "spring-security-config", "spring-security-web", "spring-security-test",
    "spring-boot-starter-security", "spring-boot-maven-plugin",
    "springdoc-openapi-starter-webmvc-ui", "springdoc-openapi",
    "hibernate-core", "hibernate-entitymanager", "h2", "mysql-connector-j",
    "postgresql", "flyway-core", "flyway-maven-plugin", "liquibase-core",
    "lombok", "mapstruct", "mapstruct-processor",
    "jackson-databind", "jackson-core", "jackson-annotations",
    "jackson-datatype-jsr310", "jackson-dataformat-xml",
    "guava", "commons-io", "commons-lang3", "commons-collections4",
    "commons-codec", "httpclient", "okhttp", "okhttp3", "retrofit2",
    "gson", "snakeyaml", "json-path", "json-smart",
    "log4j-core", "log4j-api", "logback-classic", "logback-core",
    "slf4j-api", "tomcat-embed-core", "jetty-server", "netty-all",
    "reactor-core", "reactor-netty", "rxjava", "kafka-clients",
    "mongodb-driver-sync", "lettuce-core", "jedis",
    "caffeine", "ehcache", "hazelcast",
    "jacoco-maven-plugin", "maven-compiler-plugin", "maven-surefire-plugin",
    "maven-failsafe-plugin", "maven-shade-plugin", "maven-assembly-plugin",
    "maven-jar-plugin", "maven-war-plugin", "maven-source-plugin",
    "maven-javadoc-plugin", "maven-gpg-plugin", "maven-deploy-plugin",
    "maven-release-plugin", "maven-site-plugin", "maven-resources-plugin",
    "testcontainers", "testcontainers-junit-jupiter", "wiremock",
    "awaitility", "archunit", "pitest", "checkstyle", "spotbugs",
    "pmd", "spotbugs-annotations", "error-prone-annotations",
])

# ── RubyGems built-in fallback corpus (top-100 Ruby gems) ────────────────────
BUILTIN_RUBYGEMS_TOP_100: list[str] = sorted([
    "rails", "activesupport", "actionpack", "actionview", "activerecord",
    "activemodel", "actionmailer", "activejob", "actioncable", "activestorage",
    "railties", "rack", "rake", "bundler", "json",
    "nokogiri", "devise", "puma", "sinatra", "sinatra-contrib",
    "pg", "mysql2", "sqlite3", "mongoid", "redis",
    "rspec", "rspec-rails", "rspec-core", "rspec-expectations", "rspec-mocks",
    "factory_bot", "factory_bot_rails", "faker", "database_cleaner",
    "shoulda-matchers", "capybara", "selenium-webdriver", "webmock", "vcr",
    "simplecov", "rubocop", "rubocop-rails", "rubocop-rspec", "rubocop-performance",
    "sidekiq", "resque", "delayed_job", "good_job", "solid_queue",
    "pry", "pry-rails", "byebug", "better_errors", "binding_of_caller",
    "httparty", "faraday", "typhoeus", "rest-client",
    "kaminari", "will_paginate", "pagy", "meta-tags",
    "cancancan", "pundit", "rolify", "bcrypt", "jwt",
    "omniauth", "omniauth-oauth2", "doorkeeper",
    "carrierwave", "shrine", "paperclip", "active_storage",
    "friendly_id", "ancestry", "acts_as_paranoid", "discard",
    "aasm", "state_machines", "wisper", "interactor",
    "dry-types", "dry-validation", "dry-struct", "dry-monads",
    "slim", "haml", "jbuilder", "active_model_serializers",
    "grape", "graphql", "graphql-ruby",
    "liquid", "premailer", "roadie",
    "sprockets", "sassc-rails", "bootstrap", "turbo-rails", "stimulus-rails",
    "rack-attack", "rack-cors", "rack-mini-profiler", "bullet",
    "listen", "spring", "annotate", "letter_opener", "sendgrid-ruby",
])

# ── NuGet built-in fallback corpus (top-100 .NET packages) ───────────────────
BUILTIN_NUGET_TOP_100: list[str] = sorted([
    "Newtonsoft.Json", "Serilog", "Serilog.AspNetCore", "Serilog.Sinks.Console",
    "Serilog.Sinks.File", "AutoMapper", "FluentValidation", "FluentValidation.AspNetCore",
    "MediatR", "MediatR.Extensions.Microsoft.DependencyInjection",
    "Polly", "Polly.Extensions.Http",
    "RestSharp", "Refit", "Refit.HttpClientFactory",
    "Dapper", "Dapper.SqlBuilder",
    "Microsoft.EntityFrameworkCore", "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.Tools", "Microsoft.EntityFrameworkCore.Design",
    "Npgsql.EntityFrameworkCore.PostgreSQL", "Pomelo.EntityFrameworkCore.MySql",
    "Microsoft.AspNetCore.Identity.EntityFrameworkCore",
    "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Configuration", "Microsoft.Extensions.Options",
    "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Http",
    "Microsoft.Extensions.Caching.Memory", "Microsoft.Extensions.Caching.StackExchangeRedis",
    "Microsoft.AspNetCore.Authentication.JwtBearer",
    "Microsoft.AspNetCore.Mvc.NewtonsoftJson",
    "Swashbuckle.AspNetCore", "Swashbuckle.AspNetCore.Swagger", "NSwag.AspNetCore",
    "FluentAssertions", "Shouldly",
    "xunit", "xunit.runner.visualstudio", "xunit.runner.reporters",
    "NUnit", "NUnit3TestAdapter",
    "Moq", "NSubstitute", "FakeItEasy", "Bogus", "AutoFixture",
    "BenchmarkDotNet", "coverlet.collector",
    "SonarAnalyzer.CSharp", "StyleCop.Analyzers", "Roslynator.Analyzers",
    "Hangfire", "Hangfire.SqlServer", "Hangfire.MemoryStorage",
    "StackExchange.Redis",
    "MongoDB.Driver", "MongoDB.Driver.Core", "MongoDB.Bson",
    "NLog", "NLog.Web.AspNetCore", "log4net",
    "Elastic.Clients.Elasticsearch",
    "CsvHelper", "ClosedXML", "EPPlus",
    "SixLabors.ImageSharp", "SkiaSharp",
    "MailKit", "MimeKit", "FluentEmail.Core",
    "Quartz", "Quartz.Extensions.Hosting",
    "MassTransit", "MassTransit.RabbitMQ",
    "RabbitMQ.Client", "Confluent.Kafka",
    "AWSSDK.S3", "AWSSDK.SQS", "AWSSDK.Lambda",
    "Azure.Storage.Blobs", "Azure.Messaging.ServiceBus", "Azure.Identity",
    "Google.Cloud.Storage.V1", "Google.Cloud.PubSub.V1",
    "EntityFramework", "Npgsql", "MySql.Data",
    "Microsoft.Data.SqlClient", "System.Text.Json", "System.Text.Encoding.CodePages",
    "System.Linq.Async", "System.Interactive",
])