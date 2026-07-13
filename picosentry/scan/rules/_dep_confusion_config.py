from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .cargo_utils import detect_cargo_project
from .go_utils import detect_go_project
from .nuget_utils import detect_nuget_project
from .pypi_utils import detect_pypi_project
from .rubygems_utils import detect_rubygems_project

__all__ = [
    "_CARGO_CONFIG",
    "_GO_CONFIG",
    "_INTERNAL_ALL_PATTERNS",
    "_INTERNAL_EXTRA_PATTERNS",
    "_INTERNAL_PREFIX_PATTERNS",
    "_MAVEN_KNOWN_SAFE_ARTIFACTS",
    "_MAVEN_PUBLIC_GROUP_PREFIXES",
    "_NUGET_CONFIG",
    "_PYPI_CONFIG",
    "_RUBYGEMS_CONFIG",
    "DepConfusionConfig",
]


_INTERNAL_PREFIX_PATTERNS = [
    r"^internal-",
    r"^private-",
    r"^my-",
    r"^acme-",
    r"^company-",
    r"^org-",
    r"^corp-",
]

_INTERNAL_EXTRA_PATTERNS = [
    r"^test-",
    r"^example-",
    r"^local-",
    r"-internal$",
    r"-private$",
    r"-local$",
]

_INTERNAL_ALL_PATTERNS = _INTERNAL_PREFIX_PATTERNS + _INTERNAL_EXTRA_PATTERNS


@dataclass(frozen=True)
class DepConfusionConfig:
    ecosystem: str
    rule_id: str
    detect_project: Callable[[Path], bool]
    internal_patterns: list[str] = field(default_factory=lambda: _INTERNAL_ALL_PATTERNS)
    known_public_prefixes: set[str] = field(default_factory=set)
    known_safe_names: set[str] = field(default_factory=set)
    check_single_segment: bool = False
    doc_url: str = "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4"

    def __hash__(self):
        return hash(self.ecosystem)


_MAVEN_PUBLIC_GROUP_PREFIXES: frozenset[str] = frozenset(
    {
        "org.springframework",
        "com.fasterxml",
        "org.apache",
        "com.google",
        "org.slf4j",
        "org.junit",
        "org.mockito",
        "org.hibernate",
        "io.netty",
        "io.reactivex",
        "io.micrometer",
        "io.grpc",
        "io.vertx",
        "io.quarkus",
        "io.dropwizard",
        "io.jsonwebtoken",
        "com.fasterxml.jackson",
        "com.squareup",
        "com.github",
        "net.bytebuddy",
        "net.sf",
        "org.jboss",
        "org.eclipse",
        "org.projectlombok",
        "org.checkerframework",
        "org.jetbrains",
        "com.zaxxer",
        "org.yaml",
        "org.codehaus",
        "org.gradle",
        "org.apache.maven",
        "org.apache.logging",
        "org.apache.commons",
        "org.apache.httpcomponents",
        "org.jacoco",
        "com.thoughtworks",
        "tech.units",
        "javax",
        "jakarta",
    }
)

_MAVEN_KNOWN_SAFE_ARTIFACTS: frozenset[str] = frozenset(
    {
        "api",
        "core",
        "common",
        "util",
        "utils",
        "server",
        "client",
        "annotations",
        "parent",
        "boot",
        "starter",
        "data",
        "jpa",
        "security",
        "web",
        "model",
        "dto",
        "service",
        "dao",
        "impl",
    }
)


_GO_CONFIG = DepConfusionConfig(
    ecosystem="go",
    rule_id="L2-GO-DEPC-001",
    detect_project=detect_go_project,
    internal_patterns=_INTERNAL_PREFIX_PATTERNS,
    known_public_prefixes={
        "github.com",
        "golang.org",
        "google.golang.org",
        "cloud.google.com",
        "go.uber.org",
        "k8s.io",
        "gopkg.in",
        "pkg.go.dev",
        "bitbucket.org",
        "gitlab.com",
        "go.opentelemetry.io",
        "go.etcd.io",
        "go.mongodb.org",
        "go.elastic.co",
        "go.redis.io",
        "go.opencensus.io",
        "gocloud.dev",
        "sigs.k8s.io",
        "knative.dev",
        "istio.io",
        "go.chromium.org",
        "go.starlark.net",
    },
    check_single_segment=True,
)

_CARGO_CONFIG = DepConfusionConfig(
    ecosystem="cargo",
    rule_id="L2-CARGO-DEPC-001",
    detect_project=detect_cargo_project,
    internal_patterns=_INTERNAL_ALL_PATTERNS,
    known_safe_names={"core", "alloc", "std", "proc-macro2", "proc-macro-hack"},
)

_PYPI_CONFIG = DepConfusionConfig(
    ecosystem="pypi",
    rule_id="L2-PYPI-DEPC-001",
    detect_project=detect_pypi_project,
    internal_patterns=_INTERNAL_PREFIX_PATTERNS,
)

_NUGET_CONFIG = DepConfusionConfig(
    ecosystem="nuget",
    rule_id="L2-NUGET-DEPC-001",
    detect_project=detect_nuget_project,
    internal_patterns=[
        r"^Internal\.",
        r"^Private\.",
        r"^My\.",
        r"^Company\.",
        r"^Acme\.",
        r"^Org\.",
        r"^Corp\.",
        r"-internal$",
        r"-private$",
        r"-local$",
    ],
    known_public_prefixes={
        "Microsoft.",
        "System.",
        "Newtonsoft.",
        "Serilog.",
        "AutoMapper.",
        "FluentValidation.",
        "EntityFramework.",
        "NUnit.",
        "xunit.",
        "Moq.",
        "Castle.Core",
        "log4net.",
        "NLog.",
        "StackExchange.",
        "Dapper.",
        "Hangfire.",
        "Swashbuckle.",
        "AWSSDK.",
        "Google.",
        "Amazon.",
        "Azure.",
        "RestSharp.",
        "Refit.",
        "Polly.",
        "MediatR.",
        "FluentAssertions.",
        "Shouldly.",
        "BenchmarkDotNet.",
        "coverlet.",
        "SonarAnalyzer.",
        "StyleCop.",
        "Roslynator.",
        "MongoDB.",
        "Elastic.",
        "CsvHelper.",
        "ClosedXML.",
        "EPPlus.",
        "SixLabors.",
        "SkiaSharp.",
        "MailKit.",
        "MimeKit.",
        "Quartz.",
        "MassTransit.",
        "RabbitMQ.",
        "Confluent.",
        "Npgsql.",
        "MySql.",
    },
    known_safe_names={
        "NETCore.App",
        "AspNetCore.App",
        "Runtime",
        "Collections",
        "Linq",
        "Threading.Tasks",
        "Text.Json",
        "IO",
        "Net.Http",
        "ComponentModel",
        "Data",
        "Xml",
        "Reflection",
        "Diagnostics",
        "xunit",
        "Serilog",
        "NLog",
        "Moq",
        "Polly",
        "Dapper",
        "Refit",
        "MediatR",
        "Hangfire",
        "Quartz",
        "RestSharp",
        "AutoMapper",
        "NSubstitute",
        "Bogus",
        "Shouldly",
        "CsvHelper",
        "MailKit",
    },
    check_single_segment=True,
)

_RUBYGEMS_CONFIG = DepConfusionConfig(
    ecosystem="rubygems",
    rule_id="L2-RUBYGEMS-DEPC-001",
    detect_project=detect_rubygems_project,
    internal_patterns=_INTERNAL_ALL_PATTERNS,
    known_safe_names={
        "rails",
        "rack",
        "rake",
        "bundler",
        "json",
        "minitest",
        "test-unit",
        "psych",
        "io-console",
        "bigdecimal",
        "csv",
        "date",
        "stringio",
        "strscan",
        "base64",
        "digest",
        "securerandom",
    },
)
