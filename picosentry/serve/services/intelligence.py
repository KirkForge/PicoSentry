"""Cross-project intelligence engine with correlation and threat scoring."""
import json
import logging
import re
from collections import defaultdict
from typing import Any, ClassVar

from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Intelligence")

class IntelligenceEngine:
    """Intelligence engine with pattern matching and correlation."""

    # Core pattern database — tightened to reduce false positives
    PATTERNS: ClassVar[dict[str, tuple[str, str]]] = {
        "threat_ip": (r"(?<![a-zA-Z0-9._-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})(?![a-zA-Z0-9._-])", "low"),
        "suspicious_domain": (r"(?i)(?<!\w)[a-zA-Z0-9-]+\.(?:com|net|org|io|dev|app|cloud|xyz|tk|ml|cf|biz|info|top)(?!\w)", "medium"),
        "critical_vuln": (r"CRITICAL|RCE|remote\s*code\s*execution|shell", "critical"),
        "high_vuln": (r"HIGH|vulnerability|CVE-\d{4}-\d+|exploit", "high"),
        "auth_failure": (r"failed.*auth|brute\s*force|password\s*crack|login\s*fail", "medium"),
        "anomaly": (r"anomaly|unusual|outlier|z-score|deviation", "medium"),
        "malware_signal": (r"malware|trojan|virus|backdoor|rootkit", "high"),
        "crypto_signal": (r"bitcoin|wallet|private\s*key|mnemonic", "medium"),
        "scan_activity": (r"(?<![a-zA-Z_])scan(?![a-zA-Z_])|probe|nmap|port\s*scan", "low"),
        "data_exfil": (r"exfiltrat|upload|transfer\s*data|leak", "high"),
        "privilege_esc": (r"privilege\s*escalat|sudo|admin\s*access|root", "high"),
        "persistence": (r"persistence|backdoor|cron|startup", "medium"),
        "lateral_move": (r"lateral\s*movement|pivot|jump\s*host", "high"),
        "phishing": (r"phish|spear|social\s*engineer", "medium"),
        "ddos_signal": (r"ddos|flood|syn\s*flood|amplification", "high"),
        "dns_hijack": (r"dns\s*hijack|spoof|cache\s*poison", "high"),
    }

    # Known-safe patterns to exclude from matches
    # Simple pattern for fast private-IP check (avoid importing ipaddress in hot path)
    _SIMPLE_IPV4_RE = re.compile(
        r"(?<![a-zA-Z0-9._-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})(?![a-zA-Z0-9._-])"
    )

    SAFE_IPS: ClassVar[set[str]] = {"0.0.0.0", "127.0.0.1", "127.0.1.1", "255.255.255.255", "::1", "localhost"}

    # Private/reserved IP ranges — not threat indicators
    PRIVATE_IP_PREFIXES = frozenset({
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "192.168.", "169.254.",
    })

    # Server banner patterns — IPs/domains inside these are informational, not threats
    BANNER_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"SSH-[\d.]+-", re.IGNORECASE),
        re.compile(r"(?:Apache|nginx|Postfix|Dovecot|ProFTPD|vsFTPd|OpenSSH|Dnsmasq)/[\d.]+", re.IGNORECASE),
        re.compile(r"^Server:\s", re.IGNORECASE),
        re.compile(r"(?:running|powered|built)\s+(?:on|with|using)\s", re.IGNORECASE),
    ]

    # Extensions that indicate a filename, not a keyword match
    FILENAME_EXTENSIONS = frozenset({
        ".py", ".js", ".ts", ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".h",
        ".sh", ".bash", ".zsh", ".yml", ".yaml", ".json", ".toml", ".xml",
        ".html", ".css", ".md", ".txt", ".cfg", ".ini", ".conf", ".log",
        ".sql", ".proto", ".tf", ".dockerfile",
    })
    SAFE_DOMAINS: ClassVar[set[str]] = {
        "github.com", "gitlab.com", "bitbucket.org", "docker.com", "dockerhub.com",
        "pypi.org", "npmjs.com", "godotengine.org", "unity.com", "unrealengine.com",
        "python.org", "ubuntu.com", "debian.org", "archlinux.org", "fedoraproject.org",
        "stackoverflow.com", "github.io", "readthedocs.io", "readthedocs.org",
    }
    # Module names that often trigger domain false positives
    MODULE_FALSE_POSITIVES: ClassVar[set[str]] = {
        "socket", "http", "urllib", "requests", "paramiko", "logging", "config",
        "json", "pathlib", "datetime", "re", "os", "sys", "typing", "collections",
        "hashlib", "threading", "time", "sqlite3", "base64", "math", "random",
        "string", "inspect", "asyncio", "warnings", "decimal", "enum", "csv", "html",
        "xml", "pickle", "gzip", "zipfile", "tarfile", "subprocess", "tempfile",
        "uuid", "copy", "functools", "itertools", "statistics", "dataclasses", "abc",
        "fractions", "codecs", "unicodedata", "calendar", "heapq", "bisect", "array",
        "sched", "queue", "concurrent", "multiprocessing", "email", "mailbox",
        "mimetypes", "netrc", "site", "sysconfig", "builtins", "operator", "keyword",
        "token", "tokenize", "code", "codeop", "symbol", "py_compile", "compileall",
        "dis", "pickletools", "lib2to3", "msilib", "msvcrt", "winreg", "winsound",
        "ossaudiodev", "spwd", "nis", "optparse", "imp", "formatter", "curses",
        "bdb", "pdb", "profile", "cProfile", "pstats", "trace", "reprlib",
        "symtable", "opcode", "antigravity", "this", "__future__", "unittest",
        "doctest", "pydoc", "idlelib", "ensurepip", "venv", "distutils", "setuptools",
        "pip", "pkg_resources", "wheel", "twisted", "django", "flask", "bottle",
        "cherrypy", "pyramid", "web2py", "tornado", "aiohttp", "fastapi", "starlette",
        "uvicorn", "gunicorn", "celery", "rq", "huey", "dramatiq", "kafka", "pika",
        "redis", "memcached", "psycopg2", "sqlalchemy", "alembic", "pony", "dataset",
        "records", "sqlite_utils", "tinydb", "mongoengine", "pymongo", "boto3",
        "botocore", "moto", "s3transfer", "google-cloud", "azure", "elasticsearch",
        "prometheus_client", "statsd", "grafana", "influxdb", "telegraf", "chronograf",
        "kapacitor", "questdb", "timescaledb", "crate", "clickhouse", "presto",
        "trino", "drill", "impala", "hive", "pig", "spark", "flink", "storm",
        "samza", "kafka_streams", "ksql", "nifi", "airflow", "luigi", "prefect",
        "dagster", "dbt", "great_expectations", "dask", "ray", "modin", "vaex",
        "polars", "duckdb", "datafusion", "numba", "numexpr", "cython", "pythran",
        "nuitka", "pypy", "jython", "ironpython", "mypy", "pytype", "pyre",
        "pyright", "pydantic", "attrs", "cattrs", "marshmallow", "jsonschema",
        "pytest", "nose", "green", "trial", "coverage", "flake8", "pylint",
        "pycodestyle", "pyflakes", "bandit", "safety", "semgrep", "jenkins",
        "travis", "circleci", "appveyor", "gitlab-ci", "github-actions", "concourse",
        "drone", "argo", "tekton", "spinnaker", "flux", "flagger", "helm",
        "kustomize", "skaffold", "tilt", "kompose", "kubeval", "kubeconform",
        "conftest", "opa", "gatekeeper", "kyverno", "falco", "sysdig", "trivy",
        "anchore", "clair", "grype", "syft", "snyk", "whitesource", "blackduck",
        "sonatype", "jfrog", "artifactory", "nexus", "harbor", "quay", "dockerhub",
        "ecr", "acr", "gcr", "gar", "docker", "containerd", "cri-o", "runc",
        "crun", "youki", "gvisor", "kata", "firecracker", "qemu", "kvm",
        "virtualbox", "vmware", "parallels", "hyperkit", "lxc", "lxd", "podman",
        "buildah", "skopeo", "crio", "nerdctl", "rancher", "k3s", "rke", "rke2",
        "microk8s", "minikube", "kind", "kubeadm", "kops", "eksctl", "terraform",
        "pulumi", "cdktf", "cdk8s", "crossplane", "terragrunt", "atlantis", "env0",
        "scalr", "spacelift", "digger", "infracost", "tfsec", "checkov",
        "terraformer", "tflint", "vault", "consul", "nomad", "boundary", "waypoint",
        "packer", "vagrant", "serf", "vagrant-libvirt", "vagrant-lxc",
        "vagrant-docker", "vagrant-vmware", "vagrant-parallels", "vagrant-hyperv",
        "vagrant-aws", "vagrant-azure", "vagrant-gcp", "vagrant-digitalocean",
        "vagrant-linode", "vagrant-vultr", "vagrant-hetzner", "vagrant-scaleway",
        "vagrant-proxmox", "vagrant-openstack", "vagrant-rackspace",
        "vagrant-softlayer", "vagrant-joyent", "vagrant-cloudstack", "vagrant-kvm",
        "vagrant-nspawn", "vagrant-packer", "vagrant-berkshelf", "vagrant-omnibus",
        "vagrant-cachier", "oh-my-zsh", "prezto", "zim", "zinit", "antigen",
        "antibody", "zplug", "zgen", "chezmoi", "dotbot", "yadm", "stow",
        "homeshick", "vcsh", "myrepos", "etckeeper", "git-annex", "git-lfs",
        "git-crypt", "git-secret", "transcrypt",
    }

    def __init__(self):
        self.patterns = defaultdict(list)
        self.threat_scores = defaultdict(float)
        self._load_historical()

    def _load_historical(self):
        """Load historical threat scores from picosentry.serve.database."""
        rows = db.execute("""
            SELECT source_project, severity, COUNT(*) as count
            FROM intelligence
            WHERE created_at > datetime('now', '-7 days')
            GROUP BY source_project, severity
        """)
        for row in rows:
            weight = self._severity_weight(row["severity"])
            self.threat_scores[row["source_project"]] += weight * row["count"]

    def _severity_weight(self, severity: str) -> float:
        weights = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5,
            "info": 0.1
        }
        return weights.get(severity.lower(), 0)

    def _is_inside_path(self, text: str, match_start: int, match_end: int) -> bool:
        """Check if a match is inside a file path (e.g., /home/user/project.py)."""
        before = text[max(0, match_start - 80):match_start]
        after = text[match_end:min(len(text), match_end + 40)]

        # Path separators before the match
        if '/' in before[-30:] or '\\' in before[-30:]:
            # But check it's not a URL (http:// etc)
            stripped_before = before.rstrip()
            if not stripped_before.endswith(("://", ":\\", "http:", "https:", "ftp:")):
                return True

        # Filename extension after the match (e.g., "scan_activity.py")
        for ext in self.FILENAME_EXTENSIONS:
            if after.startswith(ext) or after.lower().startswith(ext):
                return True

        # Import statement before match
        stripped = before.lstrip()
        return stripped.startswith(("import ", "from ", "require(", "include(", "#include"))

    def _is_inside_quotes(self, text: str, match_start: int, match_end: int) -> bool:
        """Check if match is inside a quoted string (import/require/code context).

        Walks backwards from the match to find the nearest unescaped opening
        quote, handling escaped quotes (\', \") correctly.
        """
        before = text[:match_start]
        # Walk backwards to find the nearest unescaped opening quote
        i = len(before) - 1
        while i >= 0:
            ch = before[i]
            if ch == '"':
                # Check if escaped
                num_backslashes = 0
                j = i - 1
                while j >= 0 and before[j] == '\\':
                    num_backslashes += 1
                    j -= 1
                if num_backslashes % 2 == 0:
                    return True  # Inside double-quoted string
                i -= 1
                continue
            if ch == "'":
                num_backslashes = 0
                j = i - 1
                while j >= 0 and before[j] == '\\':
                    num_backslashes += 1
                    j -= 1
                if num_backslashes % 2 == 0:
                    return True  # Inside single-quoted string
                i -= 1
                continue
            if ch == '\n':
                break  # Reached start of line — not inside quotes
            i -= 1
        return False

    def _is_in_banner_context(self, text: str, match_start: int) -> bool:
        """Check if the match appears inside a service banner (informational, not a threat)."""
        # Check 120 chars before the match for banner-like patterns
        before = text[max(0, match_start - 120):match_start]
        line_start = before.rfind("\n") + 1
        line_before = before[line_start:]

        for banner_re in self.BANNER_PATTERNS:
            if banner_re.search(line_before):
                return True

        # Also check: is this on a line that looks like a version/banner string?
        line = line_before.strip()
        # "Something 1.2.3" looks like a version string
        return bool(re.match(r"^[A-Za-z][A-Za-z0-9_.\-]*\s+\d", line))

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved ranges (RFC 1918, link-local)."""
        ip = ip.strip()
        if ip in self.SAFE_IPS:
            return True
        for prefix in self.PRIVATE_IP_PREFIXES:
            if ip.startswith(prefix):
                return True
        # Strict check for 172.16.0.0/12
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        return True
                except ValueError:
                    pass
        return False

    def _is_safe_ip(self, ip: str) -> bool:
        """Check if IP is known-safe or private (not a threat indicator)."""
        return ip.strip() in self.SAFE_IPS or self._is_private_ip(ip.strip())

    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is known-safe.

        Matches exact SAFE_DOMAINS and exact MODULE_FALSE_POSITIVES names.
        Does NOT match arbitrary subdomains like "socket.evil.com" which
        could bypass the check.
        """
        d = domain.strip().lower()
        if d in self.SAFE_DOMAINS:
            return True
        # Only match exact module names (e.g., "socket") not subdomains
        # like "socket.evil.com" which could be a real domain
        first_component = d.split(".")[0]
        return first_component in self.MODULE_FALSE_POSITIVES and d.count(".") == 0

    def _is_filename_keyword(self, text: str, match_start: int, match_end: int) -> bool:
        """Check if a keyword match is actually part of a filename or identifier."""
        after = text[match_end:min(len(text), match_end + 20)]
        # "scan" followed by .py, .log, etc. is a filename
        for ext in self.FILENAME_EXTENSIONS:
            if after.startswith(ext):
                return True
        # "scan" followed by _ (scan_activity, scan_results) is likely an identifier
        if after.startswith("_"):
            return True
        # "scan" preceded by _ (port_scan, vuln_scan) is an identifier
        before = text[max(0, match_start - 1):match_start]
        if before.endswith("_"):
            return True
        # "scan" in snake_case identifiers (port_scanner, scan_runner)
        return bool(after and after[0].islower())

    def extract_from_output(self, project_id: str, output: str, min_confidence: float = 0.3) -> list[dict[str, Any]]:
        """Parse project output for intelligence signals with context-aware filtering."""
        intel: list[dict[str, Any]] = []
        if not output:
            return intel

        # Failure signature classification FIRST — always include
        failure_intel = self.classify_failure(project_id, output)
        if failure_intel:
            intel.append(failure_intel)

        for intel_type, (pattern, severity) in self.PATTERNS.items():
            matches = re.finditer(pattern, output, re.IGNORECASE)
            valid_matches = []

            for match in matches:
                match_text = match.group(0)
                start, end = match.start(), match.end()

                # Skip if inside a file path
                if self._is_inside_path(output, start, end):
                    continue

                # Skip if inside quoted string
                if self._is_inside_quotes(output, start, end):
                    continue

                # Type-specific filtering
                if intel_type == "threat_ip" and self._is_safe_ip(match_text):
                    continue

                # Private IPs are not threat indicators
                if intel_type == "threat_ip" and self._is_private_ip(match_text):
                    continue

                # IPs/domains inside service banners are informational
                if intel_type in ("threat_ip", "suspicious_domain") and self._is_in_banner_context(output, start):
                    continue

                if intel_type == "suspicious_domain" and self._is_safe_domain(match_text):
                    continue

                # Keyword patterns in filenames/identifiers are false positives
                if intel_type in ("scan_activity", "malware_signal", "persistence", "auth_failure",
                                  "anomaly", "phishing") and self._is_filename_keyword(output, start, end):
                    continue

                valid_matches.append(match_text)

            if valid_matches:
                unique_matches = list(set(valid_matches))[:10]
                # Confidence: base 0.5 for any match + 0.1 per extra, capped at 1.0
                confidence = min(0.5 + (len(valid_matches) - 1) * 0.1, 1.0)

                # Apply min_confidence threshold
                if confidence < min_confidence:
                    continue

                intel.append({
                    "type": intel_type,
                    "severity": severity,
                    "data": {
                        "matches": unique_matches,
                        "match_count": len(valid_matches),
                        "project": project_id,
                        "filtered": False
                    },
                    "related": [],
                    "confidence": confidence
                })

        # Extract metrics if present in JSON format
        try:
            json_blocks = re.findall(r'\{[^}]*"metrics"[^}]*\}', output)
            for block in json_blocks:
                data = json.loads(block)
                if "metrics" in data:
                    intel.append({
                        "type": "metrics",
                        "severity": "info",
                        "data": data["metrics"],
                        "related": [],
                        "confidence": 1.0
                    })
        except (json.JSONDecodeError, re.error):
            pass

        return intel

    def classify_failure(self, project_id: str, output: str) -> dict[str, Any] | None:
        """Classify script failure type from stderr/stdout. Returns intelligence dict or None."""
        signatures = [
            ("syntax_error", r"(indentationerror|syntaxerror|unexpected token|invalid syntax)", "critical", "Python syntax/indentation error — code will never run"),
            ("permission_denied", r"(permission denied|operation not permitted|eacces|access is denied)", "high", "Insufficient privileges for operation"),
            ("missing_argument", r"(error:.*required|missing.*argument|too few arguments)", "medium", "Script invoked without required parameters"),
            ("port_in_use", r"(address already in use|oserror.*errno 98|bind.*failed)", "medium", "Socket port already in use by another process"),
            ("raw_socket_denied", r"(operation not permitted.*raw|permission denied.*socket|root required.*raw)", "high", "Raw socket requires root/capabilities"),
            ("missing_dependency", r"(modulenotfounderror|importerror|no module named)", "high", "Python dependency not installed"),
            ("file_not_found", r"(filenotfounderror|no such file|file not found)", "medium", "Referenced file missing at runtime"),
            ("timeout", r"(timeout|timed out|connection timed out)", "medium", "Operation exceeded time limit"),
            ("connection_refused", r"(connection refused|errno 111|errconnrefused)", "medium", "Target service not listening"),
        ]

        for sig_type, pattern, severity, description in signatures:
            if re.search(pattern, output, re.IGNORECASE):
                return {
                    "type": f"failure_{sig_type}",
                    "severity": severity,
                    "data": {
                        "project": project_id,
                        "signature": sig_type,
                        "description": description,
                        "match_count": 1,
                        "snippet": output[:300].replace("\n", " ")
                    },
                    "related": [],
                    "confidence": 0.95
                }

        return None

    def ingest(self, project_id: str, data: dict[str, Any]):
        """Ingest intelligence from a project run."""
        intel_type = data.get("type", "unknown")
        severity = data.get("severity", "info")
        intel_data = json.dumps(data.get("data", {}))
        related = json.dumps(data.get("related", []))
        confidence = data.get("confidence", 0.0)

        db.execute_insert("""
            INSERT INTO intelligence
            (source_project, intel_type, severity, data, related_projects, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (project_id, intel_type, severity, intel_data, related, confidence))

        self._update_threat_score(project_id, severity, data)

        logger.info("Intelligence from %s: %s [%s] (conf: %.2f)", project_id, intel_type, severity, confidence)

    def _update_threat_score(self, project_id: str, severity: str, data: dict):
        """Update composite threat score with exponential decay."""
        weight = self._severity_weight(severity)

        # Decay old scores
        for pid in self.threat_scores:
            self.threat_scores[pid] *= 0.95

        # Add new score based on match count
        match_count = data.get("data", {}).get("match_count", 1)
        self.threat_scores[project_id] += weight * match_count

        total = sum(self.threat_scores.values())
        level = self._threat_level(total)
        logger.info("Aggregate threat: %.1f [%s] (%s sources)", total, level, len(self.threat_scores))

    def _threat_level(self, score: float) -> str:
        if score >= 50:
            return "critical"
        if score >= 20:
            return "high"
        if score >= 5:
            return "medium"
        return "low"

    def get_aggregate_score(self) -> float:
        return sum(self.threat_scores.values())

    def find_correlations(self, time_window_hours: int = 24) -> list[dict[str, Any]]:
        """Find correlated intelligence across projects."""
        rows = db.execute("""
            SELECT
                i1.source_project as project1,
                i2.source_project as project2,
                i1.intel_type,
                i1.severity,
                COUNT(*) as correlation_count
            FROM intelligence i1
            JOIN intelligence i2 ON i1.intel_type = i2.intel_type
                AND i1.source_project != i2.source_project
                AND ABS(julianday(i1.created_at) - julianday(i2.created_at)) * 24 <= ?
            WHERE i1.created_at > datetime('now', '-' || ? || ' hours')
            GROUP BY project1, project2, i1.intel_type
            HAVING correlation_count >= 2
            ORDER BY correlation_count DESC
        """, (time_window_hours, str(time_window_hours)))

        return [dict(row) for row in rows]

    def get_trends(self, hours: int = 24) -> dict[str, Any]:
        """Get intelligence trends over time."""
        rows = db.execute("""
            SELECT
                intel_type,
                severity,
                strftime('%H', created_at) as hour,
                COUNT(*) as count
            FROM intelligence
            WHERE created_at > datetime('now', '-' || ? || ' hours')
            GROUP BY intel_type, severity, hour
            ORDER BY hour, count DESC
        """, (str(hours),))

        trends: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for row in rows:
            trends[row["intel_type"]][row["severity"]] += row["count"]

        return dict(trends)
