import json
import logging
import re
from collections import defaultdict
from typing import Any, ClassVar

from picosentry.serve.database.manager import db

from ._intelligence_data import (
    BANNER_PATTERNS,
    FILENAME_EXTENSIONS,
    MODULE_FALSE_POSITIVES,
    PATTERNS,
    PRIVATE_IP_PREFIXES,
    SAFE_DOMAINS,
    SAFE_IPS,
    _SIMPLE_IPV4_RE,
)

logger = logging.getLogger("picoshogun.Intelligence")


class IntelligenceEngine:
    PATTERNS: ClassVar[dict[str, tuple[str, str]]] = PATTERNS
    _SIMPLE_IPV4_RE: ClassVar[re.Pattern[str]] = _SIMPLE_IPV4_RE
    SAFE_IPS: ClassVar[set[str]] = SAFE_IPS
    PRIVATE_IP_PREFIXES: ClassVar[frozenset[str]] = PRIVATE_IP_PREFIXES
    BANNER_PATTERNS: ClassVar[list[re.Pattern[str]]] = BANNER_PATTERNS
    FILENAME_EXTENSIONS: ClassVar[frozenset[str]] = FILENAME_EXTENSIONS
    SAFE_DOMAINS: ClassVar[set[str]] = SAFE_DOMAINS
    MODULE_FALSE_POSITIVES: ClassVar[set[str]] = MODULE_FALSE_POSITIVES

    def __init__(self):
        self.patterns = defaultdict(list)
        self.threat_scores = defaultdict(float)
        self._load_historical()

    def _load_historical(self):
        rows = db.execute(f"""
            SELECT source_project, severity, COUNT(*) as count
            FROM intelligence
            WHERE created_at > {db.dialect.date_add_hours("now", -7 * 24)}
            GROUP BY source_project, severity
        """)
        for row in rows:
            weight = self._severity_weight(row["severity"])
            self.threat_scores[row["source_project"]] += weight * row["count"]

    def _severity_weight(self, severity: str) -> float:
        weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.1}
        return weights.get(severity.lower(), 0)

    def _is_inside_path(self, text: str, match_start: int, match_end: int) -> bool:
        before = text[max(0, match_start - 80) : match_start]
        after = text[match_end : min(len(text), match_end + 40)]

        if "/" in before[-30:] or "\\" in before[-30:]:
            stripped_before = before.rstrip()
            if not stripped_before.endswith(("://", ":\\", "http:", "https:", "ftp:")):
                return True

        for ext in self.FILENAME_EXTENSIONS:
            if after.startswith(ext) or after.lower().startswith(ext):
                return True

        stripped = before.lstrip()
        return stripped.startswith(("import ", "from ", "require(", "include(", "#include"))

    def _is_inside_quotes(self, text: str, match_start: int) -> bool:
        before = text[:match_start]

        i = len(before) - 1
        while i >= 0:
            ch = before[i]
            if ch == '"':
                num_backslashes = 0
                j = i - 1
                while j >= 0 and before[j] == "\\":
                    num_backslashes += 1
                    j -= 1
                if num_backslashes % 2 == 0:
                    return True  # Inside double-quoted string
                i -= 1
                continue
            if ch == "'":
                num_backslashes = 0
                j = i - 1
                while j >= 0 and before[j] == "\\":
                    num_backslashes += 1
                    j -= 1
                if num_backslashes % 2 == 0:
                    return True  # Inside single-quoted string
                i -= 1
                continue
            if ch == "\n":
                break  # Reached start of line — not inside quotes
            i -= 1
        return False

    def _is_in_banner_context(self, text: str, match_start: int) -> bool:

        before = text[max(0, match_start - 120) : match_start]
        line_start = before.rfind("\n") + 1
        line_before = before[line_start:]

        for banner_re in self.BANNER_PATTERNS:
            if banner_re.search(line_before):
                return True

        line = line_before.strip()

        return bool(re.match(r"^[A-Za-z][A-Za-z0-9_.\-]*\s+\d", line))

    def _is_private_ip(self, ip: str) -> bool:
        ip = ip.strip()
        if ip in self.SAFE_IPS:
            return True
        for prefix in self.PRIVATE_IP_PREFIXES:
            if ip.startswith(prefix):
                return True

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
        return ip.strip() in self.SAFE_IPS or self._is_private_ip(ip.strip())

    def _is_safe_domain(self, domain: str) -> bool:
        d = domain.strip().lower()
        if d in self.SAFE_DOMAINS:
            return True

        first_component = d.split(".")[0]
        return first_component in self.MODULE_FALSE_POSITIVES and d.count(".") == 0

    def _is_filename_keyword(self, text: str, match_start: int, match_end: int) -> bool:
        after = text[match_end : min(len(text), match_end + 20)]

        for ext in self.FILENAME_EXTENSIONS:
            if after.startswith(ext):
                return True

        if after.startswith("_"):
            return True

        before = text[max(0, match_start - 1) : match_start]
        if before.endswith("_"):
            return True

        return bool(after and after[0].islower())

    def extract_from_output(self, project_id: str, output: str, min_confidence: float = 0.3) -> list[dict[str, Any]]:
        intel: list[dict[str, Any]] = []
        if not output:
            return intel

        failure_intel = self.classify_failure(project_id, output)
        if failure_intel:
            intel.append(failure_intel)

        for intel_type, (pattern, severity) in self.PATTERNS.items():
            matches = re.finditer(pattern, output, re.IGNORECASE)
            valid_matches = []

            for match in matches:
                match_text = match.group(0)
                start, end = match.start(), match.end()

                if self._is_inside_path(output, start, end):
                    continue

                if self._is_inside_quotes(output, start):
                    continue

                if intel_type == "threat_ip" and self._is_safe_ip(match_text):
                    continue

                if intel_type == "threat_ip" and self._is_private_ip(match_text):
                    continue

                if intel_type in ("threat_ip", "suspicious_domain") and self._is_in_banner_context(output, start):
                    continue

                if intel_type == "suspicious_domain" and self._is_safe_domain(match_text):
                    continue

                if intel_type in (
                    "scan_activity",
                    "malware_signal",
                    "persistence",
                    "auth_failure",
                    "anomaly",
                    "phishing",
                ) and self._is_filename_keyword(output, start, end):
                    continue

                valid_matches.append(match_text)

            if valid_matches:
                unique_matches = list(set(valid_matches))[:10]

                confidence = min(0.5 + (len(valid_matches) - 1) * 0.1, 1.0)

                if confidence < min_confidence:
                    continue

                intel.append(
                    {
                        "type": intel_type,
                        "severity": severity,
                        "data": {
                            "matches": unique_matches,
                            "match_count": len(valid_matches),
                            "project": project_id,
                            "filtered": False,
                        },
                        "related": [],
                        "confidence": confidence,
                    }
                )

        try:
            json_blocks = re.findall(r'\{[^}]*"metrics"[^}]*\}', output)
            for block in json_blocks:
                data = json.loads(block)
                if "metrics" in data:
                    intel.append(
                        {
                            "type": "metrics",
                            "severity": "info",
                            "data": data["metrics"],
                            "related": [],
                            "confidence": 1.0,
                        }
                    )
        except (json.JSONDecodeError, re.error):
            pass

        return intel

    def classify_failure(self, project_id: str, output: str) -> dict[str, Any] | None:
        signatures = [
            (
                "syntax_error",
                r"(indentationerror|syntaxerror|unexpected token|invalid syntax)",
                "critical",
                "Python syntax/indentation error — code will never run",
            ),
            (
                "permission_denied",
                r"(permission denied|operation not permitted|eacces|access is denied)",
                "high",
                "Insufficient privileges for operation",
            ),
            (
                "missing_argument",
                r"(error:.*required|missing.*argument|too few arguments)",
                "medium",
                "Script invoked without required parameters",
            ),
            (
                "port_in_use",
                r"(address already in use|oserror.*errno 98|bind.*failed)",
                "medium",
                "Socket port already in use by another process",
            ),
            (
                "raw_socket_denied",
                r"(operation not permitted.*raw|permission denied.*socket|root required.*raw)",
                "high",
                "Raw socket requires root/capabilities",
            ),
            (
                "missing_dependency",
                r"(modulenotfounderror|importerror|no module named)",
                "high",
                "Python dependency not installed",
            ),
            (
                "file_not_found",
                r"(filenotfounderror|no such file|file not found)",
                "medium",
                "Referenced file missing at runtime",
            ),
            (
                "timeout",
                r"(timeout|timed out|connection timed out)",
                "medium",
                "Operation exceeded time limit",
            ),
            (
                "connection_refused",
                r"(connection refused|errno 111|errconnrefused)",
                "medium",
                "Target service not listening",
            ),
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
                        "snippet": output[:300].replace("\n", " "),
                    },
                    "related": [],
                    "confidence": 0.95,
                }

        return None

    def ingest(self, project_id: str, data: dict[str, Any], org_id: int | None = None):
        intel_type = data.get("type", "unknown")
        severity = data.get("severity", "info")
        intel_data = json.dumps(data.get("data", {}))
        related = json.dumps(data.get("related", []))
        confidence = data.get("confidence", 0.0)

        db.execute_insert(
            """
            INSERT INTO intelligence
            (source_project, intel_type, severity, data, related_projects, confidence, org_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (project_id, intel_type, severity, intel_data, related, confidence, org_id),
        )

        self._update_threat_score(project_id, severity, data)

        logger.info("Intelligence from %s: %s [%s] (conf: %.2f)", project_id, intel_type, severity, confidence)

    def _update_threat_score(self, project_id: str, severity: str, data: dict):
        weight = self._severity_weight(severity)

        for pid in self.threat_scores:
            self.threat_scores[pid] *= 0.95

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
        if db.dialect.backend == "postgres":
            time_expr = (
                f"i1.created_at BETWEEN i2.created_at - INTERVAL '{time_window_hours} hours' "
                f"AND i2.created_at + INTERVAL '{time_window_hours} hours'"
            )
        else:
            time_expr = f"ABS(julianday(i1.created_at) - julianday(i2.created_at)) * 24 <= {time_window_hours}"
        rows = db.execute(f"""
            SELECT
                i1.source_project as project1,
                i2.source_project as project2,
                i1.intel_type,
                i1.severity,
                COUNT(*) as correlation_count
            FROM intelligence i1
            JOIN intelligence i2 ON i1.intel_type = i2.intel_type
                AND i1.source_project != i2.source_project
                AND {time_expr}
            WHERE i1.created_at > {db.dialect.date_add_hours("now", -time_window_hours)}
            GROUP BY project1, project2, i1.intel_type
            HAVING correlation_count >= 2
            ORDER BY correlation_count DESC
        """)

        return [dict(row) for row in rows]

    def get_trends(self, hours: int = 24) -> dict[str, Any]:
        hour_col = db.dialect.hour_column("created_at")
        rows = db.execute(
            f"""
            SELECT
                intel_type,
                severity,
                {hour_col} as hour,
                COUNT(*) as count
            FROM intelligence
            WHERE created_at > {db.dialect.date_add_hours("now", -hours)}
            GROUP BY intel_type, severity, hour
            ORDER BY hour, count DESC
        """,
            (),
        )

        trends: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for row in rows:
            trends[row["intel_type"]][row["severity"]] += row["count"]

        return dict(trends)
