from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.prompt_guard.normalize import Normalizer
from picosentry.watch.prompt_guard.rules import RuleEngine
from picosentry.watch.types import PromptScanResult, Rule, ValidationResult


class OutputGuard:
    def __init__(
        self,
        rules_dir: Path | None = None,
        config: PicoWatchConfig | None = None,
    ) -> None:
        self._config = config or PicoWatchConfig()
        self._rules_dir = rules_dir or self._config.rules_dir / "output_policy"
        self._normalizer = Normalizer()
        self._engine = RuleEngine(rules_dir=self._rules_dir)
        self._loaded_schemas: dict[str, dict[str, Any]] = {}
        if self._config.schema_dir and self._config.schema_dir.exists():
            self._load_schemas(self._config.schema_dir)

    @property
    def rules(self) -> list[Rule]:
        return self._engine.rules

    @property
    def corpus_hash(self) -> str:
        return self._engine.corpus_hash

    def _load_schemas(self, schema_dir: Path) -> None:
        for schema_file in sorted(schema_dir.glob("*.json")):
            try:
                data = json.loads(schema_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._loaded_schemas[schema_file.stem] = data
            except (json.JSONDecodeError, OSError) as exc:
                import logging

                logging.getLogger("picowatch.output_guard").warning(
                    "Failed to load schema %s: %s", schema_file.name, exc
                )

    def validate(
        self,
        output: str,
        schema: dict[str, Any] | None = None,
        schema_name: str | None = None,
        prompt_result: PromptScanResult | None = None,
    ) -> ValidationResult:
        start = time.perf_counter()
        violations: list[str] = []
        total_score = 0.0
        redacted = output

        effective_schema = schema
        if effective_schema is None and schema_name and schema_name in self._loaded_schemas:
            effective_schema = self._loaded_schemas[schema_name]
        if effective_schema is not None:
            schema_violations = self._check_schema(output, effective_schema)
            violations.extend(schema_violations)

        normalized = self._normalizer.normalize(output)
        matches = self._engine.evaluate(normalized)
        if matches:
            for rule, _match in matches:
                violations.append(rule.id)
                total_score = max(total_score, rule.weight)

        redacted, pii_violations = self._detect_pii(output)
        for v in pii_violations:
            if v not in violations:
                violations.append(v)

        if prompt_result and prompt_result.score >= 0.4:
            total_score = min(1.0, total_score * 1.3)

        seen: set[str] = set()
        unique_violations: list[str] = []
        for v in violations:
            if v not in seen:
                seen.add(v)
                unique_violations.append(v)

        score = round(total_score, 6)
        valid = score < self._config.threshold_block and len(unique_violations) == 0

        duration_ms = round((time.perf_counter() - start) * 1000, 3)

        return ValidationResult(
            valid=valid,
            score=score,
            violations=unique_violations,
            corpus_hash=self.corpus_hash,
            corpus_version=self._config.corpus_version,
            duration_ms=duration_ms,
            redacted=redacted if redacted != output else None,
            threshold_block=self._config.threshold_block,
            threshold_warn=self._config.threshold_warn,
        )

    def _check_schema(self, output: str, schema: dict[str, Any]) -> list[str]:
        violations: list[str] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            violations.append("out_fmt_invalid_json")
            return violations

        schema_type = schema.get("type")
        if schema_type and (
            (schema_type == "object" and not isinstance(data, dict))
            or (schema_type == "array" and not isinstance(data, list))
            or (schema_type == "string" and not isinstance(data, str))
            or (schema_type == "number" and not isinstance(data, (int, float)))
            or (schema_type == "integer" and not isinstance(data, int))
            or (schema_type == "boolean" and not isinstance(data, bool))
            or (schema_type == "null" and data is not None)
        ):
            violations.append("out_fmt_type_mismatch")

        required = schema.get("required", [])
        if isinstance(data, dict) and required:
            violations.extend(f"out_fmt_missing_required_{field}" for field in required if field not in data)

        return violations

    def _detect_pii(self, text: str) -> tuple[str, list[str]]:
        violations: list[str] = []
        redacted = text

        ssh_key_pattern = re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----"
            r"[\s\S]*?"
            r"-----END\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----"
        )
        if ssh_key_pattern.search(redacted):
            violations.append("out_exfil_ssh_key")
            redacted = ssh_key_pattern.sub("[PRIVATE-KEY-REDACTED]", redacted)

        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
        if jwt_pattern.search(redacted):
            violations.append("out_pii_jwt")
            redacted = jwt_pattern.sub("[JWT-REDACTED]", redacted)

        db_url_pattern = re.compile(r"(?:postgres|mysql|mongodb|redis|mssql)://[^\s]+")
        if db_url_pattern.search(redacted):
            violations.append("out_exfil_database_url")
            redacted = db_url_pattern.sub("[DB-URL-REDACTED]", redacted)

        oauth_pattern = re.compile(
            r"(?:ya29[.\-_]|ghp_|gho_|github_pat_|glpat-|gitlab-[a-z]+-token|xox[bpas]-)[A-Za-z0-9_.\-]{20,}"
        )
        if oauth_pattern.search(redacted):
            violations.append("out_exfil_oauth_token")
            redacted = oauth_pattern.sub("[OAUTH-TOKEN-REDACTED]", redacted)

        arn_pattern = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d*:[^\s]+")
        if arn_pattern.search(redacted):
            violations.append("out_pii_aws_arn")
            redacted = arn_pattern.sub("[AWS-ARN-REDACTED]", redacted)

        api_key_pattern = re.compile(
            r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}"
            r"|(?:sk|pk|rk)_[a-zA-Z0-9]{20,}"
            r"|AIza[0-9A-Za-z_-]{35}"
            r"|ghp_[a-zA-Z0-9]{36}"
        )
        if api_key_pattern.search(redacted):
            violations.append("out_pii_api_key")
            redacted = api_key_pattern.sub("[API-KEY-REDACTED]", redacted)

        cc_pattern = re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b")
        if cc_pattern.search(redacted):
            violations.append("out_pii_credit_card")
            redacted = cc_pattern.sub("[CC-REDACTED]", redacted)

        ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        if ssn_pattern.search(redacted):
            violations.append("out_pii_ssn")
            redacted = ssn_pattern.sub("[SSN-REDACTED]", redacted)

        passport_pattern = re.compile(r"\b[A-Z]{2}\d{7,9}\b|\b[A-Z]\d{8,9}\b")
        if passport_pattern.search(redacted):
            violations.append("out_pii_passport")
            redacted = passport_pattern.sub("[PASSPORT-REDACTED]", redacted)

        crypto_pattern = re.compile(r"0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qQ][0-9a-zA-Z]{39,59}")
        if crypto_pattern.search(redacted):
            violations.append("out_pii_crypto_wallet")
            redacted = crypto_pattern.sub("[CRYPTO-WALLET-REDACTED]", redacted)

        internal_url_pattern = re.compile(
            r"(?:https?://)?(?:10\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"
            r"|localhost|127\.0\.0\.1|0\.0\.0\.0"
        )
        if internal_url_pattern.search(redacted):
            violations.append("out_exfil_internal_url")
            redacted = internal_url_pattern.sub("[INTERNAL-URL-REDACTED]", redacted)

        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        if ip_pattern.search(redacted):
            violations.append("out_pii_ip_address")
            redacted = ip_pattern.sub("[IP-REDACTED]", redacted)

        docker_secret_pattern = re.compile(r"(?:DOCKER_|KUBERNETES_|K8S_)[A-Z_]+\s*=\s*[^\s]+")
        if docker_secret_pattern.search(redacted):
            violations.append("out_exfil_docker_secret")
            redacted = docker_secret_pattern.sub("[K8S-SECRET-REDACTED]", redacted)

        env_var_pattern = re.compile(
            r"(?:AWS_(?:SECRET|ACCESS|KEY|SESSION)|GCP_(?:KEY|SECRET|TOKEN|CREDENTIALS)"
            r"|AZURE_(?:CLIENT_SECRET|SUBSCRIPTION|TENANT|KEY)|DATABASE_(?:URL|PASSWORD|URI)"
            r"|SECRET_?(?:KEY|TOKEN|VALUE)?|API_(?:KEY|SECRET|TOKEN)"
            r"|TOKEN_?(?:SECRET|KEY)?|PASSWORD|PRIVATE_KEY)"
            r"[A-Z_]*\s*=\s*[^\s]+"
        )
        if env_var_pattern.search(redacted):
            violations.append("out_exfil_env_var")
            redacted = env_var_pattern.sub("[ENV-VAR-REDACTED]", redacted)

        email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        if email_pattern.search(redacted):
            violations.append("out_pii_email")
            redacted = email_pattern.sub("[EMAIL-REDACTED]", redacted)

        phone_pattern = re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
            r"|\b\+?(?:\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
        )
        if phone_pattern.search(redacted):
            violations.append("out_pii_phone")
            redacted = phone_pattern.sub("[PHONE-REDACTED]", redacted)

        return redacted, violations
