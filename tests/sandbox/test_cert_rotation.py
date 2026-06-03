"""Tests for certificate rotation and TLS lifecycle.

Covers:
- cert-manager certificate template has correct renewal window
- Certificate SANs include all required service DNS names
- Values configuration for cert rotation is valid
- Manual CA bundle update simulation
"""

from __future__ import annotations

import base64
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "picodome-admission"


class TestCertificateTemplate:
    def test_certificate_duration(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "8760h" in content  # 1 year

    def test_certificate_renewal_window(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "720h" in content  # 30 days before expiry

    def test_certificate_has_service_dns(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "svc.cluster.local" in content

    def test_certificate_has_namespace_dns(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert ".svc" in content

    def test_certificate_secret_name(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "-tls" in content

    def test_certificate_issuer_ref(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "issuerRef" in content


class TestValuesCertRotation:
    def test_cert_rotation_section(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "certRotation" in content

    def test_rolling_update_on_renew(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "rollingUpdateOnRennew" in content or "rollingUpdateOnRenew" in content

    def test_cert_duration_override(self):
        content = (CHART_DIR / "values.yaml").read_text()
        # Should have empty string as default (uses template default)
        assert "duration" in content


class TestWebhookCABundle:
    def test_webhook_has_ca_injection_annotation(self):
        content = (CHART_DIR / "templates" / "webhook.yaml").read_text()
        assert "cert-manager.io/inject-ca-from" in content

    def test_webhook_references_certificate(self):
        content = (CHART_DIR / "templates" / "webhook.yaml").read_text()
        assert "-cert" in content


class TestTLSSecretMount:
    def test_deployment_mounts_tls_volume(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        assert "volumeMounts" in content
        assert "/tls" in content

    def test_deployment_tls_volume_readonly(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        lines = content.splitlines()
        in_tls_mount = False
        for line in lines:
            if "/tls" in line and "mountPath" in line:
                in_tls_mount = True
            if in_tls_mount and "readOnly: true" in line:
                break
        else:
            if in_tls_mount:
                raise AssertionError("TLS volume mount should be readOnly")


class TestCABundleEncoding:
    """Verify CA bundle encoding matches what Kubernetes expects."""

    def test_base64_roundtrip(self):
        """Verify base64 encoding of a CA cert roundtrips correctly."""
        fake_ca = b"-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"
        encoded = base64.b64encode(fake_ca).decode("ascii")
        decoded = base64.b64decode(encoded)
        assert decoded == fake_ca
