"""WO7-024 — serve helm chart missing PVC/SA/Secret/RBAC/NetworkPolicy/PDB templates.

The deployment.yaml references PVC and SA by name but the templates don't
exist — helm install fails. The fix adds the missing templates mirroring
the picodome chart's patterns with serve.* helpers.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "serve"
TEMPLATES_DIR = CHART_DIR / "templates"


class TestServeChartStructure:
    def test_chart_yaml_exists(self):
        assert (CHART_DIR / "Chart.yaml").is_file()

    def test_values_yaml_exists(self):
        assert (CHART_DIR / "values.yaml").is_file()

    def test_deployment_template_exists(self):
        assert (TEMPLATES_DIR / "deployment.yaml").is_file()

    def test_service_template_exists(self):
        assert (TEMPLATES_DIR / "service.yaml").is_file()

    def test_helpers_template_exists(self):
        assert (TEMPLATES_DIR / "_helpers.tpl").is_file()


class TestMissingTemplatesAdded:
    def test_pvc_template_exists(self):
        assert (TEMPLATES_DIR / "pvc.yaml").is_file()

    def test_pvc_template_uses_serve_helpers(self):
        content = (TEMPLATES_DIR / "pvc.yaml").read_text()
        assert 'include "serve.fullname"' in content
        assert "PersistentVolumeClaim" in content
        assert ".Values.persistence.enabled" in content

    def test_serviceaccount_template_exists(self):
        assert (TEMPLATES_DIR / "serviceaccount.yaml").is_file()

    def test_serviceaccount_template_uses_serve_helpers(self):
        content = (TEMPLATES_DIR / "serviceaccount.yaml").read_text()
        assert 'include "serve.serviceAccountName"' in content
        assert "ServiceAccount" in content
        assert ".Values.serviceAccount.create" in content

    def test_secret_template_exists(self):
        assert (TEMPLATES_DIR / "secret.yaml").is_file()

    def test_secret_template_uses_serve_helpers(self):
        content = (TEMPLATES_DIR / "secret.yaml").read_text()
        assert 'include "serve.fullname"' in content
        assert "Secret" in content
        assert ".Values.auth.createSecret" in content

    def test_rbac_template_exists(self):
        assert (TEMPLATES_DIR / "rbac.yaml").is_file()

    def test_rbac_template_has_role_and_binding(self):
        content = (TEMPLATES_DIR / "rbac.yaml").read_text()
        assert "kind: Role" in content
        assert "kind: RoleBinding" in content
        assert 'include "serve.fullname"' in content
        assert 'include "serve.serviceAccountName"' in content
        assert ".Values.rbac.create" in content

    def test_networkpolicy_template_exists(self):
        assert (TEMPLATES_DIR / "networkpolicy.yaml").is_file()

    def test_networkpolicy_template_uses_serve_helpers(self):
        content = (TEMPLATES_DIR / "networkpolicy.yaml").read_text()
        assert "NetworkPolicy" in content
        assert 'include "serve.selectorLabels"' in content
        assert ".Values.networkPolicy.enabled" in content

    def test_pdb_template_exists(self):
        assert (TEMPLATES_DIR / "pdb.yaml").is_file()

    def test_pdb_template_uses_serve_helpers(self):
        content = (TEMPLATES_DIR / "pdb.yaml").read_text()
        assert "PodDisruptionBudget" in content
        assert 'include "serve.selectorLabels"' in content
        assert ".Values.podDisruptionBudget.enabled" in content


class TestDeploymentReferences:
    def test_deployment_references_pvc(self):
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "persistentVolumeClaim" in content or "PVC" in content.upper() or "claimName" in content

    def test_deployment_references_serviceaccount(self):
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "serviceAccountName" in content

    def test_deployment_references_secret_checksum(self):
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "secret.yaml" in content or "checksum/tokens" in content


class TestValuesConsistency:
    def test_values_has_persistence(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "persistence:" in content

    def test_values_has_serviceAccount(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "serviceAccount:" in content

    def test_values_has_auth(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "auth:" in content

    def test_values_has_rbac(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "rbac:" in content

    def test_values_has_networkPolicy(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "networkPolicy:" in content

    def test_values_has_podDisruptionBudget(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "podDisruptionBudget:" in content
