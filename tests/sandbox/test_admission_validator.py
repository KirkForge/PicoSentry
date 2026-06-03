"""Tests for pod security validator — B17.

Covers:
- Privileged container denial
- RunAsRoot denial
- Missing security context denial
- hostPath volume denial
- hostNetwork/hostPID/hostIPC denial
- Non-root requirement
- Read-only root filesystem requirement
- Drop all capabilities requirement
- Clean pod (no violations)
- Multiple violations in one pod
- Init containers checked too
- DELETE operations (no pod spec to validate)
"""

from __future__ import annotations

from picosentry.sandbox.admission import AdmissionRequest
from picosentry.sandbox.admission.validator import DEFAULT_VALIDATOR, PodSecurityValidator


def _make_pod_request(pod_spec: dict, operation: str = "CREATE") -> AdmissionRequest:
    """Build an AdmissionRequest with a pod spec."""
    return AdmissionRequest(
        uid="test-uid",
        kind={"group": "", "version": "v1", "kind": "Pod"},
        name="test-pod",
        namespace="default",
        operation=operation,
        object_raw={"apiVersion": "v1", "kind": "Pod", "spec": pod_spec},
    )


SAFE_POD_SPEC = {
    "containers": [
        {
            "name": "app",
            "image": "nginx:latest",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
        },
    ],
    "securityContext": {
        "runAsNonRoot": True,
        "runAsUser": 1000,
    },
}


class TestPrivilegedDenial:
    def test_privileged_container_denied(self):
        validator = PodSecurityValidator(deny_privileged=True)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"privileged": True}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "privileged" in reason.lower()

    def test_non_privileged_allowed(self):
        validator = PodSecurityValidator(deny_privileged=True)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"privileged": False}},
            ],
        }
        allowed, _ = validator.validate(_make_pod_request(spec))
        assert allowed


class TestRunAsRootDenial:
    def test_run_as_root_denied(self):
        validator = PodSecurityValidator(deny_run_as_root=True)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"runAsUser": 0}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "root" in reason.lower()

    def test_non_root_allowed(self):
        validator = PodSecurityValidator(deny_run_as_root=True)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"runAsUser": 1000}},
            ],
        }
        allowed, _ = validator.validate(_make_pod_request(spec))
        assert allowed


class TestSecurityContextRequired:
    def test_missing_security_context_denied(self):
        validator = PodSecurityValidator(require_security_context=True)
        spec = {
            "containers": [{"name": "app", "image": "nginx"}],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "securityContext" in reason

    def test_with_security_context_allowed(self):
        validator = PodSecurityValidator(require_security_context=True, deny_run_as_root=False)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {}},
            ],
        }
        allowed, _ = validator.validate(_make_pod_request(spec))
        assert allowed


class TestHostPathDenial:
    def test_hostpath_denied(self):
        validator = PodSecurityValidator(deny_host_path=True)
        spec = {
            "containers": [{"name": "app", "image": "nginx", "securityContext": {}}],
            "volumes": [{"name": "host", "hostPath": {"path": "/var/run/docker.sock"}}],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "hostPath" in reason

    def test_no_hostpath_allowed(self):
        validator = PodSecurityValidator(deny_host_path=True, deny_run_as_root=False, require_security_context=False)
        spec = {
            "containers": [{"name": "app", "image": "nginx"}],
            "volumes": [{"name": "data", "emptyDir": {}}],
        }
        allowed, _ = validator.validate(_make_pod_request(spec))
        assert allowed


class TestHostNetworkDenial:
    def test_hostnetwork_denied(self):
        validator = PodSecurityValidator(deny_host_network=True)
        spec = {
            "hostNetwork": True,
            "containers": [{"name": "app", "image": "nginx", "securityContext": {}}],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "hostNetwork" in reason

    def test_hostpid_denied(self):
        validator = PodSecurityValidator(deny_host_network=True)
        spec = {
            "hostPID": True,
            "containers": [{"name": "app", "image": "nginx", "securityContext": {}}],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "hostPID" in reason

    def test_hostipc_denied(self):
        validator = PodSecurityValidator(deny_host_network=True)
        spec = {
            "hostIPC": True,
            "containers": [{"name": "app", "image": "nginx", "securityContext": {}}],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "hostIPC" in reason


class TestStrictRequirements:
    def test_require_non_root(self):
        validator = PodSecurityValidator(require_non_root=True, require_security_context=False)
        spec = {
            "securityContext": {},
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"runAsUser": 1000}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "runAsNonRoot" in reason

    def test_require_read_only_root(self):
        validator = PodSecurityValidator(require_read_only_root=True, require_security_context=False)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "readOnlyRootFilesystem" in reason

    def test_require_drop_all_caps(self):
        validator = PodSecurityValidator(require_drop_all_caps=True, require_security_context=False)
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "ALL" in reason


class TestCleanPod:
    def test_safe_pod_passes_default(self):
        allowed, _ = DEFAULT_VALIDATOR.validate(_make_pod_request(SAFE_POD_SPEC))
        assert allowed

    def test_safe_pod_passes_all_strict(self):
        validator = PodSecurityValidator(
            deny_privileged=True,
            deny_run_as_root=True,
            require_security_context=True,
            deny_host_path=True,
            deny_host_network=True,
            require_non_root=True,
            require_read_only_root=True,
            require_drop_all_caps=True,
        )
        allowed, _ = validator.validate(_make_pod_request(SAFE_POD_SPEC))
        assert allowed


class TestMultipleViolations:
    def test_multiple_violations_reported(self):
        validator = PodSecurityValidator(
            deny_privileged=True,
            deny_run_as_root=True,
            deny_host_network=True,
        )
        spec = {
            "hostNetwork": True,
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"privileged": True, "runAsUser": 0}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        # Should mention all three violations
        assert "hostNetwork" in reason
        assert "privileged" in reason
        assert "root" in reason


class TestInitContainers:
    def test_init_container_privileged_denied(self):
        validator = PodSecurityValidator(deny_privileged=True)
        spec = {
            "initContainers": [
                {"name": "init", "image": "busybox", "securityContext": {"privileged": True}},
            ],
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {}},
            ],
        }
        allowed, reason = validator.validate(_make_pod_request(spec))
        assert not allowed
        assert "init" in reason


class TestDeleteOperations:
    def test_delete_operation_allowed(self):
        """DELETE operations have no pod spec to validate."""
        validator = PodSecurityValidator(deny_privileged=True)
        req = AdmissionRequest(
            uid="test-uid",
            kind={"group": "", "version": "v1", "kind": "Pod"},
            name="test-pod",
            namespace="default",
            operation="DELETE",
            object_raw={},
        )
        allowed, _ = validator.validate(req)
        assert allowed


class TestCallable:
    def test_validator_is_callable(self):
        validator = PodSecurityValidator(deny_privileged=True)
        # Can be used directly as a validator function
        spec = {
            "containers": [
                {"name": "app", "image": "nginx", "securityContext": {"privileged": True}},
            ],
        }
        allowed, reason = validator(_make_pod_request(spec))
        assert not allowed
