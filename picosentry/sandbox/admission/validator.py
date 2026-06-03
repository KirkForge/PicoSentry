"""Pod security validator for the admission controller.

Validates pod specs against PicoDome security policies:
  - No privileged containers
  - No runAsRoot without explicit override
  - Security context required
  - No hostPath mounts
  - No host network/pid/ipc sharing
  - Read-only root filesystem recommended
  - Non-root user required
  - Capabilities drop ALL required
"""

from __future__ import annotations

import logging

from picosentry.sandbox.admission import AdmissionRequest

logger = logging.getLogger("picodome.admission.validator")


class PodSecurityValidator:
    """Validate pod specs against security policies.

    Args:
        deny_privileged: Block privileged containers.
        deny_run_as_root: Block containers running as root.
        require_security_context: Require securityContext on pods/containers.
        deny_host_path: Block hostPath volume mounts.
        deny_host_network: Block hostNetwork/hostPID/hostIPC.
        require_non_root: Require runAsNonRoot in security context.
        require_read_only_root: Require readOnlyRootFilesystem.
        require_drop_all_caps: Require capabilities.drop=["ALL"].
    """

    def __init__(
        self,
        deny_privileged: bool = True,
        deny_run_as_root: bool = True,
        require_security_context: bool = True,
        deny_host_path: bool = True,
        deny_host_network: bool = True,
        require_non_root: bool = False,
        require_read_only_root: bool = False,
        require_drop_all_caps: bool = False,
    ) -> None:
        self.deny_privileged = deny_privileged
        self.deny_run_as_root = deny_run_as_root
        self.require_security_context = require_security_context
        self.deny_host_path = deny_host_path
        self.deny_host_network = deny_host_network
        self.require_non_root = require_non_root
        self.require_read_only_root = require_read_only_root
        self.require_drop_all_caps = require_drop_all_caps

    def validate(self, req: AdmissionRequest) -> tuple[bool, str]:
        """Validate a pod admission request.

        Args:
            req: The admission request from K8s.

        Returns:
            Tuple of (allowed, reason). allowed=True if the pod passes all checks.
        """
        violations: list[str] = []

        pod = req.object_raw
        if not pod:
            return True, ""  # No pod to validate (e.g., DELETE operation)

        spec = pod.get("spec", {})
        if not spec:
            return True, ""

        # Check pod-level security context
        pod_security = spec.get("securityContext", {})

        # Check host-level sharing
        if self.deny_host_network:
            if spec.get("hostNetwork", False):
                violations.append("hostNetwork is not allowed")
            if spec.get("hostPID", False):
                violations.append("hostPID is not allowed")
            if spec.get("hostIPC", False):
                violations.append("hostIPC is not allowed")

        # Check hostPath volumes
        if self.deny_host_path:
            for vol in spec.get("volumes", []):
                if "hostPath" in vol:
                    violations.append(f"hostPath volume '{vol.get('name', 'unknown')}' is not allowed")

        # Check pod-level security context requirements
        if self.require_non_root and not pod_security.get("runAsNonRoot", False):
            violations.append("pod securityContext.runAsNonRoot must be true")

        # Check containers
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for container in containers:
            name = container.get("name", "unknown")
            has_security = "securityContext" in container
            sec = container.get("securityContext", {})

            # Security context required
            if self.require_security_context and not has_security:
                violations.append(f"container '{name}' missing securityContext")

            # Privileged
            if self.deny_privileged and sec.get("privileged", False):
                violations.append(f"container '{name}' is privileged")

            # Run as root
            if self.deny_run_as_root:
                run_as_user = sec.get("runAsUser", pod_security.get("runAsUser"))
                if run_as_user == 0:
                    violations.append(f"container '{name}' runs as root (runAsUser=0)")

            # Non-root requirement at container level
            if self.require_non_root and not sec.get("runAsNonRoot", pod_security.get("runAsNonRoot", False)):
                violations.append(f"container '{name}' securityContext.runAsNonRoot must be true")

            # Read-only root filesystem
            if self.require_read_only_root and not sec.get("readOnlyRootFilesystem", False):
                violations.append(f"container '{name}' readOnlyRootFilesystem must be true")

            # Drop all capabilities
            if self.require_drop_all_caps:
                caps = sec.get("capabilities", {})
                drop = caps.get("drop", [])
                if "ALL" not in drop:
                    violations.append(f"container '{name}' must drop ALL capabilities")

        if violations:
            reason = "; ".join(violations)
            logger.info("Pod '%s' denied: %s", req.name, reason)
            return False, reason

        logger.debug("Pod '%s' allowed", req.name)
        return True, ""

    def __call__(self, req: AdmissionRequest) -> tuple[bool, str]:
        """Allow using the validator directly as a validator function."""
        return self.validate(req)


# Default strict validator
DEFAULT_VALIDATOR = PodSecurityValidator(
    deny_privileged=True,
    deny_run_as_root=True,
    require_security_context=True,
    deny_host_path=True,
    deny_host_network=True,
)
