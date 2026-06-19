from __future__ import annotations

import logging

from picosentry.sandbox.admission import AdmissionRequest

logger = logging.getLogger("picodome.admission.validator")


class PodSecurityValidator:
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
        violations: list[str] = []

        pod = req.object_raw
        if not pod:
            return True, ""  # No pod to validate (e.g., DELETE operation)

        spec = pod.get("spec", {})
        if not spec:
            return True, ""

        pod_security = spec.get("securityContext", {})

        if self.deny_host_network:
            if spec.get("hostNetwork", False):
                violations.append("hostNetwork is not allowed")
            if spec.get("hostPID", False):
                violations.append("hostPID is not allowed")
            if spec.get("hostIPC", False):
                violations.append("hostIPC is not allowed")

        if self.deny_host_path:
            violations.extend(
                f"hostPath volume '{vol.get('name', 'unknown')}' is not allowed"
                for vol in spec.get("volumes", [])
                if "hostPath" in vol
            )

        if self.require_non_root and not pod_security.get("runAsNonRoot", False):
            violations.append("pod securityContext.runAsNonRoot must be true")

        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for container in containers:
            name = container.get("name", "unknown")
            has_security = "securityContext" in container
            sec = container.get("securityContext", {})

            if self.require_security_context and not has_security:
                violations.append(f"container '{name}' missing securityContext")

            if self.deny_privileged and sec.get("privileged", False):
                violations.append(f"container '{name}' is privileged")

            if self.deny_run_as_root:
                run_as_user = sec.get("runAsUser", pod_security.get("runAsUser"))
                if run_as_user == 0:
                    violations.append(f"container '{name}' runs as root (runAsUser=0)")

            if self.require_non_root and not sec.get("runAsNonRoot", pod_security.get("runAsNonRoot", False)):
                violations.append(f"container '{name}' securityContext.runAsNonRoot must be true")

            if self.require_read_only_root and not sec.get("readOnlyRootFilesystem", False):
                violations.append(f"container '{name}' readOnlyRootFilesystem must be true")

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
        return self.validate(req)


DEFAULT_VALIDATOR = PodSecurityValidator(
    deny_privileged=True,
    deny_run_as_root=True,
    require_security_context=True,
    deny_host_path=True,
    deny_host_network=True,
)
