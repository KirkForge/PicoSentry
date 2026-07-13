"""Policy application helper for the scan CLI service."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from picosentry.scan.policy import Policy
from picosentry.scan.rules.utils import iter_node_modules, load_package_json

if TYPE_CHECKING:
    from picosentry.scan.models import ScanResult


def _apply_policy(result: ScanResult, policy_file: str | None) -> None:
    if not policy_file:
        return

    policy_path = Path(policy_file)
    if not policy_path.is_file():
        from picosentry.scan.engine import PolicyNotFoundError

        raise PolicyNotFoundError(f"Policy file not found: {policy_file}")

    policy = Policy.from_file(policy_path)

    pkg_licenses: dict[str, str] = {}
    installed_pkgs: set[str] = set()
    root_pkg = Path(result.target) / "package.json"
    if root_pkg.is_file():
        root_data = load_package_json(root_pkg)
        root_name = root_data.get("name", "")
        if root_name:
            installed_pkgs.add(root_name)
    for pkg_json_path, pkg_data in iter_node_modules(Path(result.target)):
        pkg_name = pkg_data.get("name", pkg_json_path.parent.name)
        if (
            not pkg_name.startswith("@")
            and pkg_json_path.parent.name
            and pkg_json_path.parent.parent.name.startswith("@")
        ):
            pkg_name = f"{pkg_json_path.parent.parent.name}/{pkg_name}"
        installed_pkgs.add(pkg_name)

    for f in result.findings:
        if f.rule_id == "L2-LICENSE-001" and "license =" in f.evidence:
            lic_extract = f.evidence.split("license = ")[-1].strip("'\"")
            pkg_licenses[f.package] = lic_extract

    policy_result = policy.apply(
        result, Path(result.target), package_licenses=pkg_licenses, installed_packages=installed_pkgs
    )
    result.policy_result = policy_result
