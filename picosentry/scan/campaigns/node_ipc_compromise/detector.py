"""node-ipc compromise campaign detector."""

from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["NodeIpcCompromiseCampaign"]


class NodeIpcCompromiseCampaign(CampaignPackage):
    """Detection package for the node-ipc 9.1.6 / 9.2.3 / 12.0.1 sabotage."""

    campaign_id = "node-ipc-compromise-2022"
    rule_id = "L2-CAMP-NODE-IPC-COMPROMISE"
    ecosystems = ("npm",)
    iocs_path = Path(__file__).parent / "iocs.json"
