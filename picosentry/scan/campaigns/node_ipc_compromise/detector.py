from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["NodeIpcCompromiseCampaign"]


class NodeIpcCompromiseCampaign(CampaignPackage):
    campaign_id = "node-ipc-compromise-2022"
    rule_id = "L2-CAMP-NODE-IPC-COMPROMISE"
    ecosystems = ("npm",)
    iocs_path = Path(__file__).parent / "iocs.json"
