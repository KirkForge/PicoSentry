
from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["ShaiHuludCampaign"]


class ShaiHuludCampaign(CampaignPackage):

    campaign_id = "shai-hulud-2025"
    rule_id = "L2-CAMP-SHAI-HULUD"
    ecosystems = ("npm",)
    iocs_path = Path(__file__).parent / "iocs.json"
