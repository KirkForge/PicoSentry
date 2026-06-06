"""axios poisoning campaign detector."""

from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["AxiosPoisoningCampaign"]


class AxiosPoisoningCampaign(CampaignPackage):
    """Detection package for the axios npm supply-chain poisoning."""

    campaign_id = "axios-poisoning-2024"
    rule_id = "L2-CAMP-AXIOS-POISONING"
    ecosystems = ("npm",)
    iocs_path = Path(__file__).parent / "iocs.json"
