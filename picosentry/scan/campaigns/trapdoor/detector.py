"""TrapDoor campaign detector (cross-ecosystem: npm, pypi, cargo)."""

from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["TrapdoorCampaign"]


class TrapdoorCampaign(CampaignPackage):
    """Detection package for the TrapDoor cross-ecosystem supply-chain attack."""

    campaign_id = "trapdoor-2024"
    rule_id = "L2-CAMP-TRAPDOOR"
    ecosystems = ("npm", "pypi", "cargo")
    iocs_path = Path(__file__).parent / "iocs.json"
