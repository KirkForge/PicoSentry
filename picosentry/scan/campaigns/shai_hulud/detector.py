"""
Shai-Hulud campaign detector.

Self-propagating npm worm (2025) and Mini Shai-Hulud variants (2026).
The base class wires up the named-signature, payload-filename, and
package-match detectors. This module just declares the metadata and
exposes the class for auto-discovery.
"""

from __future__ import annotations

from pathlib import Path

from .._base import CampaignPackage

__all__ = ["ShaiHuludCampaign"]


class ShaiHuludCampaign(CampaignPackage):
    """Detection package for the Shai-Hulud npm worm family."""

    campaign_id = "shai-hulud-2025"
    rule_id = "L2-CAMP-SHAI-HULUD"
    ecosystems = ("npm",)
    iocs_path = Path(__file__).parent / "iocs.json"
