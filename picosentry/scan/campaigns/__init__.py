"""
Per-campaign IOC packages.

A campaign package is a self-contained, named unit of detection for a
specific real-world supply-chain attack (Shai-Hulud, node-ipc compromise,
TrapDoor, axios poisoning, ...). The convention is:

    campaigns/<campaign_id>/
        iocs.json     structured indicator data
        detector.py   CampaignPackage subclass
        tests/        per-campaign unit tests

The auto-discovery module:
  - exposes the base class + helpers from _base
  - exposes `iter_campaigns()` for the engine to wire up at scan time
  - re-exports the concrete detector classes for direct use in tests

The campaign layer is a *complement* to `L2-IOC-001` (which handles
arbitrary user-registered IoCs). Campaign packages activate the rich
indicator data (C2 domains, payload filenames, bundle hashes) that
`L2-IOC-001` ignores — it's the difference between "match this package
list" and "we detect Shai-Hulud, here is the proof."
"""

from __future__ import annotations

from ._base import CampaignPackage, IndicatorSet, iter_campaigns, list_campaigns

__all__ = [
    "CampaignPackage",
    "IndicatorSet",
    "iter_campaigns",
    "list_campaigns",
]
