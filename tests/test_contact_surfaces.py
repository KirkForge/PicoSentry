"""Guard: every first-party contact domain claimed in the repo must exist.

The failure mode this prevents: a plausible-looking contact domain is written
to complete a template, and the fiction propagates through LICENSE,
pyproject.toml, the Helm charts and the Dockerfile. A non-existent domain in
the commercial-licensing contact is a dead lead for every enterprise deal,
and it stays invisible until someone tries to use it.

This repo has exactly that: `kirkforge.dev` is published as the
commercial-licensing contact in LICENSE, LICENSE-SUMMARY.md,
COMMERCIAL-LICENSE.md, pyproject.toml, the Dockerfile and two Helm charts —
and it resolves at no public DNS server. It entered with the initial import
and shipped in two PyPI releases.

Two checks, both cheap:

1. Every domain that appears as a contact address in an authoritative surface
   must be in `_CONTACT_DOMAINS` below. A NEW domain is a fabrication risk and
   fails until it is consciously added — adding it is the moment to decide
   whether it is real.
2. Every domain in `_CONTACT_DOMAINS` must match its declared status. A
   "pending" domain must currently NOT resolve; when it starts resolving this
   goes red and asks to be promoted to "live". A "live" domain must resolve.

The distinction between "does not exist" and "the resolver could not answer"
is the whole point: only EAI_NONAME/EAI_NODATA mean the name does not exist.
A transient EAI_AGAIN/EAI_FAIL, a timeout, or an offline CI box must never
turn this into a red gate — only a provably-nonexistent name does.

Marked `network` so it runs in the nightly tier (scripts/test.sh fast
excludes `network`), not in the PR gate. It is a backstop for the human
review that already happens at work-order stage.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

import pytest

pytestmark = [pytest.mark.network, pytest.mark.timeout(60)]

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Surfaces that carry a first-party contact address. These are the files a
# customer, reseller or procurement agent reads to reach the vendor.
_CONTACT_SURFACES = (
    "LICENSE",
    "LICENSE-SUMMARY.md",
    "COMMERCIAL-LICENSE.md",
    "pyproject.toml",
    "Dockerfile",
    "README.md",
    "SECURITY.md",
)

# Helm charts carry a maintainer block with a contact address too.
_HELM_CHART_GLOB = "deploy/helm/*/Chart.yaml"

# Every first-party contact domain, and the state it is allowed to be in:
#   "live"    — the domain exists and resolves. Contact points may use it.
#   "pending" — the domain is claimed in a contact surface but does not
#               resolve yet. KNOWN DEBT: the contact is dead until this
#               changes. The test goes red the moment it starts resolving,
#               so promoting it to "live" is forced, never forgotten.
_CONTACT_DOMAINS: dict[str, str] = {
    # KNOWN DEBT (2026-10-21): published as the commercial-licensing contact
    # in LICENSE, LICENSE-SUMMARY.md, COMMERCIAL-LICENSE.md, pyproject.toml,
    # the Dockerfile and deploy/helm/{serve,picodome}/Chart.yaml. NXDOMAIN at
    # every public resolver. Until a real domain is registered and those
    # surfaces point at it, every enterprise licensing inquiry dead-ends.
    # Fix: register the domain, update the surfaces, then promote to "live".
    "kirkforge.dev": "pending",
}

# An email address in one of the contact surfaces. Restricted to a plausible
# TLD shape so prose in a LICENSE ("e.g. foo@bar.baz") is not picked up.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def _contact_files() -> list[Path]:
    files = [p for p in (_REPO_ROOT / name for name in _CONTACT_SURFACES) if p.is_file()]
    files.extend(sorted(_REPO_ROOT.glob(_HELM_CHART_GLOB)))
    return files


def _domains_in_contact_surfaces() -> set[str]:
    """First-party domains that appear as a contact address in a surface."""
    found: set[str] = set()
    for path in _contact_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        found.update(domain for domain in _EMAIL_RE.findall(text) if domain in _CONTACT_DOMAINS)
    return found


def _nxdomain(host: str) -> bool:
    """True only if the domain provably does not exist.

    Returns False for transient resolver failures (EAI_AGAIN, EAI_FAIL) so
    that an offline or rate-limited runner cannot turn this into a red gate.
    """
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        # EAI_NONAME/EAI_NODATA mean "this name does not exist" — a fact about
        # the world. EAI_AGAIN/EAI_FAIL mean the resolver could not answer
        # right now — a fact about the network, and NOT a failure here.
        return exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME))
    except OSError:
        return False
    return False


def test_no_unknown_contact_domain() -> None:
    """A contact domain that is not on the known list is a fabrication risk.

    This does not assert the domain resolves (that is the next test) — it
    asserts that nobody ADDED a new contact domain without thinking about
    it. The list is the review gate: a new domain must be added deliberately,
    and adding it is the moment to check that it resolves.
    """
    unknown: set[str] = set()
    for path in _contact_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        unknown.update(domain for domain in _EMAIL_RE.findall(text) if domain not in _CONTACT_DOMAINS)
    assert not unknown, (
        f"New first-party contact domain(s) in a contact surface: {sorted(unknown)}. "
        "Add it to _CONTACT_DOMAINS in tests/test_contact_surfaces.py only if "
        "the domain is real and controlled by the project — the next test "
        "will assert it matches its declared status."
    )


def test_declared_contact_domains_are_used() -> None:
    """Every declared contact domain must actually appear in a surface.

    Keeps the list honest: a domain nobody references any more (because the
    surfaces moved elsewhere) should be dropped rather than left to rot.
    """
    used = _domains_in_contact_surfaces()
    unused = sorted(set(_CONTACT_DOMAINS) - used)
    assert not unused, (
        f"Contact domain(s) declared in _CONTACT_DOMAINS but absent from every "
        f"contact surface: {unused}. Either the surfaces moved off them (drop "
        "the entry) or the surfaces are missing them."
    )


@pytest.mark.parametrize(("domain", "status"), sorted(_CONTACT_DOMAINS.items()))
def test_contact_domain_matches_declared_status(domain: str, status: str) -> None:
    """A 'live' domain must resolve; a 'pending' one must not (yet)."""
    if status == "live":
        assert not _nxdomain(domain), (
            f"{domain} is declared live but does not resolve (NXDOMAIN). It is "
            "published as a contact address — a dead end for anyone trying to "
            "reach the project."
        )
    elif status == "pending":
        assert _nxdomain(domain), (
            f"{domain} is declared pending but now RESOLVES. It is published as "
            "a contact address, so promote it to 'live' in _CONTACT_DOMAINS "
            "and close the known-debt note."
        )
    else:
        pytest.fail(f"{domain}: unknown status {status!r} — use 'live' or 'pending'")
