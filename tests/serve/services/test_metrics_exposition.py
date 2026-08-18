"""WO5.0.0-007: /metrics/prometheus exposition validity.

Exactly one sample per series per scrape (Prometheus rejects duplicate
samples), label values sanitized at the api_request boundary and escaped at
render (the endpoint label is the request's percent-decoded path, reachable
unauthenticated), and the api families stay visible in org-filtered views.
"""

from __future__ import annotations

import re

from picosentry.serve.services.metrics import MetricsCollector

_SAMPLE_RE = re.compile(r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{.*\})? (?P<value>-?[0-9.eE+]+)$")


def _parse_exposition(text: str) -> dict[str, float]:
    """Strict exposition parser (ported from watch's): {series: value}.

    Fails on malformed sample lines, duplicate series, or unsafe characters
    surviving inside label values.
    """
    samples: list[tuple[str, float]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE_RE.match(line)
        assert m, f"malformed sample line: {line!r}"
        labels = m.group("labels") or ""
        if labels:
            assert labels.endswith("}"), f"unterminated label set: {line!r}"
            for value in re.findall(r'"([^"]*)"', labels):
                assert not re.search(r"[\\{}\n\r]", value), f"unescaped label value in {line!r}"
        samples.append((m.group("name") + labels, float(m.group("value"))))
    keys = [k for k, _ in samples]
    duplicates = {k for k in keys if keys.count(k) > 1}
    assert not duplicates, f"duplicate series: {sorted(duplicates)}"
    return dict(samples)


class TestExpositionValidity:
    def test_repeated_increments_render_one_sample_per_series(self):
        mc = MetricsCollector()
        for _ in range(5):
            mc.api_request("GET", "/api/v1/x", 200, 0.1)
        for _ in range(3):
            mc.api_request("GET", "/api/v1/y", 500, 0.2)

        series = _parse_exposition(mc.to_prometheus())

        x_counter = next(
            k for k in series if k.startswith("picoshogun_api_requests_total{") and 'endpoint="/api/v1/x"' in k
        )
        y_counter = next(
            k for k in series if k.startswith("picoshogun_api_requests_total{") and 'endpoint="/api/v1/y"' in k
        )
        assert series[x_counter] == 5.0
        assert series[y_counter] == 3.0
        x_hist = next(
            k
            for k in series
            if k.startswith("picoshogun_api_request_duration_seconds{") and 'endpoint="/api/v1/x"' in k
        )
        assert series[x_hist] == 0.5  # observations summed, single sample

    def test_decorated_path_injects_nothing(self):
        mc = MetricsCollector()
        evil = '/api/v1/x"}\npicoshogun_fake_total 999\n# HELP injected'
        for _ in range(3):
            mc.api_request("GET", evil, 404, 0.01)

        text = mc.to_prometheus()

        series = _parse_exposition(text)  # raises on injected/malformed lines
        # Nothing may break out as its own exposition line: no fake sample
        # series, no injected HELP/TYPE. (The hostile path survives only as a
        # sanitized, quoted label value — valid exposition.)
        lines = [ln.strip() for ln in text.splitlines()]
        assert not any(ln.startswith(("picoshogun_fake_total", "# HELP injected", "# TYPE injected")) for ln in lines)
        assert not any("fake_total" in k.split("{")[0] for k in series)
        assert any(k.startswith("picoshogun_api_requests_total{") and 'endpoint="/api/v1/x' in k for k in series)

    def test_org_filter_keeps_api_families_visible(self):
        mc = MetricsCollector()
        mc.api_request("GET", "/health", 200, 0.05)
        mc.project_run("proj", 1.0, "completed", org_id=1)

        prom = _parse_exposition(mc.to_prometheus(org_id=1))
        assert any(k.startswith("picoshogun_api_requests_total{") for k in prom)
        assert any(k.startswith("picoshogun_project_runs_total{") for k in prom)

        data = mc.to_dict(org_id=1)
        assert "api_requests_total" in data["metrics"]

    def test_org_filter_still_hides_other_orgs_families(self):
        mc = MetricsCollector()
        mc.project_run("proj-a", 1.0, "completed", org_id=1)
        mc.project_run("proj-b", 1.0, "completed", org_id=2)

        prom = _parse_exposition(mc.to_prometheus(org_id=1))

        assert any('project="proj-a"' in k for k in prom)
        assert not any('project="proj-b"' in k for k in prom)
