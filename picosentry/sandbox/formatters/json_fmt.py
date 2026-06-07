
from __future__ import annotations

import json

from picosentry.sandbox import __version__
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult


def format_json(
    result: SandboxResult | AnalysisResult,
    indent: int = 2,
    deterministic: bool = False,
) -> str:
    return json.dumps(
        result.to_dict(deterministic=deterministic),
        indent=indent,
        default=str,
        sort_keys=True,
    )


def format_pipeline_json(
    sandbox: SandboxResult,
    analysis: AnalysisResult,
    indent: int = 2,
    deterministic: bool = False,
) -> str:
    output = {
        "l3_sandbox": sandbox.to_dict(deterministic=deterministic),
        "l4_analysis": analysis.to_dict(deterministic=deterministic),
        "pipeline": "picodome",
        "version": __version__,
    }
    return json.dumps(output, indent=indent, default=str, sort_keys=True)
