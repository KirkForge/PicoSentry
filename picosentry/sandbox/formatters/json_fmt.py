from __future__ import annotations

import json

from picosentry.sandbox import __version__
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l4.models import AnalysisResult
    from picosentry.sandbox.l3.models import SandboxResult


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
