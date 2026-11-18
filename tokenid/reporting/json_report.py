"""Machine-readable reports.

Raw tokens are omitted unless ``include_token`` is explicitly True.  Context
values are omitted unless ``include_context`` is explicitly True.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from ..models import AnalysisResult, CompareResult, DecodeResult, EntropyStats


def analysis_to_dict(
    result: AnalysisResult,
    include_token: bool = False,
    include_context: bool = False,
) -> Dict[str, Any]:
    return result.to_dict(include_token=include_token, include_context=include_context)


def compare_to_dict(
    result: CompareResult,
    include_token: bool = False,
    include_context: bool = False,
) -> Dict[str, Any]:
    return result.to_dict(include_token=include_token, include_context=include_context)


def decode_to_dict(result: DecodeResult, include_token: bool = False) -> Dict[str, Any]:
    return result.to_dict(include_token=include_token)


def entropy_to_dict(
    stats: EntropyStats, include_token: bool = False
) -> Dict[str, Any]:
    return stats.to_dict(include_token=include_token)


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
