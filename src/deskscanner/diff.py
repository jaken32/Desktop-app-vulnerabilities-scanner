"""Diff two scan reports by stable finding id.

Only the *static* findings participate: anything flagged ``volatile`` (live
local-API probe results) is excluded, as are volatile top-level fields (the
scan timestamp, probe reachability). This keeps a diff meaningful — it reflects
real changes in the bundle, not whether a background service happened to be up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, ScanResult


def _static_index(findings_dicts: list[dict]) -> dict[str, dict]:
    return {
        f["stable_id"]: f
        for f in findings_dicts
        if not f.get("volatile", False)
    }


def _result_to_finding_dicts(obj: Any) -> list[dict]:
    """Accept either a ScanResult or an already-serialised report dict."""
    if isinstance(obj, ScanResult):
        return [f.to_dict() for f in obj.findings]
    if isinstance(obj, dict) and "findings" in obj:
        return list(obj["findings"])
    raise ValueError("diff input must be a ScanResult or a report dict with 'findings'")


@dataclass
class DiffResult:
    fixed: list[dict]       # present before, gone now
    new: list[dict]         # absent before, present now
    unchanged: list[dict]   # present in both

    def to_dict(self) -> dict:
        return {
            "summary": {
                "fixed": len(self.fixed),
                "new": len(self.new),
                "unchanged": len(self.unchanged),
            },
            "fixed": self.fixed,
            "new": self.new,
            "unchanged": self.unchanged,
        }

    def has_changes(self) -> bool:
        return bool(self.fixed or self.new)


def diff_reports(previous: Any, current: Any) -> DiffResult:
    prev = _static_index(_result_to_finding_dicts(previous))
    curr = _static_index(_result_to_finding_dicts(current))

    prev_ids = set(prev)
    curr_ids = set(curr)

    fixed = [prev[i] for i in sorted(prev_ids - curr_ids)]
    new = [curr[i] for i in sorted(curr_ids - prev_ids)]
    unchanged = [curr[i] for i in sorted(prev_ids & curr_ids)]
    return DiffResult(fixed=fixed, new=new, unchanged=unchanged)
