#!/usr/bin/env python3
"""Interactively or non-interactively approve one validated fix."""
import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crs_core.approval import approve, list_candidates


def _latest_compare() -> Path:
    comparisons = sorted((ROOT / "evidence").glob("compare_*.json"), key=lambda path: path.stat().st_mtime)
    if not comparisons:
        raise SystemExit("No evidence/compare_*.json files found")
    return comparisons[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Approve one validated CRS fix")
    parser.add_argument("--compare", type=Path, default=None, help="comparison JSON path")
    parser.add_argument("--choose", help="candidate algorithm to approve")
    parser.add_argument("--approved-by", default="user")
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    compare_path = (args.compare or _latest_compare()).resolve()
    listing = list_candidates(compare_path)

    print(f"{'CANDIDATE':<18} {'VALIDATES':<10} {'RISK':<12} MARK")
    print("-" * 52)
    for candidate in listing["candidates"]:
        mark = "recommended" if candidate["target_algorithm"] == listing["recommended"] else ""
        print(f"{candidate['target_algorithm']:<18} {str(candidate.get('validates', False)):<10} "
              f"{candidate.get('risk_before')} -> {candidate.get('risk_after'):<5} {mark}")

    chosen = args.choose or input("Choose a candidate algorithm: ").strip()
    try:
        record = approve(compare_path, chosen, args.approved_by, args.note)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Approval refused: {exc}", file=sys.stderr)
        raise SystemExit(2)

    safe_algorithm = "".join(char if char.isalnum() or char in "_.-" else "_" for char in chosen)
    patch_path = compare_path.parent.parent / "approved_patches" / f"{record.asset_id}_{safe_algorithm}.patch"
    approval_path = compare_path.parent / f"approved_{record.asset_id}.json"
    print(f"Approved {record.chosen_algorithm}: risk {record.risk_before}->{record.risk_after}")
    print(f"Approval record: {approval_path}")
    print(f"Approved patch: {patch_path}")


if __name__ == "__main__":
    main()
