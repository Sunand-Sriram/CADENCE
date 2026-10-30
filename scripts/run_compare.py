#!/usr/bin/env python3
"""Compare multiple targeted fixes for one weak CBOM asset."""
import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crs_core.agents import run_martian, slice_function
from crs_core.compare import compare_alternatives
from crs_core.schemas import CrashEvent, CryptoAsset, Sanitizer


SUBSTITUTES = {
    "md5": ["SHA256", "SHA3-256"],
    "rand": ["getrandom", "arc4random"],
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare targeted CRS crypto fixes")
    parser.add_argument("asset_id", nargs="?", help="asset ID to compare")
    parser.add_argument("--asset-id", dest="asset_id_option", help="asset ID to compare")
    args = parser.parse_args()

    cbom_path = ROOT / "evidence" / "cbom.json"
    assets = [CryptoAsset.model_validate(item) for item in json.loads(cbom_path.read_text(encoding="utf-8"))]
    selected_id = args.asset_id_option or args.asset_id
    asset = next((item for item in assets if item.asset_id == selected_id), None) if selected_id else next(
        (item for item in assets if item.is_weak), None
    )
    if asset is None:
        raise SystemExit("No matching weak asset found in evidence/cbom.json")

    substitutes = SUBSTITUTES.get(asset.algorithm.lower())
    if not substitutes:
        raise SystemExit(f"No comparison substitutes configured for {asset.algorithm}")

    seed_path = ROOT / "crashes" / "seed_crash"
    event = CrashEvent(
        crash_id=CrashEvent.make_id(seed_path.read_bytes(), "fuzz_harness"),
        source_file="vuln.c",
        source_line=16,
        crash_type="signed-integer-overflow",
        sanitizer=Sanitizer.asan,
        harness="fuzz_harness",
        testcase_path=os.path.abspath(seed_path),
        repo_root=os.path.abspath(ROOT / "targets" / "target"),
    )
    func_code, func_name, _, _ = slice_function(
        str(Path(event.repo_root) / event.source_file), event.source_line
    )
    diagnosis = run_martian(event, func_code, func_name)
    result = compare_alternatives(event, diagnosis, func_code, func_name, asset, substitutes)

    print(f"Asset: {result['algorithm']} ({result['asset_id']})")
    print(f"{'CANDIDATE':<18} {'VALIDATES':<10} {'RISK':<18} {'DROP':>5} RECOMMENDED?")
    print("-" * 68)
    for candidate in result["candidates"]:
        risk = f"{candidate['risk_before']} -> {candidate['risk_after']}"
        recommended = "yes" if candidate["target_algorithm"] == result["recommended"] else "no"
        print(f"{candidate['target_algorithm']:<18} {str(candidate['validates']):<10} "
              f"{risk:<18} {candidate['risk_drop']:>5} {recommended}")

    output_path = ROOT / "evidence" / f"compare_{asset.asset_id}.json"
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote comparison to {output_path}")


if __name__ == "__main__":
    main()
