#!/usr/bin/env python3
"""Run the read-only CBOM scan and write its JSON inventory."""
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crs_core.cbom import scan_cbom


def main() -> None:
    repo_root = Path(os.getenv("CRS_REPO_ROOT", "./targets/target")).resolve()
    assets = scan_cbom(str(repo_root))
    evidence_path = ROOT / "evidence" / "cbom.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps([asset.model_dump(mode="json") for asset in assets], indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"{'ALGORITHM':<24} {'OPERATION':<10} {'FILE':<28} {'LINE':>4} {'WEAK'}")
    print("-" * 76)
    for asset in assets:
        print(f"{asset.algorithm:<24} {asset.operation:<10} {asset.file_path:<28} "
              f"{asset.line:>4} {'yes' if asset.is_weak else 'no'}")
    print(f"\nWrote {len(assets)} assets to {evidence_path}")


if __name__ == "__main__":
    main()
