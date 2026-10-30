#!/usr/bin/env python3
"""Run the deterministic quantum CBOM and print illustrative Shor cases."""
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crs_core.quantum_cbom import assess_quantum
from crs_core.schemas import CryptoAsset


def _print_assessment(assessment) -> None:
    shor_grover = f"{('Y' if assessment.shor_broken else 'N')}/{('Y' if assessment.grover_weakened else 'N')}"
    comparison = f"{assessment.mosca_x}+{assessment.mosca_y} {'>' if assessment.mosca_x + assessment.mosca_y > assessment.mosca_z else '<='} {assessment.mosca_z}"
    print(f"{assessment.algorithm:<20} {shor_grover:<9} {comparison:<12} "
          f"{str(assessment.mosca_at_risk):<8} {assessment.urgency:<9} {assessment.recommended_pqc}")


def main() -> None:
    cbom_path = ROOT / "evidence" / "cbom.json"
    assets = [CryptoAsset.model_validate(item) for item in json.loads(cbom_path.read_text(encoding="utf-8"))]
    assessments = [assess_quantum(asset) for asset in assets]

    print(f"{'ALGORITHM':<20} {'SHOR/GROVER':<9} {'X+Y VS Z':<12} {'AT_RISK':<8} {'URGENCY':<9} RECOMMENDED PQC")
    print("-" * 105)
    for assessment in assessments:
        _print_assessment(assessment)

    output_path = ROOT / "evidence" / "quantum_cbom.json"
    output_path.write_text(json.dumps([item.model_dump(mode="json") for item in assessments], indent=2) + "\n", encoding="utf-8")

    demos = [
        CryptoAsset(asset_id="demo-rsa-2048", algorithm="RSA-2048", operation="encrypt", file_path="<illustrative>", line=0),
        CryptoAsset(asset_id="demo-ecdsa-p256", algorithm="ECDSA-P256", operation="sign", file_path="<illustrative>", line=0),
    ]
    print("\nILLUSTRATIVE SHOR CASES (synthetic assets; not from cbom.json)")
    print("-" * 105)
    for asset in demos:
        _print_assessment(assess_quantum(asset))
    print(f"\nWrote {len(assessments)} assessments to {output_path}")


if __name__ == "__main__":
    main()
