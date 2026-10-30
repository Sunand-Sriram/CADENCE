#!/usr/bin/env python3
"""Score the CBOM before and after deterministic substitutions."""
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crs_core.risk import score_after, score_asset
from crs_core.schemas import CryptoAsset


SUBSTITUTES = {
    "MD5": "SHA256",
    "SHA1": "SHA256",
    "DES": "AES-256-GCM",
    "3DES": "AES-256-GCM",
    "RC4": "AES-256-GCM",
    "Blowfish": "AES-256-GCM",
    "ECB": "GCM",
    "rand": "getrandom/CSPRNG",
    "random": "getrandom/CSPRNG",
    "srand": "getrandom/CSPRNG",
}


def _substitute(algorithm: str) -> str | None:
    lowered = algorithm.lower()
    for name, substitute in SUBSTITUTES.items():
        if lowered == name.lower():
            return substitute
    return None


def main() -> None:
    cbom_path = ROOT / "evidence" / "cbom.json"
    assets = [CryptoAsset.model_validate(item) for item in json.loads(cbom_path.read_text(encoding="utf-8"))]
    records = []

    print(f"{'ALGORITHM':<24} {'SCORE':>5} {'BAND':<9} DOMINANT FACTOR")
    print("-" * 68)
    for asset in assets:
        before = score_asset(asset)
        dominant = max(before.factors, key=lambda name: before.factors[name])
        substitute = _substitute(asset.algorithm) if asset.is_weak else None
        after = score_after(asset, substitute) if substitute else None
        print(f"{asset.algorithm:<24} {before.score:>5} {before.band:<9} {dominant}")
        if after is not None:
            print(f"  {before.score} {before.band} -> {after.score} {after.band} using {substitute}")
        records.append({
            "asset": asset.model_dump(mode="json"),
            "before": before.model_dump(mode="json"),
            "after": after.model_dump(mode="json") if after else None,
            "substitute_algorithm": substitute,
        })

    risk_path = ROOT / "evidence" / "risk.json"
    risk_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {len(records)} assessments to {risk_path}")


if __name__ == "__main__":
    main()
