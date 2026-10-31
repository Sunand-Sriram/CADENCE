"""Compare targeted CRS fixes for one weak CBOM crypto asset."""
from __future__ import annotations

import hashlib
import re

from .agents import run_prism, run_vincent_targeted
from .risk import score_after, score_asset
from .schemas import CrashEvent, CryptoAsset, Diagnosis


def _crypto_replaced(original_algorithm: str, target_algorithm: str, patched_code: str) -> bool:
    """Best-effort textual check: the weak primitive's name should be gone
    from the patched function body, and the target algorithm's name should
    appear. Not a full AST check, but catches the exact failure mode where
    VINCENT fixes something else and leaves the weak call in place."""
    old_name = re.escape(original_algorithm.split("-")[0])
    new_name = re.escape(target_algorithm.split("-")[0])
    old_present = re.search(rf"\b{old_name}\b", patched_code, re.IGNORECASE)
    new_present = re.search(rf"\b{new_name}(_|\b)", patched_code, re.IGNORECASE)
    return (not old_present) and bool(new_present)


def compare_alternatives(
    event: CrashEvent,
    diagnosis: Diagnosis,
    func_code: str,
    func_name: str,
    asset: CryptoAsset,
    substitutes: list[str],
) -> dict:
    """Generate, validate, score, and rank one patch per substitute algorithm."""
    before = score_asset(asset)
    candidates = []
    for attempt, target_algorithm in enumerate(substitutes, 1):
        patch = run_vincent_targeted(
            event, diagnosis, func_code, func_name, attempt, target_algorithm
        )
        validation = run_prism(event, patch, attempt)
        crypto_verified = _crypto_replaced(asset.algorithm, target_algorithm, patch.patched_code)
        after = score_after(asset, target_algorithm)
        candidates.append({
            "target_algorithm": target_algorithm,
            "validates": validation.accepted,
            "builds": validation.builds,
            "crash_fixed": validation.crash_fixed,
            "regression_pass": validation.regression_pass,
            "execution_failed": validation.execution_failed,
            "simulated": validation.simulated,
            "crypto_verified": crypto_verified,
            "risk_before": before.score,
            "risk_after": after.score,
            "risk_drop": before.score - after.score,
            "patch_hash": hashlib.sha256(patch.patched_code.encode("utf-8")).hexdigest()[:12],
            "patched_code": patch.patched_code,
        })

    eligible = [
        candidate
        for candidate in candidates
        if candidate["validates"] and candidate["crypto_verified"]
    ]
    recommended = None
    if eligible:
        recommended = min(
            eligible,
            key=lambda candidate: (candidate["risk_after"], -candidate["risk_drop"]),
        )["target_algorithm"]
    return {
        "asset_id": asset.asset_id,
        "algorithm": asset.algorithm,
        "candidates": candidates,
        "recommended": recommended,
    }
