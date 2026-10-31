"""Deterministic human approval and patch-output workflow."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from .schemas import ApprovalRecord


def _load(compare_json_path: str | Path) -> tuple[Path, dict]:
    path = Path(compare_json_path).resolve()
    return path, json.loads(path.read_text(encoding="utf-8"))


def list_candidates(compare_json_path: str | Path) -> dict:
    """Return candidates and the comparison engine's recommendation."""
    _, comparison = _load(compare_json_path)
    return {
        "candidates": comparison.get("candidates", []),
        "recommended": comparison.get("recommended"),
    }


def _patch_text(compare_path: Path, candidate: dict) -> str:
    patch = candidate.get("patched_code", "")
    if patch:
        return patch
    # Backward-compatible lookup for artifacts created before patch text was
    # persisted: accept only an exact hash match in an evidence bundle.
    expected = candidate.get("patch_hash", "")
    evidence_dir = compare_path.parent
    for bundle_path in sorted(evidence_dir.glob("*.json")):
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        patch = bundle.get("patch", {}).get("patched_code", "") if isinstance(bundle, dict) else ""
        if patch:
            digest = hashlib.sha256(patch.encode("utf-8")).hexdigest()
            if digest == expected or digest[:12] == expected:
                return patch
    raise ValueError("chosen patch text is not available with the recorded patch hash")


def approve(
    compare_json_path: str | Path,
    chosen_algorithm: str,
    approved_by: str = "demo-reviewer",
    note: str = "",
) -> ApprovalRecord:
    """Approve one validated candidate and write its patch outside the repo."""
    compare_path, comparison = _load(compare_json_path)
    candidates = comparison.get("candidates", [])
    candidate = next(
        (item for item in candidates if item.get("target_algorithm") == chosen_algorithm),
        None,
    )
    if candidate is None:
        raise ValueError(f"unknown candidate algorithm: {chosen_algorithm}")
    if not candidate.get("validates", False):
        raise ValueError(f"cannot approve non-validating candidate: {chosen_algorithm}")

    patch_text = _patch_text(compare_path, candidate)
    full_hash = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
    recorded_hash = str(candidate.get("patch_hash", ""))
    if recorded_hash not in {full_hash, full_hash[:12]}:
        raise ValueError("candidate patch hash does not match its patch text")
    patch_hash = full_hash if len(recorded_hash) == 64 else full_hash[:12]

    record = ApprovalRecord(
        asset_id=comparison["asset_id"],
        algorithm=comparison["algorithm"],
        chosen_algorithm=chosen_algorithm,
        chosen_patch_hash=patch_hash,
        risk_before=int(candidate["risk_before"]),
        risk_after=int(candidate["risk_after"]),
        approved_by=approved_by,
        approved_at=time.time(),
        status="approved",
        note=note,
    )
    evidence_dir = compare_path.parent
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / f"approved_{record.asset_id}.json").write_text(
        json.dumps(record.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    safe_algorithm = re.sub(r"[^A-Za-z0-9_.-]+", "_", chosen_algorithm)
    patches_dir = evidence_dir.parent / "approved_patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_path = patches_dir / f"{record.asset_id}_{safe_algorithm}.patch"
    patch_path.write_text(patch_text, encoding="utf-8")
    return record
