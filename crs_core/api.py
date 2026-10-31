"""FastAPI backend for CADENCE CRS (API CONTRACT v1)."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    """Load key=value pairs from .env if present without overriding existing env."""
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    try:
        for raw_line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, val)
    except OSError:
        pass


_load_dotenv()
os.environ.setdefault("CRS_LLM_MODE", "mock")
os.environ.setdefault("CRS_TEST_CMD", "echo ok")
if os.environ.get("CRS_LLM_MODE", "mock").lower() == "mock":
    os.environ.setdefault("CRS_BUILD_CMD", "echo ok")

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import agents as _agents
from .approval import approve as run_approve
from .cbom import scan_cbom
from .compare import compare_alternatives
from .ingest import IngestError, clone_repo
from .quantum_cbom import assess_quantum
from .risk import score_after, score_asset
from .schemas import (
    CrashEvent,
    CryptoAsset,
    PatchProposal,
    QuantumAssessment,
    RiskAssessment,
    Sanitizer,
    ValidationResult,
)

# Ensure PRISM has non-empty test/build commands in mock mode even if agents was imported earlier.
if not _agents.TEST_CMD:
    _agents.TEST_CMD = os.environ.get("CRS_TEST_CMD", "echo ok")
if os.environ.get("CRS_LLM_MODE", "mock").lower() == "mock" and _agents.BUILD_CMD in {"make -C {repo}", "true"}:
    _agents.BUILD_CMD = os.environ.get("CRS_BUILD_CMD", "echo ok")
    if _agents.BUILD_CMD == "true" and os.name == "nt":
        _agents.BUILD_CMD = "echo ok"

LOGGER = logging.getLogger(__name__)

CRS_API_KEY = os.getenv("CRS_API_KEY", "")
if not CRS_API_KEY:
    LOGGER.warning("CRS_API_KEY is unset; API key authentication on mutating endpoints is disabled.")


def require_api_key(x_crs_api_key: str = Header(default="")) -> None:
    if CRS_API_KEY and x_crs_api_key != CRS_API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-CRS-API-Key header")


DEFAULT_TARGET_DIR = Path(os.getenv("CRS_REPO_ROOT", str(ROOT / "targets" / "target"))).resolve()
EVIDENCE_DIR = Path(os.getenv("CRS_EVIDENCE_DIR", str(ROOT / "evidence"))).resolve()

# Link-only harness stubs in targets/target/ are filtered from primary CBOM listings
# so call sites in vuln.c are not double-counted against crypto_stubs.c definitions.
_HARNESS_STUB_FILES = {"crypto_stubs.c", "fuzz_harness.c", "crypto_shim.h"}

SUBSTITUTES: dict[str, list[str]] = {
    "md5": ["SHA256", "SHA3-256"],
    "sha1": ["SHA256", "SHA3-256"],
    "rand": ["getrandom", "arc4random"],
    "random": ["getrandom", "arc4random"],
    "srand": ["getrandom", "arc4random"],
    "des": ["AES-256-GCM", "ChaCha20"],
    "3des": ["AES-256-GCM", "ChaCha20"],
    "rc4": ["AES-256-GCM", "ChaCha20"],
    "blowfish": ["AES-256-GCM", "ChaCha20"],
    "ecb": ["AES-256-GCM", "GCM"],
    "aes": ["AES-256-GCM", "ChaCha20"],
}

app = FastAPI(title="CADENCE CRS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IngestRequest(BaseModel):
    repo_url: str


class ApproveRequest(BaseModel):
    asset_id: str
    job_id: str = "default"
    chosen_algorithm: str
    approved_by: str = "demo-reviewer"
    note: str = ""


# In-memory job store keyed by job_id.
JOBS: dict[str, dict[str, Any]] = {}


def _local_head_commit(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        sha = (proc.stdout or "").strip()
        if proc.returncode == 0 and sha:
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    return "local"


def _serialize_asset(asset: CryptoAsset) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "algorithm": asset.algorithm,
        "operation": asset.operation,
        "file_path": asset.file_path,
        "line": asset.line,
        "is_weak": asset.is_weak,
        "weak_reason": asset.weak_reason,
    }


def _serialize_risk(assessment: RiskAssessment) -> dict[str, Any]:
    return {
        "asset_id": assessment.asset_id,
        "algorithm": assessment.algorithm,
        "score": assessment.score,
        "band": assessment.band,
        "factors": assessment.factors,
        "rationale": assessment.rationale,
    }


def _serialize_quantum(assessment: QuantumAssessment) -> dict[str, Any]:
    return {
        "asset_id": assessment.asset_id,
        "algorithm": assessment.algorithm,
        "shor_broken": assessment.shor_broken,
        "grover_weakened": assessment.grover_weakened,
        "mosca_x": assessment.mosca_x,
        "mosca_y": assessment.mosca_y,
        "mosca_z": assessment.mosca_z,
        "mosca_at_risk": assessment.mosca_at_risk,
        "urgency": assessment.urgency,
        "recommended_pqc": assessment.recommended_pqc,
        "note": assessment.note,
    }


def _serialize_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    default_simulated = os.getenv("CRS_LLM_MODE", "mock").lower() != "live"
    patch_hash = str(candidate.get("patch_hash", ""))
    return {
        "target_algorithm": str(candidate.get("target_algorithm", "")),
        "validates": bool(candidate.get("validates", False)),
        "builds": bool(candidate.get("builds", False)),
        "crash_fixed": bool(candidate.get("crash_fixed", False)),
        "regression_pass": bool(candidate.get("regression_pass", False)),
        "execution_failed": bool(candidate.get("execution_failed", False)),
        "simulated": bool(candidate.get("simulated", default_simulated)),
        "crypto_verified": bool(candidate.get("crypto_verified", False)),
        "risk_before": int(candidate.get("risk_before", 0)),
        "risk_after": int(candidate.get("risk_after", 0)),
        "risk_drop": int(candidate.get("risk_drop", 0)),
        "patch_hash": patch_hash,
        "patch_hash_short": str(candidate.get("patch_hash_short", patch_hash[:12])),
    }


def _run_pipeline(repo_path: Path, repo_name: str, commit: str, job_id: str) -> dict[str, Any]:
    """Scan CBOM (excluding harness link stubs when real files exist), score risk & quantum."""
    raw_assets = scan_cbom(str(repo_path)) if repo_path.exists() else []
    filtered_assets = [
        asset for asset in raw_assets if Path(asset.file_path).name not in _HARNESS_STUB_FILES
    ]
    primary_assets = filtered_assets if filtered_assets else raw_assets

    risk_map: dict[str, RiskAssessment] = {}
    quantum_map: dict[str, QuantumAssessment] = {}
    all_assets_map: dict[str, CryptoAsset] = {}

    for asset in raw_assets:
        all_assets_map[asset.asset_id] = asset
        risk_map[asset.asset_id] = score_asset(asset)
        quantum_map[asset.asset_id] = assess_quantum(asset)

    job_data = {
        "job_id": job_id,
        "status": "done",
        "repo": repo_name,
        "commit": commit,
        "path": str(repo_path),
        "error": None,
        "assets": primary_assets,
        "all_assets": all_assets_map,
        "risk_map": risk_map,
        "quantum_map": quantum_map,
        "comparisons": {},
        "approvals": {},
    }
    JOBS[job_id] = job_data
    return job_data


def _get_job(job_id: str | None) -> dict[str, Any]:
    effective_id = (job_id or "default").strip() or "default"
    if effective_id in JOBS:
        return JOBS[effective_id]
    if effective_id == "default":
        commit = _local_head_commit(DEFAULT_TARGET_DIR)
        return _run_pipeline(DEFAULT_TARGET_DIR, DEFAULT_TARGET_DIR.name, commit, "default")
    return {
        "job_id": effective_id,
        "status": "error",
        "repo": "",
        "commit": "",
        "path": str(DEFAULT_TARGET_DIR),
        "error": f"Unknown job_id: {effective_id}",
        "assets": [],
        "all_assets": {},
        "risk_map": {},
        "quantum_map": {},
        "comparisons": {},
        "approvals": {},
    }


def _find_asset(job: dict[str, Any], asset_id: str) -> CryptoAsset | None:
    asset = job.get("all_assets", {}).get(asset_id)
    if asset is not None:
        return asset
    default_job = _get_job("default")
    return default_job.get("all_assets", {}).get(asset_id)


def _compute_or_load_comparison(job: dict[str, Any], asset_id: str) -> dict[str, Any]:
    """Run or load compare.compare_alternatives for *asset_id* and persist to evidence/."""
    cached = job.get("comparisons", {}).get(asset_id)
    compare_path = EVIDENCE_DIR / f"compare_{asset_id}.json"

    if cached is not None and compare_path.exists():
        return cached

    asset = _find_asset(job, asset_id)
    if asset is None and not asset_id:
        # Fallback to first weak asset in the job if asset_id was omitted.
        asset = next((a for a in job.get("assets", []) if a.is_weak), None)

    if asset is None:
        if compare_path.exists():
            try:
                loaded = json.loads(compare_path.read_text(encoding="utf-8"))
                job.setdefault("comparisons", {})[asset_id] = loaded
                return loaded
            except (OSError, json.JSONDecodeError):
                pass
        return {
            "asset_id": asset_id,
            "algorithm": "",
            "candidates": [],
            "recommended": None,
        }

    substitutes = SUBSTITUTES.get(asset.algorithm.lower(), ["SHA256", "AES-256-GCM"])
    repo_root = Path(job.get("path") or DEFAULT_TARGET_DIR)
    if not (repo_root / asset.file_path).exists() and (DEFAULT_TARGET_DIR / asset.file_path).exists():
        repo_root = DEFAULT_TARGET_DIR

    source_file = asset.file_path if (repo_root / asset.file_path).exists() else "vuln.c"
    target_file_path = repo_root / source_file
    if not target_file_path.exists():
        repo_root = DEFAULT_TARGET_DIR
        source_file = "vuln.c"
        target_file_path = repo_root / source_file

    seed_path = ROOT / "crashes" / "seed_crash"
    seed_bytes = seed_path.read_bytes() if seed_path.exists() else b"seed"
    source_line = 16 if source_file == "vuln.c" else max(asset.line, 1)

    event = CrashEvent(
        crash_id=CrashEvent.make_id(seed_bytes, "fuzz_harness"),
        source_file=source_file,
        source_line=source_line,
        crash_type="signed-integer-overflow",
        sanitizer=Sanitizer.asan,
        harness="fuzz_harness",
        testcase_path=str(seed_path.resolve()),
        repo_root=str(repo_root.resolve()),
    )

    default_simulated = os.getenv("CRS_LLM_MODE", "mock").lower() != "live"

    try:
        func_code, func_name, _, _ = _agents.slice_function(
            str(target_file_path.resolve()), event.source_line
        )
        diagnosis = _agents.run_martian(event, func_code, func_name)
        result = compare_alternatives(event, diagnosis, func_code, func_name, asset, substitutes)
        result["_diagnosis"] = diagnosis.model_dump(mode="json")
        result["_crash"] = event.model_dump(mode="json")
        result["_func_code"] = func_code
        result["_func_name"] = func_name

        candidates = result.get("candidates", [])
        recommended_alg = result.get("recommended")
        selected_idx, selected_cand = next(
            (
                (idx, cand)
                for idx, cand in enumerate(candidates, 1)
                if cand.get("target_algorithm") == recommended_alg
            ),
            (1, candidates[0]) if candidates else (1, None),
        )
        if selected_cand is not None:
            result["_patch"] = PatchProposal(
                crash_id=event.crash_id,
                target_file=event.source_file,
                function_name=func_name,
                original_code=func_code,
                patched_code=str(selected_cand.get("patched_code", "")),
                rationale=(
                    f"Targeted replacement of {asset.algorithm} with "
                    f"{selected_cand.get('target_algorithm', '')}."
                ),
                attempt=selected_idx,
            ).model_dump(mode="json")
            c_fixed = bool(selected_cand.get("crash_fixed", False))
            r_pass = bool(selected_cand.get("regression_pass", False))
            exec_failed = bool(selected_cand.get("execution_failed", False))
            sim = bool(selected_cand.get("simulated", default_simulated))
            result["_validation"] = ValidationResult(
                crash_id=event.crash_id,
                attempt=selected_idx,
                builds=bool(selected_cand.get("builds", False)),
                crash_fixed=c_fixed,
                regression_pass=r_pass,
                execution_failed=exec_failed,
                simulated=sim,
                details=f"crash_fixed={c_fixed}; regression_pass={r_pass}.",
            ).model_dump(mode="json")
    except Exception as exc:
        LOGGER.exception("Comparison failed for asset %s: %s", asset.asset_id, exc)
        before = score_asset(asset)
        fallback_candidates = []
        for target_alg in substitutes:
            after = score_after(asset, target_alg)
            fallback_candidates.append({
                "target_algorithm": target_alg,
                "validates": False,
                "builds": False,
                "crash_fixed": False,
                "regression_pass": False,
                "execution_failed": True,
                "simulated": default_simulated,
                "crypto_verified": False,
                "risk_before": before.score,
                "risk_after": after.score,
                "risk_drop": before.score - after.score,
                "patch_hash": "",
                "patch_hash_short": "",
                "patched_code": "",
            })
        result = {
            "asset_id": asset.asset_id,
            "algorithm": asset.algorithm,
            "candidates": fallback_candidates,
            "recommended": None,
        }

    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        disk_payload = {
            "asset_id": result["asset_id"],
            "algorithm": result["algorithm"],
            "candidates": result["candidates"],
            "recommended": result["recommended"],
        }
        compare_path.write_text(json.dumps(disk_payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("Could not persist comparison to %s: %s", compare_path, exc)

    job.setdefault("comparisons", {})[asset.asset_id] = result
    return result


# Pre-load job_id="default" at startup so the frontend can render immediately.
_get_job("default")


@app.get("/api/health")
def get_health() -> dict[str, str]:
    mode = os.getenv("CRS_LLM_MODE", "mock").strip().lower()
    if mode not in {"mock", "live"}:
        mode = "mock"
    return {"status": "ok", "llm_mode": mode}


@app.post("/api/ingest", dependencies=[Depends(require_api_key)])
def post_ingest(payload: IngestRequest) -> dict[str, Any]:
    job_id = uuid.uuid4().hex[:12]
    repo_url = (payload.repo_url or "").strip()
    JOBS[job_id] = {
        "job_id": job_id,
        "status": "running",
        "repo": "",
        "commit": "",
        "path": "",
        "error": None,
        "assets": [],
        "all_assets": {},
        "risk_map": {},
        "quantum_map": {},
        "comparisons": {},
        "approvals": {},
    }
    try:
        info = clone_repo(repo_url)
        _run_pipeline(Path(info["path"]), info["repo"], info["commit"], job_id)
        return {
            "job_id": job_id,
            "repo": info["repo"],
            "commit": info["commit"],
            "status": JOBS[job_id]["status"],
        }
    except (IngestError, Exception) as exc:
        LOGGER.warning("Ingest failed for %r: %s", repo_url, exc)
        repo_guess = repo_url.rstrip("/").split("/")[-1]
        if repo_guess.lower().endswith(".git"):
            repo_guess = repo_guess[:-4]
        JOBS[job_id].update({
            "status": "error",
            "repo": repo_guess,
            "commit": "",
            "error": str(exc),
        })
        return {
            "job_id": job_id,
            "repo": repo_guess,
            "commit": "",
            "status": JOBS[job_id]["status"],
            "error": JOBS[job_id]["error"],
        }


@app.get("/api/ingest/{job_id}")
def get_ingest_status(job_id: str) -> dict[str, Any]:
    job = _get_job(job_id)
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "repo": job["repo"],
        "commit": job["commit"],
        "error": job["error"],
    }


@app.get("/api/cbom")
def get_cbom(job_id: str = Query(default="default")) -> dict[str, list[dict[str, Any]]]:
    job = _get_job(job_id)
    return {"assets": [_serialize_asset(asset) for asset in job.get("assets", [])]}


@app.get("/api/risk")
def get_risk(job_id: str = Query(default="default")) -> dict[str, list[dict[str, Any]]]:
    job = _get_job(job_id)
    risk_map: dict[str, RiskAssessment] = job.get("risk_map", {})
    assessments = [
        _serialize_risk(risk_map[asset.asset_id])
        for asset in job.get("assets", [])
        if asset.asset_id in risk_map
    ]
    return {"assessments": assessments}


@app.get("/api/quantum")
def get_quantum(job_id: str = Query(default="default")) -> dict[str, list[dict[str, Any]]]:
    job = _get_job(job_id)
    quantum_map: dict[str, QuantumAssessment] = job.get("quantum_map", {})
    assessments = [
        _serialize_quantum(quantum_map[asset.asset_id])
        for asset in job.get("assets", [])
        if asset.asset_id in quantum_map
    ]
    return {"assessments": assessments}


@app.get("/api/compare")
def get_compare(
    asset_id: str = Query(default=""),
    job_id: str = Query(default="default"),
) -> dict[str, Any]:
    job = _get_job(job_id)
    result = _compute_or_load_comparison(job, asset_id)
    return {
        "asset_id": str(result.get("asset_id", asset_id)),
        "algorithm": str(result.get("algorithm", "")),
        "candidates": [_serialize_candidate(c) for c in result.get("candidates", [])],
        "recommended": result.get("recommended"),
    }


@app.post("/api/approve", dependencies=[Depends(require_api_key)])
def post_approve(payload: ApproveRequest) -> dict[str, Any]:
    job = _get_job(payload.job_id)
    asset_id = (payload.asset_id or "").strip()
    chosen_algorithm = (payload.chosen_algorithm or "").strip()

    comparison = _compute_or_load_comparison(job, asset_id)
    resolved_asset_id = str(comparison.get("asset_id") or asset_id)
    compare_path = EVIDENCE_DIR / f"compare_{resolved_asset_id}.json"

    candidate = next(
        (
            item
            for item in comparison.get("candidates", [])
            if item.get("target_algorithm") == chosen_algorithm
        ),
        None,
    )
    validation_dict = comparison.get("_validation") or {}
    is_simulated = (
        bool(candidate["simulated"])
        if candidate is not None and "simulated" in candidate
        else bool(
            validation_dict.get(
                "simulated",
                os.getenv("CRS_LLM_MODE", "mock").lower() != "live",
            )
        )
    )
    if is_simulated:
        raise HTTPException(
            status_code=400,
            detail=(
                "cannot approve a patch validated in simulated/mock mode — "
                "set CRS_LLM_MODE=live and re-run compare first"
            ),
        )

    try:
        if candidate is not None and bool(candidate.get("execution_failed", False)):
            raise ValueError(f"cannot approve candidate with execution_failed=True: {chosen_algorithm}")
        approved_by = (payload.approved_by or "").strip() or "demo-reviewer"
        record = run_approve(
            compare_path,
            chosen_algorithm=chosen_algorithm,
            approved_by=approved_by,
            note=payload.note,
        )
        approval_payload = {
            "status": "approved",
            "asset_id": record.asset_id,
            "chosen_algorithm": record.chosen_algorithm,
            "risk_before": int(record.risk_before),
            "risk_after": int(record.risk_after),
            "patch_hash": record.chosen_patch_hash,
            "note": record.note or f"Approved {record.chosen_algorithm} for {record.algorithm}",
        }
        job.setdefault("approvals", {})[record.asset_id] = record.model_dump(mode="json")
        return approval_payload
    except (OSError, ValueError, KeyError) as exc:
        asset = _find_asset(job, resolved_asset_id)
        risk_before = int(candidate["risk_before"]) if candidate and "risk_before" in candidate else (
            score_asset(asset).score if asset else 0
        )
        risk_after = int(candidate["risk_after"]) if candidate and "risk_after" in candidate else (
            score_after(asset, chosen_algorithm).score if (asset and chosen_algorithm) else risk_before
        )
        return {
            "status": "refused",
            "asset_id": resolved_asset_id,
            "chosen_algorithm": chosen_algorithm,
            "risk_before": risk_before,
            "risk_after": risk_after,
            "patch_hash": str(candidate.get("patch_hash", "")) if candidate else "",
            "note": str(exc),
        }


@app.get("/api/evidence/{asset_id}")
def get_evidence(
    asset_id: str,
    job_id: str = Query(default="default"),
) -> dict[str, Any]:
    job = _get_job(job_id)
    asset = _find_asset(job, asset_id)

    risk_obj = job.get("risk_map", {}).get(asset_id) or (score_asset(asset) if asset else None)
    quantum_obj = job.get("quantum_map", {}).get(asset_id) or (assess_quantum(asset) if asset else None)

    compare_path = EVIDENCE_DIR / f"compare_{asset_id}.json"
    comparison = job.get("comparisons", {}).get(asset_id)
    if comparison is None and compare_path.exists():
        try:
            comparison = json.loads(compare_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            comparison = None

    approved_path = EVIDENCE_DIR / f"approved_{asset_id}.json"
    approval = job.get("approvals", {}).get(asset_id)
    if approval is None and approved_path.exists():
        try:
            approval = json.loads(approved_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            approval = None

    # Include any crash/diagnosis/patch/validation bundle from evidence/ if present.
    crash_bundle: dict[str, Any] = {}
    if EVIDENCE_DIR.exists():
        for path in sorted(EVIDENCE_DIR.glob("*.json")):
            if path.name.startswith(("compare_", "approved_")) or path.name in {
                "cbom.json",
                "risk.json",
                "quantum_cbom.json",
            }:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and {"diagnosis", "patch", "validation"}.issubset(data):
                    crash_bundle = data
                    break
            except (OSError, json.JSONDecodeError):
                continue

    # Assemble patch and validation from the standalone crash bundle or active comparison candidate.
    derived_patch = comparison.get("_patch") if comparison else None
    derived_validation = comparison.get("_validation") if comparison else None
    if comparison and (derived_patch is None or derived_validation is None or approval):
        candidates = comparison.get("candidates", [])
        target_alg = (
            approval.get("chosen_algorithm")
            if isinstance(approval, dict) and approval.get("chosen_algorithm")
            else comparison.get("recommended")
        )
        selected_idx, selected_cand = next(
            (
                (idx, cand)
                for idx, cand in enumerate(candidates, 1)
                if cand.get("target_algorithm") == target_alg
            ),
            (1, candidates[0]) if candidates else (1, None),
        )
        if selected_cand is not None:
            crash_info = crash_bundle.get("crash") or comparison.get("_crash") or {}
            diag_info = crash_bundle.get("diagnosis") or comparison.get("_diagnosis") or {}
            crash_id = str(crash_info.get("crash_id") or diag_info.get("crash_id") or asset_id)
            target_file = str(
                crash_info.get("source_file") or (asset.file_path if asset else "vuln.c")
            )
            func_name = str(
                comparison.get("_func_name") or diag_info.get("faulty_function") or "decrypt_record"
            )
            orig_code = str(comparison.get("_func_code") or "")
            derived_patch = PatchProposal(
                crash_id=crash_id,
                target_file=target_file,
                function_name=func_name,
                original_code=orig_code,
                patched_code=str(selected_cand.get("patched_code", "")),
                rationale=(
                    f"Targeted replacement of {comparison.get('algorithm', '')} with "
                    f"{selected_cand.get('target_algorithm', '')}."
                ),
                attempt=selected_idx,
            ).model_dump(mode="json")
            c_fixed = bool(selected_cand.get("crash_fixed", False))
            r_pass = bool(selected_cand.get("regression_pass", False))
            exec_failed = bool(selected_cand.get("execution_failed", False))
            sim = bool(
                selected_cand.get(
                    "simulated",
                    os.getenv("CRS_LLM_MODE", "mock").lower() != "live",
                )
            )
            derived_validation = ValidationResult(
                crash_id=crash_id,
                attempt=selected_idx,
                builds=bool(selected_cand.get("builds", False)),
                crash_fixed=c_fixed,
                regression_pass=r_pass,
                execution_failed=exec_failed,
                simulated=sim,
                details=f"crash_fixed={c_fixed}; regression_pass={r_pass}.",
            ).model_dump(mode="json")

    return {
        "asset_id": asset_id,
        "job_id": job["job_id"],
        "repo": job["repo"],
        "commit": job["commit"],
        "asset": _serialize_asset(asset) if asset else None,
        "risk": _serialize_risk(risk_obj) if risk_obj else None,
        "quantum": _serialize_quantum(quantum_obj) if quantum_obj else None,
        "comparison": {
            "asset_id": comparison.get("asset_id", asset_id),
            "algorithm": comparison.get("algorithm", asset.algorithm if asset else ""),
            "candidates": comparison.get("candidates", []),
            "recommended": comparison.get("recommended"),
        } if comparison else None,
        "approval": approval,
        "crash": crash_bundle.get("crash") or (comparison.get("_crash") if comparison else None),
        "diagnosis": crash_bundle.get("diagnosis") or (comparison.get("_diagnosis") if comparison else None),
        "patch": crash_bundle.get("patch") or derived_patch,
        "validation": crash_bundle.get("validation") or derived_validation,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8900)
