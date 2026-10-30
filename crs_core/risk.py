"""Deterministic before/after risk scoring for CBOM crypto assets."""
from __future__ import annotations

import re

from .schemas import CryptoAsset, RiskAssessment


# Every factor is 0-100. The weighted score is rounded to the nearest integer.
WEIGHTS = {
    "weakness": 0.35,
    "exposure": 0.20,
    "data_sensitivity": 0.15,
    "lifetime": 0.15,
    "feasibility": 0.15,
}

_WEAKNESS_SCORES = {
    "MD5": 95,
    "SHA1": 85,
    "DES": 95,
    "3DES": 95,
    "RC4": 95,
    "BLOWFISH": 90,
    "ECB": 90,
    "RAND": 95,
    "RANDOM": 95,
    "SRAND": 95,
}


def _key(algorithm: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", algorithm.upper())


def _weakness(asset: CryptoAsset) -> int:
    key = _key(asset.algorithm)
    if key in _WEAKNESS_SCORES:
        score = _WEAKNESS_SCORES[key]
    elif "ECB" in key:
        score = _WEAKNESS_SCORES["ECB"]
    elif key in {"AESGCM", "AES256GCM", "SHA256", "SHA384", "SHA512", "SHA3", "GETRANDOM", "CSPRNG"}:
        score = 10
    elif key.startswith("RSA2048"):
        score = 30
    elif key.startswith("AES") or key.startswith("CHACHA20"):
        score = 15
    else:
        score = 25
    return min(100, score + (5 if asset.is_weak else 0))


def _factors(asset: CryptoAsset) -> dict[str, int]:
    weak = asset.is_weak or _key(asset.algorithm) in _WEAKNESS_SCORES or "ECB" in _key(asset.algorithm)
    operation = asset.operation.lower()
    weakness = _weakness(asset)

    # Strong modern primitives have low defaults; weak assets get explicit
    # exposure/feasibility bumps because they are riskier and need migration.
    exposure = 20 + (40 if weak else 0)
    data_sensitivity = 20 + (25 if weak and operation in {"encrypt", "decrypt", "random"} else 0)
    lifetime = 25 + (25 if weak else 0)
    feasibility = 20 + (40 if weak else 0)
    return {
        "weakness": weakness,
        "exposure": min(100, exposure),
        "data_sensitivity": min(100, data_sensitivity),
        "lifetime": min(100, lifetime),
        "feasibility": min(100, feasibility),
    }


def _band(score: int) -> str:
    if score <= 19:
        return "Low"
    if score <= 39:
        return "Moderate"
    if score <= 69:
        return "High"
    return "Critical"


def score_asset(asset: CryptoAsset) -> RiskAssessment:
    """Score one asset with the fixed five-factor weighted model."""
    factors = _factors(asset)
    score = round(sum(factors[name] * WEIGHTS[name] for name in WEIGHTS))
    dominant = max(WEIGHTS, key=lambda name: factors[name] * WEIGHTS[name])
    rationale = f"{dominant} is the dominant factor at {factors[dominant]}/100."
    return RiskAssessment(
        asset_id=asset.asset_id,
        algorithm=asset.algorithm,
        score=score,
        band=_band(score),
        factors=factors,
        rationale=rationale,
    )


def score_after(original: CryptoAsset, substitute_algorithm: str) -> RiskAssessment:
    """Score the same asset after replacing only its algorithm."""
    substitute = original.model_copy(update={
        "algorithm": substitute_algorithm,
        "is_weak": _key(substitute_algorithm) in _WEAKNESS_SCORES or "ECB" in _key(substitute_algorithm),
        "weak_reason": "",
    })
    return score_asset(substitute)
