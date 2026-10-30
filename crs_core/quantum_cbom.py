"""Deterministic quantum-risk classification using Mosca's inequality."""
from __future__ import annotations

import re

from .schemas import CryptoAsset, QuantumAssessment


def _key(algorithm: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", algorithm.upper())


def _key_bits(algorithm: str, default: int = 128) -> int:
    match = re.search(r"(?:AES|CHACHA)[^0-9]*(128|192|256)", algorithm.upper())
    return int(match.group(1)) if match else default


def _classify(algorithm: str) -> tuple[bool, bool, bool, str, str]:
    """Return (quantum vulnerable, Shor, Grover, recommendation, note)."""
    key = _key(algorithm)
    if key in {"MD5", "SHA1", "DES", "RC4", "RAND", "RANDOM", "SRAND"}:
        return False, False, False, "no action", "Already classically weak; quantum effects are not the limiting risk."
    if any(name in key for name in ("RSA", "DSA", "ECDSA", "ECDH", "DH", "ED25519", "CURVE25519")):
        if "ECDSA" in key or "ED25519" in key or "SIGN" in key:
            recommendation = "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)"
            note = "Shor's algorithm breaks the asymmetric signature scheme."
        else:
            recommendation = "ML-KEM (Kyber)"
            note = "Shor's algorithm breaks the asymmetric key-establishment scheme."
        return True, True, False, recommendation, note
    if any(name in key for name in ("AES", "CHACHA20", "3DES")):
        bits = _key_bits(algorithm, 256 if "CHACHA20" in key else 128)
        vulnerable = bits < 256
        recommendation = "AES-256" if vulnerable else "no action"
        note = "Grover halves effective key strength; 256-bit symmetric keys remain at 128-bit effective strength." \
            if not vulnerable else "Grover halves effective key strength; this key size is conditionally at risk."
        return vulnerable, False, True, recommendation, note
    if any(name in key for name in ("SHA256", "SHA384", "SHA512", "SHA3", "HMAC")):
        return False, False, True, "no action", "Grover weakens hashes, but this family retains at least 256-bit security parameters."
    return False, False, False, "no action", "No quantum break was identified for this asset classification."


def assess_quantum(
    asset: CryptoAsset,
    x_shelf_life: int = 10,
    y_migration: int = 3,
    z_crqc: int = 10,
) -> QuantumAssessment:
    """Assess one asset with Mosca's X + Y > Z inequality."""
    quantum_vulnerable, shor_broken, grover_weakened, recommendation, note = _classify(asset.algorithm)
    margin = x_shelf_life + y_migration - z_crqc
    at_risk = margin > 0 and quantum_vulnerable
    if not at_risk:
        urgency = "None"
    elif shor_broken:
        urgency = "Critical" if margin >= 0 else "High"
    elif margin >= 5:
        urgency = "High"
    else:
        urgency = "Medium"
    return QuantumAssessment(
        asset_id=asset.asset_id,
        algorithm=asset.algorithm,
        quantum_vulnerable=quantum_vulnerable,
        shor_broken=shor_broken,
        grover_weakened=grover_weakened,
        mosca_x=x_shelf_life,
        mosca_y=y_migration,
        mosca_z=z_crqc,
        mosca_at_risk=at_risk,
        urgency=urgency,
        recommended_pqc=recommendation,
        note=note,
    )
