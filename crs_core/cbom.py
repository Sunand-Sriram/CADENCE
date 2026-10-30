"""Read-only static crypto inventory for C and C header files."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .schemas import CryptoAsset


_DETECTORS = (
    # Hashes and common OpenSSL hash APIs.
    ("MD5", re.compile(r"\bMD5(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA1", re.compile(r"\bSHA[-_ ]?1(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA224", re.compile(r"\bSHA[-_ ]?224(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA256", re.compile(r"\bSHA[-_ ]?256(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA384", re.compile(r"\bSHA[-_ ]?384(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA512", re.compile(r"\bSHA[-_ ]?512(?:\b|_)", re.IGNORECASE), "hash"),
    ("SHA3", re.compile(r"\bSHA[-_ ]?3(?:\b|_)", re.IGNORECASE), "hash"),
    # Symmetric ciphers and modes.
    ("AES", re.compile(r"\bAES(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("DES", re.compile(r"\bDES(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("3DES", re.compile(r"\b(?:3DES|TRIPLEDES)(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("RC4", re.compile(r"\bRC4(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("Blowfish", re.compile(r"\bBLOWFISH(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("ChaCha20", re.compile(r"\bCHACHA20(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("ECB", re.compile(r"\bECB(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("CBC", re.compile(r"\bCBC(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("CTR", re.compile(r"\bCTR(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("GCM", re.compile(r"\bGCM(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("CFB", re.compile(r"\bCFB(?:\b|_)", re.IGNORECASE), "encrypt"),
    ("OFB", re.compile(r"\bOFB(?:\b|_)", re.IGNORECASE), "encrypt"),
    # Asymmetric primitives.
    ("RSA", re.compile(r"\bRSA(?:\b|_)", re.IGNORECASE), "crypto"),
    ("DSA", re.compile(r"\bDSA(?:\b|_)", re.IGNORECASE), "crypto"),
    ("ECDSA", re.compile(r"\bECDSA(?:\b|_)", re.IGNORECASE), "sign"),
    ("ECDH", re.compile(r"\bECDH(?:\b|_)", re.IGNORECASE), "kdf"),
    ("DH", re.compile(r"\bDH(?:\b|_)", re.IGNORECASE), "kdf"),
    ("Ed25519", re.compile(r"\bED25519(?:\b|_)", re.IGNORECASE), "sign"),
    ("Curve25519", re.compile(r"\bCURVE25519(?:\b|_)", re.IGNORECASE), "crypto"),
    # MACs, KDFs, and insecure random sources.
    ("HMAC", re.compile(r"\bHMAC(?:\b|_)", re.IGNORECASE), "mac"),
    ("PBKDF2", re.compile(r"\bPBKDF2(?:\b|_)", re.IGNORECASE), "kdf"),
    ("bcrypt", re.compile(r"\bBCRYPT(?:\b|_)", re.IGNORECASE), "kdf"),
    ("scrypt", re.compile(r"\bSCRYPT(?:\b|_)", re.IGNORECASE), "kdf"),
    ("Argon2", re.compile(r"\bARGON2(?:\b|_)", re.IGNORECASE), "kdf"),
    ("rand", re.compile(r"\brand\s*\(", re.IGNORECASE), "random"),
    ("random", re.compile(r"\brandom\s*\(", re.IGNORECASE), "random"),
    ("srand", re.compile(r"\bsrand\s*\(", re.IGNORECASE), "random"),
    # Common library entry points that are crypto by contract.
    ("EVP", re.compile(r"\bEVP_[A-Za-z0-9_]+\b"), "crypto"),
    ("libsodium crypto_api", re.compile(r"\bcrypto_[A-Za-z0-9_]+\b"), "crypto"),
    ("mbedtls crypto_api", re.compile(r"\bmbedtls_[A-Za-z0-9_]+\b"), "crypto"),
)


def _library(line: str) -> str | None:
    lowered = line.lower()
    for name in ("openssl", "mbedtls", "libsodium", "wolfssl", "boringssl", "nettle"):
        if name in lowered:
            return name
    if re.search(r"\b(?:EVP|MD5|SHA\d*|AES|DES|RSA|HMAC)_", line):
        return "openssl"
    if "crypto_" in line:
        return "libsodium"
    if "mbedtls_" in line:
        return "mbedtls"
    return None


def _operation(default: str, line: str) -> str:
    lowered = line.lower()
    if default in {"hash", "random"}:
        return default
    if "decrypt" in lowered:
        return "decrypt"
    if "encrypt" in lowered or "cipher" in lowered:
        return "encrypt"
    if "hash" in lowered or "digest" in lowered:
        return "hash"
    if "sign" in lowered or "verify" in lowered:
        return "sign"
    if "hmac" in lowered or "mac" in lowered:
        return "mac"
    if "kdf" in lowered or "pbkdf" in lowered or "scrypt" in lowered:
        return "kdf"
    return default


def _is_prototype(line: str) -> bool:
    """Avoid treating a C function declaration as a crypto operation."""
    return bool(re.match(
        r"^\s*(?:static\s+|extern\s+)?(?:const\s+)?(?:unsigned\s+)?"
        r"(?:void|char|short|int|long|size_t|[A-Za-z_]\w*)\s+\**\w+\s*\([^;]*\)\s*;\s*$",
        line,
    ))


def _weakness(algorithm: str, operation: str) -> tuple[bool, str]:
    reasons = {
        "MD5": "MD5 is cryptographically broken.",
        "SHA1": "SHA-1 is deprecated for collision-resistant security use.",
        "DES": "DES has an obsolete, too-small key size.",
        "3DES": "3DES is deprecated and has inadequate security margin.",
        "RC4": "RC4 has known biases and is deprecated.",
        "ECB": "ECB mode leaks plaintext patterns.",
    }
    if algorithm in reasons:
        return True, reasons[algorithm]
    if algorithm in {"rand", "random", "srand"} and operation == "random":
        return True, "rand()/random() is not suitable for security-sensitive randomness."
    return False, ""


def _asset(file_path: str, line: int, algorithm: str, operation: str,
           library: str | None) -> CryptoAsset:
    asset_id = hashlib.sha1(f"{file_path}:{line}:{algorithm}".encode()).hexdigest()[:12]
    is_weak, weak_reason = _weakness(algorithm, operation)
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        operation=operation,
        file_path=file_path,
        line=line,
        library=library,
        is_weak=is_weak,
        weak_reason=weak_reason,
    )


def scan_cbom(repo_root: str) -> list[CryptoAsset]:
    """Scan C/C headers below *repo_root* without modifying the repository."""
    root = Path(repo_root).resolve()
    assets: dict[tuple[str, int, str], CryptoAsset] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".c", ".h"}:
            continue
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if _is_prototype(line):
                continue
            library = _library(line)
            for algorithm, pattern, default_operation in _DETECTORS:
                if pattern.search(line):
                    operation = _operation(default_operation, line)
                    key = (relative, line_number, algorithm)
                    assets[key] = _asset(relative, line_number, algorithm, operation, library)
    return sorted(assets.values(), key=lambda item: (item.file_path, item.line, item.algorithm))
