"""Read-only static crypto inventory for C and C header files."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .schemas import CryptoAsset


_PRIMITIVES = (
    ("MD5", re.compile(r"\bMD5\b", re.IGNORECASE), "hash"),
    ("SHA1", re.compile(r"\bSHA[-_ ]?1\b", re.IGNORECASE), "hash"),
    ("SHA256", re.compile(r"\bSHA[-_ ]?256\b", re.IGNORECASE), "hash"),
    ("SHA512", re.compile(r"\bSHA[-_ ]?512\b", re.IGNORECASE), "hash"),
    ("AES", re.compile(r"\bAES\b", re.IGNORECASE), "encrypt"),
    ("DES", re.compile(r"\bDES\b", re.IGNORECASE), "encrypt"),
    ("3DES", re.compile(r"\b3DES\b|\bTRIPLEDES\b", re.IGNORECASE), "encrypt"),
    ("RC4", re.compile(r"\bRC4\b", re.IGNORECASE), "encrypt"),
    ("ChaCha20", re.compile(r"\bCHACHA20\b", re.IGNORECASE), "encrypt"),
    ("ECB", re.compile(r"\bECB\b", re.IGNORECASE), "encrypt"),
    ("CBC", re.compile(r"\bCBC\b", re.IGNORECASE), "encrypt"),
    ("GCM", re.compile(r"\bGCM\b", re.IGNORECASE), "encrypt"),
    ("CTR", re.compile(r"\bCTR\b", re.IGNORECASE), "encrypt"),
    ("rand", re.compile(r"\brand\s*\(", re.IGNORECASE), "random"),
    ("random", re.compile(r"\brandom\s*\(", re.IGNORECASE), "random"),
    ("arc4random", re.compile(r"\barc4random\s*\(", re.IGNORECASE), "random"),
    ("getrandom", re.compile(r"\bgetrandom\s*\(", re.IGNORECASE), "random"),
)

_LENGTH_OPS = (
    ("integer-length-arithmetic", re.compile(
        r"\b(?:\w*(?:len|length|size|count|capacity|bytes|bits)\w*)\b\s*[+\-*/]"
        r"|[+\-*/]\s*\b(?:\w*(?:len|length|size|count|capacity|bytes|bits)\w*)\b",
        re.IGNORECASE,
    ), "length"),
    ("length-value", re.compile(
        r"\b(?:\w*(?:len|length|size|count|capacity|bytes|bits)\w*)\b",
        re.IGNORECASE,
    ), "length"),
    ("big-int", re.compile(r"\b(?:mpz\w*|BN_\w*|big[_-]?int(?:eger)?)\b"), "bigint"),
    ("memory-allocation", re.compile(r"\b(?:malloc|calloc|realloc)\s*\("), "length"),
    ("length-copy", re.compile(r"\b(?:memcpy|memmove)\s*\("), "length"),
)


def _library(line: str) -> str | None:
    lowered = line.lower()
    for name in ("openssl", "mbedtls", "libsodium", "wolfssl", "boringssl", "nettle"):
        if name in lowered:
            return name
    return None


def _operation(default: str, line: str) -> str:
    lowered = line.lower()
    if default not in {"hash", "random", "length", "bigint"}:
        if "decrypt" in lowered:
            return "decrypt"
        if "hash" in lowered or "digest" in lowered:
            return "hash"
    return default


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
    if algorithm in {"rand", "random"} and operation == "random":
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
            library = _library(line)
            for algorithm, pattern, default_operation in _PRIMITIVES + _LENGTH_OPS:
                if pattern.search(line):
                    operation = _operation(default_operation, line)
                    key = (relative, line_number, algorithm)
                    assets[key] = _asset(relative, line_number, algorithm, operation, library)
    return sorted(assets.values(), key=lambda item: (item.file_path, item.line, item.algorithm))
