"""
crs_core.schemas
================
Strict, typed contracts shared by the broker and the agent driver.

Every message that crosses a process boundary (LibAFL -> broker -> driver,
and MARTIAN -> VINCENT -> PRISM inside the driver) is one of these models.
Keeping them here means all four team members mock against the same shapes.
"""
from __future__ import annotations

import enum
import hashlib
import time

from pydantic import BaseModel, Field


class Sanitizer(str, enum.Enum):
    asan = "address"
    ubsan = "undefined"
    msan = "memory"
    tsan = "thread"
    unknown = "unknown"


class CrashEvent(BaseModel):
    """Produced by the broker from a LibAFL solution. Consumed by the driver."""
    crash_id: str
    harness: str                       # fuzz target / harness name
    testcase_path: str                 # absolute path (in Kali) to the crashing input
    repo_root: str                     # target source root, for slicing + PRISM build
    sanitizer: Sanitizer = Sanitizer.unknown
    crash_type: str = ""               # e.g. heap-buffer-overflow, signed-integer-overflow
    source_file: str = ""              # file holding the crash site, relative to repo_root
    source_line: int = 0
    crash_frame: str = ""              # "file:line" convenience string
    stderr_tail: str = ""              # tail of the sanitizer report
    discovered_at: float = Field(default_factory=time.time)

    @staticmethod
    def make_id(testcase: bytes, harness: str) -> str:
        return hashlib.sha1(harness.encode() + b"::" + testcase).hexdigest()[:16]


class Diagnosis(BaseModel):
    """MARTIAN output. The <think> trace is kept verbatim as evidence."""
    crash_id: str
    root_cause: str = ""
    vulnerability_class: str = "other"   # timing-channel | integer-overflow | bigint-memory | other
    faulty_function: str = ""
    reasoning_trace: str = ""            # the DeepSeek-R1 <think>...</think> content
    confidence: float = 0.0


class PatchProposal(BaseModel):
    """VINCENT output. An ultra-conservative drop-in replacement for ONE function."""
    crash_id: str
    target_file: str
    function_name: str
    original_code: str                   # verbatim original, used by PRISM to locate + replace
    patched_code: str
    rationale: str = ""
    attempt: int = 1


class ValidationResult(BaseModel):
    """PRISM output. Fully deterministic; no model involved."""
    crash_id: str
    attempt: int
    builds: bool = False
    crash_fixed: bool = False            # original PoV no longer triggers the sanitizer
    regression_pass: bool = False
    execution_failed: bool = False
    simulated: bool = False
    details: str = ""

    @property
    def accepted(self) -> bool:
        return (
            self.builds
            and self.crash_fixed
            and self.regression_pass
            and not self.execution_failed
        )


class CryptoAsset(BaseModel):
    """One statically detected cryptographic or crypto-adjacent operation."""
    asset_id: str
    algorithm: str
    operation: str
    file_path: str
    line: int
    library: str | None = None
    is_weak: bool = False
    weak_reason: str = ""


class RiskAssessment(BaseModel):
    """Deterministic weighted risk assessment for one CryptoAsset."""
    asset_id: str
    algorithm: str
    score: int
    band: str
    factors: dict[str, int]
    rationale: str


class QuantumAssessment(BaseModel):
    """Deterministic quantum-decryption and Mosca-inequality assessment."""
    asset_id: str
    algorithm: str
    quantum_vulnerable: bool
    shor_broken: bool
    grover_weakened: bool
    mosca_x: int
    mosca_y: int
    mosca_z: int
    mosca_at_risk: bool
    urgency: str
    recommended_pqc: str
    note: str


class ApprovalRecord(BaseModel):
    """A human selection of one validated candidate fix."""
    asset_id: str
    algorithm: str
    chosen_algorithm: str
    chosen_patch_hash: str
    risk_before: int
    risk_after: int
    approved_by: str = "user"
    approved_at: float
    status: str
    note: str
