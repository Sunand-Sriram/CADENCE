import logging
import json
import os
from pathlib import Path

from crs_core.agents import orchestrate_repair, run_martian, run_vincent, slice_function
from crs_core.schemas import CrashEvent, Sanitizer


logging.basicConfig(level=logging.INFO, format="%(message)s")

ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "crashes" / "seed_crash"
HARNESS = "fuzz_harness"
SEED_BYTES = SEED_PATH.read_bytes()

event = CrashEvent(
    crash_id=CrashEvent.make_id(SEED_BYTES, HARNESS),
    source_file="vuln.c",
    source_line=6,
    crash_type="signed-integer-overflow",
    sanitizer=Sanitizer.asan,
    harness=HARNESS,
    testcase_path=os.path.abspath(SEED_PATH),
    repo_root=os.path.abspath(ROOT / "targets" / "target"),
)

func_code, func_name, _, _ = slice_function(event.repo_root + "/" + event.source_file, event.source_line)
diagnosis = run_martian(event, func_code, func_name)
print("Diagnosis:")
print(diagnosis.model_dump_json(indent=2))

patch = run_vincent(event, diagnosis, func_code, func_name, attempt=1)
print("PatchProposal:")
print(patch.model_dump_json(indent=2))

assert diagnosis.vulnerability_class == "integer-overflow"
assert "signed integer overflow" in diagnosis.reasoning_trace
assert diagnosis.reasoning_trace.strip()
assert "<think>" not in diagnosis.root_cause
assert patch.patched_code.startswith("void decrypt_record(")
assert patch.patched_code.rstrip().endswith("}")

result = orchestrate_repair(event)
print("ValidationResult:")
print(result.model_dump_json(indent=2))

evidence_path = ROOT / "evidence" / f"{event.crash_id}.json"
print(f"evidence_path: {evidence_path}")
print(f"evidence_exists: {evidence_path.exists()}")
if not result.accepted:
    print(f"PRISM failure details: {result.details}")
    raise SystemExit("orchestrate_repair did not produce an accepted result")

assert evidence_path.exists()
evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
assert {"diagnosis", "patch", "validation"}.issubset(evidence)
