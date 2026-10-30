import os
from pathlib import Path

from crs_core.schemas import CrashEvent, Sanitizer


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

print(event.model_dump_json(indent=2))
print(event.crash_id)
