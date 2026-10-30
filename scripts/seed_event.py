import argparse
import os
from pathlib import Path

from crs_core.schemas import CrashEvent, Sanitizer


ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "crashes" / "seed_crash"
HARNESS = "fuzz_harness"
def main() -> None:
    parser = argparse.ArgumentParser(description="Create and optionally submit a demo CrashEvent")
    parser.add_argument("--submit", action="store_true", help="enqueue the event on Celery")
    parser.add_argument("--salt", default="", help="append a string to the seed bytes before hashing")
    args = parser.parse_args()

    seed_bytes = SEED_PATH.read_bytes() + args.salt.encode("utf-8")
    event = CrashEvent(
        crash_id=CrashEvent.make_id(seed_bytes, HARNESS),
        source_file="vuln.c",
        source_line=6,
        crash_type="signed-integer-overflow",
        sanitizer=Sanitizer.asan,
        harness=HARNESS,
        testcase_path=os.path.abspath(SEED_PATH),
        repo_root=os.path.abspath(ROOT / "targets" / "target"),
    )

    print(event.model_dump_json(indent=2))
    if args.submit:
        from crs_core.broker import submit

        print(f"queued: {submit(event)}")
    print(event.crash_id)

if __name__ == "__main__":
    main()
