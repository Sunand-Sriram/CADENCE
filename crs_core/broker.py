"""
crs_core.broker
===============
Asynchronous crash-ingest pipeline. Runs in the Kali VM.

Two ingest paths, one queue:
  * a filesystem watcher on LibAFL's solutions/objectives directory, and
  * an HTTP endpoint (for a LibAFL custom event hook that POSTs crash metadata).

Both normalise to a CrashEvent, dedup by crash_id, and enqueue a Celery task
that hands the event to the agent driver. Redis (on the Windows host via
Docker Desktop) is both broker and result backend.

Run one of:
    python -m crs_core.broker watch      # filesystem watcher
    python -m crs_core.broker api        # FastAPI ingest on :8900
    celery -A crs_core.broker worker -c 1 # the worker that runs repairs

Env:
    CRS_REDIS_URL     redis://<windows-ip>:6379/0
    CRS_SOLUTIONS_DIR LibAFL solutions dir to watch        (default ./crashes)
    CRS_REPO_ROOT     target source root                   (default ./targets/target)
    CRS_HARNESS_BIN   sanitized harness that replays inputs (default ./targets/target/fuzz_harness)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

import redis as redis_lib
from celery import Celery

from .schemas import CrashEvent, Sanitizer

# --------------------------------------------------------------------------- #
# Config (env-driven; the bridged VM must reach the Windows host IP)
# --------------------------------------------------------------------------- #
REDIS_URL = os.getenv("CRS_REDIS_URL", "redis://127.0.0.1:6379/0")
WATCH_DIR = Path(os.getenv("CRS_SOLUTIONS_DIR", "./crashes"))
REPO_ROOT = os.getenv("CRS_REPO_ROOT", "./targets/target")
HARNESS_BIN = os.getenv("CRS_HARNESS_BIN", "./targets/target/fuzz_harness")
REPRODUCE_TIMEOUT = int(os.getenv("CRS_REPRODUCE_TIMEOUT", "60"))

celery_app = Celery("crs", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_acks_late=True,                 # a crashed worker re-queues the task
    worker_prefetch_multiplier=1,        # one heavy repair at a time per worker
    task_default_retry_delay=10,
    broker_connection_retry_on_startup=True,
    result_expires=86400,
)

_rds = redis_lib.Redis.from_url(REDIS_URL)
_DEDUP_SET = "crs:seen_crashes"

# --------------------------------------------------------------------------- #
# Sanitizer report parsing
# --------------------------------------------------------------------------- #
_SUMMARY_RE = re.compile(
    r"(?:ERROR|SUMMARY):\s*"
    r"(?:AddressSanitizer|UndefinedBehaviorSanitizer|libFuzzer|MemorySanitizer)[:\s]+"
    r"([A-Za-z0-9_\-]+)"
)
# first application stack frame: "#3 0x.. in func /path/file.c:123:7"
_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+([^\s:]+):(\d+)")


def _parse_report(text: str):
    crash_type = ""
    m = _SUMMARY_RE.search(text)
    if m:
        crash_type = m.group(1)

    src_file, src_line = "", 0
    fm = _FRAME_RE.search(text)          # first frame is usually the app frame
    if fm:
        src_file, src_line = fm.group(1), int(fm.group(2))

    san = Sanitizer.unknown
    if "AddressSanitizer" in text:
        san = Sanitizer.asan
    elif "UndefinedBehaviorSanitizer" in text:
        san = Sanitizer.ubsan
    elif "MemorySanitizer" in text:
        san = Sanitizer.msan
    elif "ThreadSanitizer" in text:
        san = Sanitizer.tsan
    return crash_type, src_file, src_line, san


def _reproduce(testcase: Path) -> str:
    """Replay the crashing input against the sanitized harness; return stderr."""
    try:
        proc = subprocess.run(
            [HARNESS_BIN, str(testcase)],
            capture_output=True,
            timeout=REPRODUCE_TIMEOUT,
        )
        return (proc.stderr or b"").decode("utf-8", "replace")
    except FileNotFoundError:
        return f"HARNESS_NOT_FOUND: {HARNESS_BIN}"
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def _relativize(src_file: str) -> str:
    """Store source paths relative to repo_root so slicing + PRISM agree."""
    if not src_file:
        return ""
    try:
        return str(Path(src_file).resolve().relative_to(Path(REPO_ROOT).resolve()))
    except ValueError:
        return src_file  # already relative, or outside the repo


def build_event(testcase: Path) -> CrashEvent:
    data = testcase.read_bytes()
    report = _reproduce(testcase)
    ctype, sfile, sline, san = _parse_report(report)
    rel = _relativize(sfile)
    return CrashEvent(
        crash_id=CrashEvent.make_id(data, HARNESS_BIN),
        harness=Path(HARNESS_BIN).name,
        testcase_path=str(testcase.resolve()),
        repo_root=str(Path(REPO_ROOT).resolve()),
        sanitizer=san,
        crash_type=ctype,
        source_file=rel,
        source_line=sline,
        crash_frame=f"{rel}:{sline}" if rel else "",
        stderr_tail=report[-4000:],
    )


def submit(event: CrashEvent) -> bool:
    """Enqueue unless we have seen this crash_id before. Returns True if queued."""
    if _rds.sadd(_DEDUP_SET, event.crash_id) == 0:
        return False
    handle_crash.delay(event.model_dump())
    return True


# --------------------------------------------------------------------------- #
# Celery task: the only place the driver is invoked
# --------------------------------------------------------------------------- #
@celery_app.task(bind=True, name="crs.handle_crash", max_retries=2)
def handle_crash(self, event_dict: dict):
    from .agents import orchestrate_repair  # lazy import: avoids a load-time cycle

    event = CrashEvent(**event_dict)
    try:
        result = orchestrate_repair(event)
        _rds.set(f"crs:result:{event.crash_id}", result.model_dump_json())
        status = "FIXED" if result.accepted else "UNRESOLVED"
        print(f"[worker] {event.crash_id} -> {status} ({result.details[:80]})")
        return result.model_dump()
    except Exception as exc:  # transient infra errors (Ollama down, etc.) -> retry
        print(f"[worker] {event.crash_id} error: {exc!r}; retrying")
        raise self.retry(exc=exc)


# --------------------------------------------------------------------------- #
# Ingest path A: LibAFL solutions-directory watcher
# --------------------------------------------------------------------------- #
def watch_solutions() -> None:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    class _Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            path = Path(event.src_path)
            time.sleep(0.3)  # let LibAFL finish writing the file
            try:
                ev = build_event(path)
            except Exception as ex:
                print(f"[watcher] skip {path.name}: {ex}")
                return
            if submit(ev):
                print(f"[watcher] queued {ev.crash_id} {ev.crash_type or '?'} @ {ev.crash_frame or '?'}")
            else:
                print(f"[watcher] dup {ev.crash_id}")

    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    obs = Observer()
    obs.schedule(_Handler(), str(WATCH_DIR), recursive=True)
    obs.start()
    print(f"[watcher] watching {WATCH_DIR.resolve()} -> {REDIS_URL}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()


# --------------------------------------------------------------------------- #
# Ingest path B: HTTP endpoint for a LibAFL custom event hook
# --------------------------------------------------------------------------- #
def make_api():
    from fastapi import FastAPI

    api = FastAPI(title="CRS crash ingest")

    @api.post("/crash")
    def ingest(event: CrashEvent):
        return {"crash_id": event.crash_id, "queued": submit(event)}

    @api.get("/result/{crash_id}")
    def result(crash_id: str):
        raw = _rds.get(f"crs:result:{crash_id}")
        return json.loads(raw) if raw else {"crash_id": crash_id, "status": "pending"}

    return api


if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "watch"
    if mode == "watch":
        watch_solutions()
    elif mode == "api":
        import uvicorn

        uvicorn.run(make_api(), host="0.0.0.0", port=int(os.getenv("CRS_API_PORT", "8900")))
    else:
        print("usage: python -m crs_core.broker [watch|api]")
