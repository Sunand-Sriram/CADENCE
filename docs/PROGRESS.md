# Progress

## 2026-10-31 — Step 1 — Scaffold

- Created the CRS project directories, environment templates, dependency list,
  worker/reset scripts, README, and progress log without modifying `crs_core`.
- Configured mock mode and the requested local Redis, target, crash, evidence,
  and mock paths.
- Verify result: `.venv/bin/python` reports Python 3.11.18, but `python -c
  "import crs_core"` fails with `ModuleNotFoundError` because this checkout does
  not contain the pre-existing `crs_core/` package.

## 2026-10-31 — Step 2 — target + seed event

- Added the single-function crypto-adjacent C target in `targets/target/vuln.c`,
  with a signed length-calculation overflow at line 6, plus the arbitrary-byte
  seed in `crashes/seed_crash`.
- Added `scripts/seed_event.py`, which constructs `CrashEvent` directly from
  the seed and prints its indented JSON followed by the crash ID.
- Verify result: the injector ran successfully in the Python 3.11 venv and
  emitted a valid Pydantic `CrashEvent`.

## 2026-10-31 — Step 3 — mock LLM seam

- Added the environment-controlled offline seam in `_complete()` with mock
  responses for MARTIAN and VINCENT; the live LiteLLM-to-Ollama path remains
  unchanged. No changes were made to `schemas.py` or `broker.py`.
- Added `mocks/martian.txt` with `<think>` reasoning and a Diagnosis-shaped
  JSON response, and `mocks/vincent.txt` with a complete fixed
  `decrypt_record` function and rationale.
- Verify result: importing `_complete` and loading both mock responses passed
  in the Python 3.11 venv; logging showed mock mode and the selected files.
