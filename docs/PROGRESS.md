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

## 2026-10-31 — Step 4 — tree-sitter slicing

- Added `scripts/check_slice.py` to exercise `slice_function` at the vulnerable
  line in `targets/target/vuln.c`.
- Diagnosed the initial `<window>` fallback as an API mismatch between
  `tree_sitter_languages==1.10.2` and `tree_sitter==0.26.0`; constrained
  `tree_sitter` to `<0.21` in `requirements.txt`.
- Verify result: the checker returned the real `decrypt_record` body with
  `function_name=decrypt_record`, `start_line=4`, and `end_line=14`.

## 2026-10-31 — Step 5 — agents in mock mode

- Added `scripts/check_agents.py` to construct the seed `CrashEvent`, slice the
  target, run MARTIAN and VINCENT, and print their Pydantic results.
- Verify result: with `CRS_LLM_MODE=mock`, both `_complete` calls logged mock
  file selection and made no network call; Diagnosis captured the `<think>`
  reasoning separately with clean JSON fields, and PatchProposal contained a
  complete `decrypt_record` function.

## 2026-10-31 — Step 6 — PRISM + full loop

- Extended `scripts/check_agents.py` to run `orchestrate_repair(event)`, print
  the complete `ValidationResult`, and verify accepted evidence contains the
  diagnosis, patch, and validation bundle.
- Ran with mock LLMs, `CRS_BUILD_CMD=true`, and `CRS_TEST_CMD="echo ok"`.
  PRISM copied the target to scratch, applied the verbatim function patch,
  treated the absent harness's sanitizer-free output as fixed, and passed the
  regression command on attempt 1.
- Verify result: `builds=True`, `crash_fixed=True`, `regression_pass=True`,
  `accepted=True`; `evidence/0334b4d5b14eb1db.json` was created.

## 2026-10-31 — Step 7 — autonomous Celery flow + status + reset

- Added `--submit` and salted crash IDs to `scripts/seed_event.py`, configured
  the macOS-safe Celery worker command, and added `scripts/status.py` plus a
  Redis-aware `scripts/reset_demo.sh` that preserves `crashes/seed_crash`.
- Started the Docker-backed Redis worker and submitted `--submit --salt run1`;
  worker task `crs.handle_crash` ran the full repair loop without further
  action and logged `48064f906ee86511 -> FIXED`.
- Verify result: status reported `48064f906ee86511 integer-overflow FIXED`;
  reset completed with `crs:*` keys cleared and crash/evidence files removed.
- Fixed the worker launcher to put the repository `.venv/bin` on `PATH`, and
  quoted the local ignored `.env` test command so it loads as `echo ok`.

## 2026-10-31 — Step 8 — live-mode fixes (reasoning_trace + vuln_class normalization)

- Captured Ollama/LiteLLM split reasoning from `message.reasoning_content` or
  `message.reasoning`, while retaining inline `<think>` parsing and mock-mode
  behavior.
- Tightened the MARTIAN vulnerability-label instruction and normalized parsed
  values to one allowed class, coercing echoed multi-value hints safely.
- Verify result: mock `scripts/check_agents.py` passed with a single
  `integer-overflow` vulnerability class.

## 2026-10-31 — Step 9 — reset_demo.sh works with Docker or native Redis

- Made `scripts/reset_demo.sh` prefer a host `redis-cli`, otherwise use a
  running `crs-redis` Docker container, with a clear manual-cleanup warning
  when neither backend is available.
- Preserved `crashes/seed_crash`, cleared other crash/evidence files, and
  retained scan-and-delete with `flushdb` fallback for `crs:*` keys.
- Verify result: reset ran without error on macOS using the available Redis
  backend path.

## 2026-10-31 — Step 10 — CBOM crypto inventory

- Added the independent, read-only `scan_cbom()` pass for C/C headers and the
  `scripts/run_cbom.py` table/JSON output, without changing the crash pipeline.
- Added `CryptoAsset` to the end of `crs_core/schemas.py`, including stable
  asset IDs and weak-primitive reasons for legacy algorithms and modes.
- Verify result: scanning `targets/target/vuln.c` detected length arithmetic,
  allocation, and length-copy operations in `decrypt_record`; `evidence/cbom.json`
  was written.
