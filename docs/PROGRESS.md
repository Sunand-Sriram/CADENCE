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
