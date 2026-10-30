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

## 2026-10-31 — Step 10b — crypto-only CBOM + crypto in target

- Restricted CBOM detection to cryptographic primitives and common crypto APIs;
  removed all length, memory, copy, and integer-arithmetic detectors.
- Added MD5, AES, and `rand()` stand-ins to `decrypt_record` while preserving
  the existing overflow statement for the crash demo.
- Verify result: CBOM output contained only crypto assets, marked the weak
  primitives, and contained no non-crypto entries.

## 2026-10-31 — Step 11 — deterministic crypto risk engine (before/after)

- Added a fixed five-factor, weighted deterministic risk engine with Low through
  Critical bands and one-line dominant-factor rationales.
- Added before/after substitution scoring for weak CBOM algorithms and a CLI
  that writes `evidence/risk.json`.
- Verify result: MD5 and `rand` scored Critical before replacement and dropped
  sharply with SHA256 and getrandom/CSPRNG; AES remained Low.

## 2026-10-31 — Step 12 — quantum CBOM (Mosca's inequality)

- Added a separate deterministic quantum assessment model using tunable
  Mosca X + Y > Z values and Shor/Grover algorithm-family classification.
- Added `scripts/run_quantum.py` to write `evidence/quantum_cbom.json` and
  print synthetic RSA-2048 and ECDSA-P256 Shor examples for demonstration.
- Verify result: AES was classified as Grover-weakened but not at risk, while
  both illustrative asymmetric assets were Critical and Shor-broken.

## 2026-10-31 — Step 13 — multi-alternative fix comparison

- Added targeted VINCENT generation plus isolated PRISM validation for each
  substitute algorithm, with deterministic before/after risk scoring and rank.
- Added `scripts/run_compare.py` to compare weak CBOM assets and write a
  per-asset comparison artifact with the recommended validated alternative.
- Verify result: mock mode produced and validated both MD5 alternatives,
  included risk drops and patch hashes, and selected a recommendation.

## 2026-10-31 — Step 14 — human approval / fix selection

- Added deterministic human approval records for validated comparison
  candidates, including the selected risk transition and patch hash.
- Added an approval CLI that marks the recommendation, refuses non-validating
  choices, and writes approved function patches outside the original repo.
- Verify result: SHA256 was approved from the mock comparison at risk 66 -> 17;
  non-validating candidate approval was refused.

## 2026-10-31 — Step 15 — repo ingest + FastAPI backend (API CONTRACT v1)

- Implemented `crs_core/ingest.py` with `clone_repo(url)` for shallow-cloning
  repositories (`git clone --depth 1`) into `workspace/<repo>/`, resolving the
  pinned commit SHA via `git rev-parse HEAD`, reusing valid existing clones,
  and raising `IngestError` on bad URLs or clone failures.
- Implemented `crs_core/api.py` (FastAPI on `0.0.0.0:8900` with CORS enabled)
  matching every endpoint path and field name in `docs/API_CONTRACT.md`,
  pre-loading `job_id="default"` from `targets/target/`, filtering harness
  stubs (`crypto_stubs.c`, `fuzz_harness.c`) from primary CBOM listings, and
  wrapping `compare.py` and `approval.py`.
- Verify result: started `uvicorn crs_core.api:app --host 0.0.0.0 --port 8900`
  and verified all 9 contract endpoints (`/api/health`, `/api/ingest`,
  `/api/ingest/{job_id}`, `/api/cbom`, `/api/risk`, `/api/quantum`,
  `/api/compare`, `/api/approve`, `/api/evidence/{asset_id}`) via `httpx`
  against `job_id="default"` and an ingested repository.

## 2026-10-31 — Step 16 — frontend scaffold + live/mock toggle + CBOM panel

- Created the vanilla single-page frontend with live API calls by default,
  contract-shaped mock data, backend-unreachable messaging, and a rendered
  CBOM table.
- Verify result: frontend is runnable with `python -m http.server 5500` from
  `frontend/`; remaining dashboard sections are labeled stubs for follow-up.

## 2026-10-31 — Step 16b — UI redesign (palette, restrained, no filler)

- Reworked the frontend to a light cream/navy dashboard with sand dividers,
  coral weak badges, and restrained rectangular controls.
- Removed unbuilt sections and filler cards so only the header, ingest bar,
  quiet backend state, and real CBOM table render.

## 2026-10-31 — Step 17 — risk panel

- Added the data-driven Risk Assessment table below CBOM with score, severity
  band, and rationale fields from `/api/risk?job_id=default`.
- The panel is omitted when risk assessments are empty or unavailable.
