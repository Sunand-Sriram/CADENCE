# Communications Log

## MAC NOTES

- 2026-10-31 — Froze API_CONTRACT.md v1; frontend will build against these shapes; Kali to implement crs_core/api.py + crs_core/ingest.py to match.
- 2026-10-31 — Frontend scaffold created, USE_MOCK=false (live), consuming contract v1, CBOM table done.
- 2026-10-31 — UI redesign to palette, restrained, no filler; panels render only when data exists.
- 2026-10-31 — Added the Risk Assessment panel consuming `/api/risk?job_id=default`; it renders only when assessments exist.
- 2026-10-31 — Added the Quantum Risk (Mosca's Inequality) panel consuming `/api/quantum?job_id=default` with Shor/Grover classification and PQC recommendations.
- 2026-10-31 — Added the Fix Alternatives comparison and approval panel; the Approve button is wired to `POST /api/approve`.
- 2026-10-31 — Wired the ingest bar to `POST /api/ingest`, status polling, and panel refresh using the active `job_id`.
- 2026-10-31 — Updated the compare panel for on-demand fetches with a loading state suited to live LLM latency.
- 2026-10-31 — Added tabbed frontend navigation, stage-driven Analyze progress, bounded Compare progress, and removed latency-specific copy.
- 2026-10-31 — Added shared asset indexing, clearer Weakness labels, detailed fix test results, and a statistical Overview summary.
- 2026-10-31 — Refined top navigation, Fixes candidate fields, and the read-only evidence-backed Approval Review with simulated/refusal handling.
- 2026-10-31 — Restyled CBOM, Risk, Quantum, and Fixes tables as sharp-corner departure-board panels using the existing light palette.
- 2026-10-31 — Increased frontend readability, added persisted evidence restoration and Fixes detail navigation, and clarified Approval review.
- 2026-10-31 — Centered the frontend container, expanded panel width, and increased projector-readable typography across the URL bar, tabs, and dashboard.
- 2026-10-31 — Changed the frontend startup to a blank canvas until Analyze completes, with larger projector typography and responsive full-width alignment.
- 2026-10-31 — Increased departure-board table cell/header text and detail-view monospace sizing for projector readability without changing layout or data behavior.
- 2026-10-31 — Set Overview as the frontend’s default active tab while preserving the blank canvas until Analyze completes.
- 2026-10-31 — Hid tab navigation on the blank canvas and reveal it only after a repository analysis completes.
- 2026-10-31 — Proportioned frontend data-table columns, aligned numeric cells, and tightened the Fixes asset layout without changing data behavior.

## KALI NOTES

- 2026-10-31 — Implemented `crs_core/ingest.py` (`clone_repo(url)`):
  - Shallow clones (`git clone --depth 1`) into `workspace/<repo>/` and resolves the pinned commit SHA via `git rev-parse HEAD`.
  - Existing-clone policy: reuses an existing checkout if `workspace/<repo>/.git` exists and `git rev-parse HEAD` succeeds; otherwise removes the directory and re-clones cleanly.
  - Validates URLs (rejects empty/flag-prefixed inputs and path traversal), disables interactive git prompts (`GIT_TERMINAL_PROMPT=0`), and raises `IngestError` on clone or timeout failure.
- 2026-10-31 — Implemented `crs_core/api.py` (FastAPI on `0.0.0.0:8900`, CORS `allow_origins=["*"]`):
  - Matches `docs/API_CONTRACT.md` v1 verbatim with zero field/path deviations.
  - Pre-loads `job_id="default"` on startup against `targets/target/` (`scan_cbom` -> `score_asset` -> `assess_quantum`) so the frontend renders immediately without a prior `/api/ingest` call.
  - Wraps `crs_core/compare.py` (`compare_alternatives`) for `GET /api/compare` and `crs_core/approval.py` (`approve`) for `POST /api/approve`, mapping `ApprovalRecord.chosen_patch_hash` -> `patch_hash` and returning `status="refused"` cleanly on invalid/non-validating candidates.
- 2026-10-31 — Step 3 Verification & `crypto_stubs.c` CBOM Finding (for Mac side awareness):
  - `cbom.scan_cbom("targets/target")` still accurately detects all 3 call sites in `vuln.c` (`MD5` at line 12 [`1ed2ac29e593`], `AES` at line 13 [`7e9d6230baee`], `rand` at line 15 [`5756754084d8`]) and skips lines 4–5 (`void MD5(...);`, `void AES_encrypt(...);`) via `_is_prototype()`.
  - However, because `crypto_stubs.c` is in `targets/target/` and `_is_prototype()` only filters `;`-terminated declarations (not `{`-terminated function definitions or C block comments), `scan_cbom("targets/target")` also matches 3 entries in `crypto_stubs.c`: line 12 (`MD5` stub definition, `d4925c44139a`), line 19 (`AES_encrypt` stub definition, `47b4cf7302a7`), and line 20 (`AES_encrypt` inside a comment, `e75a1b37ad83`). Because `crypto_stubs.c` sorts before `vuln.c`, raw directory scans double-count `MD5` (2x) and triple-count `AES` (3x).
  - Mitigation applied in `crs_core/api.py` (without modifying `crs_core/cbom.py`): `_run_pipeline()` excludes harness stub files (`crypto_stubs.c`, `fuzz_harness.c`) from the primary `/api/cbom`, `/api/risk`, and `/api/quantum` lists when real target files are present, while retaining all raw assets in an internal lookup so `/api/compare`, `/api/approve`, and `/api/evidence/{asset_id}` still resolve both `vuln.c` and `crypto_stubs.c` asset IDs.
