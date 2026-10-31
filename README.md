# CADENCE

**Cryptographic Asset Discovery ENgine for Compliance & Encryption**

> Find the weak crypto. Prove the fix.

CADENCE is an AI-driven, fully local, air-gapped platform that ingests any
codebase from a GitHub URL, inventories its cryptography, scores both
**classical** and **quantum** risk, and then **autonomously generates,
validates, and recommends fixes** — with a human in the loop for final
approval. It does not just *flag* weak crypto; it *proves* the fix works
before recommending it.

---

## Why CADENCE

Real codebases are full of cryptographic weaknesses — broken hashes
(MD5/SHA-1), obsolete ciphers (DES/RC4/ECB), insecure randomness — and most
go unnoticed. On top of that, a quantum deadline looms: Shor's algorithm
breaks today's RSA and ECC, so under *"harvest now, decrypt later"* data
stolen today is decrypted tomorrow.

Existing scanners only **flag** problems. They can't prove a fix works, they
ignore quantum risk, and they leave developers guessing. CADENCE closes that
gap with a single tool that **finds, prioritizes (classical *and* quantum),
and verifies** cryptographic fixes.

---

## Pipeline

```
Ingest GitHub repo
      → Crypto CBOM (inventory crypto assets only)
      → Classical risk (deterministic 5-factor score)
      → Quantum CBOM (Mosca's inequality, NIST PQC targets)
      → AI fix: diagnose → patch → re-test (local LLMs)
      → Recommend best candidate
      → Human approves (refuses any unvalidated fix)
```

## Features

- **Ingest any public GitHub repo** by URL — crypto-only analysis of the
  whole codebase.
- **CBOM** — a Cryptography Bill of Materials: every crypto asset with
  algorithm, operation, and `file:line`.
- **Classical risk engine** — deterministic 0–100 score from 5 weighted
  factors (weakness, exposure, data sensitivity, lifetime, feasibility),
  with before/after scoring for candidate fixes.
- **Quantum CBOM** — scores each asset with **Mosca's inequality**
  (`X + Y > Z`), flags Shor-broken (RSA/ECC) and Grover-weakened assets,
  and recommends NIST PQC targets (ML-KEM / ML-DSA / SLH-DSA).
- **Autonomous fix + validation** — local LLMs generate candidate patches;
  a deterministic engine compiles and re-runs the exploit to confirm the fix
  (`builds`, `crash_fixed`, `regression_pass`, `crypto_verified`).
- **Multiple ranked candidates** per vulnerability — best one recommended.
- **Human approval** — a reviewer signs off; the system **refuses to approve
  any fix whose validation ran in simulated mode**.
- **Fully local & air-gapped** — local LLMs via Ollama, no cloud, source code
  and findings never leave the environment.

---

## Architecture

CADENCE runs across one controlled environment. Fuzzing, building, and the
API run on a Linux host; inference runs on local models reachable over the
LAN; Redis is the queue between them.

```
  WINDOWS HOST (GPU)                      LINUX HOST (Kali)
  ┌───────────────────────────┐          ┌──────────────────────────────┐
  │ Ollama (0.0.0.0:11434)     │◀── HTTP ─│ FastAPI API (0.0.0.0:8900)   │
  │   deepseek-r1:7b  MARTIAN  │  LiteLLM │   ingest · cbom · risk       │
  │   qwen2.5-coder:14b VINCENT│          │   quantum · compare · approve│
  │ OLLAMA_MAX_LOADED_MODELS=1 │          │ Celery worker + PRISM        │
  │ Redis (Docker) :6379       │◀── TCP ──│ LibAFL + ASan harness build  │
  └───────────────────────────┘          │ vanilla-JS dashboard (:5500) │
                                          └──────────────────────────────┘
```

### The engine (`crs_core/`)

| Module | Role |
|---|---|
| `schemas.py` | Typed contracts shared across all stages |
| `ingest.py` | Clone a GitHub repo (HTTPS only; SSRF-guarded) |
| `cbom.py` | Crypto-only static scan → CBOM |
| `risk.py` | Deterministic 5-factor risk scoring (before/after) |
| `quantum_cbom.py` | Mosca's-inequality quantum risk + PQC targets |
| `agents.py` | **MARTIAN** (diagnose) → **VINCENT** (patch) → **PRISM** (deterministic validate) |
| `compare.py` | Generate + rank multiple fix candidates |
| `approval.py` | Human approval, bound to a patch hash |
| `broker.py` | Celery/Redis crash-ingest pipeline |
| `api.py` | FastAPI surface the dashboard consumes |

---

## Technology stack

FastAPI · Python · tree-sitter (AST slicing) · Celery + Redis ·
LibAFL + AddressSanitizer · LiteLLM → Ollama ·
DeepSeek-R1 & Qwen2.5-Coder (local) · CycloneDX-style CBOM ·
vanilla HTML/CSS/JS dashboard.

---

## Getting started

### Prerequisites

- A Linux host (tested on Kali) with Python 3.11+, `clang`/`gcc`, Redis.
- A machine running **Ollama** with the models pulled, reachable over the LAN:
  ```bash
  ollama pull deepseek-r1:7b
  ollama pull qwen2.5-coder:14b
  # expose Ollama: OLLAMA_HOST=0.0.0.0, OLLAMA_MAX_LOADED_MODELS=1
  ```

### Configure (`.env`)

```bash
CRS_LLM_MODE=live                 # mock | live
OLLAMA_BASE_URL=http://<ollama-host>:11434
CRS_REDIS_URL=redis://127.0.0.1:6379/0
CRS_REPO_ROOT=./targets/target
CRS_BUILD_CMD=make -C {repo}
CRS_TEST_CMD=make -C {repo} test
CRS_MARTIAN_MODEL=ollama_chat/deepseek-r1:7b
CRS_VINCENT_MODEL=ollama_chat/qwen2.5-coder:14b
```

### Run

```bash
# 1. deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. backend API
uvicorn crs_core.api:app --host 0.0.0.0 --port 8900

# 3. (optional) autonomous worker
celery -A crs_core.broker worker -c 1

# 4. frontend — set API_BASE + USE_MOCK=false in frontend/app.js
cd frontend && python3 -m http.server 5500
```

Open the dashboard, paste a GitHub repo URL, and click **Analyze**.

---

## API (selected)

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/ingest` | Clone + scan a repo |
| GET  | `/api/cbom` | Crypto asset inventory |
| GET  | `/api/risk` | Classical risk scores |
| GET  | `/api/quantum` | Quantum (Mosca) assessment |
| GET  | `/api/compare` | Ranked fix candidates |
| POST | `/api/approve` | Approve a validated fix |
| GET  | `/api/evidence/{asset_id}` | Full evidence bundle |

---

## Security notes

- **Air-gapped by design** — all inference is local; no code or findings
  leave the environment.
- **SSRF-guarded ingest** — HTTPS only; private/loopback/link-local hosts are
  rejected before any clone.
- **Sandboxed validation** — patches are built and run in a disposable copy
  with resource limits; the original source is never modified.
- **No false "fixed"** — a fix is only *validated* if it builds, the exploit
  no longer triggers the sanitizer, a regression passes, and the crypto
  replacement is verified; approval is refused for simulated validations.

---

## Team

B.M.S. College of Engineering, Bengaluru.

Repository: https://github.com/Sunand-Sriram/CADENCE
