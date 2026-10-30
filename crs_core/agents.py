"""
crs_core.agents
===============
The strict multi-agent driver. Runs in the Kali VM; reaches the two local
models over the network via LiteLLM -> Ollama on the Windows host.

Pipeline for one CrashEvent:
    slice (tree-sitter)  ->  MARTIAN (DeepSeek-R1, diagnosis)
                         ->  VINCENT (Qwen-Coder, drop-in patch)  <-\
                         ->  PRISM   (deterministic build/rerun)  --/ bounded loop

Design rules enforced here:
  * Context handed to the models is ONLY the enclosing function (Buttercup
    slicing) plus the sanitizer tail -- keeps tokens and VRAM small.
  * The loop is sequential, so only one model is GPU-resident at a time.
    Set OLLAMA_MAX_LOADED_MODELS=1 on the Windows host to guarantee it.
  * DeepSeek-R1's <think>...</think> is split out and kept as evidence;
    JSON is parsed only from what follows.
  * PRISM is deterministic. A patch is accepted only if the project builds,
    the original PoV no longer trips the sanitizer, AND a regression passes.

Env:
    OLLAMA_BASE_URL        http://<windows-ip>:11434
    CRS_MARTIAN_MODEL      ollama_chat/deepseek-r1:7b
    CRS_VINCENT_MODEL      ollama_chat/qwen2.5-coder:14b
    CRS_LLM_TIMEOUT        per-call seconds                  (default 600)
    CRS_MAX_PATCH_ATTEMPTS bounded VINCENT<->PRISM retries   (default 4)
    CRS_HARNESS_BIN_REL    harness path relative to repo     (default fuzz_harness)
    CRS_BUILD_CMD          build command, {repo} templated   (default "make -C {repo}")
    CRS_TEST_CMD           regression command (REQUIRED for acceptance)
    CRS_EVIDENCE_DIR       where accepted bundles are written (default ./evidence)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import litellm

from .schemas import CrashEvent, Diagnosis, PatchProposal, ValidationResult

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
MARTIAN_MODEL = os.getenv("CRS_MARTIAN_MODEL", "ollama_chat/deepseek-r1:7b")
VINCENT_MODEL = os.getenv("CRS_VINCENT_MODEL", "ollama_chat/qwen2.5-coder:14b")
LLM_TIMEOUT = int(os.getenv("CRS_LLM_TIMEOUT", "600"))
MAX_ATTEMPTS = int(os.getenv("CRS_MAX_PATCH_ATTEMPTS", "4"))

HARNESS_BIN_REL = os.getenv("CRS_HARNESS_BIN_REL", "fuzz_harness")
BUILD_CMD = os.getenv("CRS_BUILD_CMD", "make -C {repo}")
TEST_CMD = os.getenv("CRS_TEST_CMD", "")          # empty -> acceptance impossible (by design)
EVIDENCE_DIR = Path(os.getenv("CRS_EVIDENCE_DIR", "./evidence"))

BUILD_TIMEOUT = int(os.getenv("CRS_BUILD_TIMEOUT", "600"))
RUN_TIMEOUT = int(os.getenv("CRS_RUN_TIMEOUT", "60"))

# --------------------------------------------------------------------------- #
# LLM transport
# --------------------------------------------------------------------------- #
def _complete(model: str, prompt: str, temperature: float = 0.1, max_tokens: int = 2048) -> str:
    """One-shot completion against local Ollama. R1 ignores system prompts, so
    everything goes in a single user turn."""
    resp = litellm.completion(
        model=model,
        api_base=OLLAMA_BASE_URL,
        api_key="ollama",                       # placeholder; Ollama needs no key
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=LLM_TIMEOUT,
    )
    return resp["choices"][0]["message"]["content"] or ""


_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL)


def split_think(text: str) -> tuple[str, str]:
    """Return (reasoning, answer). Handles closed and truncated <think> blocks."""
    thoughts = _THINK_RE.findall(text)
    answer = _THINK_RE.sub("", text).strip()
    if "<think>" in answer and "</think>" not in text:   # truncated, never closed
        head, _, tail = answer.partition("<think>")
        thoughts.append(tail)
        answer = head.strip()
    return "\n".join(t.strip() for t in thoughts), answer


def extract_json(text: str) -> Optional[dict]:
    """Pull a JSON object from a model reply: fenced block first, then the first
    balanced {...}."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = []
    if fence:
        candidates.append(fence.group(1))
    # balanced-brace scan as a fallback
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
        start = text.find("{", start + 1)
        if len(candidates) > 5:
            break
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            continue
    return None


# --------------------------------------------------------------------------- #
# Slicing (Buttercup-style): crash line -> enclosing function block
# --------------------------------------------------------------------------- #
_EXT_LANG = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".java": "java", ".py": "python",
    ".rs": "rust", ".go": "go", ".js": "javascript", ".ts": "typescript",
}
_FUNC_NODES = {
    "function_definition", "function_declarator", "method_declaration",
    "function_declaration", "constructor_declaration", "function_item",
    "method_definition",
}


def _node_name(node, src: bytes) -> str:
    for child in node.children:
        if child.type in ("identifier", "name", "field_identifier"):
            return src[child.start_byte:child.end_byte].decode("utf-8", "replace")
    # C: name lives under the declarator
    for child in node.children:
        if "declarator" in child.type:
            return _node_name(child, src) or ""
    return ""


def slice_function(abs_path: str, line: int) -> tuple[str, str, int, int]:
    """Return (code, function_name, start_line, end_line) for the smallest
    function node spanning `line`. Falls back to a +/-20 line window."""
    path = Path(abs_path)
    src = path.read_bytes()
    target_row = max(line - 1, 0)

    try:
        from tree_sitter_languages import get_parser
        lang = _EXT_LANG.get(path.suffix.lower(), "c")
        tree = get_parser(lang).parse(src)
    except Exception:
        tree = None

    best = None
    if tree is not None:
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] <= target_row <= node.end_point[0]:
                if node.type in _FUNC_NODES:
                    span = node.end_point[0] - node.start_point[0]
                    if best is None or span < (best.end_point[0] - best.start_point[0]):
                        best = node
                stack.extend(node.children)

    if best is not None:
        code = src[best.start_byte:best.end_byte].decode("utf-8", "replace")
        return code, _node_name(best, src) or "<unknown>", best.start_point[0] + 1, best.end_point[0] + 1

    lines = src.decode("utf-8", "replace").splitlines()
    lo, hi = max(0, line - 20), min(len(lines), line + 20)
    return "\n".join(lines[lo:hi]), "<window>", lo + 1, hi


# --------------------------------------------------------------------------- #
# MARTIAN -- analysis agent (DeepSeek-R1)
# --------------------------------------------------------------------------- #
def run_martian(event: CrashEvent, func_code: str, func_name: str) -> Diagnosis:
    prompt = f"""You are a cryptographic vulnerability analyst. A fuzzer crashed inside the function below.

CRASH TYPE: {event.crash_type or 'unknown'}
SANITIZER: {event.sanitizer.value}
LOCATION: {event.crash_frame or 'unknown'}
SANITIZER REPORT (tail):
{event.stderr_tail[-1500:]}

FUNCTION UNDER ANALYSIS ({func_name}):
```
{func_code}
```

Reason step by step inside <think>...</think>. Then output ONLY one JSON object, no prose after it:
{{"root_cause": "<concise>", "vulnerability_class": "timing-channel|integer-overflow|bigint-memory|other", "faulty_function": "{func_name}", "confidence": 0.0}}"""
    raw = _complete(MARTIAN_MODEL, prompt, temperature=0.1)
    reasoning, answer = split_think(raw)
    data = extract_json(answer) or {}
    return Diagnosis(
        crash_id=event.crash_id,
        root_cause=str(data.get("root_cause", "")).strip(),
        vulnerability_class=str(data.get("vulnerability_class", "other")).strip() or "other",
        faulty_function=str(data.get("faulty_function", func_name)).strip() or func_name,
        reasoning_trace=reasoning,
        confidence=float(data.get("confidence", 0.0) or 0.0),
    )


# --------------------------------------------------------------------------- #
# VINCENT -- patch agent (Qwen2.5-Coder)
# --------------------------------------------------------------------------- #
def run_vincent(
    event: CrashEvent,
    diagnosis: Diagnosis,
    func_code: str,
    func_name: str,
    attempt: int,
    feedback: str = "",
) -> PatchProposal:
    fb = f"\nPREVIOUS ATTEMPT FAILED VALIDATION. Fix the cause, do not just reformat:\n{feedback}\n" if feedback else ""
    prompt = f"""You are a security patch engineer. Produce an ULTRA-CONSERVATIVE drop-in replacement for exactly ONE function. Change only what is needed to remove the vulnerability. Keep the signature, the name, and all legitimate behaviour and outputs identical.

VULNERABILITY CLASS: {diagnosis.vulnerability_class}
ROOT CAUSE: {diagnosis.root_cause}
{fb}
ORIGINAL FUNCTION ({func_name}):
```
{func_code}
```

Output ONLY one JSON object, no prose:
{{"patched_code": "<the complete replacement function, compilable as-is>", "rationale": "<one sentence>"}}"""
    raw = _complete(VINCENT_MODEL, prompt, temperature=0.0)
    _, answer = split_think(raw)          # coder model rarely emits <think>, strip anyway
    data = extract_json(answer) or {}
    return PatchProposal(
        crash_id=event.crash_id,
        target_file=event.source_file,
        function_name=func_name,
        original_code=func_code,
        patched_code=str(data.get("patched_code", "")).strip(),
        rationale=str(data.get("rationale", "")).strip(),
        attempt=attempt,
    )


# --------------------------------------------------------------------------- #
# PRISM -- deterministic validator (NO model)
# --------------------------------------------------------------------------- #
def _run(cmd: str, cwd: str, timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, shell=True, capture_output=True, timeout=timeout
        )
        out = (proc.stdout or b"").decode("utf-8", "replace") + \
              (proc.stderr or b"").decode("utf-8", "replace")
        return proc.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as exc:
        return False, f"RUN_ERROR: {exc!r}"


def _sanitizer_triggered(text: str) -> bool:
    return any(s in text for s in (
        "AddressSanitizer", "UndefinedBehaviorSanitizer",
        "MemorySanitizer", "ThreadSanitizer", "ERROR: libFuzzer",
    ))


def _make_scratch(repo_root: str) -> str:
    """Isolated copy of the target so the original snapshot is never touched."""
    dst = tempfile.mkdtemp(prefix="crs_scratch_")
    shutil.copytree(repo_root, dst, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git"))
    return dst


def run_prism(event: CrashEvent, patch: PatchProposal, attempt: int) -> ValidationResult:
    scratch = _make_scratch(event.repo_root)
    try:
        target = Path(scratch) / event.source_file
        if not target.exists():
            return ValidationResult(crash_id=event.crash_id, attempt=attempt,
                                    details=f"target file missing in scratch: {event.source_file}")

        text = target.read_text(encoding="utf-8", errors="replace")
        original = patch.original_code.strip()
        if original and original not in text:
            # the model hallucinated the function body -> refuse, do not guess
            return ValidationResult(crash_id=event.crash_id, attempt=attempt,
                                    details="original function not found verbatim; patch not applied")
        target.write_text(text.replace(original, patch.patched_code.strip(), 1),
                          encoding="utf-8")

        builds, build_log = _run(BUILD_CMD.format(repo=scratch), cwd=scratch, timeout=BUILD_TIMEOUT)
        if not builds:
            return ValidationResult(crash_id=event.crash_id, attempt=attempt,
                                    builds=False, details=f"build failed:\n{build_log[-1500:]}")

        harness = str(Path(scratch) / HARNESS_BIN_REL)
        _, run_log = _run(f'"{harness}" "{event.testcase_path}"', cwd=scratch, timeout=RUN_TIMEOUT)
        crash_fixed = not _sanitizer_triggered(run_log)

        if TEST_CMD:
            regression_pass, test_log = _run(TEST_CMD.format(repo=scratch), cwd=scratch, timeout=BUILD_TIMEOUT)
        else:
            regression_pass, test_log = False, "CRS_TEST_CMD unset: cannot confirm no regression"

        detail = (f"crash_fixed={crash_fixed}; regression_pass={regression_pass}. "
                  f"{'' if crash_fixed else 'PoV still triggers sanitizer. '}"
                  f"{test_log[-600:] if not regression_pass else ''}")
        return ValidationResult(crash_id=event.crash_id, attempt=attempt, builds=True,
                                crash_fixed=crash_fixed, regression_pass=regression_pass,
                                details=detail.strip())
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Orchestrator: the one entry point the Celery task calls
# --------------------------------------------------------------------------- #
def _persist(event: CrashEvent, diag: Diagnosis, patch: PatchProposal, result: ValidationResult) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "crash": event.model_dump(),
        "diagnosis": diag.model_dump(),
        "patch": patch.model_dump(),
        "validation": result.model_dump(),
    }
    (EVIDENCE_DIR / f"{event.crash_id}.json").write_text(json.dumps(bundle, indent=2))


def orchestrate_repair(event: CrashEvent) -> ValidationResult:
    if not event.source_file:
        return ValidationResult(crash_id=event.crash_id, attempt=0,
                                details="no source location in crash; cannot slice")

    abs_path = str(Path(event.repo_root) / event.source_file)
    func_code, func_name, _, _ = slice_function(abs_path, event.source_line)

    diagnosis = run_martian(event, func_code, func_name)

    feedback, last = "", None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        patch = run_vincent(event, diagnosis, func_code, func_name, attempt, feedback)
        if not patch.patched_code:
            feedback = "no patch produced; return a complete replacement function"
            last = ValidationResult(crash_id=event.crash_id, attempt=attempt, details=feedback)
            continue

        result = run_prism(event, patch, attempt)
        last = result
        if result.accepted:
            _persist(event, diagnosis, patch, result)
            return result
        feedback = result.details        # structured failure drives the next attempt

    return last or ValidationResult(crash_id=event.crash_id, attempt=0, details="no attempts made")
