"""Repository ingestion: shallow-clone a Git repository and pin its commit SHA."""
from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE = ROOT / "workspace"
CLONE_TIMEOUT_SECONDS = 120

_SAFE_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ALLOWED_SCHEMES = {"http", "https", "git", "ssh", "file"}


class IngestError(RuntimeError):
    """Raised when a repository URL is invalid or cloning fails."""


def _derive_repo_name(url: str) -> str:
    """Validate *url* and extract a sanitized repository directory name."""
    if not isinstance(url, str) or not url.strip():
        raise IngestError("Repository URL must be a non-empty string.")
    cleaned = url.strip()
    if cleaned.startswith("-"):
        raise IngestError("Repository URL must not start with '-'.")

    local_path = Path(cleaned)
    if local_path.exists():
        raw_name = local_path.resolve().name
    else:
        parsed = urlparse(cleaned)
        if parsed.scheme and parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            raise IngestError(f"Unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.scheme and "@" not in cleaned:
            raise IngestError(f"Invalid repository URL: {cleaned!r}")
        path_part = parsed.path if parsed.scheme else cleaned.split(":", 1)[-1]
        raw_name = path_part.rstrip("/\\").split("/")[-1].split("\\")[-1]

    if raw_name.lower().endswith(".git"):
        raw_name = raw_name[:-4]

    if not raw_name or raw_name in {".", ".."} or not _SAFE_REPO_RE.match(raw_name):
        raise IngestError(f"Could not derive a safe repository name from URL: {url!r}")
    return raw_name


def _remove_readonly(func, path, _exc_info) -> None:
    """Clear read-only bit (e.g. .git packfiles on Windows) and retry removal."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _resolve_head(repo_dir: Path) -> str:
    """Run `git rev-parse HEAD` inside *repo_dir* and return the 40-char SHA."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IngestError(f"Failed to run git rev-parse HEAD in {repo_dir}: {exc}") from exc

    sha = (proc.stdout or "").strip()
    if proc.returncode != 0 or not sha:
        stderr = (proc.stderr or "").strip()
        raise IngestError(f"Could not resolve HEAD commit in {repo_dir}: {stderr or 'empty output'}")
    return sha


def clone_repo(url: str, workspace_dir: str | Path | None = None) -> dict[str, str]:
    """Shallow-clone *url* into `workspace/<repo>/` and return repo metadata.

    Existing clone policy:
    If `workspace/<repo>/.git` already exists and has a valid HEAD commit,
    reuse the existing checkout and return its resolved HEAD SHA. If the
    directory exists but is not a valid git checkout, remove it and re-clone
    cleanly.
    """
    repo_name = _derive_repo_name(url)
    workspace_root = Path(workspace_dir).resolve() if workspace_dir else DEFAULT_WORKSPACE.resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    dest = (workspace_root / repo_name).resolve()
    if dest.parent != workspace_root:
        raise IngestError(f"Refusing path outside workspace: {dest}")

    if dest.exists():
        if (dest / ".git").exists():
            try:
                commit = _resolve_head(dest)
                LOGGER.info("Reusing existing clone for %s at %s (%s)", repo_name, dest, commit)
                return {"repo": repo_name, "commit": commit, "path": str(dest)}
            except IngestError:
                LOGGER.warning("Existing directory %s is not a valid git repo; re-cloning.", dest)
        shutil.rmtree(dest, onerror=_remove_readonly)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--", url.strip(), str(dest)],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if dest.exists():
            shutil.rmtree(dest, onerror=_remove_readonly)
        raise IngestError(f"Timed out after {CLONE_TIMEOUT_SECONDS}s cloning {url!r}") from exc
    except OSError as exc:
        raise IngestError(f"Failed to invoke git clone for {url!r}: {exc}") from exc

    if proc.returncode != 0:
        if dest.exists():
            shutil.rmtree(dest, onerror=_remove_readonly)
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise IngestError(f"git clone failed for {url!r}: {stderr or f'exit code {proc.returncode}'}")

    commit = _resolve_head(dest)
    return {"repo": repo_name, "commit": commit, "path": str(dest)}
