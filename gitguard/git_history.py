"""Git history scanning and repository cloning via subprocess.

We shell out to ``git`` directly rather than depending on a library so the
tool works anywhere git is installed and never imports/executes repo code.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .models import Finding, Source
from .scanner import ScanConfig, scan_text
from .utils import GitGuardError, parse_github_url

# Cap how much history we scan so huge repos don't hang.
DEFAULT_MAX_COMMITS = 500
GIT_TIMEOUT = 120


def git_available() -> bool:
    return shutil.which("git") is not None


def _run_git(args: list[str], cwd: Optional[Path] = None, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def clone_repo(url: str, dest: Path, *, depth: Optional[int] = None) -> Path:
    """Clone a GitHub repo into ``dest`` (a temp dir). Never executes hooks."""

    if not git_available():
        raise GitGuardError(
            "git is not installed, so remote repositories cannot be cloned.",
            fixes=["Install git", "Or scan a local clone / ZIP instead"],
        )
    # Validate the URL shape early for a friendlier error.
    parse_github_url(url)

    args = ["clone", "--quiet"]
    if depth:
        args += ["--depth", str(depth)]
    args += [url, str(dest)]
    # Disable any credential/hook prompts; keep the clone non-interactive.
    env_proc = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
        check=False,
        env={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo", "PATH": _path_env()},
    )
    if env_proc.returncode != 0:
        raise GitGuardError(
            "Could not clone repository.",
            reason=f"git exited with code {env_proc.returncode}: "
            f"{env_proc.stderr.strip() or 'no details'}",
            fixes=[
                "Check the URL is correct",
                "Make sure the repository is public or that you are authenticated",
                "Try cloning manually and scanning the local folder instead",
            ],
        )
    return dest


def _path_env() -> str:
    import os

    return os.environ.get("PATH", "/usr/bin:/bin")


def is_git_repo(path: Path) -> bool:
    if not git_available():
        return False
    res = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=path)
    return res.returncode == 0 and res.stdout.strip() == "true"


def _list_commits(repo: Path, max_commits: int) -> list[tuple[str, str, str]]:
    """Return ``(hash, author, iso_date)`` for up to ``max_commits`` commits."""

    res = _run_git(
        ["log", f"-n{max_commits}", "--pretty=format:%H%x1f%an%x1f%aI"],
        cwd=repo,
    )
    if res.returncode != 0:
        return []
    commits = []
    for line in res.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 3:
            commits.append((parts[0], parts[1], parts[2]))
    return commits


def _commit_diff_added(repo: Path, commit: str) -> dict[str, list[tuple[int, str]]]:
    """Return added lines per file for ``commit`` as ``{path: [(line, text)]}``.

    Only added lines (``+`` in a unified diff) are returned, with their new
    line numbers, so we report where a secret was introduced.
    """

    res = _run_git(
        ["show", "--unified=0", "--no-color", "--format=", commit],
        cwd=repo,
    )
    if res.returncode != 0:
        return {}

    added: dict[str, list[tuple[int, str]]] = {}
    current_file: Optional[str] = None
    new_line = 0
    for raw in res.stdout.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
            added.setdefault(current_file, [])
        elif raw.startswith("@@"):
            # @@ -a,b +c,d @@  -> grab c
            try:
                plus = raw.split("+", 1)[1]
                new_line = int(plus.split(",")[0].split(" ")[0])
            except (IndexError, ValueError):
                new_line = 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if current_file is not None:
                added[current_file].append((new_line, raw[1:]))
                new_line += 1
    return added


def scan_history(
    repo: Path,
    config: ScanConfig,
    *,
    max_commits: int = DEFAULT_MAX_COMMITS,
    progress=None,
) -> tuple[list[Finding], int]:
    """Scan added lines across commit history.

    Returns ``(findings, commits_scanned)``. Never raises on git issues; it
    degrades to an empty result so the current-files scan still succeeds.
    """

    if not git_available() or not is_git_repo(repo):
        return [], 0

    commits = _list_commits(repo, max_commits)
    findings: list[Finding] = []
    scanned = 0
    for commit_hash, author, date in commits:
        if progress:
            progress(commit_hash[:8])
        try:
            added = _commit_diff_added(repo, commit_hash)
        except subprocess.TimeoutExpired:
            continue
        scanned += 1
        for file_path, lines in added.items():
            # Reconstruct just the added lines into a pseudo-blob, preserving
            # original line numbers by padding. To keep numbers accurate we
            # scan line-by-line instead.
            for line_no, text in lines:
                line_findings = scan_text(
                    text,
                    f"{file_path}",
                    config,
                    source=Source.HISTORY,
                    commit=commit_hash[:10],
                    author=author,
                    date=date,
                )
                # scan_text reports line 1; fix to the real line number.
                for f in line_findings:
                    f.line = line_no
                findings.extend(line_findings)
    return findings, scanned


def dedupe_history_against_current(
    current: list[Finding], history: list[Finding]
) -> list[Finding]:
    """Keep history findings whose secret preview isn't already in current files.

    This surfaces secrets that were *removed* from the working tree but still
    live in history (the dangerous case), while avoiding duplicate noise for
    secrets that are still present.
    """

    seen = {(f.rule_id, f.match_preview) for f in current}
    out = []
    history_seen: set[tuple[str, str, str]] = set()
    for f in history:
        key = (f.rule_id, f.match_preview)
        if key in seen:
            continue
        # Collapse the same secret appearing across many commits.
        commit_key = (f.rule_id, f.match_preview, f.path)
        if commit_key in history_seen:
            continue
        history_seen.add(commit_key)
        out.append(f)
    return out


def temp_clone_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="gitguard-clone-"))
