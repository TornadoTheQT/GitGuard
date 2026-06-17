"""Shared helpers: redaction, file classification, ignore rules, errors."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

# Directories ignored by default during a scan.
DEFAULT_IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", "vendor", ".next", ".cache",
    "coverage", "venv", ".venv", "__pycache__", "target", "bin", "obj",
    ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".gradle",
}

# Extensions treated as binary and skipped outright.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc",
    ".jar", ".war", ".wasm", ".node", ".lock",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}


class GitGuardError(Exception):
    """User-facing error with an optional remediation hint.

    The CLI prints ``message`` plus the ``fixes`` list as friendly guidance,
    hiding the traceback unless ``--debug`` is set.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str | None = None,
        fixes: Iterable[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.fixes = list(fixes) if fixes else []


def redact(secret: str, *, show: bool = False, keep_start: int = 6, keep_end: int = 4) -> str:
    """Redact a secret, keeping a few leading/trailing characters.

    ``sk_live_abc123...def4``. When ``show`` is True the secret is returned
    verbatim (used only behind the explicit ``--show-secrets`` flag).
    """

    secret = secret.strip()
    if show:
        return secret
    if len(secret) <= keep_start + keep_end:
        # Too short to safely reveal anything; mask entirely but keep length cue.
        return "*" * len(secret)
    return f"{secret[:keep_start]}...{secret[-keep_end:]}"


def is_probably_binary(path: Path, sniff_bytes: int = 4096) -> bool:
    """Return True if the file looks binary (NUL byte or undecodable)."""

    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(sniff_bytes)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    # Heuristic: a high ratio of non-text bytes implies binary.
    if not chunk:
        return False
    text_chars = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    nontext = chunk.translate(None, text_chars)
    return len(nontext) / len(chunk) > 0.30


def should_ignore_dir(name: str, ignored: set[str]) -> bool:
    return name in ignored


def is_hidden(path: Path) -> bool:
    return path.name.startswith(".")


def iter_files(
    root: Path,
    *,
    ignored_dirs: set[str],
    include_hidden: bool,
    max_file_size: int,
    follow_symlinks: bool = False,
) -> Iterable[Path]:
    """Yield scannable files under ``root``.

    Skips ignored directories, hidden entries (unless ``include_hidden``),
    symlinks that escape the root, and oversized files. The traversal is
    iterative so very deep trees won't hit recursion limits.
    """

    root = root.resolve()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            try:
                if entry.is_symlink() and not follow_symlinks:
                    # Never follow symlinks that point outside the scan root.
                    target = entry.resolve()
                    if not str(target).startswith(str(root)):
                        continue
                if entry.is_dir():
                    if should_ignore_dir(entry.name, ignored_dirs):
                        continue
                    if not include_hidden and is_hidden(entry):
                        continue
                    stack.append(entry)
                elif entry.is_file():
                    if not include_hidden and is_hidden(entry):
                        continue
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        continue
                    if size > max_file_size:
                        continue
                    yield entry
            except (OSError, PermissionError):
                continue


def relative_to(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


GITHUB_URL_RE = re.compile(
    r"^(?:https?://|git@)(?:www\.)?github\.com[:/]"
    r"([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


def is_github_url(target: str) -> bool:
    return bool(GITHUB_URL_RE.match(target.strip()))


def parse_github_url(target: str) -> tuple[str, str]:
    m = GITHUB_URL_RE.match(target.strip())
    if not m:
        raise GitGuardError(
            f"Not a valid GitHub repository URL: {target!r}",
            fixes=[
                "Use a form like https://github.com/owner/repo",
                "Make sure there are no extra path segments or query strings",
            ],
        )
    return m.group(1), m.group(2)
