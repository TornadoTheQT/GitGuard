"""Agent-backed remediation support for ``gitguard scan --fix``.

This module keeps the AI/editing layer behind a narrow subprocess boundary:
GitGuard prepares a disposable workspace, asks a fix agent to edit that workspace,
then GitGuard computes, validates, displays, and applies the resulting diff.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .archive import safe_extract_zip
from .models import Report, Source
from .report import to_ai
from .utils import GitGuardError, is_github_url, parse_github_url

MIN_NODE_VERSION = (22, 19)
OPENCLAW_VERSION_TIMEOUT = 15
FIX_AGENT_NPM_PACKAGES = ("openclaw@latest", "@anthropic-ai/claude-code@latest")
DEFAULT_FIX_AGENT_MODEL = "claude-cli/claude-sonnet-4-6"

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv"
)
_DIFF_IGNORED_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
}


@dataclass
class ToolStatus:
    """Availability details for one external command."""

    name: str
    ok: bool
    detail: str
    path: Optional[str] = None
    version: Optional[str] = None


@dataclass
class FixAgentStatus:
    """Combined dependency status for the remediation layer."""

    node: ToolStatus
    agent: ToolStatus
    claude: Optional[ToolStatus] = None

    @property
    def ready(self) -> bool:
        claude_ok = True if self.claude is None else self.claude.ok
        return self.node.ok and self.agent.ok and claude_ok

    def problem_summary(self) -> str:
        problems = [
            status.detail
            for status in (self.node, self.agent, self.claude)
            if status is not None and not status.ok
        ]
        return "; ".join(problems) or "Fix agent is ready"


@dataclass
class PreparedTarget:
    """A target copied into an editable remediation workspace."""

    original: str
    target_type: str
    temp_root: Path
    baseline_root: Path
    work_root: Path
    apply_mode: str
    apply_root: Optional[Path] = None
    fixed_zip_path: Optional[Path] = None
    default_patch_path: Optional[Path] = None

    def cleanup(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)


@dataclass(frozen=True)
class FileChange:
    """A file-level change discovered between baseline and edited workspaces."""

    path: str
    kind: str
    text: bool


@dataclass
class PatchResult:
    """Unified diff plus structured changes."""

    diff: str
    changes: list[FileChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


@dataclass
class FixAgentRun:
    """Captured result from a fix-agent invocation."""

    stdout: str
    stderr: str
    response: Optional[dict[str, Any]] = None


@dataclass
class TestResult:
    """Result from a user-provided verification command."""

    command: str
    cwd: Path
    returncode: int
    stdout: str
    stderr: str


def parse_node_version(raw: str) -> Optional[tuple[int, int, int]]:
    """Parse ``node --version`` style output."""

    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", raw.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _run_version(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def check_fix_agent_environment(*, check_claude: bool = True) -> FixAgentStatus:
    """Check whether Node and the external fix-agent CLI are usable."""

    node_path = shutil.which("node")
    if not node_path:
        node = ToolStatus(
            "node",
            False,
            "Node.js was not found on PATH",
        )
    else:
        try:
            proc = _run_version([node_path, "--version"], OPENCLAW_VERSION_TIMEOUT)
            version_raw = (proc.stdout or proc.stderr).strip()
            parsed = parse_node_version(version_raw)
            ok = proc.returncode == 0 and parsed is not None and parsed[:2] >= MIN_NODE_VERSION
            detail = (
                f"Node.js {version_raw}"
                if ok
                else f"Node.js {version_raw or 'unknown'} is below v22.19.0"
            )
            node = ToolStatus("node", ok, detail, path=node_path, version=version_raw)
        except (OSError, subprocess.SubprocessError) as exc:
            node = ToolStatus(
                "node",
                False,
                f"Could not run node --version: {exc}",
                path=node_path,
            )

    agent_path = shutil.which("openclaw")
    if not agent_path:
        agent = ToolStatus(
            "fix-agent",
            False,
            "Fix agent CLI was not found on PATH",
        )
    else:
        try:
            proc = _run_version([agent_path, "--version"], OPENCLAW_VERSION_TIMEOUT)
            version_raw = (proc.stdout or proc.stderr).strip()
            ok = proc.returncode == 0
            detail = (
                _agent_version_detail(version_raw)
                if ok
                else f"fix-agent version check exited {proc.returncode}"
            )
            agent = ToolStatus(
                "fix-agent", ok, detail, path=agent_path, version=version_raw
            )
        except (OSError, subprocess.SubprocessError) as exc:
            agent = ToolStatus(
                "fix-agent",
                False,
                f"Could not run fix-agent version check: {exc}",
                path=agent_path,
            )

    claude = check_claude_environment() if check_claude else None
    return FixAgentStatus(node=node, agent=agent, claude=claude)


def check_claude_environment() -> ToolStatus:
    """Check whether the Claude CLI exists and is authenticated."""

    claude_path = shutil.which("claude")
    if not claude_path:
        return ToolStatus(
            "claude",
            False,
            "Claude CLI was not found on PATH",
        )

    try:
        version_proc = _run_version(
            [claude_path, "--version"], OPENCLAW_VERSION_TIMEOUT
        )
        version = (version_proc.stdout or version_proc.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(
            "claude",
            False,
            f"Could not run claude --version: {exc}",
            path=claude_path,
        )

    try:
        auth_proc = _run_version(
            [claude_path, "auth", "status", "--json"], OPENCLAW_VERSION_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(
            "claude",
            False,
            f"Could not check Claude auth status: {exc}",
            path=claude_path,
            version=version,
        )

    raw = (auth_proc.stdout or auth_proc.stderr).strip()
    logged_in = False
    auth_method = None
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                logged_in = bool(data.get("loggedIn"))
                auth_method = data.get("authMethod") or data.get("apiProvider")
        except json.JSONDecodeError:
            logged_in = auth_proc.returncode == 0 and "logged" in raw.lower()

    if auth_proc.returncode == 0 and logged_in:
        detail = f"Claude CLI {version or 'installed'} authenticated"
        if auth_method:
            detail += f" via {auth_method}"
        return ToolStatus("claude", True, detail, path=claude_path, version=version)

    return ToolStatus(
        "claude",
        False,
        "Claude CLI is installed but not logged in",
        path=claude_path,
        version=version,
    )


def _agent_version_detail(raw: str) -> str:
    match = re.search(r"(\d{4}\.\d+\.\d+(?:\s+\([^)]+\))?)", raw)
    if match:
        return f"Fix agent runtime {match.group(1)}"
    return "Fix agent runtime responded"


def require_fix_agent_available(model: Optional[str] = None) -> FixAgentStatus:
    """Raise a user-facing error if agentic remediation cannot run."""

    status = check_fix_agent_environment(check_claude=_uses_claude_model(model))
    if status.ready:
        return status
    raise GitGuardError(
        "Fix agent is not ready.",
        reason=status.problem_summary(),
        fixes=[
            "Install Node.js v22.19.0 or newer",
            "Run `gitguard setup-fix-agent` to install and configure the fix-agent stack",
            "Complete `claude auth login` if the setup command asks you to sign in",
            "Re-run `gitguard doctor` to confirm the setup",
        ],
    )


def _uses_claude_model(model: Optional[str]) -> bool:
    return model is None or model.startswith("claude-cli/")


def npm_global_bin_path() -> Optional[Path]:
    """Return npm's global bin directory using npm config, if available."""

    npm = shutil.which("npm")
    if not npm:
        return None
    try:
        proc = _run_version([npm, "config", "get", "prefix"], OPENCLAW_VERSION_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    prefix = (proc.stdout or proc.stderr).strip()
    if proc.returncode != 0 or not prefix:
        return None
    return Path(prefix).expanduser() / "bin"


def prepare_remediation_target(target: str) -> PreparedTarget:
    """Create baseline/work copies for a scan target."""

    temp_root = Path(tempfile.mkdtemp(prefix="gitguard-fix-")).resolve()
    baseline = temp_root / "baseline"
    work = temp_root / "work"

    try:
        if is_github_url(target):
            from . import git_history

            owner, repo = parse_github_url(target)
            clone_dir = temp_root / "repo-source"
            git_history.clone_repo(target, clone_dir)
            _copy_tree(clone_dir, baseline, ignore=_COPY_IGNORE)
            _copy_tree(clone_dir, work, ignore=_COPY_IGNORE)
            return PreparedTarget(
                original=target,
                target_type="github",
                temp_root=temp_root,
                baseline_root=baseline,
                work_root=work,
                apply_mode="patch",
                default_patch_path=Path.cwd()
                / f"gitguard-{owner}-{repo}-agent.patch",
            )

        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise GitGuardError(
                f"Target does not exist: {target}",
                fixes=[
                    "Check the path for typos",
                    "Pass a file, a folder, a .zip file, or a GitHub URL",
                ],
            )

        if path.is_file() and path.suffix.lower() == ".zip":
            extracted = temp_root / "zip-source"
            safe_extract_zip(path, extracted)
            _copy_tree(extracted, baseline)
            _copy_tree(extracted, work)
            return PreparedTarget(
                original=str(path),
                target_type="zip",
                temp_root=temp_root,
                baseline_root=baseline,
                work_root=work,
                apply_mode="zip",
                fixed_zip_path=path.with_name(f"{path.stem}.fixed.zip"),
            )

        if path.is_file():
            baseline.mkdir(parents=True, exist_ok=True)
            work.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, baseline / path.name)
            shutil.copy2(path, work / path.name)
            return PreparedTarget(
                original=str(path),
                target_type="file",
                temp_root=temp_root,
                baseline_root=baseline,
                work_root=work,
                apply_mode="local",
                apply_root=path.parent,
            )

        if path.is_dir():
            _copy_tree(path, baseline, ignore=_COPY_IGNORE)
            _copy_tree(path, work, ignore=_COPY_IGNORE)
            return PreparedTarget(
                original=str(path),
                target_type="directory",
                temp_root=temp_root,
                baseline_root=baseline,
                work_root=work,
                apply_mode="local",
                apply_root=path,
            )

        raise GitGuardError(
            f"Don't know how to remediate: {target}",
            fixes=["Pass a file, a folder, a .zip file, or a GitHub URL"],
        )
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise


def _copy_tree(src: Path, dest: Path, ignore=None) -> None:
    shutil.copytree(src, dest, symlinks=True, ignore=ignore)


def build_remediation_prompt(report: Report, prepared: PreparedTarget) -> str:
    """Build the task contract handed to the fix agent."""

    current_count = sum(1 for f in report.findings if f.source == Source.CURRENT)
    history_count = len(report.findings) - current_count
    brief = to_ai(report)
    return f"""# GitGuard Fix Agent Task

You are running underneath GitGuard. Edit files only inside this workspace:

`{prepared.work_root}`

Do not edit files outside that directory, do not run destructive git commands,
do not commit, do not push, and do not print full secret values.

GitGuard will compute the diff, ask the user for review, apply accepted local
changes, write ZIP/patch artifacts where relevant, re-scan, and run any
user-provided verification commands. Your job is only to make the smallest
safe edits in the temporary workspace.

Target type: {prepared.target_type}
Original target: {prepared.original}
Current-file findings: {current_count}
Git-history findings: {history_count}

Rules:
- For hardcoded secrets, remove literal credentials from source, load values
  from environment/config instead, update `.env.example` and `.gitignore` when
  appropriate, and leave rotation/revocation as a manual action.
- For code vulnerabilities, apply each recommendation with the smallest
  behavior-preserving change.
- If a finding is from git history only, do not invent a current-file edit for
  it; leave a short note in your response that history cleanup/rotation remains
  manual.
- Preserve unrelated behavior and formatting.

{brief}
"""


def run_fix_agent(
    prepared: PreparedTarget,
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: int = 900,
) -> FixAgentRun:
    """Run a one-shot local fix-agent turn against the work tree."""

    prompt_path = prepared.temp_root / "gitguard-fix-agent.md"
    prompt_path.write_text(prompt, encoding="utf-8")
    session_key = f"gitguard-{uuid.uuid4().hex[:12]}"
    message = (
        f"Read and follow the GitGuard remediation instructions in {prompt_path}. "
        f"Edit only {prepared.work_root}."
    )
    args = [
        "openclaw",
        "agent",
        "--agent",
        "main",
        "--local",
        "--json",
        "--session-key",
        session_key,
    ]
    if model:
        args += ["--model", model]
    args += ["--message", message]

    try:
        proc = subprocess.Popen(
            args,
            cwd=str(prepared.work_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _terminate_process_group(proc)
            stdout, stderr = proc.communicate()
            raise GitGuardError(
                "Fix agent timed out.",
                reason=f"Timed out after {timeout} seconds",
                fixes=[
                    "Retry with a larger `--fix-timeout`",
                    "Run a narrower scan target",
                    "Fix fewer findings in one pass",
                ],
            ) from exc
        except KeyboardInterrupt:
            _terminate_process_group(proc)
            raise
    except OSError as exc:
        raise GitGuardError(
            "Could not start the fix agent.",
            reason=str(exc),
            fixes=[
                "Install and configure the external fix-agent runtime",
                "Make sure the fix-agent executable is on PATH",
            ],
        ) from exc

    if proc.returncode != 0:
        reason = (stderr or stdout or "no details").strip()
        raise GitGuardError(
            "Fix agent failed.",
            reason=f"fix agent exited {proc.returncode}: {reason}",
            fixes=[
                "Run `gitguard doctor` to check fix-agent setup",
                "Complete any missing model auth/setup in the fix-agent runtime",
                "Retry with a smaller target if the task timed out upstream",
            ],
        )

    response = None
    if stdout.strip():
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                response = parsed
        except json.JSONDecodeError:
            response = None

    return FixAgentRun(stdout=stdout, stderr=stderr, response=response)


def _terminate_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        proc.kill()


def generate_patch(baseline_root: Path, work_root: Path) -> PatchResult:
    """Return a relative unified diff from baseline to edited workspace."""

    baseline_files = set(_walk_diff_files(baseline_root))
    work_files = set(_walk_diff_files(work_root))
    all_paths = sorted(baseline_files | work_files)

    diff_chunks: list[str] = []
    changes: list[FileChange] = []
    for rel in all_paths:
        before = baseline_root / rel
        after = work_root / rel

        if rel not in baseline_files:
            kind = "added"
        elif rel not in work_files:
            kind = "deleted"
        elif _same_file_bytes(before, after):
            continue
        else:
            kind = "modified"

        text_diff = _file_diff(before if before.exists() else None,
                               after if after.exists() else None,
                               rel)
        text = text_diff is not None
        if text_diff is None:
            text_diff = f"Binary or non-text file changed: {rel}\n"
        diff_chunks.append(text_diff)
        changes.append(FileChange(path=rel, kind=kind, text=text))

    return PatchResult(diff="\n".join(diff_chunks), changes=changes)


def _walk_diff_files(root: Path) -> list[str]:
    out: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [
            d for d in dirs
            if d not in _DIFF_IGNORED_PARTS and not (Path(current) / d).is_symlink()
        ]
        rel_dir = Path(current).relative_to(root)
        for name in files:
            rel = rel_dir / name if str(rel_dir) != "." else Path(name)
            if any(part in _DIFF_IGNORED_PARTS for part in rel.parts):
                continue
            out.append(rel.as_posix())
    return out


def _same_file_bytes(left: Path, right: Path) -> bool:
    if left.is_symlink() or right.is_symlink():
        if not (left.is_symlink() and right.is_symlink()):
            return False
        try:
            return os.readlink(left) == os.readlink(right)
        except OSError:
            return False
    try:
        return left.read_bytes() == right.read_bytes()
    except OSError:
        return False


def _read_text_for_diff(path: Path) -> Optional[list[str]]:
    if path.is_symlink():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.splitlines()


def _file_diff(before: Optional[Path], after: Optional[Path], rel: str) -> Optional[str]:
    before_lines = [] if before is None else _read_text_for_diff(before)
    after_lines = [] if after is None else _read_text_for_diff(after)
    if before_lines is None or after_lines is None:
        return None
    lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        lineterm="",
    )
    return "\n".join(lines) + "\n"


def write_patch(diff: str, path: Path) -> Path:
    dest = path.expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.write_text(diff, encoding="utf-8")
    except OSError as exc:
        raise GitGuardError(
            f"Could not write patch to {dest}",
            reason=str(exc),
            fixes=["Choose a different `--patch-out` path"],
        ) from exc
    return dest


def validate_changes_for_apply(
    changes: list[FileChange],
    *,
    apply_root: Path,
    work_root: Path,
) -> None:
    """Ensure changed relative paths cannot escape the destination root."""

    root = apply_root.resolve()
    for change in changes:
        rel = Path(change.path)
        if rel.is_absolute() or ".." in rel.parts:
            raise GitGuardError(
                f"Unsafe path in fix-agent patch: {change.path}",
                fixes=["Review the generated diff manually"],
            )

        src = work_root / rel
        dest = apply_root / rel
        if change.kind in {"added", "modified"} and src.is_symlink():
            raise GitGuardError(
                f"Refusing to apply symlink change: {change.path}",
                fixes=["Review the generated diff manually"],
            )
        if dest.is_symlink():
            raise GitGuardError(
                f"Refusing to overwrite symlink: {change.path}",
                fixes=["Review the generated diff manually"],
            )
        if not _path_within(root, dest.parent):
            raise GitGuardError(
                f"Patch path escapes target root: {change.path}",
                fixes=["Review the generated diff manually"],
            )


def _path_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def apply_changes_to_local_target(
    changes: list[FileChange],
    *,
    work_root: Path,
    apply_root: Path,
) -> None:
    """Apply validated workspace changes to the original local target."""

    validate_changes_for_apply(changes, apply_root=apply_root, work_root=work_root)
    for change in changes:
        rel = Path(change.path)
        src = work_root / rel
        dest = apply_root / rel
        if change.kind == "deleted":
            if dest.exists():
                dest.unlink()
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def write_fixed_zip(work_root: Path, dest: Path) -> Path:
    """Write an edited ZIP artifact from a remediation workspace."""

    out = dest.expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel in _walk_all_files(work_root):
                path = work_root / rel
                if path.is_symlink():
                    continue
                zf.write(path, rel)
    except OSError as exc:
        raise GitGuardError(
            f"Could not write fixed ZIP artifact: {out}",
            reason=str(exc),
            fixes=["Choose a writable location for the ZIP artifact"],
        ) from exc
    return out


def _walk_all_files(root: Path) -> list[str]:
    out: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
        rel_dir = Path(current).relative_to(root)
        for name in files:
            rel = rel_dir / name if str(rel_dir) != "." else Path(name)
            out.append(rel.as_posix())
    return out


def run_test_commands(commands: list[str], cwd: Path) -> list[TestResult]:
    """Run user-provided verification commands."""

    results: list[TestResult] = []
    for command in commands:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        results.append(
            TestResult(
                command=command,
                cwd=cwd,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        )
    return results
