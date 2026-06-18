"""GitGuard command-line interface (Typer)."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .models import Report, Severity, Source
from .report import render_report, to_ai, to_csv, to_json, write_output
from .scanner import ScanConfig, finalize_report, scan_directory, scan_single_file
from .utils import (
    DEFAULT_IGNORED_DIRS,
    GitGuardError,
    is_github_url,
)

app = typer.Typer(
    name="gitguard",
    help="Scan folders, ZIPs, and GitHub repos for exposed secrets.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


def _print_error(exc: GitGuardError, debug: bool) -> None:
    from rich import box

    body = f"[bold red]✗ {exc.message}[/bold red]"
    if exc.reason:
        body += f"\n[dim]Reason:[/dim] {exc.reason}"
    if exc.fixes:
        body += "\n\n[bold]Try this:[/bold]"
        for fix in exc.fixes:
            body += f"\n  [cyan]→[/cyan] {fix}"
    err_console.print()
    err_console.print(
        Panel(
            body,
            border_style="red",
            box=box.ROUNDED,
            title="[bold red]GitGuard error[/bold red]",
            title_align="left",
            padding=(1, 2),
        )
    )
    if debug:
        err_console.print_exception()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"gitguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """GitGuard: a secret-scanning CLI."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="File, folder, .zip file, or GitHub URL."),
    history: bool = typer.Option(False, "--history", help="Scan git commit history."),
    json_out: bool = typer.Option(False, "--json", help="Output JSON (default for --out)."),
    csv_out: bool = typer.Option(False, "--csv", help="Output CSV."),
    ai: bool = typer.Option(
        False, "--ai",
        help="Output a Markdown remediation brief for an AI coding agent.",
    ),
    out: Optional[Path] = typer.Option(
        None, "--out",
        help="Save report to a file (JSON unless --csv/--ai is given).",
    ),
    no_entropy: bool = typer.Option(False, "--no-entropy", help="Disable entropy scanning."),
    max_file_size: float = typer.Option(
        5.0, "--max-file-size", help="Skip files larger than this many MB."
    ),
    include_hidden: bool = typer.Option(
        False, "--include-hidden", help="Include hidden files and folders."
    ),
    strict: bool = typer.Option(False, "--strict", help="Increase sensitivity."),
    vulns: bool = typer.Option(
        False, "--vulns",
        help="Also scan for code vulnerabilities (injection, eval, weak crypto…).",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Only show findings."),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit nonzero if a finding at this severity or higher exists "
        "(INFO/LOW/MEDIUM/HIGH/CRITICAL).",
    ),
    show_secrets: bool = typer.Option(
        False, "--show-secrets", help="Show full secrets (DANGEROUS)."
    ),
    debug: bool = typer.Option(False, "--debug", help="Show tracebacks on error."),
) -> None:
    """Scan a TARGET for exposed secrets."""

    fail_threshold: Optional[Severity] = None
    if fail_on:
        try:
            fail_threshold = Severity.from_name(fail_on)
        except ValueError as exc:
            _print_error(GitGuardError(str(exc)), debug)
            raise typer.Exit(2)

    if show_secrets:
        confirmed = typer.confirm(
            "⚠ --show-secrets will print full credentials to the terminal. Continue?",
            default=False,
        )
        if not confirmed:
            raise typer.Exit(1)

    config = ScanConfig(
        use_entropy=not no_entropy,
        max_file_size=int(max_file_size * 1024 * 1024),
        include_hidden=include_hidden,
        strict=strict,
        ignored_dirs=set(DEFAULT_IGNORED_DIRS),
        show_secrets=show_secrets,
        scan_vulns=vulns,
    )

    tmp_dirs: list[Path] = []
    try:
        report = _run_scan(
            target, config, history=history, quiet=quiet, tmp_dirs=tmp_dirs
        )
    except GitGuardError as exc:
        _print_error(exc, debug)
        raise typer.Exit(2)
    except KeyboardInterrupt:  # pragma: no cover
        err_console.print("\n[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(130)
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    try:
        _emit(report, console, json_out, csv_out, ai, out, quiet, debug)
    except GitGuardError as exc:
        _print_error(exc, debug)
        raise typer.Exit(2)

    if fail_threshold is not None:
        worst = max((f.severity for f in report.findings), default=Severity.INFO)
        if report.findings and worst >= fail_threshold:
            raise typer.Exit(1)


def _run_scan(
    target: str,
    config: ScanConfig,
    *,
    history: bool,
    quiet: bool,
    tmp_dirs: list[Path],
) -> Report:
    """Resolve the target type, run the scan, return a Report."""

    from . import archive, git_history

    target_type: str
    root: Path

    if is_github_url(target):
        target_type = "github"
        clone_dir = git_history.temp_clone_dir()
        tmp_dirs.append(clone_dir)
        with _spinner("Cloning repository", quiet):
            git_history.clone_repo(target, clone_dir)
        root = clone_dir
    else:
        path = Path(target).expanduser()
        if not path.exists():
            raise GitGuardError(
                f"Target does not exist: {target}",
                fixes=[
                    "Check the path for typos",
                    "Pass a file, a folder, a .zip file, or a GitHub URL",
                ],
            )
        if path.is_file() and path.suffix.lower() == ".zip":
            target_type = "zip"
            extract_dir = Path(tempfile.mkdtemp(prefix="gitguard-zip-"))
            tmp_dirs.append(extract_dir)
            with _spinner("Extracting archive", quiet):
                archive.safe_extract_zip(path, extract_dir)
            root = extract_dir
        elif path.is_file():
            # Single-file scan (e.g. "main.js"): no directory walk needed.
            if history and not quiet:
                err_console.print(
                    "[yellow]--history is ignored when scanning a single file.[/yellow]"
                )
            with _spinner("Scanning file", quiet):
                report = scan_single_file(path, config, target_label=target)
            report.tool_version = __version__
            return report
        elif path.is_dir():
            target_type = "directory"
            root = path
        else:
            raise GitGuardError(
                f"Don't know how to scan: {target}",
                fixes=["Pass a file, a folder, a .zip file, or a GitHub URL"],
            )

    report = _scan_with_progress(root, config, target, target_type, quiet)

    if history:
        _scan_history_into(report, root, config, quiet)

    report.tool_version = __version__
    return report


def _scan_with_progress(
    root: Path, config: ScanConfig, target_label: str, target_type: str, quiet: bool
) -> Report:
    if quiet:
        return scan_directory(
            root, config, target_label=target_label, target_type=target_type
        )
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning files…", total=None)

        def cb(label: str) -> None:
            progress.update(task, description=f"Scanning {label}")

        return scan_directory(
            root, config, target_label=target_label,
            target_type=target_type, progress=cb,
        )


def _scan_history_into(
    report: Report, root: Path, config: ScanConfig, quiet: bool
) -> None:
    from . import git_history

    if not git_history.git_available():
        err_console.print(
            "[yellow]git not found; skipping history scan.[/yellow]"
        )
        return
    if not git_history.is_git_repo(root):
        err_console.print(
            "[yellow]Target is not a git repository; skipping history scan.[/yellow]"
        )
        return

    with _spinner("Scanning git history", quiet):
        hist_findings, commits = git_history.scan_history(root, config)
    report.stats.commits_scanned = commits
    deduped = git_history.dedupe_history_against_current(
        report.findings, hist_findings
    )
    combined = report.findings + deduped
    finalize_report(report, combined)


def _spinner(description: str, quiet: bool):
    if quiet:
        return _NullCtx()
    return console.status(f"[cyan]{description}…[/cyan]")


class _NullCtx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# Output formats: selector flag -> (renderer, file extension, label).
_FORMATS = {
    "json": (to_json, "json", "JSON"),
    "csv": (to_csv, "csv", "CSV"),
    "ai": (to_ai, "md", "AI remediation brief"),
}


def _emit(
    report: Report,
    console: Console,
    json_out: bool,
    csv_out: bool,
    ai: bool,
    out: Optional[Path],
    quiet: bool,
    debug: bool,
) -> None:
    selected = [name for name, on in
                (("json", json_out), ("csv", csv_out), ("ai", ai)) if on]
    if len(selected) > 1:
        _print_error(
            GitGuardError("Choose only one of --json, --csv, or --ai."), debug
        )
        raise typer.Exit(2)

    fmt = selected[0] if selected else None
    # --out defaults to JSON, so an explicit --json flag is not required.
    if fmt is None and out is not None:
        fmt = "json"

    # No format and no output file -> rich terminal report.
    if fmt is None:
        render_report(report, console, quiet=quiet)
        return

    renderer, ext, label = _FORMATS[fmt]
    content = renderer(report)
    if out:
        dest = _resolve_out(out, ext)
        write_output(content, dest)
        console.print(f"[green]{label} written to {dest}[/green]")
    elif fmt == "json":
        console.print_json(content)
    else:
        console.print(content, markup=False, highlight=False)


def _resolve_out(out: Path, ext: str) -> Path:
    """Resolve the --out path. If it points at a directory (existing, or written
    with a trailing slash), drop a default-named report inside it instead of
    failing with 'Is a directory'."""
    out = out.expanduser()
    if out.is_dir() or str(out).endswith(("/", os.sep)):
        return out / f"gitguard-report.{ext}"
    return out


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

@app.command()
def rules() -> None:
    """List all detection rules."""

    from rich import box
    from rich.table import Table
    from rich.text import Text

    from .models import Severity
    from .rules import RULES

    def sev_cell(sev: Severity) -> Text:
        t = Text()
        t.append(f"{sev.symbol} ", style=sev.accent)
        t.append(sev.name, style=sev.color)
        return t

    table = Table(
        title="[bold]GitGuard Detection Rules[/bold]",
        title_justify="left",
        box=box.SIMPLE_HEAVY,
        header_style="bold grey70",
        row_styles=["", "on grey7"],
        padding=(0, 1),
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("ID", no_wrap=True, style="cyan")
    table.add_column("Name", no_wrap=True)
    table.add_column("Description", style="grey74")
    for rule in sorted(RULES, key=lambda r: -int(r.severity)):
        table.add_row(
            sev_cell(rule.severity),
            rule.id,
            rule.name,
            rule.description,
        )
    table.add_row(
        sev_cell(Severity.MEDIUM),
        "high-entropy-string",
        "High-entropy String",
        "Random-looking strings near secret context.",
    )
    console.print()
    console.print(table)
    console.print(
        Text(f"  {len(RULES) + 1} rules · severity may shift with context",
             style="dim")
    )


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------

@app.command()
def fix(
    report_path: Path = typer.Argument(..., help="A previous JSON report file."),
    debug: bool = typer.Option(False, "--debug", help="Show tracebacks on error."),
) -> None:
    """Generate remediation artifacts from a JSON report."""

    import json

    from .fixes import build_fix_plan

    if not report_path.exists():
        _print_error(
            GitGuardError(
                f"Report file not found: {report_path}",
                fixes=["Run `gitguard scan <target> --json --out report.json` first"],
            ),
            debug,
        )
        raise typer.Exit(2)
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        report = Report.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        _print_error(
            GitGuardError(
                f"Could not read report: {report_path}",
                reason=str(exc),
                fixes=["Make sure it is a JSON report produced by `gitguard scan`"],
            ),
            debug,
        )
        raise typer.Exit(2)

    plan = build_fix_plan(report)
    _render_fix_plan(plan)


def _render_fix_plan(plan) -> None:
    from rich import box
    from rich.rule import Rule
    from rich.text import Text

    console.print()
    title = Text()
    title.append("🛠  ", style="bold cyan")
    title.append("GitGuard", style="bold white")
    title.append("  ·  remediation plan", style="dim")
    console.print(Rule(title, style="cyan", align="left"))

    def section(emoji: str, title: str, lines: list[str], style: str = "cyan") -> None:
        if not lines:
            return
        body = "\n".join(lines)
        console.print(
            Panel(
                body,
                title=f"{emoji} [bold]{title}[/bold]",
                title_align="left",
                border_style=style,
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )

    section("📄", ".gitignore additions", plan.gitignore)
    section("🔑", ".env.example", plan.env_example)
    section("⛔", "Key revocation checklist", plan.revocation_checklist, "red")
    section("📘", "README security setup", plan.readme_steps)
    section("⚙", "GitHub Actions secrets", plan.github_actions_guide)
    if not any(
        [plan.gitignore, plan.env_example, plan.revocation_checklist]
    ):
        console.print(
            Panel(
                "[green]✓ No remediation needed — report had no findings.[/green]",
                border_style="green",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

@app.command()
def doctor(
    target: Optional[str] = typer.Argument(
        None, help="Optional target to validate."
    ),
) -> None:
    """Check the environment and (optionally) whether a target can be scanned."""

    from rich import box
    from rich.table import Table

    from . import git_history

    console.print()
    table = Table(
        title="[bold]🩺 GitGuard Doctor[/bold]",
        title_justify="left",
        box=box.SIMPLE_HEAVY,
        header_style="bold grey70",
        padding=(0, 1),
    )
    table.add_column("", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Detail", style="grey74")

    def row(name: str, ok: bool, detail: str) -> None:
        status = "[bold green]✓ OK[/bold green]" if ok else "[bold red]✗ FAIL[/bold red]"
        table.add_row(status, name, detail)

    from . import REQUIRES_PYTHON, REQUIRES_PYTHON_STR

    py_ok = sys.version_info[:2] >= REQUIRES_PYTHON
    row(
        "Python version",
        py_ok,
        f"{sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro} (need >= {REQUIRES_PYTHON_STR})",
    )

    git_ok = git_history.git_available()
    row("git installed", git_ok, shutil.which("git") or "not found on PATH")

    cwd = Path.cwd()
    row("Working directory", cwd.exists(), str(cwd))

    try:
        readable = bool(list(cwd.iterdir())) or True
        row("Directory readable", readable, "permissions OK")
    except (OSError, PermissionError) as exc:
        row("Directory readable", False, str(exc))

    if target:
        ok, detail = _validate_target(target)
        row("Target scannable", ok, detail)

    console.print(table)
    if not git_ok:
        console.print(
            "[yellow]Note:[/yellow] without git, --history and GitHub cloning "
            "are unavailable; local folders and ZIPs still work."
        )


def _validate_target(target: str) -> tuple[bool, str]:
    if is_github_url(target):
        return True, "valid GitHub URL (clone attempted at scan time)"
    path = Path(target).expanduser()
    if not path.exists():
        return False, "path does not exist"
    if path.is_dir():
        return True, "directory"
    if path.suffix.lower() == ".zip":
        return True, "zip archive"
    if path.is_file():
        return True, "file"
    return False, "unsupported target (expected file, folder, .zip, or GitHub URL)"


def run() -> None:  # console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
