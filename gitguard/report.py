"""Rendering: rich terminal output, JSON, and CSV serialization."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .models import Report, Severity, Source


def to_json(report: Report, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


def to_csv(report: Report) -> str:
    buf = io.StringIO()
    fields = [
        "severity", "rule_id", "rule_name", "path", "line", "column",
        "match_preview", "confidence", "source", "commit", "author", "date",
        "reason", "recommendation",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for f in report.findings:
        row = f.to_dict()
        writer.writerow({k: row.get(k, "") for k in fields})
    return buf.getvalue()


def to_ai(report: Report) -> str:
    """Render a Markdown remediation brief for an AI coding agent.

    The format is deterministic and self-describing: a task preamble, a summary,
    then findings grouped by file (most severe first) with the issue, location,
    and concrete fix steps so an agent like Claude Code can act on it directly.
    """

    from .fixes import fixes_for_finding

    sev_counts = report.severity_counts()
    cov = report.category_counts()
    secrets = report.secret_findings()
    vulns = [f for f in report.findings if f.category == "vulnerability"]

    lines: list[str] = []
    lines.append("# GitGuard Security Remediation Brief")
    lines.append("")
    lines.append(
        "You are a coding agent. Fix every security issue listed below in this "
        "repository. Work through findings from most to least severe."
    )
    lines.append("")
    lines.append("## How to fix")
    lines.append("")
    lines.append(
        "- **Hardcoded secrets / credentials:** remove the literal value from "
        "the file, load it from an environment variable instead (e.g. "
        "`process.env.NAME` / `os.environ[\"NAME\"]`), add the source file or "
        "`.env` to `.gitignore`, and add the key to `.env.example`. Treat any "
        "real secret as compromised and note that it must be rotated."
    )
    lines.append(
        "- **Code vulnerabilities:** apply the suggested fix for each pattern "
        "(parameterized queries, output encoding, safe APIs, input validation)."
    )
    lines.append(
        "- Do not commit real secrets. Do not weaken unrelated code. Make the "
        "smallest change that resolves each finding."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Risk score: **{report.risk_score}/100**")
    lines.append(
        f"- Findings: **{len(report.findings)}** "
        f"(secrets: {len(secrets)}, vulnerabilities: {len(vulns)})"
    )
    sev_str = ", ".join(
        f"{name} {sev_counts[name]}"
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if sev_counts[name]
    )
    lines.append(f"- By severity: {sev_str or 'none'}")
    lines.append(
        "- Coverage — provider: {provider}, generic: {generic}, "
        "context: {context}, entropy: {entropy}, "
        "vulnerability: {vulnerability}".format(**cov)
    )
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    # Group by file, files ordered by their worst finding, findings by severity.
    by_file: dict[str, list] = {}
    for f in report.findings:
        by_file.setdefault(f.path, []).append(f)

    def file_rank(path: str) -> int:
        return -max(int(x.severity) for x in by_file[path])

    for path in sorted(by_file, key=lambda p: (file_rank(p), p)):
        lines.append(f"### `{path}`")
        lines.append("")
        items = sorted(
            by_file[path], key=lambda x: (-int(x.severity), x.line, x.rule_id)
        )
        for f in items:
            kind = "vulnerability" if f.category == "vulnerability" else "secret"
            loc = f"line {f.line}, col {f.column}"
            if f.source.value == "history":
                loc += f" (git history{', ' + f.commit[:8] if f.commit else ''})"
            lines.append(
                f"- **[{f.severity.name}] {f.rule_name}** "
                f"(`{f.rule_id}`, {kind}) — {loc}"
            )
            lines.append(f"  - Match: `{f.match_preview}`")
            if f.risk:
                lines.append(f"  - Why it matters: {f.risk}")
            # Vulnerabilities carry their own recommendation; secrets get the
            # richer per-rule rotation/revocation steps.
            steps = [f.recommendation] if kind == "vulnerability" else fixes_for_finding(f)
            for step in steps:
                if step:
                    lines.append(f"  - Fix: {step}")
        lines.append("")

    if not report.findings:
        lines.append("_No findings — nothing to fix._")
        lines.append("")

    return "\n".join(lines)


def _risk_color(score: int) -> str:
    if score >= 75:
        return "red"
    if score >= 40:
        return "dark_orange3"
    if score >= 15:
        return "yellow"
    if score > 0:
        return "cyan"
    return "green"


def _risk_verdict(score: int) -> str:
    if score >= 75:
        return "CRITICAL EXPOSURE"
    if score >= 40:
        return "HIGH RISK"
    if score >= 15:
        return "MODERATE RISK"
    if score > 0:
        return "LOW RISK"
    return "CLEAN"


def _top_folders(report: Report, limit: int = 5) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for f in report.findings:
        folder = str(Path(f.path).parent) or "."
        if folder == "":
            folder = "."
        counter[folder] += 1
    return counter.most_common(limit)


def _conf_bar(conf: float, cells: int = 5) -> Text:
    """Render a confidence value (0..1) as a small segmented bar."""
    filled = max(0, min(cells, round(conf * cells)))
    color = "green" if conf >= 0.7 else "yellow" if conf >= 0.4 else "red3"
    bar = Text()
    bar.append("▰" * filled, style=color)
    bar.append("▱" * (cells - filled), style="grey37")
    bar.append(f" {int(round(conf * 100)):>3}%", style="dim")
    return bar


def render_report(
    report: Report,
    console: Console,
    *,
    quiet: bool = False,
    show_fixes: bool = True,
) -> None:
    """Render a full scan report to the terminal."""

    if not quiet:
        _render_header(console)

    if not report.findings:
        _render_clean(report, console, quiet=quiet)
        return

    if not quiet:
        _render_summary(report, console)
        _render_severity_bar(report, console)

    _render_findings_table(report, console)

    if not quiet:
        _render_coverage(report, console)
        _render_heatmap(report, console)

    if show_fixes:
        _render_fixes(report, console)


def _render_header(console: Console) -> None:
    title = Text()
    title.append("🛡  ", style="bold cyan")
    title.append("GitGuard", style="bold white")
    title.append("  ·  secret scan report", style="dim")
    console.print()
    console.print(Rule(title, style="cyan", align="left"))


def _render_clean(report: Report, console: Console, *, quiet: bool) -> None:
    body = Text(justify="center")
    body.append("✓ No secrets detected\n", style="bold green")
    body.append(
        f"{report.stats.files_scanned} files scanned"
        f" · {report.stats.duration_seconds:.2f}s",
        style="dim",
    )
    console.print(
        Panel(
            Align.center(body),
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def _risk_gauge(report: Report) -> Panel:
    score = report.risk_score
    color = _risk_color(score)
    verdict = _risk_verdict(score)

    width = 22
    filled = max(0, min(width, round(score / 100 * width)))

    content = Text(justify="center")
    content.append(f"{score}", style=f"bold {color}")
    content.append(" / 100\n\n", style="dim")
    content.append("█" * filled, style=color)
    content.append("░" * (width - filled), style="grey37")
    content.append("\n\n")
    content.append(f"{verdict}", style=f"bold {color}")

    return Panel(
        Align.center(content, vertical="middle"),
        title="[bold]Risk Score[/bold]",
        border_style=color,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _facts_panel(report: Report) -> Panel:
    facts = Table.grid(padding=(0, 2))
    facts.add_column(justify="right", style="dim")
    facts.add_column(justify="left", style="bold")

    facts.add_row("target", report.target)
    facts.add_row("type", report.target_type)
    facts.add_row("files scanned", str(report.stats.files_scanned))
    if report.stats.files_skipped:
        facts.add_row("files skipped", str(report.stats.files_skipped))
    if report.stats.commits_scanned:
        facts.add_row("commits scanned", str(report.stats.commits_scanned))
    facts.add_row("findings", str(len(report.findings)))
    facts.add_row("duration", f"{report.stats.duration_seconds:.2f}s")

    return Panel(
        facts,
        title="[bold]Scan[/bold]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _render_summary(report: Report, console: Console) -> None:
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=3)
    grid.add_column(ratio=2)
    grid.add_row(_facts_panel(report), _risk_gauge(report))
    console.print(grid)


def _render_severity_bar(report: Report, console: Console) -> None:
    counts = report.severity_counts()
    total = sum(counts.values())
    if not total:
        return

    width = 44
    present = [s for s in sorted(Severity, reverse=True) if counts[s.name]]

    bar = Text()
    used = 0
    for i, sev in enumerate(present):
        n = counts[sev.name]
        if i == len(present) - 1:
            seg = width - used  # last segment absorbs rounding remainder
        else:
            seg = max(1, round(n / total * width))
        seg = max(0, min(seg, width - used))
        bar.append("█" * seg, style=sev.accent)
        used += seg

    legend = Text()
    for sev in present:
        legend.append(f"  {sev.symbol} ", style=sev.accent)
        legend.append(f"{sev.name} ", style=sev.color)
        legend.append(f"{counts[sev.name]}", style="bold")

    console.print(Group(bar, legend))


def _render_findings_table(report: Report, console: Console) -> None:
    table = Table(
        title="[bold]Findings[/bold]",
        title_justify="left",
        box=box.SIMPLE_HEAVY,
        header_style="bold grey70",
        expand=True,
        padding=(0, 1),
        row_styles=["", "on grey7"],
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", overflow="fold", style="cyan", min_width=16)
    table.add_column("Secret", overflow="fold", style="grey70", min_width=13)
    table.add_column("Confidence", no_wrap=True)

    has_history = any(f.source == Source.HISTORY for f in report.findings)

    for f in report.findings:
        sev = Text()
        sev.append(f"{f.severity.symbol} ", style=f.severity.accent)
        sev.append(f.severity.name, style=f.severity.color)

        loc = Text()
        # Mark history findings inline so we don't need a whole column for it.
        if f.source == Source.HISTORY:
            loc.append("⟲ ", style="magenta")
        loc.append(f.path, style="cyan")
        loc.append(f":{f.line}:{f.column}", style="dim")

        table.add_row(
            sev,
            f.rule_name,
            loc,
            f.match_preview,
            _conf_bar(f.confidence),
        )
    console.print(table)
    if has_history:
        console.print(
            Text("  ⟲ = found in git history", style="dim magenta")
        )


def _render_coverage(report: Report, console: Console) -> None:
    """Detection-method breakdown — shows which systems found what (part 11)."""

    cov = report.category_counts()
    rows = [
        ("Provider Secrets", cov["provider"], "Named vendor patterns (AWS, Stripe…)"),
        ("Generic Secrets", cov["generic"], "Structural patterns (keys, JWTs, URLs)"),
        ("Context Secrets", cov["context"], "Sensitive variable-name assignments"),
        ("Entropy Secrets", cov["entropy"], "High-randomness strings"),
    ]
    if cov["vulnerability"]:
        rows.append(
            ("Vulnerabilities", cov["vulnerability"], "Code-vulnerability patterns")
        )

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", style="grey78", no_wrap=True)
    grid.add_column(justify="right", style="bold")
    grid.add_column(justify="left", style="dim")
    for label, count, hint in rows:
        style = "bold white" if count else "dim"
        grid.add_row(f"Detected {label}", Text(str(count), style=style), hint)

    total_secrets = len(report.secret_findings())
    grid.add_row(
        "[bold]Total Secret Findings[/bold]",
        Text(str(total_secrets), style="bold cyan"),
        "",
    )

    console.print(
        Panel(
            grid,
            title="[bold]Detection Coverage[/bold]",
            title_align="left",
            border_style="grey50",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def _render_heatmap(report: Report, console: Console) -> None:
    folders = _top_folders(report)
    if not folders:
        return
    table = Table(
        title="[bold]Top Risky Folders[/bold]",
        title_justify="left",
        box=box.SIMPLE,
        header_style="bold grey70",
        expand=True,
    )
    table.add_column("Folder", style="cyan", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    table.add_column("", ratio=1)
    max_count = folders[0][1] or 1
    for folder, count in folders:
        bar_len = max(1, int((count / max_count) * 30))
        # Gradient: hotter (red) the closer to the max.
        ratio = count / max_count
        color = "red" if ratio >= 0.75 else "dark_orange3" if ratio >= 0.4 else "yellow"
        bar = Text("█" * bar_len, style=color)
        table.add_row(folder, str(count), bar)
    console.print(table)


def _render_fixes(report: Report, console: Console) -> None:
    from .fixes import fixes_for_finding

    # Show remediation for the most severe distinct rules to avoid a wall of text.
    shown: set[str] = set()
    lines = Text()
    for f in report.findings:
        if f.rule_id in shown:
            continue
        if shown:
            lines.append("\n")
        shown.add(f.rule_id)
        lines.append(f"{f.severity.symbol} ", style=f.severity.accent)
        lines.append(f"{f.rule_name}", style="bold")
        lines.append(f"  ({f.severity.name})\n", style=f.severity.color)
        for step in fixes_for_finding(f):
            lines.append("    → ", style="cyan")
            lines.append(f"{step}\n", style="grey74")
        if len(shown) >= 6:
            break
    remaining = len({f.rule_id for f in report.findings}) - len(shown)
    if remaining > 0:
        lines.append(
            f"\n+ {remaining} more rule type(s) — see the full report.",
            style="dim italic",
        )
    console.print(
        Panel(
            lines,
            title="[bold]Remediation[/bold]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def write_output(content: str, out_path: Path) -> None:
    from .utils import GitGuardError

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
    except (OSError, PermissionError) as exc:
        raise GitGuardError(
            f"Could not write report to {out_path}",
            reason=str(exc),
            fixes=["Check the directory exists and is writable",
                   "Choose a different --out path"],
        ) from exc
