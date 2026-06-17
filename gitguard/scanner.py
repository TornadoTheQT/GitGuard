"""Core scanning engine: regex + assignment + entropy detection, scoring."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from . import entropy as entropy_mod
from .assignments import extract_assignments, is_sensitive_name
from .models import Finding, Report, ScanStats, Severity, Source
from .rules import (
    CONTEXT_CREDENTIAL_RULE,
    ENTROPY_RULE,
    NEGATIVE_CONTEXT,
    PLACEHOLDER_CREDENTIAL_RULE,
    PLACEHOLDER_VALUES,
    POSITIVE_CONTEXT,
    PRODUCTION_CONTEXT,
    RULES,
    STRONG_FAKE_CONTEXT,
    WEAK_CREDENTIALS,
    WEAK_CREDENTIAL_RULE,
    WEAK_FAKE_CONTEXT,
    Rule,
)
from .utils import (
    DEFAULT_IGNORED_DIRS,
    is_probably_binary,
    iter_files,
    redact,
    relative_to,
)

# How many characters around a match define its "context window".
CONTEXT_WINDOW = 60

# Detection-method priority used when correlating overlapping findings.
# Higher wins, so a provider match beats a generic/context/entropy match for
# the same span (fixes the DATABASE_URL double-report).
_CATEGORY_PRIORITY = {
    "provider": 4,
    "generic": 3,
    "context": 2,
    "entropy": 1,
    "vulnerability": 0,
}

# Path fragments that mark a file as security-sensitive (config/env/secrets).
_SENSITIVE_FILE_HINTS = (
    ".env", "config", "settings", "secret", "credential", "prod",
    "application.properties", "appsettings",
)

ProgressCallback = Callable[[str], None]


@dataclass
class ScanConfig:
    """Tunable knobs for a scan, populated from CLI options."""

    use_entropy: bool = True
    max_file_size: int = 5 * 1024 * 1024
    include_hidden: bool = False
    strict: bool = False
    ignored_dirs: set[str] = None  # type: ignore[assignment]
    follow_symlinks: bool = False
    show_secrets: bool = False
    scan_vulns: bool = False

    def __post_init__(self) -> None:
        if self.ignored_dirs is None:
            self.ignored_dirs = set(DEFAULT_IGNORED_DIRS)


@dataclass
class _Candidate:
    """A finding plus the line span it occupies, used for correlation."""

    finding: Finding
    span: tuple[int, int]
    category: str


def _context_window(line: str, start: int, end: int) -> str:
    lo = max(0, start - CONTEXT_WINDOW)
    hi = min(len(line), end + CONTEXT_WINDOW)
    return line[lo:hi].lower()


def _is_sensitive_file(path_label: str) -> bool:
    low = path_label.lower()
    return any(hint in low for hint in _SENSITIVE_FILE_HINTS)


def _value_is_placeholder(secret: str) -> bool:
    """True when the secret value *itself* looks fake (independent of context)."""

    low = secret.lower()
    if low in PLACEHOLDER_VALUES:
        return True
    return any(
        p in low for p in ("placeholder", "your_api_key", "your_secret",
                            "your_token", "changeme", "change_me", "xxxx")
    )


def _looks_placeholder(secret: str, context: str) -> bool:
    """Broad placeholder check used by the (noise-tolerant) entropy filter."""

    if _value_is_placeholder(secret):
        return True
    return any(neg in context for neg in NEGATIVE_CONTEXT)


def _has_strong_fake_context(context: str) -> bool:
    return any(neg in context for neg in STRONG_FAKE_CONTEXT)


def _has_weak_fake_context(context: str) -> bool:
    return any(neg in context for neg in WEAK_FAKE_CONTEXT)


def _has_positive_context(context: str) -> bool:
    return any(pos in context for pos in POSITIVE_CONTEXT)


def _has_production_context(context: str) -> bool:
    return any(p in context for p in PRODUCTION_CONTEXT)


def adjust_severity(
    base: Severity,
    secret: str,
    context: str,
    *,
    strict: bool,
) -> tuple[Severity, float, list[str]]:
    """Apply context heuristics to a base severity.

    Returns ``(severity, confidence_delta, reasons)``. Placeholders are
    demoted toward INFO; positive context bumps severity/confidence up.
    """

    reasons: list[str] = []
    severity = base
    conf_delta = 0.0

    # A value that is itself a known placeholder, or strong "fake" markers
    # nearby (placeholder/dummy/changeme/...), demote the finding to INFO.
    if _value_is_placeholder(secret) or _has_strong_fake_context(context):
        reasons.append("appears to be a placeholder/example value")
        return Severity.INFO, -0.4, reasons

    # Weak markers (example.com hostnames, test dirs) only reduce confidence and
    # nudge severity down by one level — they shouldn't nuke a real credential.
    if _has_weak_fake_context(context):
        reasons.append("near a weak placeholder marker (example/demo)")
        conf_delta -= 0.15
        if base <= Severity.MEDIUM:
            severity = Severity(max(int(Severity.LOW), int(base) - 1))
        return severity, conf_delta, reasons

    if _has_positive_context(context):
        reasons.append("located near sensitive context words")
        conf_delta += 0.15
        if base < Severity.CRITICAL and base >= Severity.MEDIUM:
            severity = Severity(min(int(base) + 1, int(Severity.CRITICAL)))

    if _has_production_context(context):
        reasons.append("located in a production context")
        conf_delta += 0.1
        if base < Severity.CRITICAL:
            severity = Severity(min(int(severity) + 1, int(Severity.CRITICAL)))

    if strict and severity < Severity.CRITICAL:
        conf_delta += 0.05

    return severity, conf_delta, reasons


def _make_finding(
    rule: Rule,
    secret: str,
    path_label: str,
    line_no: int,
    column: int,
    context: str,
    *,
    strict: bool,
    show_secrets: bool = False,
    source: Source = Source.CURRENT,
    commit: Optional[str] = None,
    author: Optional[str] = None,
    date: Optional[str] = None,
) -> Finding:
    severity, conf_delta, reasons = adjust_severity(
        rule.severity, secret, context, strict=strict
    )
    confidence = max(0.05, min(0.99, rule.confidence + conf_delta))
    reason = f"Matched rule '{rule.name}'"
    if reasons:
        reason += "; " + "; ".join(reasons)
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=severity,
        path=path_label,
        line=line_no,
        column=column,
        match_preview=redact(secret, show=show_secrets),
        confidence=round(confidence, 2),
        reason=reason,
        risk=rule.risk,
        recommendation=rule.recommendation,
        source=source,
        commit=commit,
        author=author,
        date=date,
        category=rule.category,
    )


def scan_text(
    text: str,
    path_label: str,
    config: ScanConfig,
    *,
    source: Source = Source.CURRENT,
    commit: Optional[str] = None,
    author: Optional[str] = None,
    date: Optional[str] = None,
) -> list[Finding]:
    """Scan a blob of text and return findings.

    Each line is run through three detectors — provider/generic regexes, the
    assignment (variable-name) engine, and entropy — then overlapping findings
    are correlated so a single secret is reported once at its strongest.
    """

    findings: list[Finding] = []
    sensitive_file = _is_sensitive_file(path_label)
    kw = dict(source=source, commit=commit, author=author, date=date)

    for idx, line in enumerate(text.splitlines(), start=1):
        if len(line) > 20_000:
            # Avoid pathological minified lines blowing up regex backtracking.
            line = line[:20_000]

        candidates: list[_Candidate] = []

        # 1. Regex rules (provider + generic structural).
        for rule in RULES:
            for m in rule.finditer(line):
                secret = m.group(rule.secret_group) or m.group(0)
                start = m.start(rule.secret_group) if rule.secret_group else m.start()
                context = _context_window(line, m.start(), m.end())
                fnd = _make_finding(
                    rule, secret, path_label, idx, start + 1, context,
                    strict=config.strict, show_secrets=config.show_secrets, **kw,
                )
                candidates.append(_Candidate(fnd, (m.start(), m.end()), rule.category))

        # 2. Assignment / context engine (variable-name based).
        candidates.extend(
            _context_candidates(line, idx, path_label, config, sensitive_file, kw)
        )

        # 3. Entropy.
        if config.use_entropy:
            candidates.extend(
                _entropy_candidates(line, idx, path_label, config, sensitive_file, kw)
            )

        findings.extend(_correlate(candidates))

    # Vulnerability patterns are independent of secret correlation (part 9).
    if config.scan_vulns:
        from .vulns import scan_text_for_vulns

        findings.extend(
            scan_text_for_vulns(
                text, path_label, show_secrets=config.show_secrets, **kw
            )
        )

    return findings


def _correlate(candidates: list[_Candidate]) -> list[Finding]:
    """Collapse overlapping candidates, keeping the strongest per span.

    Sort so the most desirable candidate (highest detection priority, then
    severity, then confidence) comes first, then greedily keep candidates whose
    span does not overlap one already kept.
    """

    candidates.sort(
        key=lambda c: (
            _CATEGORY_PRIORITY.get(c.category, 0),
            int(c.finding.severity),
            c.finding.confidence,
        ),
        reverse=True,
    )
    kept: list[_Candidate] = []
    for c in candidates:
        s, e = c.span
        if any(s < ke and ks < e for ks, ke in (k.span for k in kept)):
            continue
        kept.append(c)
    return [k.finding for k in kept]


def _context_candidates(
    line: str,
    line_no: int,
    path_label: str,
    config: ScanConfig,
    sensitive_file: bool,
    kw: dict,
) -> list[_Candidate]:
    """Flag hard-coded credentials by variable name (parts 1, 4, 6)."""

    out: list[_Candidate] = []
    for a in extract_assignments(line):
        if not is_sensitive_name(a.name):
            continue
        value = a.value.strip()
        if not value:
            continue
        low = value.lower()
        context = _context_window(line, a.name_col, a.value_end)

        if _value_is_placeholder(value) or low in PLACEHOLDER_VALUES:
            rule = PLACEHOLDER_CREDENTIAL_RULE
            severity = Severity.INFO
            reason = "Sensitive variable assigned an obvious placeholder value"
        elif low in WEAK_CREDENTIALS:
            rule = WEAK_CREDENTIAL_RULE
            severity = Severity.HIGH
            reason = "Sensitive variable assigned a weak, well-known credential"
        else:
            # High-entropy values are owned by the entropy detector, which
            # promotes them — avoid double-reporting (part 7).
            if config.use_entropy and entropy_mod.is_high_entropy(
                value, strict=config.strict
            ):
                continue
            rule = CONTEXT_CREDENTIAL_RULE
            severity = rule.severity
            reason = f"Hard-coded value assigned to sensitive variable '{a.name}'"
            # Promote in production / sensitive-file contexts (part 8 spirit).
            if _has_production_context(context) or sensitive_file:
                severity = Severity.HIGH
                reason += "; in a production/config context"

        confidence = rule.confidence + (0.1 if sensitive_file else 0.0)
        finding = Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=severity,
            path=path_label,
            line=line_no,
            column=a.value_col + 1,
            match_preview=redact(value, show=config.show_secrets),
            confidence=round(min(0.95, confidence), 2),
            reason=reason,
            risk=rule.risk,
            recommendation=rule.recommendation,
            category=rule.category,
            **kw,
        )
        out.append(_Candidate(finding, (a.name_col, a.value_end), rule.category))
    return out


def _entropy_candidates(
    line: str,
    line_no: int,
    path_label: str,
    config: ScanConfig,
    sensitive_file: bool,
    kw: dict,
) -> list[_Candidate]:
    out: list[_Candidate] = []
    for token, col in entropy_mod.iter_candidates(line):
        token_end = col + len(token)
        context = _context_window(line, col, token_end)

        near_secret = _has_positive_context(context)
        if entropy_mod.looks_like_uuid(token) and not near_secret:
            continue
        if entropy_mod.looks_like_hash(token) and not near_secret:
            continue
        if _looks_placeholder(token, context):
            continue
        if not entropy_mod.is_high_entropy(token, strict=config.strict):
            continue
        # Without nearby secret context, only report in strict mode to cut noise.
        if not near_secret and not config.strict:
            continue

        ent = entropy_mod.shannon_entropy(token)
        production = _has_production_context(context)

        # Promotion (part 8): a random value that is near a secret AND lives in a
        # config/env/production context is treated as a real HIGH-risk secret.
        if near_secret and (sensitive_file or production):
            severity = Severity.HIGH
        elif near_secret:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        confidence = ENTROPY_RULE.confidence + (0.2 if near_secret else 0.0)
        if sensitive_file or production:
            confidence += 0.15
        reason = (
            f"High Shannon entropy ({ent:.2f} bits/char) over {len(token)} chars"
        )
        if near_secret:
            reason += "; near sensitive context words"
        if sensitive_file:
            reason += "; in a config/env file"
        elif production:
            reason += "; in a production context"

        finding = Finding(
            rule_id=ENTROPY_RULE.id,
            rule_name=ENTROPY_RULE.name,
            severity=severity,
            path=path_label,
            line=line_no,
            column=col + 1,
            match_preview=redact(token, show=config.show_secrets),
            confidence=round(min(0.9, confidence), 2),
            reason=reason,
            risk=ENTROPY_RULE.risk,
            recommendation=ENTROPY_RULE.recommendation,
            category=ENTROPY_RULE.category,
            **kw,
        )
        out.append(_Candidate(finding, (col, token_end), ENTROPY_RULE.category))
    return out


def scan_file(path: Path, path_label: str, config: ScanConfig) -> list[Finding]:
    """Scan a single file from disk, skipping binaries and unreadable files."""

    if is_probably_binary(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []
    return scan_text(text, path_label, config)


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

def compute_risk_score(findings: Iterable[Finding]) -> int:
    """Aggregate findings into a 0-100 risk score.

    Severity counts drive the base score; history and config/env locations add
    weight; placeholder-only findings barely move the needle.
    """

    findings = list(findings)
    if not findings:
        return 0

    score = 0.0
    for f in findings:
        contribution = f.severity.base_score
        # Confidence scales the contribution so low-confidence noise matters less.
        contribution *= 0.5 + 0.5 * f.confidence
        if f.source == Source.HISTORY:
            contribution += 5  # secrets in history are already leaked
        label = f.path.lower()
        if any(k in label for k in (".env", "config", "secret", "prod")):
            contribution += 3
        score += contribution

    return int(max(0, min(100, round(score))))


def finalize_report(report: Report, findings: list[Finding]) -> Report:
    # Sort by severity desc, then confidence desc, then path/line for stability.
    findings.sort(
        key=lambda f: (-int(f.severity), -f.confidence, f.path, f.line)
    )
    report.findings = findings
    report.risk_score = compute_risk_score(findings)
    return report


def scan_directory(
    root: Path,
    config: ScanConfig,
    *,
    target_label: str,
    target_type: str,
    progress: Optional[ProgressCallback] = None,
) -> Report:
    """Walk ``root`` and scan every eligible file."""

    start = time.monotonic()
    stats = ScanStats()
    findings: list[Finding] = []

    for path in iter_files(
        root,
        ignored_dirs=config.ignored_dirs,
        include_hidden=config.include_hidden,
        max_file_size=config.max_file_size,
        follow_symlinks=config.follow_symlinks,
    ):
        label = relative_to(path, root)
        if progress:
            progress(label)
        if is_probably_binary(path):
            stats.files_skipped += 1
            continue
        try:
            stats.bytes_scanned += path.stat().st_size
        except OSError:
            pass
        file_findings = scan_file(path, label, config)
        findings.extend(file_findings)
        stats.files_scanned += 1

    stats.duration_seconds = round(time.monotonic() - start, 3)
    report = Report(
        target=target_label,
        target_type=target_type,
        stats=stats,
    )
    return finalize_report(report, findings)
