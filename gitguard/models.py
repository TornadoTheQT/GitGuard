"""Structured data models for GitGuard findings and reports."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Severity levels ordered so that higher == more dangerous.

    The integer ordering lets us compare severities (e.g. for ``--fail-on``)
    and pick the worst finding easily.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.name for s in cls)
            raise ValueError(
                f"Unknown severity {name!r}. Valid values: {valid}"
            ) from exc

    # Base contribution to the overall risk score.
    @property
    def base_score(self) -> int:
        return {
            Severity.CRITICAL: 35,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        """Style used for severity labels/badges in markup."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "bold dark_orange3",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "dim",
        }[self]

    @property
    def accent(self) -> str:
        """A plain foreground color (no attributes) suitable for bars/blocks."""
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "dark_orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "grey50",
        }[self]

    @property
    def symbol(self) -> str:
        """A compact glyph used to prefix the severity in tables/legends."""
        return {
            Severity.CRITICAL: "●",
            Severity.HIGH: "▲",
            Severity.MEDIUM: "◆",
            Severity.LOW: "▾",
            Severity.INFO: "·",
        }[self]


class Source(str, enum.Enum):
    """Where a finding was discovered."""

    CURRENT = "current"
    HISTORY = "history"


@dataclass
class Finding:
    """A single detected secret or sensitive value."""

    rule_id: str
    rule_name: str
    severity: Severity
    path: str
    line: int
    column: int
    match_preview: str
    confidence: float
    reason: str
    risk: str
    recommendation: str
    source: Source = Source.CURRENT
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    category: str = "secret"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["source"] = self.source.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        data = dict(data)
        data["severity"] = Severity.from_name(data["severity"])
        data["source"] = Source(data.get("source", "current"))
        # Drop any unexpected keys so future report versions don't crash old code.
        known = cls.__dataclass_fields__.keys()
        clean = {k: v for k, v in data.items() if k in known}
        return cls(**clean)


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    commits_scanned: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """The full result of a scan."""

    target: str
    target_type: str
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    risk_score: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_version: str = "0.0.0"

    def severity_counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    # Detection-method buckets used for the coverage breakdown (part 11).
    COVERAGE_BUCKETS = ("provider", "generic", "context", "entropy", "vulnerability")

    def category_counts(self) -> dict[str, int]:
        counts = {b: 0 for b in self.COVERAGE_BUCKETS}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    def secret_findings(self) -> list["Finding"]:
        """All findings except code-vulnerability findings."""
        return [f for f in self.findings if f.category != "vulnerability"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "gitguard",
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "target": self.target,
            "target_type": self.target_type,
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts(),
            "coverage": self.category_counts(),
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Report":
        stats_data = data.get("stats", {}) or {}
        known_stats = ScanStats.__dataclass_fields__.keys()
        stats = ScanStats(**{k: v for k, v in stats_data.items() if k in known_stats})
        return cls(
            target=data.get("target", "unknown"),
            target_type=data.get("target_type", "unknown"),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            stats=stats,
            risk_score=int(data.get("risk_score", 0)),
            generated_at=data.get("generated_at", ""),
            tool_version=data.get("tool_version", "0.0.0"),
        )
