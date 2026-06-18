"""Tests for output formats (--json default, --csv, --ai) and single-file scans."""

import json

from typer.testing import CliRunner

from gitguard.cli import app
from gitguard.models import Report
from gitguard.report import to_ai
from gitguard.scanner import ScanConfig, scan_single_file, scan_text

from .demo_source import build_demo_source

runner = CliRunner()
DEMO = build_demo_source()


def _write_demo(tmp_path, name="main.js"):
    p = tmp_path / name
    p.write_text(DEMO)
    return p


# --- single-file scanning ----------------------------------------------------

def test_scan_single_file(tmp_path):
    p = _write_demo(tmp_path)
    report = scan_single_file(p, ScanConfig(use_entropy=True), target_label=str(p))
    assert report.target_type == "file"
    assert report.stats.files_scanned == 1
    assert len(report.secret_findings()) >= 20


def test_cli_scans_single_file(tmp_path):
    p = _write_demo(tmp_path)
    result = runner.invoke(app, ["scan", str(p), "--quiet"])
    assert result.exit_code == 0


# --- AI remediation brief ----------------------------------------------------

def test_to_ai_has_sections_and_fixes():
    findings = scan_text(DEMO, "main.js", ScanConfig(use_entropy=True, scan_vulns=True))
    from gitguard.scanner import finalize_report

    report = finalize_report(Report(target="t", target_type="file"), findings)
    brief = to_ai(report)
    assert "# GitGuard Security Remediation Brief" in brief
    assert "## How to fix" in brief
    assert "## Findings" in brief
    assert "Fix:" in brief
    # Vulnerabilities use their own recommendation, not the secret-rotation text.
    assert "parameterized" in brief.lower() or "argument arrays" in brief.lower()


# --- format selection via CLI ------------------------------------------------

def test_out_defaults_to_json(tmp_path):
    p = _write_demo(tmp_path)
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(p), "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["tool"] == "gitguard"
    assert "coverage" in data


def test_ai_format_to_file(tmp_path):
    p = _write_demo(tmp_path)
    out = tmp_path / "fix.md"
    result = runner.invoke(app, ["scan", str(p), "--ai", "--vulns", "--out", str(out)])
    assert result.exit_code == 0
    assert out.read_text().startswith("# GitGuard Security Remediation Brief")


def test_csv_still_works(tmp_path):
    p = _write_demo(tmp_path)
    result = runner.invoke(app, ["scan", str(p), "--csv"])
    assert result.exit_code == 0
    assert "severity,rule_id" in result.stdout


def test_conflicting_formats_rejected(tmp_path):
    p = _write_demo(tmp_path)
    result = runner.invoke(app, ["scan", str(p), "--json", "--ai"])
    assert result.exit_code == 2


def test_out_directory_gets_default_filename(tmp_path):
    p = _write_demo(tmp_path)
    result = runner.invoke(app, ["scan", str(p), "--out", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "gitguard-report.json").exists()
