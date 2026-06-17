"""Tests for scanning, ignore rules, ZIP safety, and report serialization."""

import json
import zipfile
from pathlib import Path

import pytest

from gitguard.archive import safe_extract_zip
from gitguard.models import Report
from gitguard.report import to_csv, to_json
from gitguard.scanner import ScanConfig, scan_directory
from gitguard.utils import GitGuardError, iter_files, DEFAULT_IGNORED_DIRS


@pytest.fixture
def config():
    return ScanConfig(use_entropy=False)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_scan_directory_finds_secret(tmp_path, config):
    write(tmp_path / "app.py", "key = 'sk_live_" + "a" * 24 + "'")
    report = scan_directory(
        tmp_path, config, target_label=str(tmp_path), target_type="directory"
    )
    assert any(f.rule_id == "stripe-live-secret" for f in report.findings)
    assert report.stats.files_scanned == 1


def test_ignored_directories_skipped(tmp_path, config):
    write(tmp_path / "node_modules" / "lib.js", "ghp_" + "a" * 36)
    write(tmp_path / "src" / "main.py", "x = 1")
    report = scan_directory(
        tmp_path, config, target_label=str(tmp_path), target_type="directory"
    )
    assert report.findings == []
    # Only the non-ignored file is counted.
    assert report.stats.files_scanned == 1


def test_hidden_files_skipped_by_default(tmp_path, config):
    write(tmp_path / ".env", "STRIPE=sk_live_" + "a" * 24)
    report = scan_directory(
        tmp_path, config, target_label=str(tmp_path), target_type="directory"
    )
    assert report.stats.files_scanned == 0


def test_hidden_files_included_when_requested(tmp_path):
    write(tmp_path / ".env", "STRIPE_KEY=sk_live_" + "a" * 24)
    config = ScanConfig(use_entropy=False, include_hidden=True)
    report = scan_directory(
        tmp_path, config, target_label=str(tmp_path), target_type="directory"
    )
    assert any(f.rule_id == "stripe-live-secret" for f in report.findings)


def test_binary_file_skipped(tmp_path, config):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01ghp_" + b"a" * 36)
    report = scan_directory(
        tmp_path, config, target_label=str(tmp_path), target_type="directory"
    )
    assert report.findings == []


def test_max_file_size_skips_large(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 2048)
    config = ScanConfig(use_entropy=False, max_file_size=1024)
    files = list(iter_files(
        tmp_path, ignored_dirs=DEFAULT_IGNORED_DIRS,
        include_hidden=False, max_file_size=1024,
    ))
    assert big not in files


# --- ZIP extraction safety ----------------------------------------------------

def test_safe_zip_extraction(tmp_path):
    zpath = tmp_path / "good.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("a/b.txt", "hello")
    dest = tmp_path / "out"
    safe_extract_zip(zpath, dest)
    assert (dest / "a" / "b.txt").read_text() == "hello"


def test_zip_slip_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    dest = tmp_path / "out"
    with pytest.raises(GitGuardError):
        safe_extract_zip(zpath, dest)
    assert not (tmp_path / "escape.txt").exists()


def test_zip_absolute_path_rejected(tmp_path):
    zpath = tmp_path / "abs.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("/etc/evil.txt", "pwned")
    dest = tmp_path / "out"
    with pytest.raises(GitGuardError):
        safe_extract_zip(zpath, dest)


# --- report serialization -----------------------------------------------------

def test_json_report_roundtrip(tmp_path, config):
    write(tmp_path / "app.py", "key = 'sk_live_" + "a" * 24 + "'")
    report = scan_directory(
        tmp_path, config, target_label="t", target_type="directory"
    )
    data = json.loads(to_json(report))
    assert data["tool"] == "gitguard"
    assert data["findings"]
    restored = Report.from_dict(data)
    assert len(restored.findings) == len(report.findings)
    assert restored.findings[0].rule_id == report.findings[0].rule_id


def test_csv_report_has_header(tmp_path, config):
    write(tmp_path / "app.py", "key = 'sk_live_" + "a" * 24 + "'")
    report = scan_directory(
        tmp_path, config, target_label="t", target_type="directory"
    )
    csv_out = to_csv(report)
    assert csv_out.splitlines()[0].startswith("severity,rule_id")


def test_no_findings_clean(tmp_path, config):
    write(tmp_path / "clean.py", "x = 1\nprint('hello world')\n")
    report = scan_directory(
        tmp_path, config, target_label="t", target_type="directory"
    )
    assert report.findings == []
    assert report.risk_score == 0


def test_symlink_outside_root_not_followed(tmp_path, config):
    outside = tmp_path / "outside"
    outside.mkdir()
    write(outside / "secret.py", "key='sk_live_" + "a" * 24 + "'")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    report = scan_directory(
        root, config, target_label="t", target_type="directory"
    )
    assert report.findings == []
