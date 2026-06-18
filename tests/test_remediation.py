import os
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gitguard.cli import app
from gitguard.models import Report
from gitguard.remediation import (
    FileChange,
    PreparedTarget,
    apply_changes_to_local_target,
    build_remediation_prompt,
    check_fix_agent_environment,
    generate_patch,
    parse_node_version,
    prepare_remediation_target,
    validate_changes_for_apply,
    write_fixed_zip,
)
from gitguard.scanner import ScanConfig, finalize_report, scan_text
from gitguard.utils import GitGuardError

runner = CliRunner()


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _fake_tool_dir(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "node",
        "#!/bin/sh\n"
        "echo v22.19.0\n",
    )
    _write_executable(
        bin_dir / "openclaw",
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('FixAgent 2026.6.8')\n"
        "    raise SystemExit(0)\n"
        "root = pathlib.Path.cwd()\n"
        "for path in root.glob('*.py'):\n"
        "    path.write_text('import os\\nkey = os.environ[\"STRIPE_SECRET_KEY\"]\\n')\n"
        "(root / '.env.example').write_text('STRIPE_SECRET_KEY=your_value_here\\n')\n"
        "print(json.dumps({'payloads': [{'text': 'done'}]}))\n",
    )
    _write_executable(
        bin_dir / "claude",
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('2.1.157 (Claude Code)')\n"
        "    raise SystemExit(0)\n"
        "if sys.argv[1:4] == ['auth', 'status', '--json']:\n"
        "    print(json.dumps({'loggedIn': True, 'authMethod': 'claude.ai'}))\n"
        "    raise SystemExit(0)\n"
        "if sys.argv[1:3] == ['auth', 'login']:\n"
        "    print('login ok')\n"
        "    raise SystemExit(0)\n"
        "print('ok')\n",
    )
    return bin_dir


def test_parse_node_version():
    assert parse_node_version("v22.19.0") == (22, 19, 0)
    assert parse_node_version("22.22.3") == (22, 22, 3)
    assert parse_node_version("not-node") is None


def test_check_fix_agent_environment_with_fake_tools(tmp_path, monkeypatch):
    bin_dir = _fake_tool_dir(tmp_path)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    status = check_fix_agent_environment()

    assert status.ready
    assert status.node.version == "v22.19.0"
    assert "FixAgent" in status.agent.version
    assert status.claude is not None
    assert status.claude.ok


def test_build_remediation_prompt_includes_workspace_and_report(tmp_path):
    findings = scan_text(
        "key = 'sk_live_" + "a" * 24 + "'",
        "app.py",
        ScanConfig(use_entropy=False),
    )
    report = finalize_report(Report(target="t", target_type="file"), findings)
    prepared = PreparedTarget(
        original="app.py",
        target_type="file",
        temp_root=tmp_path,
        baseline_root=tmp_path / "baseline",
        work_root=tmp_path / "work",
        apply_mode="local",
        apply_root=tmp_path,
    )

    prompt = build_remediation_prompt(report, prepared)

    assert str(prepared.work_root) in prompt
    assert "GitGuard Security Remediation Brief" in prompt
    assert "Do not edit files outside" in prompt


def test_generate_patch_and_apply_local_changes(tmp_path):
    original = tmp_path / "project"
    original.mkdir()
    (original / "app.py").write_text("key = 'old'\n")
    baseline = tmp_path / "baseline"
    work = tmp_path / "work"
    baseline.mkdir()
    work.mkdir()
    (baseline / "app.py").write_text("key = 'old'\n")
    (work / "app.py").write_text("key = 'new'\n")
    (work / ".env.example").write_text("KEY=your_value_here\n")

    patch = generate_patch(baseline, work)
    apply_changes_to_local_target(
        patch.changes,
        work_root=work,
        apply_root=original,
    )

    assert "key = 'new'" in (original / "app.py").read_text()
    assert (original / ".env.example").exists()
    assert "--- a/app.py" in patch.diff


def test_validate_changes_rejects_path_traversal(tmp_path):
    with pytest.raises(GitGuardError):
        validate_changes_for_apply(
            [FileChange("../escape.py", "modified", True)],
            apply_root=tmp_path,
            work_root=tmp_path,
        )


def test_prepare_and_write_fixed_zip(tmp_path):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app.py", "key = 'old'\n")
        zf.writestr("node_modules/lib.js", "module.exports = 1\n")

    prepared = prepare_remediation_target(str(zip_path))
    try:
        assert prepared.apply_mode == "zip"
        (prepared.work_root / "app.py").write_text("key = 'new'\n")
        fixed = write_fixed_zip(prepared.work_root, prepared.fixed_zip_path)
    finally:
        prepared.cleanup()

    with zipfile.ZipFile(fixed) as zf:
        assert zf.read("app.py").decode() == "key = 'new'\n"
        assert zf.read("node_modules/lib.js").decode() == "module.exports = 1\n"


def test_prepare_github_url_uses_patch_mode_without_network(tmp_path, monkeypatch):
    from gitguard import git_history

    def fake_clone(url, dest):
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("print('hi')\n")
        return dest

    monkeypatch.setattr(git_history, "clone_repo", fake_clone)

    prepared = prepare_remediation_target("https://github.com/example/project")
    try:
        assert prepared.apply_mode == "patch"
        assert prepared.default_patch_path.name == "gitguard-example-project-agent.patch"
        assert (prepared.work_root / "app.py").exists()
    finally:
        prepared.cleanup()


def test_scan_fix_with_fake_agent_applies_reviewed_changes(tmp_path):
    bin_dir = _fake_tool_dir(tmp_path)
    target = tmp_path / "app.py"
    target.write_text("key = 'sk_live_" + "a" * 24 + "'\n")

    result = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--fix",
            "--test-cmd",
            f"{sys.executable} -c \"print('ok')\"",
        ],
        input="y\n",
        env={"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"},
    )

    assert result.exit_code == 0, result.output
    assert "os.environ" in target.read_text()
    assert (tmp_path / ".env.example").exists()
    assert "Verification commands" in result.output


def test_scan_fix_no_findings_skips_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    target = tmp_path / "clean.py"
    target.write_text("print('clean')\n")

    result = runner.invoke(app, ["scan", str(target), "--fix"])

    assert result.exit_code == 0, result.output
    assert "fix agent stayed idle" in result.output


def test_scan_fix_refuses_too_many_findings_before_agent_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    for idx in range(26):
        (tmp_path / f"app{idx}.py").write_text(
            "key = 'sk_live_" + ("a" * 24) + "'\n"
        )

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix", "--quiet"])

    assert result.exit_code == 2
    assert "Too many findings" in result.output
    assert "fix-max-findings" in result.output
