"""Tests for regex detection, context scoring, redaction, and severity."""

import pytest

from gitguard.models import Severity, Source
from gitguard.scanner import (
    ScanConfig,
    adjust_severity,
    compute_risk_score,
    scan_text,
)
from gitguard.utils import redact


@pytest.fixture
def config():
    return ScanConfig(use_entropy=False)


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_detect_aws_access_key(config):
    findings = scan_text("key = 'AKIAIOSFODNN7EXAMPLE'", "f.py", config)
    # Placeholder demotion may apply because of EXAMPLE; still detected.
    assert "aws-access-key" in rule_ids(findings)


def test_detect_github_token(config):
    token = "ghp_" + "a" * 36
    findings = scan_text(f"token={token}", "f.py", config)
    assert "github-token" in rule_ids(findings)


def test_detect_stripe_live_key_is_critical(config):
    secret = "sk_live_" + "a" * 24
    findings = scan_text(f"STRIPE_KEY = '{secret}'", "config.py", config)
    f = next(x for x in findings if x.rule_id == "stripe-live-secret")
    assert f.severity == Severity.CRITICAL


def test_detect_private_key(config):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEp= ...\n"
    findings = scan_text(text, "id_rsa", config)
    assert "private-key" in rule_ids(findings)


def test_detect_database_url(config):
    text = "DATABASE_URL=postgres://user:s3cr3tpw@db.example.com:5432/app"
    findings = scan_text(text, ".env", config)
    f = next(x for x in findings if x.rule_id == "db-url")
    assert f.severity == Severity.CRITICAL


def test_detect_openai_key(config):
    secret = "sk-" + "A1b2" * 12  # 48 chars after sk-
    findings = scan_text(f"OPENAI_API_KEY={secret}", "f.py", config)
    assert "openai-key" in rule_ids(findings)


def test_generic_secret_assignment(config):
    findings = scan_text("password = 'hunter2hunter2'", "app.py", config)
    assert "generic-secret-assignment" in rule_ids(findings)


def test_jwt_detection(config):
    jwt = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + ".sig" + "c" * 12
    findings = scan_text(f"auth={jwt}", "f.py", config)
    assert "jwt" in rule_ids(findings)


# --- false positive reduction -------------------------------------------------

def test_placeholder_demoted_to_info(config):
    findings = scan_text("API_KEY = 'YOUR_API_KEY'", "README.md", config)
    # Either not flagged as severe, or demoted to INFO.
    for f in findings:
        assert f.severity == Severity.INFO


def test_example_context_lowers_severity(config):
    secret = "sk_live_" + "a" * 24
    findings = scan_text(f"# example only\nkey='{secret}'  # placeholder", "x.md", config)
    f = next(x for x in findings if x.rule_id == "stripe-live-secret")
    assert f.severity == Severity.INFO


# --- context scoring ----------------------------------------------------------

def test_positive_context_bumps_severity():
    sev, delta, reasons = adjust_severity(
        Severity.MEDIUM, "abc123def456", "password = production", strict=False
    )
    assert sev >= Severity.HIGH
    assert delta > 0


def test_production_context_bumps():
    sev, _, reasons = adjust_severity(
        Severity.HIGH, "abc123def456ghi", "live production key", strict=False
    )
    assert sev == Severity.CRITICAL


# --- redaction ----------------------------------------------------------------

def test_redact_keeps_edges():
    out = redact("sk_live_abcdef1234567890xyz")
    assert out.startswith("sk_liv")
    assert out.endswith("0xyz")
    assert "..." in out
    assert "abcdef1234567890" not in out


def test_redact_short_secret_fully_masked():
    assert redact("abc") == "***"


def test_redact_show_true_returns_full():
    assert redact("supersecretvalue", show=True) == "supersecretvalue"


# --- severity scoring ---------------------------------------------------------

def test_risk_score_zero_with_no_findings():
    assert compute_risk_score([]) == 0


def test_risk_score_capped_at_100(config):
    secret = "sk_live_" + "a" * 24
    text = "\n".join(f"k{i} = '{secret}'" for i in range(20))
    findings = scan_text(text, "prod_config.py", config)
    assert compute_risk_score(findings) == 100


def test_history_finding_increases_score(config):
    secret = "ghp_" + "z" * 36
    current = scan_text(f"t={secret}", "a.py", config)
    hist = scan_text(
        f"t={secret}", "a.py", config, source=Source.HISTORY, commit="abcd1234"
    )
    assert compute_risk_score(hist) >= compute_risk_score(current)
