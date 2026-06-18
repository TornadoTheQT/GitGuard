"""Tests for the enhanced detection engine: context, assignments, new rules,
dedup/correlation, entropy promotion, vulnerability mode, and coverage."""

from pathlib import Path

import pytest

from gitguard.assignments import extract_assignments, is_sensitive_name
from gitguard.models import Severity
from gitguard.scanner import ScanConfig, scan_text

from .demo_source import build_demo_source

# Built from fragments at runtime (no literal secret stored on disk).
DEMO = build_demo_source()


@pytest.fixture
def cfg():
    return ScanConfig(use_entropy=True)


def ids(findings):
    return {f.rule_id for f in findings}


def by_line(findings, line):
    return [f for f in findings if f.line == line]


# --- part 1: context-based credential discovery ------------------------------

@pytest.mark.parametrize("name", [
    "JWT_SECRET", "SESSION_SECRET", "COOKIE_SECRET", "DB_PASSWORD",
    "DATABASE_PASSWORD", "ADMIN_PASSWORD", "ROOT_PASSWORD", "AUTH_TOKEN",
    "API_KEY", "WEBHOOK_SECRET", "DISCORD_BOT_TOKEN",
])
def test_sensitive_names_are_flagged(cfg, name):
    findings = scan_text(f'{name} = "lowentropyvalue"', "app.js", cfg)
    assert findings, f"{name} should produce a finding"
    assert any(f.category == "context" for f in findings)


def test_is_sensitive_name_avoids_false_positives():
    assert is_sensitive_name("API_KEY")
    assert is_sensitive_name("jwtSecret")
    assert not is_sensitive_name("primaryKey")
    assert not is_sensitive_name("author")
    assert not is_sensitive_name("publicKey")


# --- part 2: additional secret rules -----------------------------------------

@pytest.mark.parametrize("text,rule", [
    ("REDIS = 'redis://:pw@cache:6379/0'", "redis-url"),
    ("REDIS = 'rediss://:pw@cache:6379/0'", "redis-url"),
    ("BROKER = 'amqp://user:pw@rabbit:5672'", "amqp-url"),
    ("MAIL = 'smtp://u:p@smtp.example.com:587'", "smtp-url"),
    ("FILES = 'sftp://u:p@host:22'", "ftp-url"),
    ("GL = 'glpat-aaaaaaaaaaaaaaaaaaaa'", "gitlab-token"),
    ("MG = 'key-" + "a" * 32 + "'", "mailgun-key"),
    ("FB = 'https://my-app.firebaseio.com'", "firebase-url"),
])
def test_additional_rules(cfg, text, rule):
    assert rule in ids(scan_text(text, "config.js", cfg))


def test_discord_mfa_token(cfg):
    token = "mfa." + "a" * 84
    assert "discord-mfa-token" in ids(scan_text(f"t = '{token}'", "x.js", cfg))


# --- part 4: placeholders produce INFO (not suppressed) ----------------------

@pytest.mark.parametrize("value", [
    "YOUR_API_KEY", "CHANGE_ME", "CHANGEME", "DUMMY", "FAKE_KEY",
    "TEST_TOKEN", "PLACEHOLDER",
])
def test_placeholders_reported_as_info(cfg, value):
    findings = scan_text(f'API_KEY = "{value}"', "app.js", cfg)
    info = [f for f in findings if f.rule_id == "placeholder-credential"]
    assert info, f"{value} should yield a placeholder finding"
    assert info[0].severity == Severity.INFO


# --- part 5: assignment parsing engine ---------------------------------------

@pytest.mark.parametrize("line", [
    'const SECRET = "abc"',
    'let TOKEN = "abc"',
    'var X = "abc"',
    'PASSWORD: "abc"',
    'JWT_SECRET="abc"',
    '"apiKey": "abc"',
    'export const KEY = "abc"',
])
def test_assignment_extraction_quoted(line):
    found = extract_assignments(line)
    assert found and found[0].value == "abc"


def test_assignment_extraction_unquoted_env():
    found = extract_assignments("DB_PASSWORD=admin123")
    assert found[0].name == "DB_PASSWORD"
    assert found[0].value == "admin123"


def test_assignment_extraction_yaml_unquoted():
    found = extract_assignments("  password: hunter2value")
    assert found[0].name == "password"
    assert found[0].value == "hunter2value"


# --- part 6: weak hardcoded credentials => HIGH ------------------------------

@pytest.mark.parametrize("value", [
    "password123", "admin123", "root", "supersecret", "secret123",
    "letmein", "welcome123",
])
def test_weak_credentials_are_high(cfg, value):
    findings = scan_text(f'ADMIN_PASSWORD = "{value}"', "app.js", cfg)
    weak = [f for f in findings if f.rule_id == "weak-credential"]
    assert weak, f"{value} should be a weak credential"
    assert weak[0].severity == Severity.HIGH


# --- part 7: duplicate suppression / correlation -----------------------------

def test_no_duplicate_for_database_url(cfg):
    findings = scan_text(
        'DATABASE_URL = "postgres://u:pw@db:5432/app"', ".env", cfg
    )
    assert ids(findings) == {"db-url"}


def test_provider_beats_context_on_same_value(cfg):
    secret = "sk_live_" + "a" * 24
    findings = scan_text(f'API_KEY = "{secret}"', "config.js", cfg)
    # One finding, the specific provider rule — not a generic duplicate.
    assert ids(findings) == {"stripe-live-secret"}


# --- part 8: entropy promotion -----------------------------------------------

def test_entropy_promoted_in_config_context(cfg):
    secret = "Xk9Lm2Qp7Rs4Tv8Wy3Zb6Nc1Df5GhJ2"
    findings = scan_text(f"apiSecret = {secret}", "prod.env", cfg)
    ent = [f for f in findings if f.rule_id == "high-entropy-string"]
    assert ent and ent[0].severity == Severity.HIGH


def test_entropy_stays_medium_without_promotion(cfg):
    secret = "Xk9Lm2Qp7Rs4Tv8Wy3Zb6Nc1Df5GhJ2"
    findings = scan_text(f"secret_token = {secret}", "util.js", cfg)
    ent = [f for f in findings if f.rule_id == "high-entropy-string"]
    assert ent and ent[0].severity == Severity.MEDIUM


# --- part 9: vulnerability mode ----------------------------------------------

def test_vulns_only_with_flag():
    text = 'const q = "SELECT * FROM u WHERE id = " + req.params.id;\ndb.query(q);'
    off = scan_text(text, "h.js", ScanConfig(scan_vulns=False))
    on = scan_text(text, "h.js", ScanConfig(scan_vulns=True))
    assert not [f for f in off if f.category == "vulnerability"]
    assert "sql-injection" in ids(on)


@pytest.mark.parametrize("text,rule", [
    ('el.innerHTML = req.query.x', "xss"),
    ('child_process.execSync("ls " + d)', "command-injection"),
    ('return eval(req.body.x)', "unsafe-eval"),
    ('crypto.createHash("md5")', "weak-crypto"),
    ('Math.random()', "insecure-random"),
    ('res.send("e: " + err.stack)', "error-leak"),
    ('obj["__proto__"][k] = v', "prototype-pollution"),
    ('Object.assign(target, req.body)', "unsafe-merge"),
])
def test_vuln_patterns(text, rule):
    findings = scan_text(text, "h.js", ScanConfig(scan_vulns=True))
    assert rule in ids(findings)


# --- part 10: expected coverage on the demo fixture --------------------------

def test_fixture_minimum_secret_findings():
    cfg = ScanConfig(use_entropy=True)
    findings = scan_text(DEMO, "vulnerable-demo.js", cfg)
    secrets = [f for f in findings if f.category != "vulnerability"]
    assert len(secrets) >= 20, f"expected >= 20 secrets, got {len(secrets)}"


def test_fixture_with_vulns_in_expected_range():
    cfg = ScanConfig(use_entropy=True, scan_vulns=True)
    findings = scan_text(DEMO, "vulnerable-demo.js", cfg)
    assert 35 <= len(findings) <= 60, f"expected 35-50+, got {len(findings)}"


def test_fixture_covers_required_rule_types():
    cfg = ScanConfig(use_entropy=True)
    found = ids(scan_text(DEMO, "vulnerable-demo.js", cfg))
    required = {
        "aws-access-key", "github-token", "stripe-live-secret", "openai-key",
        "discord-bot-token", "slack-token", "db-url", "redis-url",
        "private-key", "bearer-token", "weak-credential",
        "generic-secret-assignment", "placeholder-credential",
        "high-entropy-string",
    }
    missing = required - found
    assert not missing, f"missing rule types: {missing}"


# --- part 11: coverage breakdown ---------------------------------------------

def test_coverage_buckets_populated():
    cfg = ScanConfig(use_entropy=True)
    from gitguard.scanner import finalize_report
    from gitguard.models import Report

    findings = scan_text(DEMO, "vulnerable-demo.js", cfg)
    report = finalize_report(Report(target="t", target_type="directory"), findings)
    cov = report.category_counts()
    for bucket in ("provider", "generic", "context", "entropy"):
        assert cov[bucket] > 0, f"{bucket} bucket empty"
