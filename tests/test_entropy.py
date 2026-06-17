"""Tests for Shannon entropy detection and its false-positive guards."""

from gitguard.entropy import (
    is_high_entropy,
    looks_like_hash,
    looks_like_uuid,
    shannon_entropy,
)
from gitguard.scanner import ScanConfig, scan_text


def test_entropy_of_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_random_is_high():
    assert shannon_entropy("aB3xZ9qL2mN8pQ7rT4wY") > 3.5


def test_english_text_is_low_entropy():
    assert not is_high_entropy("thequickbrownfoxjumps")


def test_random_token_is_high_entropy():
    assert is_high_entropy("aB3xZ9qL2mN8pQ7rT4wK1cV")


def test_short_token_not_flagged():
    assert not is_high_entropy("aB3xZ9")


def test_uuid_detection():
    assert looks_like_uuid("123e4567-e89b-12d3-a456-426614174000")
    assert not looks_like_uuid("not-a-uuid")


def test_hash_detection():
    assert looks_like_hash("a" * 40)  # sha1 length
    assert looks_like_hash("0" * 64)  # sha256 length
    assert not looks_like_hash("abc")


def test_uuid_not_flagged_without_context():
    config = ScanConfig(use_entropy=True)
    text = "id = '123e4567-e89b-12d3-a456-426614174000'"
    findings = [f for f in scan_text(text, "f.py", config)
                if f.rule_id == "high-entropy-string"]
    assert findings == []


def test_high_entropy_flagged_near_secret_context():
    config = ScanConfig(use_entropy=True)
    secret = "Xk9Lm2Qp7Rs4Tv8Wy3Zb6Nc1Df5Gh"
    text = f"secret_token = {secret}"
    findings = [f for f in scan_text(text, "f.py", config)
                if f.rule_id == "high-entropy-string"]
    assert findings, "expected an entropy finding near secret context"


def test_placeholder_not_flagged_by_entropy():
    config = ScanConfig(use_entropy=True)
    text = "api_key = 'YOUR_API_KEY_PLACEHOLDER_VALUE'"
    findings = [f for f in scan_text(text, "f.py", config)
                if f.rule_id == "high-entropy-string"]
    assert findings == []
