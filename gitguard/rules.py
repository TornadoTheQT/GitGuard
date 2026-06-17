"""Detection rules: regexes, context words, and severity metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Severity


@dataclass(frozen=True)
class Rule:
    """A single regex-based detection rule."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    # Index of the capture group holding the actual secret (0 == whole match).
    secret_group: int = 0
    confidence: float = 0.9
    risk: str = ""
    recommendation: str = ""
    # Detection-method bucket used for coverage reporting:
    # "provider" (named vendor), "generic" (structural), "context", "entropy".
    category: str = "provider"

    def finditer(self, text: str):
        return self.pattern.finditer(text)


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Context words. Presence near a match raises or lowers confidence/severity.
# ---------------------------------------------------------------------------

POSITIVE_CONTEXT = {
    "apikey", "api_key", "password", "passwd", "pwd", "secret", "token",
    "authorization", "bearer", "credential", "private", "production",
    "prod", "live", "database", "connection", "access_key", "auth",
    "jwt", "session", "cookie", "webhook", "passphrase",
}

# Words that mark a "production"/"live" context and warrant a severity bump.
PRODUCTION_CONTEXT = {"prod", "production", "live"}

# Strong "this value is not real" markers. Their presence near a match demotes
# even a high-confidence finding to INFO (but still reports it — see part 4).
STRONG_FAKE_CONTEXT = {
    "placeholder", "dummy", "fake", "sample", "changeme", "change_me",
    "your_api_key", "your-api-key", "not-a-real-key", "redacted", "mock",
    "<your", "insert_", "your_secret", "your_token", "fake_key", "test_token",
}

# Weak markers that legitimately appear in real values (e.g. ``example.com``
# hostnames, ``test`` directories). These only nudge confidence/severity down,
# they do not by themselves nuke a strong finding.
WEAK_FAKE_CONTEXT = {"example", "xxx", "todo", "demo"}

# Union used by noisy detectors (entropy) where aggressive filtering is fine.
NEGATIVE_CONTEXT = STRONG_FAKE_CONTEXT | WEAK_FAKE_CONTEXT

# Obvious placeholder values. These no longer suppress a finding outright;
# instead they produce an INFO finding so coverage gaps stay visible (part 4).
PLACEHOLDER_VALUES = {
    "your_api_key", "your-api-key", "changeme", "change_me", "xxxxxxxx",
    "0123456789", "1234567890", "not-a-real-key", "redacted", "placeholder",
    "todo", "dummy", "example", "fake_key", "test_token", "your_secret",
    "your_token", "yourkey", "example_key", "sample_key", "foobar",
}

# Weak-but-real credentials that should be treated as HIGH when assigned to a
# sensitive variable name (part 6).
WEAK_CREDENTIALS = {
    "password", "password1", "password123", "passw0rd", "admin", "admin123",
    "administrator", "root", "toor", "supersecret", "secret", "secret123",
    "letmein", "welcome", "welcome123", "changeme", "qwerty", "qwerty123",
    "123456", "1234567", "12345678", "123456789", "iloveyou", "monkey",
    "dragon", "test123", "default", "guest", "p@ssw0rd", "hunter2",
}

# ---------------------------------------------------------------------------
# Sensitive variable-name detection (used by the assignment engine).
# A name is "sensitive" if any of its tokens is a strong secret word, or if it
# contains "key" qualified by an access-ish word (so ``API_KEY`` matches but
# ``primaryKey`` does not).
# ---------------------------------------------------------------------------

STRONG_NAME_TOKENS = {
    "secret", "secrets", "password", "passwd", "pwd", "passphrase",
    "token", "apikey", "credential", "credentials", "privatekey",
    "accesskey", "jwt", "bearer", "webhook", "dsn", "auth", "oauth",
    "clientsecret", "encryptionkey", "signingkey", "sessionsecret",
    "cookiesecret",
}

# When a name has a bare "key" token, it is only sensitive if also qualified by
# one of these (avoids primaryKey/foreignKey/sortKey false positives).
KEY_QUALIFIER_TOKENS = {
    "api", "access", "private", "secret", "signing", "encryption",
    "master", "client", "auth", "session", "refresh", "app",
}


# ---------------------------------------------------------------------------
# Rule definitions.
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    Rule(
        id="aws-access-key",
        name="AWS Access Key ID",
        pattern=_c(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        description="Amazon Web Services access key ID.",
        confidence=0.95,
        risk="Grants programmatic access to AWS resources; can lead to full "
        "account takeover and large cloud bills.",
        recommendation="Deactivate the key in IAM, rotate credentials, and "
        "review CloudTrail for unauthorized use.",
    ),
    Rule(
        id="aws-secret-key",
        name="AWS Secret Access Key",
        pattern=_c(
            r"(?i)aws.{0,20}?(?:secret|access).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity=Severity.CRITICAL,
        secret_group=1,
        description="AWS secret access key (40-char base64).",
        confidence=0.8,
        risk="Pairs with an access key ID to fully authenticate to AWS.",
        recommendation="Rotate immediately in IAM and audit usage.",
    ),
    Rule(
        id="github-token",
        name="GitHub Personal Access Token",
        pattern=_c(r"ghp_[A-Za-z0-9_]{36,}"),
        severity=Severity.HIGH,
        description="GitHub personal access token (classic).",
        confidence=0.95,
        risk="Allows repository and organization access depending on scopes.",
        recommendation="Revoke in GitHub Developer Settings and create a new "
        "fine-grained token stored in CI secrets.",
    ),
    Rule(
        id="github-fine-grained",
        name="GitHub Fine-grained Token",
        pattern=_c(r"github_pat_[A-Za-z0-9_]{22,}"),
        severity=Severity.HIGH,
        description="GitHub fine-grained personal access token.",
        confidence=0.95,
        risk="Scoped GitHub access token.",
        recommendation="Revoke in GitHub Developer Settings.",
    ),
    Rule(
        id="gitlab-token",
        name="GitLab Personal Access Token",
        pattern=_c(r"glpat-[A-Za-z0-9_\-]{20,}"),
        severity=Severity.HIGH,
        description="GitLab personal access token.",
        confidence=0.95,
        risk="Grants API and repository access to GitLab.",
        recommendation="Revoke the token in GitLab > Access Tokens.",
    ),
    Rule(
        id="stripe-live-secret",
        name="Stripe Live Secret Key",
        pattern=_c(r"sk_live_[A-Za-z0-9]{20,}"),
        severity=Severity.CRITICAL,
        description="Stripe live mode secret key.",
        confidence=0.97,
        risk="Full access to a live Stripe account: charges, refunds, payouts "
        "and customer data.",
        recommendation="Roll the key in the Stripe Dashboard immediately and "
        "switch to restricted keys.",
    ),
    Rule(
        id="stripe-restricted",
        name="Stripe Restricted Key",
        pattern=_c(r"rk_live_[A-Za-z0-9]{20,}"),
        severity=Severity.HIGH,
        description="Stripe live restricted key.",
        confidence=0.9,
        risk="Scoped access to a live Stripe account.",
        recommendation="Roll the key in the Stripe Dashboard.",
    ),
    Rule(
        id="openai-key",
        name="OpenAI API Key",
        # Project/standard keys start with sk- (avoid clashing with sk_live_).
        pattern=_c(r"sk-(?:proj-)?[A-Za-z0-9_\-]{40,}"),
        severity=Severity.HIGH,
        description="OpenAI API secret key.",
        confidence=0.85,
        risk="Allows billed API usage on the owner's OpenAI account.",
        recommendation="Revoke the key in the OpenAI dashboard and rotate.",
    ),
    Rule(
        id="slack-token",
        name="Slack Token",
        pattern=_c(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        severity=Severity.HIGH,
        description="Slack API token.",
        confidence=0.9,
        risk="Access to Slack workspace data and messaging.",
        recommendation="Revoke the token in the Slack app settings.",
    ),
    Rule(
        id="slack-webhook",
        name="Slack Webhook URL",
        pattern=_c(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        severity=Severity.MEDIUM,
        description="Slack incoming webhook URL.",
        confidence=0.85,
        risk="Allows posting messages into a Slack channel.",
        recommendation="Regenerate the webhook URL in Slack.",
    ),
    Rule(
        id="discord-bot-token",
        name="Discord Bot Token",
        pattern=_c(r"[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}"),
        severity=Severity.HIGH,
        description="Discord bot token.",
        confidence=0.8,
        risk="Full control of a Discord bot account.",
        recommendation="Regenerate the token in the Discord developer portal.",
    ),
    Rule(
        id="discord-mfa-token",
        name="Discord MFA Token",
        pattern=_c(r"mfa\.[A-Za-z0-9_\-]{80,}"),
        severity=Severity.HIGH,
        description="Discord multi-factor (user) token.",
        confidence=0.8,
        risk="Authenticates as a Discord user account.",
        recommendation="Change the account password to invalidate the token.",
    ),
    Rule(
        id="discord-webhook",
        name="Discord Webhook URL",
        pattern=_c(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
            r"\d+/[A-Za-z0-9_\-]+"
        ),
        severity=Severity.MEDIUM,
        description="Discord incoming webhook URL.",
        confidence=0.85,
        risk="Allows posting messages into a Discord channel.",
        recommendation="Delete and regenerate the webhook in Discord.",
    ),
    Rule(
        id="google-api-key",
        name="Google API Key",
        pattern=_c(r"AIza[0-9A-Za-z\-_]{35}"),
        severity=Severity.HIGH,
        description="Google API key.",
        confidence=0.85,
        risk="Access to enabled Google Cloud APIs; may incur billing.",
        recommendation="Restrict or regenerate the key in Google Cloud Console.",
    ),
    Rule(
        id="firebase-url",
        name="Firebase Database URL",
        pattern=_c(r"https://[a-z0-9.\-]+\.firebaseio\.com"),
        severity=Severity.MEDIUM,
        description="Firebase Realtime Database URL.",
        confidence=0.7,
        risk="May expose a Firebase database if security rules are permissive.",
        recommendation="Review Firebase security rules and rotate keys.",
    ),
    Rule(
        id="twilio-key",
        name="Twilio API Key",
        pattern=_c(r"SK[0-9a-fA-F]{32}"),
        severity=Severity.HIGH,
        description="Twilio API key SID.",
        confidence=0.7,
        risk="Access to Twilio messaging/voice; can incur charges.",
        recommendation="Delete the key in the Twilio console.",
    ),
    Rule(
        id="twilio-account-sid",
        name="Twilio Account SID",
        pattern=_c(r"AC[0-9a-fA-F]{32}"),
        severity=Severity.MEDIUM,
        description="Twilio account SID.",
        confidence=0.6,
        risk="Identifies a Twilio account; pairs with an auth token.",
        recommendation="Rotate the paired Twilio auth token.",
    ),
    Rule(
        id="sendgrid-key",
        name="SendGrid API Key",
        pattern=_c(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
        severity=Severity.HIGH,
        description="SendGrid API key.",
        confidence=0.9,
        risk="Allows sending email through the owner's SendGrid account.",
        recommendation="Revoke the key in the SendGrid dashboard.",
    ),
    Rule(
        id="mailgun-key",
        name="Mailgun API Key",
        pattern=_c(r"key-[0-9a-zA-Z]{32}"),
        severity=Severity.HIGH,
        description="Mailgun API key.",
        confidence=0.75,
        risk="Allows sending email through the owner's Mailgun account.",
        recommendation="Rotate the key in the Mailgun dashboard.",
    ),
    Rule(
        id="private-key",
        name="Private Key Block",
        pattern=_c(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"
        ),
        severity=Severity.CRITICAL,
        description="PEM/OpenSSH private key material.",
        confidence=0.98,
        risk="Private keys authenticate servers, users, or signing identities. "
        "Exposure compromises everything they protect.",
        recommendation="Treat the key as compromised: revoke, rotate, and "
        "re-issue certificates that depend on it.",
        category="generic",
    ),
    Rule(
        id="db-url",
        name="Database Connection URL",
        pattern=_c(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://"
            r"[^\s:'\"]+(:[^\s@'\"]+)?@[^\s/'\"]+",
        ),
        severity=Severity.CRITICAL,
        description="Database connection string, often with credentials.",
        confidence=0.9,
        risk="Embedded credentials grant direct access to a database, exposing "
        "or destroying data.",
        recommendation="Rotate the database password, restrict network access, "
        "and move the connection string to a secrets manager.",
        category="generic",
    ),
    Rule(
        id="redis-url",
        name="Redis Connection URL",
        pattern=_c(r"rediss?://[^\s'\"]+"),
        severity=Severity.HIGH,
        description="Redis connection string (redis:// or rediss://).",
        confidence=0.8,
        risk="May embed credentials and grant access to a Redis instance.",
        recommendation="Rotate the Redis password and restrict network access.",
        category="generic",
    ),
    Rule(
        id="amqp-url",
        name="AMQP / RabbitMQ URL",
        pattern=_c(r"amqps?://[^\s'\"]+"),
        severity=Severity.HIGH,
        description="AMQP/RabbitMQ connection string.",
        confidence=0.8,
        risk="May embed credentials for a message broker.",
        recommendation="Rotate broker credentials and restrict access.",
        category="generic",
    ),
    Rule(
        id="smtp-url",
        name="SMTP Credentials URL",
        pattern=_c(r"smtps?://[^\s'\"]+:[^\s@'\"]+@[^\s'\"]+"),
        severity=Severity.HIGH,
        description="SMTP connection string with embedded credentials.",
        confidence=0.85,
        risk="Allows sending email as the configured account.",
        recommendation="Rotate the SMTP password and use a secrets manager.",
        category="generic",
    ),
    Rule(
        id="ftp-url",
        name="FTP / SFTP Credentials URL",
        pattern=_c(r"(?:s?ftp|ftps)://[^\s'\"]+:[^\s@'\"]+@[^\s'\"]+"),
        severity=Severity.HIGH,
        description="FTP/SFTP connection string with embedded credentials.",
        confidence=0.85,
        risk="Grants file-transfer access to the configured host.",
        recommendation="Rotate the password and prefer key-based SFTP auth.",
        category="generic",
    ),
    Rule(
        id="jwt",
        name="JSON Web Token",
        pattern=_c(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        severity=Severity.MEDIUM,
        description="JWT-like string (header.payload.signature).",
        confidence=0.7,
        risk="May be a session or access token granting authenticated access.",
        recommendation="Invalidate the session and rotate signing secrets.",
        category="generic",
    ),
    Rule(
        id="bearer-token",
        name="Authorization Bearer Token",
        pattern=_c(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9._\-]{12,})"),
        severity=Severity.HIGH,
        secret_group=1,
        description="Hard-coded HTTP bearer token.",
        confidence=0.75,
        risk="Authenticated access to an API as the token owner.",
        recommendation="Rotate the token and load it from the environment.",
        category="generic",
    ),
]


RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}


@dataclass
class EntropyRule:
    """Pseudo-rule used to report high-entropy detections uniformly."""

    id: str = "high-entropy-string"
    name: str = "High-entropy String"
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.4
    risk: str = (
        "A long, random-looking string near a secret context may be an "
        "undetected credential."
    )
    recommendation: str = (
        "Confirm whether the value is a secret; if so, move it to a secure "
        "store and rotate it."
    )
    category: str = "entropy"


ENTROPY_RULE = EntropyRule()


# Pseudo-rules for the assignment/context engine. They are not regexes; the
# engine builds findings from them so categories and remediation stay uniform.
@dataclass(frozen=True)
class ContextRule:
    id: str
    name: str
    severity: Severity
    confidence: float
    risk: str
    recommendation: str
    category: str = "context"


CONTEXT_CREDENTIAL_RULE = ContextRule(
    id="generic-secret-assignment",
    name="Hardcoded Credential Assignment",
    severity=Severity.MEDIUM,
    confidence=0.6,
    risk="A sensitive-looking variable is assigned a hard-coded literal value "
    "that anyone with source access can read.",
    recommendation="Move the value to an environment variable or secrets "
    "manager and rotate it if it was ever real.",
)

WEAK_CREDENTIAL_RULE = ContextRule(
    id="weak-credential",
    name="Weak Hardcoded Credential",
    severity=Severity.HIGH,
    confidence=0.85,
    risk="A sensitive variable is assigned a weak, well-known credential that "
    "is trivially guessable and likely real.",
    recommendation="Replace with a strong unique secret, store it outside "
    "source control, and rotate immediately.",
)

PLACEHOLDER_CREDENTIAL_RULE = ContextRule(
    id="placeholder-credential",
    name="Placeholder Credential",
    severity=Severity.INFO,
    confidence=0.3,
    risk="A sensitive variable holds an obvious placeholder. Harmless now, but "
    "marks where a real secret is expected to live.",
    recommendation="Ensure the real value is injected from the environment at "
    "runtime, never committed.",
)
