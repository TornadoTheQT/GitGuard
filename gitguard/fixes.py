"""Deterministic remediation advice generated from finding rule types.

No external AI is called; suggestions are templated per rule category so the
output is reproducible and offline-safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Report

# Per-rule revocation/rotation steps.
_RULE_FIXES: dict[str, list[str]] = {
    "aws-access-key": [
        "Deactivate then delete the key in the AWS IAM console.",
        "Create a replacement key and store it in a secrets manager.",
        "Review CloudTrail logs for unauthorized API activity.",
    ],
    "aws-secret-key": [
        "Rotate the access key pair in AWS IAM immediately.",
        "Audit CloudTrail for suspicious calls.",
    ],
    "github-token": [
        "Revoke the token in GitHub > Settings > Developer settings > Tokens.",
        "Create a fine-grained token with minimal scopes.",
        "Store it as a GitHub Actions secret instead of in code.",
    ],
    "github-fine-grained": [
        "Revoke the token in GitHub Developer settings.",
        "Re-issue with least-privilege repository access.",
    ],
    "stripe-live-secret": [
        "Roll the key immediately in the Stripe Dashboard (Developers > API keys).",
        "Switch to restricted keys scoped to only what you need.",
        "Store the key in your deployment platform's secret store.",
    ],
    "stripe-restricted": [
        "Roll the restricted key in the Stripe Dashboard.",
    ],
    "openai-key": [
        "Revoke the key at platform.openai.com/api-keys.",
        "Generate a new key and set a usage limit.",
        "Load it from an environment variable.",
    ],
    "private-key": [
        "Treat the private key as fully compromised.",
        "Revoke and re-issue any certificates or SSH keys derived from it.",
        "Remove the key from git history (git filter-repo / BFG).",
    ],
    "db-url": [
        "Rotate the database password now.",
        "Restrict database network access (allowlist / VPC).",
        "Check database access logs for unfamiliar connections.",
        "Move the connection string to a secrets manager.",
    ],
    "slack-token": ["Revoke the token in your Slack app's OAuth settings."],
    "slack-webhook": ["Regenerate the incoming webhook URL in Slack."],
    "discord-bot-token": ["Regenerate the bot token in the Discord developer portal."],
    "discord-mfa-token": ["Change the account password to invalidate the token."],
    "discord-webhook": ["Delete and recreate the webhook in Discord channel settings."],
    "google-api-key": [
        "Restrict or regenerate the key in Google Cloud Console > Credentials.",
    ],
    "firebase-url": ["Review Firebase security rules and rotate any exposed keys."],
    "sendgrid-key": ["Revoke the key in the SendGrid dashboard."],
    "mailgun-key": ["Rotate the key in the Mailgun dashboard."],
    "twilio-key": ["Delete the API key in the Twilio console."],
    "twilio-account-sid": ["Rotate the paired Twilio auth token."],
    "gitlab-token": ["Revoke the token in GitLab > Settings > Access Tokens."],
    "redis-url": ["Rotate the Redis password and restrict network access."],
    "amqp-url": ["Rotate broker credentials and lock down access."],
    "smtp-url": ["Rotate the SMTP password and use a secrets manager."],
    "ftp-url": ["Rotate the password and prefer key-based SFTP auth."],
    "jwt": ["Invalidate active sessions and rotate the signing secret."],
    "bearer-token": ["Rotate the token and load it from the environment."],
    "weak-credential": [
        "Replace the weak value with a strong, unique secret immediately.",
        "Rotate it everywhere it was used and store it outside source control.",
    ],
    "placeholder-credential": [
        "Inject the real value from the environment at runtime; never commit it.",
    ],
}

_GENERIC_FIX = [
    "Rotate the value if it was ever a real secret.",
    "Move it to an environment variable or secrets manager.",
    "Remove it from source control and from git history.",
]


@dataclass
class FixPlan:
    """A bundle of remediation artifacts produced from a report."""

    gitignore: list[str] = field(default_factory=list)
    env_example: list[str] = field(default_factory=list)
    revocation_checklist: list[str] = field(default_factory=list)
    readme_steps: list[str] = field(default_factory=list)
    github_actions_guide: list[str] = field(default_factory=list)


def fixes_for_finding(finding: Finding) -> list[str]:
    return _RULE_FIXES.get(finding.rule_id, _GENERIC_FIX)


def _gitignore_recommendations(report: Report) -> list[str]:
    recs: list[str] = []
    paths = {f.path for f in report.findings}
    env_committed = any(
        p.split("/")[-1].startswith(".env") and ".env.example" not in p
        for p in paths
    )
    if env_committed:
        recs += [".env", ".env.local", ".env.*.local"]
    # Always-useful baseline entries.
    recs += ["*.pem", "*.key", "id_rsa", "*.p12", "secrets.json"]
    # De-dupe while keeping order.
    seen: set[str] = set()
    out = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _env_example(report: Report) -> list[str]:
    """Suggest a .env.example with placeholder values for detected variables."""

    keys: list[str] = []
    seen: set[str] = set()
    for f in report.findings:
        # Pull the variable name from generic assignments and known providers.
        name = _guess_env_var(f)
        if name and name not in seen:
            seen.add(name)
            keys.append(name)
    return [f"{k}=your_{k.lower()}_here" for k in keys]


def _guess_env_var(finding: Finding) -> str | None:
    mapping = {
        "aws-access-key": "AWS_ACCESS_KEY_ID",
        "aws-secret-key": "AWS_SECRET_ACCESS_KEY",
        "github-token": "GITHUB_TOKEN",
        "stripe-live-secret": "STRIPE_SECRET_KEY",
        "openai-key": "OPENAI_API_KEY",
        "db-url": "DATABASE_URL",
        "slack-token": "SLACK_TOKEN",
        "google-api-key": "GOOGLE_API_KEY",
        "sendgrid-key": "SENDGRID_API_KEY",
    }
    if finding.rule_id in mapping:
        return mapping[finding.rule_id]
    if finding.rule_id == "generic-secret-assignment":
        return "SECRET_VALUE"
    return None


def _revocation_checklist(report: Report) -> list[str]:
    checklist: list[str] = []
    seen_rules: set[str] = set()
    # One entry per distinct rule, most severe first.
    for f in sorted(report.findings, key=lambda x: -int(x.severity)):
        if f.rule_id in seen_rules:
            continue
        seen_rules.add(f.rule_id)
        steps = fixes_for_finding(f)
        checklist.append(f"[{f.severity.name}] {f.rule_name} ({f.path}:{f.line})")
        checklist += [f"    - {s}" for s in steps]
    return checklist


def _readme_steps() -> list[str]:
    return [
        "## Security setup",
        "",
        "1. Copy `.env.example` to `.env` and fill in real values.",
        "2. Never commit `.env`; it is listed in `.gitignore`.",
        "3. Store production secrets in your platform's secret manager.",
        "4. Rotate any credential that was previously committed.",
        "5. Run `gitguard scan . --history` in CI to catch regressions.",
    ]


def _github_actions_guide() -> list[str]:
    return [
        "## GitHub Actions secrets",
        "",
        "1. Go to Settings > Secrets and variables > Actions.",
        "2. Add each secret (e.g. STRIPE_SECRET_KEY, DATABASE_URL).",
        "3. Reference them in workflows via ${{ secrets.NAME }}.",
        "4. Add a scan step:",
        "",
        "```yaml",
        "      - name: Secret scan",
        "        run: gitguard scan . --history --fail-on HIGH",
        "```",
    ]


def build_fix_plan(report: Report) -> FixPlan:
    return FixPlan(
        gitignore=_gitignore_recommendations(report),
        env_example=_env_example(report),
        revocation_checklist=_revocation_checklist(report),
        readme_steps=_readme_steps(),
        github_actions_guide=_github_actions_guide(),
    )
