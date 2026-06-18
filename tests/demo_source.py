"""Builds the intentionally-vulnerable demo source used by the test suite.

The secrets are assembled from fragments at runtime so that no literal
credential is ever stored on disk (this repo runs a secret-cleaning step that
would otherwise scrub a static fixture file). The generated text exercises every
detection system: provider regexes, generic/structural regexes, the assignment
(variable-name) engine, entropy, and the vulnerability scanner.
"""

from __future__ import annotations

# --- constructed "secrets" (repetitive on purpose; not real) ----------------
_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_SECRET_LINE = "aws_secret_access_key='" + "A" * 40 + "'"
_GITHUB = "ghp_" + "a" * 36
_STRIPE = "sk_live_" + "a" * 24
_OPENAI = "sk-proj-" + "a" * 40
_SLACK = "xoxb-1234567890-" + "a" * 20
_GOOGLE = "AIza" + "a" * 35
_SENDGRID = "SG." + "a" * 22 + "." + "b" * 43
_DISCORD = "N" + "a" * 23 + "." + "a" * 6 + "." + "a" * 27
_POSTGRES = "postgres://admin:" + "pw" + "@db.prod.example.com:5432/app"
_MONGO = "mongodb+srv://root:" + "pw" + "@cluster0.mongodb.net/prod"
_REDIS = "redis://:" + "redispw" + "@cache.prod.internal:6379/0"
_SMTP = "smtp://mailer:" + "smtppass" + "@smtp.example.com:587"
# High-entropy value (same style that already survives in test_entropy.py).
_ENTROPY = "Xk9Lm2Qp7Rs4Tv8Wy3Zb6Nc1Df5GhJ2pK"
_BEARER = "Bearer " + "aB3xZ9qL2mN8pQ7rT4wYkE1cV6dH0jF"
_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA...\\n"
    "-----END RSA PRIVATE KEY-----"
)


def build_demo_source() -> str:
    """Return the demo JavaScript source as a single string."""

    return "\n".join([
        "// vulnerable-demo.js — synthetic, for detection testing only.",
        "const child_process = require('child_process');",
        "const crypto = require('crypto');",
        "",
        "// Provider secrets",
        f"const AWS_ACCESS_KEY_ID = '{_AWS_ID}';",
        f"const awsSecret = \"{_AWS_SECRET_LINE}\";",
        f"const GITHUB_TOKEN = '{_GITHUB}';",
        f"const STRIPE_KEY = '{_STRIPE}';",
        f"const OPENAI_API_KEY = '{_OPENAI}';",
        f"const SLACK_TOKEN = '{_SLACK}';",
        f"const GOOGLE_API_KEY = '{_GOOGLE}';",
        f"const SENDGRID_API_KEY = '{_SENDGRID}';",
        f"const DISCORD_BOT_TOKEN = '{_DISCORD}';",
        "",
        "// Connection URLs",
        f"const POSTGRES_URL = '{_POSTGRES}';",
        f"const MONGO_URL = '{_MONGO}';",
        f"const REDIS_URL = '{_REDIS}';",
        f"const SMTP_URL = '{_SMTP}';",
        "",
        "// Context-based credentials (low entropy, no provider pattern)",
        "const JWT_SECRET = 'supersecretjwtkey';",
        "const SESSION_SECRET = 'keyboardcat';",
        "const COOKIE_SECRET = 'anothersecretvalue';",
        "const WEBHOOK_SECRET = 'whsec_topsecretvalue';",
        "const API_KEY = 'myhardcodedapikey';",
        "const AUTH_TOKEN = 'static-auth-token-value';",
        "",
        "// Weak hardcoded credentials",
        "const DB_PASSWORD = 'admin123';",
        "const DATABASE_PASSWORD = 'password123';",
        "const ADMIN_PASSWORD = 'letmein';",
        "const ROOT_PASSWORD = 'root';",
        "",
        "// Placeholders (INFO, not suppressed)",
        "const PLACEHOLDER_API_KEY = 'YOUR_API_KEY';",
        "const DUMMY_SECRET = 'DUMMY';",
        "const TEST_PASSWORD = 'CHANGE_ME';",
        "",
        "// Private key + bearer + production high-entropy secret",
        f"const PRIVATE_KEY = '{_PRIVATE_KEY}';",
        f"const headers = {{ Authorization: '{_BEARER}' }};",
        f"const prodDatabaseSecret = '{_ENTROPY}';",
        "",
        "// Code vulnerabilities (reported only with --vulns)",
        "function getUser(req, res, db) {",
        "  const q = 'SELECT * FROM users WHERE id = ' + req.params.id;",
        "  db.query(q);",
        "  const row = db.findById(req.params.userid);",
        "  res.send('user: ' + JSON.stringify(row));",
        "}",
        "function render(req) {",
        "  document.getElementById('out').innerHTML = req.query.html;",
        "}",
        "function runCommand(req) {",
        "  child_process.execSync('ls ' + req.query.dir);",
        "}",
        "function readUserFile(req, res) {",
        "  const fs = require('fs');",
        "  fs.readFile(req.query.path, (e, data) => res.send(data));",
        "}",
        "function proxy(req) {",
        "  return fetch(req.query.url);",
        "}",
        "function evaluate(req) {",
        "  return eval(req.body.expression);",
        "}",
        "function hashPassword(pw) {",
        "  return crypto.createHash('md5').update(pw).digest('hex');",
        "}",
        "function makeToken() {",
        "  return Math.random().toString(36);",
        "}",
        "function handleError(err, res) {",
        "  res.status(500).send('Error: ' + err.stack);",
        "}",
        "function merge(req, target) {",
        "  return Object.assign(target, req.body);",
        "}",
        "function pollute(obj, key, val) {",
        "  obj['__proto__'][key] = val;",
        "}",
        "",
    ])
