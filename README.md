# GitGuard

A production-quality **secret-scanning CLI**. GitGuard scans local folders,
ZIP archives, and GitHub repositories (including git history) for exposed API
keys, tokens, passwords, and private keys. It scores severity, shows exact
file/line locations, and generates deterministic remediation advice — all
offline. **Plain scans never send your secrets anywhere.** If you opt into
`scan --fix`, GitGuard creates a temporary copy and spins up a configured fix
agent to edit it.

```
GitGuard Scan Report
Risk Score: 100/100

CRITICAL  .env:1            Stripe Live Secret Key
CRITICAL  .env:2            Database Connection URL
CRITICAL  id_rsa:1          Private Key Block
HIGH      src/client.ts:1   OpenAI API Key
INFO      config/dev.json:1 Sensitive Variable Assignment (placeholder)
```

## Install

The quickest path is the bundled installer. It autodetects a suitable Python
interpreter, creates a virtual environment, and installs GitGuard into it:

```bash
# from a clone of this repo
./install.sh            # installs the gitguard CLI
./install.sh --dev      # also installs dev/test extras (pytest)

source .venv/bin/activate
gitguard --help
```

The installer reads the minimum Python version from `pyproject.toml`, probes the
versioned interpreters on your `PATH` (`python3.13`, `python3.12`, … down to the
minimum, then `python3`/`python`), and uses the newest one that qualifies. Set
`VENV=path` to install into a different location.

Prefer to do it by hand? The classic flow still works:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .          # or: pip install -e ".[dev]"
```

This installs the `gitguard` command. The supported Python version is declared
once in `pyproject.toml` (`requires-python`); `gitguard doctor` reports whether
your interpreter meets it. `git` is only needed for `--history` and for scanning
remote GitHub URLs.

## Commands

### `scan` — scan a target

```bash
gitguard scan <target> [options]
```

`<target>` may be a **single file** (e.g. `main.js`), a **local folder**, a
**`.zip` file**, or a **GitHub URL** (`https://github.com/owner/repo`).

| Option | Description |
| --- | --- |
| `--history` | Also scan git commit history (added lines across commits). |
| `--csv` | Emit a CSV report (instead of the default JSON). |
| `--ai` | Emit a Markdown remediation brief for an AI coding agent (e.g. Claude Code). |
| `--json` | Emit a JSON report. JSON is already the default for `--out`, so this is optional. |
| `--out <path>` | Write the report to a file (**JSON by default**; `.csv`/`.md` with `--csv`/`--ai`). A directory writes `gitguard-report.<ext>` inside it. |
| `--no-entropy` | Disable Shannon-entropy detection. |
| `--max-file-size <mb>` | Skip files larger than this (default 5 MB). |
| `--include-hidden` | Include hidden files/folders (e.g. `.env`). |
| `--strict` | Increase sensitivity (lower entropy thresholds, more candidates). |
| `--vulns` | Also scan for code vulnerabilities (injection, eval, weak crypto…). |
| `--quiet` | Only show the findings table. |
| `--fail-on <severity>` | Exit non-zero if a finding ≥ this severity exists (CI). |
| `--fix` | Ask GitGuard's fix agent to propose reviewed fixes in a temporary workspace. |
| `--test-cmd <cmd>` | Verification command to run from the fixed target root after accepted `--fix` changes. Repeatable. |
| `--model <provider/model>` | Optional fix-agent model override for `--fix`. |
| `--fix-timeout <seconds>` | Seconds to wait for the fix agent (default 900). |
| `--patch-out <path>` | Save the proposed fix-agent diff to a patch file. |
| `--fix-max-findings <n>` | Maximum findings for one fix-agent pass (default 25; use 0 to disable). |
| `--show-secrets` | Reveal full secrets (prompts for confirmation; dangerous). |
| `--debug` | Show tracebacks instead of friendly errors. |

> **Output formats:** the terminal report is the default when printing to the
> screen. When you pass `--out`, the file is **JSON unless** you add `--csv` or
> `--ai` — you no longer need `--json`. Only one of `--json`/`--csv`/`--ai` may
> be used at a time.

> **Note:** `.env` and other dotfiles are *hidden* and skipped by default. Pass
> `--include-hidden` to scan them.

Examples:

```bash
gitguard scan main.js                            # scan a single file
gitguard scan ./myproject --include-hidden
gitguard scan ./release.zip --out report.json    # JSON, no --json needed
gitguard scan . --vulns --ai --out FIX.md        # AI-agent remediation brief
gitguard scan . --vulns --fix --test-cmd pytest  # reviewed fix-agent edits
gitguard scan https://github.com/owner/repo --history
gitguard scan . --history --fail-on HIGH         # CI gate
```

### Fixing findings with an AI agent (`--ai`)

`--ai` emits a self-contained Markdown brief — a task preamble, a summary, and
every finding grouped by file with its location, the reason it matters, and
concrete fix steps. Hand it to an agent like Claude Code to remediate:

```bash
gitguard scan . --vulns --ai --out SECURITY_FIXES.md
# then, in your agent: "Work through SECURITY_FIXES.md and fix each finding."
```

### Fixing findings directly with the fix agent (`--fix`)

`--fix` keeps GitGuard as the user-facing CLI and spins up a fix agent under
the hood. GitGuard scans first, writes an in-memory remediation task, copies the
target into a temporary workspace, asks the agent to edit that copy, displays
the proposed diff, and applies or writes artifacts only after confirmation.

```bash
gitguard scan . --vulns --fix
gitguard scan . --vulns --fix --test-cmd "pytest -q"
gitguard scan ./release.zip --fix              # writes release.fixed.zip
gitguard scan https://github.com/owner/repo --fix --patch-out fix.patch
```

Local files/folders can be applied back to the original target after review.
ZIP targets write a fixed ZIP artifact. GitHub URL targets write a patch
artifact only; GitGuard never pushes, opens PRs, or commits for you.

For reliable edits, run `--fix` on a focused file or folder. GitGuard refuses
very noisy runs by default because handing a large repo full of test fixtures or
scanner examples to one agent pass is slow and usually produces bad edits.

Requirements for `--fix`:

- Node.js v22.19.0 or newer.
- A configured fix-agent runtime on `PATH`.
- Model setup/auth completed for the model you want to use.

### `rules` — list detection rules

```bash
gitguard rules
```

### `fix` — generate remediation from a report

```bash
gitguard scan . --include-hidden --json --out report.json
gitguard fix report.json
```

Produces: `.gitignore` additions, a `.env.example`, a key-revocation
checklist, README security setup steps, and a GitHub Actions secrets guide.

### `doctor` — check the environment

```bash
gitguard doctor [target]
```

Checks Python version, git availability, fix-agent readiness for `--fix`, the
working directory, permissions, and (optionally) whether a target is scannable.

## Detection methods

GitGuard layers four independent detection systems and then **correlates**
overlapping hits so one secret is reported once, at its strongest (e.g. a
`DATABASE_URL` is a single *Database Connection URL* finding, not a duplicate
generic assignment). The end-of-scan **Detection Coverage** panel breaks down
how many findings each system contributed, so coverage gaps are visible.

1. **Provider regexes** — vendor-specific patterns: AWS, GitHub/GitLab, Stripe,
   OpenAI, Slack, Discord (bot/MFA/webhook), Google, Firebase, Twilio, SendGrid,
   Mailgun, and more. Run `gitguard rules` for the full list.
2. **Generic / structural regexes** — private-key blocks, JWTs, bearer tokens,
   and connection URLs for Postgres/MySQL/MongoDB, **Redis**, **AMQP/RabbitMQ**,
   **SMTP**, and **FTP/SFTP**.
3. **Assignment engine** — parses `name = value` / `name: value` across
   JavaScript, TypeScript, Python, JSON, YAML, TOML, INI and `.env`, then flags
   hard-coded credentials by **variable name** (`JWT_SECRET`, `DB_PASSWORD`,
   `API_KEY`, `AUTH_TOKEN`, …) even when the value matches no known pattern.
   Weak well-known values (`admin123`, `letmein`, `root`, …) become `HIGH`;
   obvious placeholders (`YOUR_API_KEY`, `CHANGE_ME`, `DUMMY`, …) are reported as
   `INFO` rather than suppressed.
4. **Shannon entropy** — long, high-randomness strings near secret context.
   These are **promoted to `HIGH`** when in a config/env file or a
   production context. UUIDs, hashes, and placeholders are filtered out.

**Context scoring** runs across all layers: proximity to words like `password`,
`token`, `jwt`, `session`, `production`, or `live` raises severity; markers like
`placeholder`/`dummy`/`changeme` demote toward `INFO`.

**Git history** — with `--history`, added lines across commits are scanned,
surfacing secrets removed from the working tree but still live in history, with
commit hash, author, and date.

### Vulnerability mode (`--vulns`)

Pass `--vulns` to additionally scan source for common code-vulnerability
patterns — SQL injection, XSS / stored XSS, command injection, path traversal,
SSRF, unsafe `eval`, weak cryptography, insecure randomness, broken access
control, IDOR, sensitive error leakage, dangerous file uploads, prototype
pollution, and unsafe object merges. These are heuristic and advisory; they are
reported separately from secrets and counted in their own coverage bucket.

### Severity & risk score

Levels: `CRITICAL > HIGH > MEDIUM > LOW > INFO`. The 0–100 risk score is built
from severity counts (CRITICAL +35, HIGH +20, MEDIUM +10, LOW +3), scaled by
confidence, with extra weight for secrets found in history or in
config/env/production files, and capped at 100.

## CI usage

```yaml
name: secret-scan
on: [push, pull_request]
jobs:
  gitguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # needed for --history
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: gitguard scan . --history --include-hidden --fail-on HIGH
```

The job fails if any HIGH or CRITICAL secret is detected.

## Safety & security

- Secrets are **redacted by default** (`first6…last4`); full values only appear
  behind `--show-secrets` after an explicit confirmation prompt.
- Remote repos are cloned into a **temporary directory** that is **deleted**
  after the scan. Cloning is non-interactive (`GIT_TERMINAL_PROMPT=0`).
- ZIP extraction is hardened against **zip-slip / path traversal** and absolute
  paths, and **skips symlink entries**.
- Symlinks that escape the scan root are **not followed**.
- Plain GitGuard scans **never execute** scanned code and **never validate
  keys** by calling provider APIs — nothing leaves your machine.
- `scan --fix` is an explicit opt-in to model-assisted remediation. It copies
  the target to a temporary workspace and allows your configured fix agent to
  inspect and edit that copy before GitGuard shows you the diff.

## Limitations

- Regex detection cannot catch every secret format; entropy detection trades
  recall for precision and may miss low-entropy secrets.
- History scanning examines added lines per commit up to a cap (500 commits) and
  is not a substitute for tools like `git filter-repo` / BFG for *removing*
  secrets.
- A clean scan is **not** a guarantee that no secrets exist. Treat any
  previously committed credential as compromised and rotate it.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Project layout

```
gitguard/
  cli.py          # Typer CLI (scan, rules, fix, doctor)
  scanner.py      # detection engine, context scoring, risk score
  rules.py        # regex rules + context word lists
  entropy.py      # Shannon entropy helpers
  git_history.py  # cloning + commit-history scanning
  archive.py      # safe ZIP extraction
  report.py       # rich/JSON/CSV rendering
  fixes.py        # deterministic remediation generation
  remediation.py  # agent-backed reviewed fix flow
  models.py       # Finding / Report dataclasses + Severity
  utils.py        # redaction, file walking, ignore rules, errors
tests/
```

## License

MIT
