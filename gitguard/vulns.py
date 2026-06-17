"""Heuristic source-code vulnerability detection (the ``--vulns`` mode).

This is deliberately separate from secret scanning: it looks for dangerous code
*patterns* (injection, eval, weak crypto, ...) rather than leaked credentials.
Detection is regex-based and heuristic — it favours recall, so findings are
advisory and should be confirmed by a human.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity, Source


@dataclass(frozen=True)
class VulnRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    recommendation: str
    confidence: float = 0.5


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


VULN_RULES: list[VulnRule] = [
    VulnRule(
        id="sql-injection",
        name="SQL Injection",
        # String concatenation or template interpolation inside a SQL string.
        pattern=_c(
            r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\n;]*"
            r"(?:\"\s*\+|'\s*\+|\$\{|%\s*\(|%s|\+\s*req\.|\.format\()"
        ),
        severity=Severity.HIGH,
        description="SQL query built with string concatenation or interpolation.",
        recommendation="Use parameterized queries / prepared statements.",
        confidence=0.55,
    ),
    VulnRule(
        id="xss",
        name="Cross-Site Scripting (XSS)",
        pattern=_c(r"(?i)\.innerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\("),
        severity=Severity.HIGH,
        description="Unsanitized HTML sink that can execute injected markup.",
        recommendation="Use textContent or a sanitizer (DOMPurify) before render.",
        confidence=0.55,
    ),
    VulnRule(
        id="stored-xss",
        name="Stored XSS (React dangerouslySetInnerHTML)",
        pattern=_c(r"dangerouslySetInnerHTML"),
        severity=Severity.HIGH,
        description="React raw-HTML injection sink.",
        recommendation="Avoid raw HTML; sanitize content before injecting.",
        confidence=0.6,
    ),
    VulnRule(
        id="command-injection",
        name="Command Injection",
        pattern=_c(
            r"(?i)(?:child_process|\bexec\s*\(|execSync\s*\(|\bspawn\s*\(|"
            r"os\.system\s*\(|os\.popen\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True)"
        ),
        severity=Severity.CRITICAL,
        description="Shell command execution, often with untrusted input.",
        recommendation="Avoid shells; pass argument arrays and validate input.",
        confidence=0.55,
    ),
    VulnRule(
        id="path-traversal",
        name="Path Traversal",
        pattern=_c(
            r"(?i)(?:readFile|readFileSync|sendFile|createReadStream|open)\s*\([^)]*"
            r"(?:req\.(?:params|query|body)|\.\./|__dirname\s*\+)"
        ),
        severity=Severity.HIGH,
        description="File access built from user-controlled path input.",
        recommendation="Resolve and validate paths against an allowed base dir.",
        confidence=0.5,
    ),
    VulnRule(
        id="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        pattern=_c(
            r"(?i)(?:fetch|axios(?:\.get|\.post)?|requests\.(?:get|post)|"
            r"urllib\.request\.urlopen|http\.get)\s*\([^)]*"
            r"(?:req\.(?:params|query|body)|request\.(?:args|form))"
        ),
        severity=Severity.HIGH,
        description="Outbound request to a user-controlled URL.",
        recommendation="Allowlist destinations and block internal address ranges.",
        confidence=0.5,
    ),
    VulnRule(
        id="unsafe-eval",
        name="Unsafe Eval",
        pattern=_c(r"(?i)(?:\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]|exec\s*\(\s*compile\s*\()"),
        severity=Severity.HIGH,
        description="Dynamic code evaluation that can execute injected code.",
        recommendation="Remove eval/new Function; use safe parsing instead.",
        confidence=0.6,
    ),
    VulnRule(
        id="weak-crypto",
        name="Weak Cryptography",
        pattern=_c(r"(?i)(?:createHash\s*\(\s*['\"](?:md5|sha1)|\bMD5\b|\bSHA1\b|\bDES\b|\bRC4\b|hashlib\.(?:md5|sha1)\s*\()"),
        severity=Severity.MEDIUM,
        description="Use of a broken or weak hashing/encryption algorithm.",
        recommendation="Use SHA-256+/bcrypt/argon2 and AES-GCM as appropriate.",
        confidence=0.6,
    ),
    VulnRule(
        id="insecure-random",
        name="Insecure Randomness",
        pattern=_c(r"(?i)Math\.random\s*\(\)|\brandom\.random\s*\(\)|\brandom\.randint\s*\("),
        severity=Severity.MEDIUM,
        description="Non-cryptographic RNG used where security may be required.",
        recommendation="Use crypto.randomBytes / secrets module for tokens.",
        confidence=0.45,
    ),
    VulnRule(
        id="broken-access-control",
        name="Broken Access Control",
        pattern=_c(r"(?i)(?://\s*)?(?:TODO|FIXME)?[^\n]*\b(?:auth|authoriz|isAdmin|requireLogin|checkPermission)\w*\s*(?:=\s*(?:false|0)|//)"),
        severity=Severity.HIGH,
        description="Authorization check appears disabled or bypassed.",
        recommendation="Enforce server-side authorization on every protected route.",
        confidence=0.4,
    ),
    VulnRule(
        id="idor",
        name="Insecure Direct Object Reference (IDOR)",
        pattern=_c(
            r"(?i)(?:findById|find_by_id|findOne|get_object_or_404|\.get\s*\()\s*\(?[^)]*"
            r"req\.(?:params|query)\.\w*id"
        ),
        severity=Severity.MEDIUM,
        description="Object looked up directly by user-supplied id without an "
        "ownership check.",
        recommendation="Verify the current user is authorized for the object.",
        confidence=0.4,
    ),
    VulnRule(
        id="error-leak",
        name="Sensitive Error Leakage",
        pattern=_c(
            r"(?i)(?:res\.(?:send|json|write)|response\.write)\s*\([^)]*"
            r"(?:err\b|error\b|\.stack|exception)"
        ),
        severity=Severity.MEDIUM,
        description="Error object or stack trace returned to the client.",
        recommendation="Log details server-side; return a generic error message.",
        confidence=0.45,
    ),
    VulnRule(
        id="dangerous-upload",
        name="Dangerous File Upload",
        pattern=_c(r"(?i)multer\s*\(|req\.files\b|request\.files\b|\.save\s*\(\s*os\.path\.join"),
        severity=Severity.MEDIUM,
        description="File upload handling without obvious type/size restrictions.",
        recommendation="Validate type, size, and storage path; never trust names.",
        confidence=0.4,
    ),
    VulnRule(
        id="prototype-pollution",
        name="Prototype Pollution Risk",
        pattern=_c(r"(?i)__proto__|prototype\s*\[|constructor\s*\[\s*['\"]prototype"),
        severity=Severity.HIGH,
        description="Direct manipulation of object prototype chain.",
        recommendation="Reject __proto__/constructor keys; use Map or null-proto.",
        confidence=0.5,
    ),
    VulnRule(
        id="unsafe-merge",
        name="Unsafe Object Merge",
        pattern=_c(
            r"(?i)(?:Object\.assign\s*\([^,]+,\s*req\.|_\.merge\s*\(|"
            r"_\.defaultsDeep\s*\(|Object\.assign\s*\(\s*\{\}\s*,\s*req\.)"
        ),
        severity=Severity.MEDIUM,
        description="Deep/object merge of untrusted input (pollution vector).",
        recommendation="Validate and allowlist keys before merging user input.",
        confidence=0.45,
    ),
]

VULN_RULES_BY_ID: dict[str, VulnRule] = {r.id: r for r in VULN_RULES}


def scan_text_for_vulns(
    text: str,
    path_label: str,
    *,
    show_secrets: bool = False,
    source: Source = Source.CURRENT,
    commit=None,
    author=None,
    date=None,
) -> list[Finding]:
    """Scan a blob of text for code-vulnerability patterns."""

    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if len(line) > 20_000:
            line = line[:20_000]
        for rule in VULN_RULES:
            for m in rule.pattern.finditer(line):
                snippet = m.group(0).strip()
                if len(snippet) > 80:
                    snippet = snippet[:77] + "…"
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        path=path_label,
                        line=idx,
                        column=m.start() + 1,
                        match_preview=snippet,
                        confidence=round(rule.confidence, 2),
                        reason=f"Matched vulnerability pattern '{rule.name}'",
                        risk=rule.description,
                        recommendation=rule.recommendation,
                        source=source,
                        commit=commit,
                        author=author,
                        date=date,
                        category="vulnerability",
                    )
                )
                break  # one finding per rule per line keeps output readable
    return findings
