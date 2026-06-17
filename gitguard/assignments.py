"""Language-agnostic assignment extraction.

A single regex-light pass pulls ``name = value`` / ``name: value`` pairs out of
JavaScript, TypeScript, Python, JSON, YAML, TOML, INI and ``.env`` files. The
extracted assignments are analysed independently of the secret regexes so that
hard-coded credentials are caught by *variable name* even when the value
matches no known provider pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import KEY_QUALIFIER_TOKENS, STRONG_NAME_TOKENS

# Optional declaration keywords (JS/TS, and a few others) preceding a name.
_DECL = r"(?:\b(?:const|let|var|export|public|private|protected|static|final|val|def)\s+)*"

# Quoted form: const NAME = "v" | NAME: 'v' | "NAME": "v" | NAME=`v`
_QUOTED_RE = re.compile(
    _DECL
    + r"""['"]?(?P<name>[A-Za-z_$][\w$\-]*)['"]?\s*[:=]\s*"""
    + r"""(?P<q>['"`])(?P<value>[^'"`\n]*)(?P=q)""",
    re.VERBOSE,
)

# Unquoted form (env / ini / yaml / toml): NAME=value | NAME: value
# Value must not start with a quote (quoted form handles those) or a comment.
_UNQUOTED_RE = re.compile(
    r"""^\s*(?:export\s+)?(?P<name>[A-Za-z_][\w\-.]*)\s*[:=]\s*"""
    r"""(?P<value>[^\s#'"`][^\n#]*?)\s*$""",
    re.VERBOSE,
)


@dataclass(frozen=True)
class Assignment:
    """A single extracted ``name = value`` pair on one line."""

    name: str
    value: str
    name_col: int  # 0-based column of the variable name
    value_col: int  # 0-based column where the value text begins
    value_end: int  # 0-based column just past the value text
    quoted: bool


def _split_tokens(name: str) -> list[str]:
    """Split an identifier into lowercase word tokens.

    Handles snake_case, kebab-case, dotted, and camelCase/PascalCase, e.g.
    ``dbPassword`` -> ``["db", "password"]`` and ``API_KEY`` -> ``["api", "key"]``.
    """

    tokens: list[str] = []
    for part in re.split(r"[._\-\s]+", name):
        for tok in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", part):
            tokens.append(tok.lower())
    return tokens


def is_sensitive_name(name: str) -> bool:
    """True when a variable name implies it holds a credential.

    A name is sensitive if any token is a strong secret word (secret, password,
    token, ...), or if it has a ``key`` token qualified by an access-ish word
    (so ``API_KEY`` matches but ``primaryKey`` does not).
    """

    tokens = set(_split_tokens(name))
    if tokens & STRONG_NAME_TOKENS:
        return True
    if "key" in tokens and (tokens & KEY_QUALIFIER_TOKENS):
        return True
    return False


def extract_assignments(line: str) -> list[Assignment]:
    """Return all assignments found on ``line`` (quoted and unquoted)."""

    out: list[Assignment] = []
    seen_spans: list[tuple[int, int]] = []

    for m in _QUOTED_RE.finditer(line):
        span = (m.start("value"), m.end("value"))
        out.append(
            Assignment(
                name=m.group("name"),
                value=m.group("value"),
                name_col=m.start("name"),
                value_col=span[0],
                value_end=span[1],
                quoted=True,
            )
        )
        seen_spans.append((m.start(), m.end()))

    for m in _UNQUOTED_RE.finditer(line):
        # Skip if this region was already captured as a quoted assignment.
        if any(s <= m.start("name") < e for s, e in seen_spans):
            continue
        out.append(
            Assignment(
                name=m.group("name"),
                value=m.group("value"),
                name_col=m.start("name"),
                value_col=m.start("value"),
                value_end=m.end("value"),
                quoted=False,
            )
        )
    return out
