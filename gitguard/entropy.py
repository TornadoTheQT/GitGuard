"""Shannon entropy helpers used for detecting high-randomness secrets."""

from __future__ import annotations

import math
import re

# Characters that typically make up tokens/keys. Used to extract candidate
# substrings from a line for entropy analysis.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits per char) of ``data``.

    An empty string has zero entropy. Random base64-ish strings tend to
    score above ~4.0 while natural English words score well below ~3.5.
    """

    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def iter_candidates(line: str) -> list[tuple[str, int]]:
    """Yield ``(token, column)`` candidate substrings worth entropy testing."""

    return [(m.group(0), m.start()) for m in _TOKEN_RE.finditer(line)]


def looks_like_uuid(token: str) -> bool:
    return bool(_UUID_RE.match(token))


def looks_like_hash(token: str) -> bool:
    # Common hash digest lengths (md5/sha1/sha256/sha512).
    return bool(_HEX_RE.match(token)) and len(token) in (32, 40, 56, 64, 128)


def _char_classes(token: str) -> int:
    classes = 0
    if any(c.islower() for c in token):
        classes += 1
    if any(c.isupper() for c in token):
        classes += 1
    if any(c.isdigit() for c in token):
        classes += 1
    if any(not c.isalnum() for c in token):
        classes += 1
    return classes


def is_high_entropy(
    token: str,
    *,
    min_length: int = 20,
    threshold: float = 4.0,
    strict: bool = False,
) -> bool:
    """Heuristic: is ``token`` likely a random secret rather than prose?

    We require a minimum length, a minimum entropy, and at least two character
    classes (mix of cases/digits). In ``strict`` mode the thresholds drop so
    more candidates are flagged.
    """

    if strict:
        min_length = max(16, min_length - 4)
        threshold -= 0.4

    if len(token) < min_length:
        return False
    if _char_classes(token) < 2:
        return False
    return shannon_entropy(token) >= threshold
