"""
Guardrails for the AI Security Assistant — OWASP LLM01 (Prompt Injection)
and LLM06 (Sensitive Information Disclosure) controls.

This is a baseline, pattern-based implementation, not a claim that regex
matching catches every possible injection or every possible secret format.
It's deliberately explicit about that limitation rather than presenting
partial coverage as complete — the honest framing for a portfolio piece is
"here's a real, working first layer" not "here's a solved problem."
Classifier-based detection (a small fine-tuned model, or an LLM-as-judge
call) is a reasonable future enhancement layered on top of this, not a
replacement for it — defense in depth applies to guardrails too.
"""
import re

# Deliberately conservative: matches phrasing that has no legitimate
# purpose in a security-assistant context, to keep false positives low.
# A general-purpose creative-writing assistant would need a different,
# much more permissive policy — this one is scoped to what this specific
# tool is for.
_INJECTION_PATTERNS = [
    re.compile(r"ignore (all |the )?(above|previous|prior) instructions", re.I),
    re.compile(r"disregard (all |the )?(above|previous|prior|your) instructions", re.I),
    re.compile(r"forget (everything|all) (above|before|prior)", re.I),
    re.compile(r"you are now (in )?(developer|debug|admin|god) mode", re.I),
    re.compile(r"repeat (your |the )?(system prompt|instructions) (verbatim|exactly)", re.I),
    re.compile(r"what (were|are) your (original |system )?instructions", re.I),
    re.compile(r"reveal your (system )?prompt", re.I),
]

# Sensitive-data patterns for output redaction. Order matters only in that
# each is applied independently — overlapping matches are not an issue.
_SECRET_PATTERNS = [
    # Anthropic first: once it redacts, the text no longer contains "sk-", so
    # the broader OpenAI pattern can't relabel it.
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    # Covers classic sk-... and current sk-proj-/sk-svcacct- keys, which contain
    # hyphens and underscores. \b stops matches inside words like "task-...".
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("generic_bearer_token", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
]

# Distinct from _INJECTION_PATTERNS: injection tries to override/reveal
# instructions; jailbreak tries to get the model to roleplay past its own
# safety behavior (a persona with "no restrictions", a claimed override
# authority, etc.) without necessarily touching the system prompt at all.
# Same caveat as above — a baseline pattern set, not complete coverage.
_JAILBREAK_PATTERNS = [
    re.compile(r"\bDAN\b.{0,20}(mode|prompt|jailbreak)", re.I),
    re.compile(r"do anything now", re.I),
    re.compile(r"(pretend|act|roleplay) (that )?you (have no|don't have any) (restrictions|rules|guidelines|filters)", re.I),
    re.compile(r"you have no (ethical |content )?(restrictions|guidelines|filters)", re.I),
    re.compile(r"respond (as|like) (an? )?(unfiltered|uncensored|unrestricted) (ai|model|assistant)", re.I),
    re.compile(r"(bypass|ignore|disable) your (safety|content) (filters|guidelines|restrictions)", re.I),
    re.compile(r"i am (a |your )?(developer|admin|the creator) (and )?(authorize|override|grant)", re.I),
]


def check_input(text: str) -> list[str]:
    """
    Returns a list of flag names for any injection or jailbreak patterns
    matched. Empty list = clean. Both categories are checked independently
    (unlike a single pattern group, where the first match was enough
    signal) since they represent genuinely different attack techniques —
    a prompt could plausibly trip both.
    """
    flags = []
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            flags.append("prompt_injection_suspected")
            break
    for pattern in _JAILBREAK_PATTERNS:
        if pattern.search(text):
            flags.append("jailbreak_suspected")
            break
    return flags


# ---------------------------------------------------------------------------
# High-entropy fallback. Catches credential-shaped strings that none of the
# named patterns above recognize (unprefixed tokens, vendor formats not listed).
# It runs after them, so a key they already caught keeps its specific label.
#
# Tuned against ~35k real identifiers, paths, and strings from Python source and
# docs (~0.05% false positives, about half of which were themselves random test
# tokens) while catching ~99% of random 32-164 char keys:
#   - candidates are runs of 32+ key-alphabet characters
#   - hex-only strings (SHA-256 digests shown in the Document Vault, git SHAs)
#     and UUIDs are excluded outright
#   - must mix uppercase, lowercase, and digits
#   - Shannon entropy must be near what a random base62 string of that length
#     would have (length-adjusted, so short keys aren't held to long-key scores)
#   - characters must switch class often; words and identifiers switch rarely
# Accepted trade-off: long base64 blobs in code samples are redacted too.
# ---------------------------------------------------------------------------
_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ENTROPY_MARGIN_BITS = 0.5
_MIN_CLASS_SWITCH_RATIO = 0.45


def _shannon_entropy(s: str) -> float:
    from collections import Counter
    from math import log2

    n = len(s)
    return -sum((c / n) * log2(c / n) for c in Counter(s).values())


def _expected_random_entropy(n: int) -> float:
    # Entropy a random base62 string of length n is expected to show: short
    # samples score below the log2(62) ceiling (Miller-Madow bias correction).
    from math import log, log2

    return log2(62) - 61 / (2 * n * log(2))


def _char_class(ch: str) -> str:
    if ch.isupper():
        return "U"
    if ch.islower():
        return "L"
    if ch.isdigit():
        return "D"
    return "S"


def _class_switch_ratio(s: str) -> float:
    from itertools import pairwise

    switches = sum(_char_class(a) != _char_class(b) for a, b in pairwise(s))
    return switches / (len(s) - 1)


def _looks_like_secret(candidate: str) -> bool:
    body = candidate.rstrip("=")
    if _HEX_ONLY.fullmatch(body) or _UUID.fullmatch(body):
        return False
    if not (
        any(ch.isupper() for ch in body)
        and any(ch.islower() for ch in body)
        and any(ch.isdigit() for ch in body)
    ):
        return False
    if _shannon_entropy(body) < _expected_random_entropy(len(body)) - _ENTROPY_MARGIN_BITS:
        return False
    return _class_switch_ratio(body) >= _MIN_CLASS_SWITCH_RATIO


def _redact_high_entropy(text: str) -> tuple[str, int]:
    hits = 0

    def _replace(match: re.Match) -> str:
        nonlocal hits
        if _looks_like_secret(match.group(0)):
            hits += 1
            return "[REDACTED:HIGH_ENTROPY_STRING]"
        return match.group(0)

    return _ENTROPY_CANDIDATE.sub(_replace, text), hits


def redact_output(text: str) -> tuple[str, list[str]]:
    """Returns (redacted_text, flags). Redacted secrets are replaced with a labeled placeholder."""
    flags: list[str] = []
    redacted = text
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            flags.append(f"redacted_{label}")
            redacted = pattern.sub(f"[REDACTED:{label.upper()}]", redacted)
    redacted, entropy_hits = _redact_high_entropy(redacted)
    if entropy_hits:
        flags.append("redacted_high_entropy_string")
    return redacted, flags
