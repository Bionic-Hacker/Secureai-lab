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
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
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


def redact_output(text: str) -> tuple[str, list[str]]:
    """Returns (redacted_text, flags). Redacted secrets are replaced with a labeled placeholder."""
    flags: list[str] = []
    redacted = text
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            flags.append(f"redacted_{label}")
            redacted = pattern.sub(f"[REDACTED:{label.upper()}]", redacted)
    return redacted, flags
