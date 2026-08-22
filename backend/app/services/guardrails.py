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


def check_input(text: str) -> list[str]:
    """Returns a list of flag names for any injection patterns matched. Empty list = clean."""
    flags = []
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            flags.append("prompt_injection_suspected")
            break  # one flag is enough signal; no need to enumerate every matching pattern
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
