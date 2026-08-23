"""
Maps a normalized vulnerability category to a representative CVSS 3.1
score and vector string.

This is a curated heuristic, not a computed score — static analysis
finds a *pattern*, not a specific, exploitable instance with known
exploitability/impact in your actual deployment. The vectors here
represent a reasonable worst-case for that category of finding, the same
way a SAST tool's own built-in severity rating is a heuristic. Presenting
this as a precisely computed CVSS score for each individual finding would
overstate what static analysis can actually determine — the real CVSS
score for a specific vulnerability depends on deployment context this
tool doesn't have visibility into.
"""
from dataclasses import dataclass


@dataclass
class CvssInfo:
    score: float
    vector: str
    severity: str  # "critical" | "high" | "medium" | "low"


_CVSS_MAP: dict[str, CvssInfo] = {
    "sql_injection": CvssInfo(9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    "command_injection": CvssInfo(9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    "insecure_deserialization": CvssInfo(9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    "hardcoded_credentials": CvssInfo(7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    "ssrf": CvssInfo(7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    "path_traversal": CvssInfo(7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    "xss": CvssInfo(6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "medium"),
    "weak_crypto": CvssInfo(5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "medium"),
    "insecure_random": CvssInfo(5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "medium"),
    "unknown": CvssInfo(4.0, "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", "low"),
}

# Bandit test IDs -> category. Not exhaustive — Bandit has ~70 checks;
# this covers the categories this project's spec explicitly names.
_BANDIT_CATEGORY_MAP = {
    "B105": "hardcoded_credentials", "B106": "hardcoded_credentials", "B107": "hardcoded_credentials",
    "B301": "insecure_deserialization", "B302": "insecure_deserialization", "B506": "insecure_deserialization",
    "B602": "command_injection", "B603": "command_injection", "B604": "command_injection",
    "B605": "command_injection", "B606": "command_injection", "B607": "command_injection",
    "B608": "sql_injection", "B609": "sql_injection",
    "B310": "ssrf", "B410": "ssrf",
    "B303": "weak_crypto", "B304": "weak_crypto", "B305": "weak_crypto",
    "B311": "insecure_random",
}

# Our own Semgrep rule IDs -> category (matches security-rules.yaml exactly)
_SEMGREP_CATEGORY_MAP = {
    "sql-injection-fstring": "sql_injection",
    "sql-injection-js-template": "sql_injection",
    "xss-innerhtml-assignment": "xss",
    "xss-react-dangerously-set": "xss",
    "command-injection-shell-true": "command_injection",
    "command-injection-node-exec": "command_injection",
    "hardcoded-password-assignment": "hardcoded_credentials",
    "insecure-deserialization-pickle": "insecure_deserialization",
    "insecure-deserialization-yaml-load": "insecure_deserialization",
    "ssrf-requests-user-url": "ssrf",
    "path-traversal-open": "path_traversal",
}


def category_for_bandit(test_id: str) -> str:
    return _BANDIT_CATEGORY_MAP.get(test_id, "unknown")


def category_for_semgrep(rule_id: str) -> str:
    # Semgrep prefixes rule IDs with the config path (e.g.
    # "security-rules.sql-injection-fstring") — match on the suffix.
    short_id = rule_id.rsplit(".", 1)[-1]
    return _SEMGREP_CATEGORY_MAP.get(short_id, "unknown")


def cvss_for_category(category: str) -> CvssInfo:
    return _CVSS_MAP.get(category, _CVSS_MAP["unknown"])
