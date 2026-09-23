"""
Regression tests for output-guardrail secret redaction.

Found during live testing of the retrieval-only fallback: current-format
OpenAI project keys (sk-proj-..., containing hyphens and underscores) passed
through redact_output untouched, because the pattern only allowed
alphanumerics after "sk-". The same review found master-build-plan.md
claimed entropy-based detection that didn't exist yet; it does now.

Entropy samples below are fixed strings, not generated per run, so the
suite can't flake on an unlucky random draw.
"""

import pytest

from app.services import guardrails

# --- named patterns ----------------------------------------------------------

_PROJ_BODY = "pHuOz0Go6kL6Or8Q0HQNrNNd3z3-J7htPkd0vu4NWDjWBfJHJMChOoLOEnIi_JC1"


@pytest.mark.parametrize(
    "secret, expected_flag",
    [
        ("sk-" + "aB3xQ9" * 8, "redacted_openai_key"),
        ("sk-proj-" + _PROJ_BODY, "redacted_openai_key"),
        ("sk-svcacct-" + _PROJ_BODY, "redacted_openai_key"),
        ("sk-ant-api03-" + _PROJ_BODY, "redacted_anthropic_key"),
    ],
)
def test_named_api_keys_are_redacted(secret, expected_flag):
    redacted, flags = guardrails.redact_output(f"API_KEY = {secret}")
    assert secret not in redacted
    assert expected_flag in flags


# --- entropy fallback: must redact -------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "XOKllQx8IqHyS1OhcOwOT4ZWLaaaMLboMcqNntsk",  # unprefixed 40-char token
        _PROJ_BODY,  # 64-char key body with - and _
        "/H/wuaslLCAqId4fKFkrMHYLRrLW6fS8TM6XlkVh",  # base64-encoded secret
    ],
)
def test_unprefixed_high_entropy_tokens_are_redacted(secret):
    redacted, flags = guardrails.redact_output(f"token: {secret}")
    assert secret not in redacted
    assert "[REDACTED:HIGH_ENTROPY_STRING]" in redacted
    assert "redacted_high_entropy_string" in flags


# --- entropy fallback: must NOT redact ---------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",  # SHA-256 digest
        "3719b34e7c2a9f1d0b8e6a5c4d3f2e1a0b9c8d7e",  # git SHA
        "019ffe4d-27e9-709a-802d-99f1a8b690f4",  # UUID
        "ThisIsAVeryLongIdentifierNameForTesting2026",  # camelCase identifier
        "/mnt/user-data/uploads/Screenshot_from_2026-09-23_11-21-19",  # file path
        "prometheus-fastapi-instrumentator-7-0-0-Starlette",  # package/version string
        "test_hyphenated_prose_is_not_mistaken_for_a_key",  # snake_case name
        "Next up is the task-list-management-feature-for-the-dashboard work.",  # prose
        "The retrieval layer filters chunks by document permission before any context reaches the model.",
    ],
)
def test_ordinary_text_is_left_alone(text):
    redacted, flags = guardrails.redact_output(text)
    assert redacted == text
    assert flags == []


def test_named_pattern_keeps_its_specific_label():
    # A key the regex already caught must not be double-counted by the entropy pass.
    _, flags = guardrails.redact_output("sk-proj-" + _PROJ_BODY)
    assert flags == ["redacted_openai_key"]
