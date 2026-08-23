"""
Threat modeling service.

The AI-generation path reuses Phase 4's chat provider and input guardrail
directly — same infrastructure, same "nothing AI-generated is final
without human review" governance pattern already established for the
assistant. What's new here is defensive parsing: the model is asked to
return structured JSON, and local models in particular don't always
comply cleanly (markdown code fences, a preamble sentence before the
JSON, an occasional malformed field). Rather than let a parse failure
silently produce zero threats, a failed parse still creates one
human-reviewable entry containing the raw model output — nothing the
model produced is ever silently discarded, even when it can't be
automatically structured.
"""
import json
import re
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_model import ThreatEntry, ThreatModel
from app.schemas.threat_model import STRIDE_CATEGORIES
from app.services import chat, guardrails
from app.services.chat.base import ChatMessage

_SYSTEM_PROMPT = (
    "You are a security engineer performing STRIDE threat modeling. Given a "
    "system or feature description, identify realistic threats across the six "
    "STRIDE categories: spoofing, tampering, repudiation, info_disclosure, dos, "
    "elevation. Not every category needs an entry — only include genuinely "
    "applicable threats, and include more than one entry for a category if "
    "warranted. For each threat, propose a concrete mitigation.\n\n"
    "Respond with ONLY a JSON array, no other text before or after it. Each "
    "element must have exactly these keys: stride_category (one of: spoofing, "
    "tampering, repudiation, info_disclosure, dos, elevation), "
    "threat_description (string), affected_asset (string), mitigation (string)."
)


class ThreatGenerationError(Exception):
    pass


def _extract_json_array(raw: str) -> str:
    """Strip markdown code fences and any preamble/postamble text around a JSON array."""
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.DOTALL)
    if fenced:
        return fenced.group(1)
    bracket_start = raw.find("[")
    bracket_end = raw.rfind("]")
    if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
        return raw[bracket_start : bracket_end + 1]
    return raw


def _parse_threats(raw_response: str) -> list[dict]:
    candidate = _extract_json_array(raw_response)
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        # Nothing the model produced gets silently dropped — surface it as a
        # single entry a human can read, categorize, and fix manually.
        return [{
            "stride_category": "info_disclosure",
            "threat_description": (
                "AI generation produced a response that couldn't be parsed as "
                "structured output. Raw model response follows for manual review: "
                + raw_response[:1500]
            ),
            "affected_asset": "unknown — review raw output",
            "mitigation": "Review manually and either re-run generation or add threats by hand.",
        }]

    if not isinstance(parsed, list):
        parsed = [parsed]

    cleaned = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        category = str(item.get("stride_category", "")).strip().lower()
        if category not in STRIDE_CATEGORIES:
            category = "info_disclosure"  # safe default rather than dropping the entry
        cleaned.append({
            "stride_category": category,
            "threat_description": str(item.get("threat_description", "")).strip()[:2000] or "(not provided)",
            "affected_asset": str(item.get("affected_asset", "")).strip()[:256] or "(not provided)",
            "mitigation": str(item.get("mitigation", "")).strip()[:2000] or "(not provided)",
        })
    return cleaned or _parse_threats("")  # empty list is itself a parse failure worth surfacing


async def generate_threats(system_description: str) -> list[dict]:
    input_flags = guardrails.check_input(system_description)
    if input_flags:
        raise ThreatGenerationError(
            "System description matched an instruction-override pattern and was not sent to the model."
        )

    messages = [
        ChatMessage("system", _SYSTEM_PROMPT),
        ChatMessage("user", system_description),
    ]
    try:
        raw_response = await chat.generate(messages, max_tokens=1200)
    except chat.ChatError as exc:
        raise ThreatGenerationError(str(exc)) from exc

    return _parse_threats(raw_response)


async def create_threat_model(
    db: AsyncSession, user_id: uuid.UUID, title: str, system_description: str, generate_with_ai: bool
) -> ThreatModel:
    model = ThreatModel(title=title, system_description=system_description, created_by=user_id)
    db.add(model)
    await db.flush()

    if generate_with_ai:
        threats = await generate_threats(system_description)
        for t in threats:
            db.add(ThreatEntry(threat_model_id=model.id, ai_generated=True, **t))
        await db.flush()

    return model
