"""
Client for Kyora IQ's compliance MCP server — an external, read-only
reference for security/privacy/AI compliance frameworks (NIST 800-53,
HIPAA, SOC 2, ISO 42001, EU AI Act, OWASP, MITRE, and others).

This app is an MCP *client* here, not a server: SecureAI Lab's own
framework-coverage data (app/data/framework_coverage.json) is a
curated, hand-verified claim about what THIS project actually
implements. Kyora IQ's server is a separate, general-purpose
reference — used to enrich or cross-check that data, never to
replace the "verified reality, not aspiration" discipline the
project's own coverage grid is built on (see Chapter 33).

Connection details (transport, auth) match Kyora IQ's own published
quickstart exactly: streamable HTTP to /mcp, bearer token on every
request. The token is never hardcoded — it's supplied by the
instructor and set as KYORA_MCP_TOKEN, an env var only.
"""
import json
import logging

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from app.core.config import get_settings

logger = logging.getLogger("secureai.kyora")
settings = get_settings()


class KyoraServiceError(Exception):
    """Raised when the Kyora IQ MCP server is unreachable or returns an error."""


async def _call_tool(tool_name: str, arguments: dict) -> dict:
    if not settings.kyora_mcp_token:
        raise KyoraServiceError("KYORA_MCP_TOKEN is not configured.")

    headers = {"Authorization": f"Bearer {settings.kyora_mcp_token}"}
    try:
        async with streamablehttp_client(settings.kyora_mcp_url, headers=headers) as (
            read, write, _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
    except Exception as exc:
        raise KyoraServiceError(f"Kyora IQ request failed: {exc}") from exc

    if not result.content:
        return {}

    # Tool results come back as text content; Kyora IQ's tools return
    # JSON-encoded text specifically (per their own quickstart example).
    raw = result.content[0].text
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # Not JSON - return as-is under a single key rather than
        # silently dropping content the caller might still want.
        return {"raw": raw}


async def list_frameworks() -> dict:
    return await _call_tool("list_frameworks", {})


async def search_controls(query: str) -> dict:
    return await _call_tool("search_controls", {"query": query})


async def get_control(framework_id: str, control_id: str) -> dict:
    return await _call_tool(
        "get_control", {"framework_id": framework_id, "control_id": control_id}
    )


async def get_mappings(framework_id: str, control_id: str) -> dict:
    return await _call_tool(
        "get_mappings", {"framework_id": framework_id, "control_id": control_id}
    )


async def list_risks(layer: str | None = None) -> dict:
    args = {"layer": layer} if layer else {}
    return await _call_tool("list_risks", args)


async def get_risk(risk_id: str) -> dict:
    return await _call_tool("get_risk", {"risk_id": risk_id})


async def analyze_gap(have_framework: str, want_framework: str) -> dict:
    return await _call_tool(
        "analyze_gap", {"have_framework": have_framework, "want_framework": want_framework}
    )
