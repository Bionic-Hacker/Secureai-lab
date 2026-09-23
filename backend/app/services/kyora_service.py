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

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


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

    # Tool results come back as text content; Kyora IQ's tools return
    # JSON-encoded text specifically (per their own quickstart example).
    raw = result.content[0].text if result.content else ""
    return _interpret_result(bool(result.isError), raw)


def _interpret_result(is_error: bool, raw: str) -> dict:
    """
    Kyora IQ fails in two shapes, and both used to reach callers as if they
    were data (found by probing the live server before wiring these tools
    to endpoints):
      - protocol-level tool errors (isError=True), e.g. argument validation
      - application-level refusals: {"ok": false, "error": "..."}, e.g. an
        unknown control ID or an empty search query
    """
    if is_error:
        raise KyoraServiceError(f"Kyora IQ tool error: {raw[:300]}")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # Not JSON - return as-is under a single key rather than
        # silently dropping content the caller might still want.
        return {"raw": raw}
    if isinstance(data, dict) and data.get("ok") is False:
        message = str(data.get("error") or "Kyora IQ rejected the request.")
        # "no control 'x' in <framework>" / "no risk ..." -> not found
        status_code = 404 if message.lower().startswith("no ") else 400
        raise KyoraServiceError(message, status_code=status_code)
    return data


async def list_frameworks() -> dict:
    return await _call_tool("list_frameworks", {})


async def search_controls(query: str, framework: str = "", layer: str = "", limit: int = 10) -> dict:
    args: dict = {"query": query, "limit": limit}
    if framework:
        args["framework"] = framework
    if layer:
        args["layer"] = layer
    return await _call_tool("search_controls", args)


# The server's schema names this argument "framework", not "framework_id" -
# the original client sent framework_id, so every call failed validation.
async def get_control(framework: str, control_id: str) -> dict:
    return await _call_tool("get_control", {"framework": framework, "control_id": control_id})


async def get_mappings(framework: str, control_id: str) -> dict:
    return await _call_tool("get_mappings", {"framework": framework, "control_id": control_id})


async def list_risks(layer: str | None = None) -> dict:
    args = {"layer": layer} if layer else {}
    return await _call_tool("list_risks", args)


async def get_risk(risk_id: str) -> dict:
    return await _call_tool("get_risk", {"risk_id": risk_id})


async def analyze_gap(have_framework: str, want_framework: str) -> dict:
    return await _call_tool(
        "analyze_gap", {"have_framework": have_framework, "want_framework": want_framework}
    )
