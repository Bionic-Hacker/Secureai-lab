"""
Kyora IQ client tests. Both bugs below were found by probing the live MCP
server before wiring more of its tools to endpoints:
  - get_control/get_mappings sent "framework_id"; the server's schema
    requires "framework", so every call failed validation.
  - failures (protocol errors and {"ok": false} refusals) were returned to
    callers as if they were data instead of raising.
No network: _call_tool is replaced with a recorder.
"""

import asyncio

import pytest

from app.services import kyora_service


class TestInterpretResult:
    def test_json_payload_is_returned(self):
        assert kyora_service._interpret_result(False, '{"ok": true, "n": 1}') == {"ok": True, "n": 1}

    def test_payload_without_ok_key_is_returned(self):
        assert kyora_service._interpret_result(False, '{"frameworks": []}') == {"frameworks": []}

    def test_empty_result_is_empty_dict(self):
        assert kyora_service._interpret_result(False, "") == {}

    def test_non_json_text_is_preserved(self):
        assert kyora_service._interpret_result(False, "plain text") == {"raw": "plain text"}

    def test_protocol_error_raises_502(self):
        with pytest.raises(kyora_service.KyoraServiceError) as exc:
            kyora_service._interpret_result(True, "Error executing tool get_control: validation error")
        assert exc.value.status_code == 502

    def test_unknown_id_refusal_raises_404(self):
        with pytest.raises(kyora_service.KyoraServiceError) as exc:
            kyora_service._interpret_result(
                False, '{"ok": false, "error": "no control \'x\' in hipaa-security-rule"}'
            )
        assert exc.value.status_code == 404

    def test_other_refusal_raises_400(self):
        with pytest.raises(kyora_service.KyoraServiceError) as exc:
            kyora_service._interpret_result(False, '{"ok": false, "error": "query must not be empty"}')
        assert exc.value.status_code == 400
        assert "query must not be empty" in exc.value.message


@pytest.fixture
def recorded(monkeypatch):
    calls = []

    async def fake_call_tool(name, args):
        calls.append((name, args))
        return {"ok": True}

    monkeypatch.setattr(kyora_service, "_call_tool", fake_call_tool)
    return calls


class TestToolArguments:
    def test_get_control_sends_framework_not_framework_id(self, recorded):
        asyncio.run(kyora_service.get_control("hipaa-security-rule", "312-a-1"))
        assert recorded == [("get_control", {"framework": "hipaa-security-rule", "control_id": "312-a-1"})]

    def test_get_mappings_sends_framework_not_framework_id(self, recorded):
        asyncio.run(kyora_service.get_mappings("nist-800-53-r5", "ac-17"))
        assert recorded == [("get_mappings", {"framework": "nist-800-53-r5", "control_id": "ac-17"})]

    def test_search_sends_filters_only_when_set(self, recorded):
        asyncio.run(kyora_service.search_controls("encryption"))
        asyncio.run(kyora_service.search_controls("logging", framework="eu-ai-act", layer="governance", limit=5))
        assert recorded == [
            ("search_controls", {"query": "encryption", "limit": 10}),
            (
                "search_controls",
                {"query": "logging", "limit": 5, "framework": "eu-ai-act", "layer": "governance"},
            ),
        ]
