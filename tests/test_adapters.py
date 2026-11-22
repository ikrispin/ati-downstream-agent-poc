import json
import os
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from ati_downstream import cli, model, sources
from ati_downstream.config import Settings
from ati_downstream.models import InvestigationRequest
from ati_downstream.oauth import AuthenticationRequired, OAuthStorage, support_auth


def test_config_and_independent_composition(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "ATI_A2A_TOKEN": "service-secret",
        "ATI_LLM_API_KEY": "model-secret",
        "ATI_LLM_MODEL": "test-model",
        "ATI_LLM_BASE_URL": "https://model.test/v1",
        "ATI_STATE_DIR": str(tmp_path / "state"),
    }.items():
        monkeypatch.setenv(name, value)
    settings = Settings.load()
    assert settings.model_name == "test-model"
    assert "model-secret" not in repr(settings)
    assert "service-secret" not in repr(settings)
    assert settings.investigator().max_rounds == 7
    settings.model_key = ""
    with pytest.raises(ValueError, match="Configure"):
        settings.investigator()


async def test_model_adapter_sends_tools_and_preserves_ids(monkeypatch):
    actual_client = httpx.AsyncClient

    def server(request):
        body = json.loads(request.content)
        assert body["messages"][0]["content"] == "Investigate"
        assert body["tools"][0]["function"]["name"] == "get_redhat_cve"
        assert request.headers["authorization"] == "Bearer private-key"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "function": {
                                        "name": "get_redhat_cve",
                                        "arguments": '{"cve_id":"CVE-2023-38545"}',
                                    },
                                }
                            ],
                            "reasoning_content": "not returned",
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kw: actual_client(**kw, transport=httpx.MockTransport(server)),
    )
    reply = await model.ChatModel("https://model.test/v1", "GLM", "private-key").complete(
        [{"role": "user", "content": "Investigate"}], sources.SourceTools.schemas
    )
    assert reply["tool_calls"][0]["id"] == "call-1"
    assert "reasoning_content" not in reply


async def test_oauth_state_is_private_and_separate_from_mas(tmp_path):
    storage = OAuthStorage(tmp_path / "oauth")
    assert await storage.get_tokens() is None
    await storage.set_tokens(
        OAuthToken(access_token="private-access", token_type="Bearer", expires_in=3600)
    )
    await storage.set_client_info(
        OAuthClientInformationFull(
            client_id="test-client", redirect_uris=["http://localhost:8121/callback"]
        )
    )
    assert (await storage.get_tokens()).access_token == "private-access"
    assert (await storage.get_client_info()).client_id == "test-client"
    assert os.stat(tmp_path / "oauth/tokens.json").st_mode & 0o777 == 0o600
    auth = support_auth("https://support.test/mcp", tmp_path / "oauth")
    with pytest.raises(AuthenticationRequired):
        await auth.context.redirect_handler("https://auth.test")


@pytest.mark.parametrize("mode", ["structured", "text-json", "text", "error", "missing", "schema"])
async def test_mcp_adapter_schema_and_response_handling(tmp_path, monkeypatch, mode):
    seen = []

    @asynccontextmanager
    async def streams(*args, **kwargs):
        yield ("read", "write", None)

    class Session:
        def __init__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def initialize(self):
            pass

        async def list_tools(self):
            return SimpleNamespace(
                tools=[]
                if mode == "missing"
                else [
                    SimpleNamespace(
                        name="vulnerability__get_cve",
                        inputSchema={
                            "properties": {} if mode == "schema" else {"cve": {"type": "string"}}
                        },
                    )
                ]
            )

        async def call_tool(self, name, arguments):
            seen.append(arguments)
            return SimpleNamespace(
                isError=mode == "error",
                structuredContent={"affected_systems": 0} if mode == "structured" else None,
                content=[
                    SimpleNamespace(
                        type="text",
                        text='{"affected_systems":0}' if mode == "text-json" else "some evidence",
                    )
                ],
            )

    monkeypatch.setattr(sources, "streamablehttp_client", streams)
    monkeypatch.setattr(sources, "ClientSession", Session)
    tools = sources.SourceTools("http://lightspeed.test", "", tmp_path)
    if mode in {"error", "missing", "schema"}:
        with pytest.raises((ValueError, RuntimeError)):
            await tools._mcp_call(
                "http://lightspeed.test", "vulnerability__get_cve", {"cve_id": "CVE-2023-38545"}
            )
    else:
        data = await tools.call(
            "vulnerability__get_cve",
            {"cve_id": "CVE-2023-38545"},
            InvestigationRequest.parse("CVE-2023-38545"),
        )
        assert seen == [{"cve": "CVE-2023-38545"}]
        assert data["data"] == (["some evidence"] if mode == "text" else {"affected_systems": 0})


async def test_missing_mcp_url_fails_before_connecting(tmp_path):
    tools = sources.SourceTools("", "", tmp_path)
    with pytest.raises(ValueError, match="not configured"):
        await tools._mcp_call("", "vulnerability__get_cve", {})


async def test_grouped_support_auth_failure_has_a_safe_action(tmp_path, monkeypatch):
    tools = sources.SourceTools("", "https://support.test/mcp", tmp_path)

    async def fail(*args, **kwargs):
        raise ExceptionGroup("private backend details", [AuthenticationRequired("private-token")])

    monkeypatch.setattr(tools, "_mcp_call", fail)
    with pytest.raises(AuthenticationRequired, match="support-login") as error:
        await tools.call(
            "GetCaseDetailsByCaseId",
            {"caseId": "00012345"},
            InvestigationRequest.parse("CVE-2023-38545 Support Case 00012345"),
        )
    assert "private" not in str(error.value)


async def test_cli_uses_authenticated_a2a_v1(monkeypatch):
    actual_client = httpx.AsyncClient

    def server(request):
        assert request.headers["A2A-Version"] == "1.0"
        assert request.headers["Authorization"] == "Bearer test"
        assert json.loads(request.content)["method"] == "SendMessage"
        return httpx.Response(200, json={"result": {"task": {"id": "returned-task"}}})

    monkeypatch.setattr(
        cli.httpx,
        "AsyncClient",
        lambda **kw: actual_client(**kw, transport=httpx.MockTransport(server)),
    )
    assert (await cli.invoke(Settings(token="test", model_key=""), "CVE-2023-38545"))["result"][
        "task"
    ]["id"] == "returned-task"
