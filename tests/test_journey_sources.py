import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from mcp.types import CallToolResult, TextContent, Tool

from ati_lscore import sources
from ati_lscore.models import InvestigationRequest, SourceFailure, ToolArgumentsError
from ati_lscore.sources import SourceTools


def request(journey=True):
    return InvestigationRequest(
        "CVE-2023-38545", "CVE-2023-38545", None, "r", journey, "demo" if journey else None
    )


@pytest.mark.parametrize("method", ["inspect_fleet", "search_support", "threat_intel"])
async def test_new_collectors_require_explicit_journey_scope(tmp_path, method):
    tools = SourceTools("", "", tmp_path, environment="demo")
    with pytest.raises(ToolArgumentsError):
        await getattr(tools, method)(request(False))


async def test_threat_collector_uses_only_request_cve(tmp_path, monkeypatch):
    from ati_lscore import threat_intel

    seen = []

    def fetch(cve_id):
        seen.append(cve_id)
        return {"cve_id": cve_id}

    monkeypatch.setattr(threat_intel, "fetch_threat_intel", fetch)
    assert await SourceTools("", "", tmp_path, environment="demo").threat_intel(request()) == {
        "cve_id": "CVE-2023-38545"
    }
    assert seen == ["CVE-2023-38545"]


async def test_fleet_collector_reports_missing_configuration_safely(tmp_path):
    with pytest.raises(SourceFailure, match="source_not_configured"):
        await SourceTools("", "", tmp_path, environment="demo").inspect_fleet(request())


async def test_environment_alias_must_match_the_configured_connection(tmp_path):
    with pytest.raises(ToolArgumentsError):
        await SourceTools("", "", tmp_path, environment="other").inspect_fleet(request())


def fake_mcp(monkeypatch, pages, response=None, *, error=None):
    """Use real MCP catalog/result models without opening a transport."""
    seen = {"catalog_cursors": [], "calls": [], "closed": False, "auth_calls": []}
    authentication = object()

    def auth(url, path):
        seen["auth_calls"].append((url, path))
        return authentication

    @asynccontextmanager
    async def streams(url, **kwargs):
        seen["transport"] = {"url": url, **kwargs}
        yield "read", "write", None

    class Session:
        def __init__(self, read, write):
            assert (read, write) == ("read", "write")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            seen["closed"] = True

        async def initialize(self):
            seen["initialized"] = True

        async def list_tools(self, *, cursor=None):
            seen["catalog_cursors"].append(cursor)
            if error is not None:
                raise error
            index = len(seen["catalog_cursors"]) - 1
            definitions, next_cursor = pages[min(index, len(pages) - 1)]
            return SimpleNamespace(
                tools=[Tool(**tool) for tool in definitions], nextCursor=next_cursor
            )

        async def call_tool(self, name, arguments):
            seen["calls"].append((name, arguments))
            return response(name, arguments) if callable(response) else response

    monkeypatch.setattr(sources, "streamablehttp_client", streams)
    monkeypatch.setattr(sources, "ClientSession", Session)
    monkeypatch.setattr(sources, "support_auth", auth)
    seen["authentication"] = authentication
    return seen


def definition(name, properties, required=()):
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        },
    }


@pytest.mark.parametrize("encoding", ["structured", "json"])
async def test_collect_paginates_catalog_and_decodes_real_mcp_results(
    tmp_path, monkeypatch, encoding
):
    catalog = [definition("read_synthetic", {"id": {"type": "string"}}, ("id",))]
    value = {"result": {"value": 0}}
    result = (
        CallToolResult(content=[], structuredContent=value)
        if encoding == "structured"
        else CallToolResult(content=[TextContent(type="text", text=json.dumps(value))])
    )
    seen = fake_mcp(monkeypatch, [([], "next-page"), (catalog, None)], result)

    async def operation(actual_catalog, call):
        assert actual_catalog[0]["name"] == "read_synthetic"
        assert actual_catalog[0]["inputSchema"] == catalog[0]["inputSchema"]
        return await call("read_synthetic", {"id": "example"})

    tools = SourceTools("https://fleet.invalid/mcp", "", tmp_path, environment="demo")
    assert await tools._mcp_collect(tools.lightspeed_url, operation) == value
    assert seen["catalog_cursors"] == [None, "next-page"]
    assert seen["calls"] == [("read_synthetic", {"id": "example"})]
    assert seen["closed"] and seen["initialized"]
    assert seen["auth_calls"] == [] and seen["transport"]["auth"] is None
    assert seen["transport"]["timeout"] == 25 and seen["transport"]["sse_read_timeout"] == 30


async def test_collect_catalog_pagination_has_a_hard_limit(tmp_path, monkeypatch):
    seen = fake_mcp(monkeypatch, [([], "still-more")])

    async def never_run(*args):
        pytest.fail("An incomplete catalog must not authorize any operation")

    with pytest.raises(SourceFailure, match="source_catalog_limit"):
        await SourceTools("", "", tmp_path)._mcp_collect("https://fleet.invalid", never_run)
    assert len(seen["catalog_cursors"]) == 3 and not seen["calls"] and seen["closed"]


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (CallToolResult(content=[], isError=True), "mcp_tool_error"),
        (CallToolResult(content=[]), "source_invalid_response"),
        (
            CallToolResult(content=[TextContent(type="text", text="private raw response")]),
            "source_invalid_response",
        ),
        (
            CallToolResult(
                content=[TextContent(type="text", text="{}"), TextContent(type="text", text="{}")]
            ),
            "source_invalid_response",
        ),
    ],
)
async def test_collect_rejects_tool_errors_and_unverified_content(
    tmp_path, monkeypatch, result, code
):
    fake_mcp(monkeypatch, [([], None)], result)

    async def operation(catalog, call):
        return await call("read_synthetic", {})

    with pytest.raises(SourceFailure) as failure:
        await SourceTools("", "", tmp_path)._mcp_collect("https://fleet.invalid", operation)
    assert failure.value.code == code and "private" not in str(failure.value)


@pytest.mark.parametrize(
    ("error", "code", "retryable"),
    [
        (httpx.ReadTimeout("private token"), "source_timeout", True),
        (httpx.ConnectError("private token"), "source_unavailable", True),
        (
            ExceptionGroup("private token", [httpx.ReadTimeout("private token")]),
            "source_timeout",
            True,
        ),
        *[
            (
                httpx.HTTPStatusError(
                    "private token",
                    request=httpx.Request("GET", "https://secret.invalid"),
                    response=httpx.Response(status),
                ),
                code,
                retryable,
            )
            for status, code, retryable in [
                (401, "source_authentication", False),
                (429, "source_rate_limited", True),
                (503, "source_unavailable", True),
            ]
        ],
    ],
)
async def test_collect_normalizes_transport_failures_without_private_details(
    tmp_path, monkeypatch, error, code, retryable
):
    seen = fake_mcp(monkeypatch, [([], None)], error=error)

    async def never_run(*args):
        pytest.fail("A failed catalog cannot reach an operation")

    with pytest.raises(SourceFailure) as failure:
        await SourceTools("", "", tmp_path)._mcp_collect("https://fleet.invalid", never_run)
    assert failure.value.code == code and failure.value.retryable is retryable
    assert "private" not in str(failure.value) and "secret" not in str(failure.value)
    assert seen["closed"] and not seen["calls"]


async def test_inspect_fleet_uses_real_catalog_contract_and_enriches_only_matching_hosts(
    tmp_path, monkeypatch
):
    host = str(UUID(int=1))
    catalog = [
        definition(
            "vulnerability__get_cve_systems",
            {
                "cve": {"type": "string"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
            ("cve",),
        ),
        definition("inventory__get_host_details", {"host_ids": {"type": "string"}}, ("host_ids",)),
        definition("inventory__get_host_system_profile", {"host_ids": {"type": "string"}}),
        definition("remediations__create_vuln_playbook", {}),
    ]

    def response(name, arguments):
        if name == "vulnerability__get_cve_systems":
            payload = {
                "result": {
                    "data": [{"id": host, "attributes": {"status": 0}}],
                    "meta": {"total_items": 1},
                }
            }
            return CallToolResult(content=[], structuredContent=payload)
        assert arguments == {"host_ids": host}
        return CallToolResult(
            content=[
                TextContent(type="text", text=json.dumps({"data": [{"id": host, "marker": name}]}))
            ]
        )

    seen = fake_mcp(monkeypatch, [(catalog[:1], "inventory-page"), (catalog[1:], None)], response)
    result = await SourceTools(
        "https://fleet.invalid/mcp?token=private", "", tmp_path, environment="demo"
    ).inspect_fleet(request())
    assert result["total_affected_systems"] == 1
    assert result["systems"][0]["system_id"] == host
    assert result["coverage"]["inventory_details"] == "complete"
    assert result["coverage"]["system_profiles"] == "complete"
    assert "private" not in result["source_url"]
    assert [name for name, _ in seen["calls"]] == [
        "vulnerability__get_cve_systems",
        "inventory__get_host_details",
        "inventory__get_host_system_profile",
    ]
    assert seen["calls"][0][1] == {"cve": "CVE-2023-38545", "limit": 10, "offset": 0}
    assert seen["auth_calls"] == []


async def test_support_wrapper_authenticates_searches_exact_cve_and_returns_only_summary(
    tmp_path, monkeypatch
):
    fields = {
        "keyword": {"type": "string"},
        "maxResults": {"type": "integer"},
        **{
            name: {"type": "boolean"}
            for name in (
                "reducedInformation",
                "includePrivate",
                "includeSecureSupport",
                "includeAllCustomerCases",
            )
        },
    }
    catalog = [
        {
            "name": "GetCasesByFilter",
            "inputSchema": {
                "type": "object",
                "properties": {"input": {"$ref": "#/definitions/Filter"}},
                "required": ["input"],
                "definitions": {
                    "Filter": {
                        "type": "object",
                        "properties": fields,
                        "additionalProperties": False,
                    }
                },
            },
        }
    ]
    payload = {
        "result": {
            "totalCount": 1,
            "cases": [
                {
                    "caseNumber": "00012345",
                    "summary": "CVE-2023-38545 private-body",
                    "contactName": "private-person",
                    "status": "Closed",
                    "severity": "3",
                }
            ],
        }
    }
    seen = fake_mcp(
        monkeypatch, [(catalog, None)], CallToolResult(content=[], structuredContent=payload)
    )
    url = "https://support.invalid/mcp?token=private"
    result = await SourceTools("", url, tmp_path, environment="demo").search_support(request())
    assert seen["auth_calls"] == [(url, tmp_path / "oauth")]
    assert seen["transport"]["auth"] is seen["authentication"]
    assert seen["calls"] == [
        (
            "GetCasesByFilter",
            {
                "input": {
                    "keyword": "CVE-2023-38545",
                    "maxResults": 5,
                    "reducedInformation": True,
                    "includePrivate": False,
                    "includeSecureSupport": False,
                    "includeAllCustomerCases": False,
                }
            },
        )
    ]
    assert result["cases"][0]["case_id"] == "00012345" and result["cases"][0]["cve_mentioned"]
    assert result["coverage"]["case_search"] == "complete"
    assert all(sentinel not in str(result) for sentinel in ("private-body", "private-person"))


@pytest.mark.parametrize("method", ["inspect_fleet", "search_support"])
@pytest.mark.parametrize("catalog_mode", ["missing", "invalid_schema"])
async def test_wrappers_fail_closed_for_missing_or_incompatible_catalogs(
    tmp_path, monkeypatch, method, catalog_mode
):
    name = "vulnerability__get_cve_systems" if method == "inspect_fleet" else "GetCasesByFilter"
    catalog = (
        []
        if catalog_mode == "missing"
        else [definition(name, {"tenant": {"type": "string"}}, ("tenant",))]
    )
    seen = fake_mcp(monkeypatch, [(catalog, None)])
    tools = SourceTools(
        "https://fleet.invalid", "https://support.invalid", tmp_path, environment="demo"
    )
    result = await getattr(tools, method)(request())
    assert result["status"] in {"unsupported", "unverified"}
    assert not seen["calls"]
