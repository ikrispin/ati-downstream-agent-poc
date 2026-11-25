"""Keep safe structured MCP failure categories without interpreting provider prose."""

import asyncio
import json

import pytest
from mcp.types import CallToolResult, TextContent
from test_journey_sources import definition, fake_mcp

from ati_lscore.models import SourceFailure
from ati_lscore.sources import SourceTools

PRIVATE = "private-token https://private.invalid/case/00000000?secret=private-token"
URL = "https://synthetic.invalid/mcp"


def graphql_error(status):
    return {
        "message": PRIVATE,
        "path": ["privateCasePath"],
        "extensions": {"code": "CONNECTOR_FETCH", "http": {"status": status}},
    }


def result(payload, encoding="structured", *, is_error=True):
    if encoding == "structured":
        return CallToolResult(
            content=[TextContent(type="text", text=PRIVATE)],
            structuredContent=payload,
            isError=is_error,
        )
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))], isError=is_error
    )


async def invoke(tools, boundary):
    if boundary == "legacy":
        return await tools._mcp_call(URL, "read_synthetic", {})

    async def operation(catalog, call):
        return await call("read_synthetic", {})

    return await tools._mcp_collect(URL, operation)


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
@pytest.mark.parametrize("encoding", ["structured", "json"])
@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (404, "source_not_found", False),
        (401, "source_authentication", False),
        (403, "source_authentication", False),
        (429, "source_rate_limited", True),
        (500, "source_unavailable", True),
        (503, "source_unavailable", True),
    ],
)
async def test_graphql_http_failure_survives_mcp_boundary_safely(
    tmp_path, monkeypatch, boundary, encoding, status, code, retryable
):
    payload = {"data": {"case": None}, "errors": [graphql_error(status)]}
    seen = fake_mcp(
        monkeypatch, [([definition("read_synthetic", {})], None)], result(payload, encoding)
    )
    with pytest.raises(SourceFailure) as caught:
        await invoke(SourceTools(URL, "", tmp_path), boundary)
    assert caught.value.code == code
    assert caught.value.retryable is retryable
    assert str(caught.value) == code
    assert "private" not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert seen["closed"] and len(seen["calls"]) == 1


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
@pytest.mark.parametrize(
    "payload",
    [
        {"message": "HTTP 404 " + PRIVATE},
        {"status": 404, "extensions": {"http": {"status": 404}}},
        {"data": {"errors": [graphql_error(404)]}},
        {"errors": [graphql_error("404")]},
        {"errors": [graphql_error(True)]},
        {"errors": [graphql_error(400)]},
        {"errors": [graphql_error(700)]},
        {"errors": [graphql_error(404), graphql_error(401)]},
        {"errors": [graphql_error(503), {"message": PRIVATE}]},
        {"errors": []},
        {"errors": {"extensions": {"http": {"status": 404}}}},
    ],
)
async def test_unknown_or_mixed_error_shapes_keep_generic_safe_category(
    tmp_path, monkeypatch, boundary, payload
):
    fake_mcp(monkeypatch, [([definition("read_synthetic", {})], None)], result(payload))
    with pytest.raises(SourceFailure) as caught:
        await invoke(SourceTools(URL, "", tmp_path), boundary)
    assert caught.value.code == "mcp_tool_error"
    assert caught.value.retryable is False
    assert str(caught.value) == "mcp_tool_error"


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
async def test_multiple_errors_can_share_one_known_safe_category(tmp_path, monkeypatch, boundary):
    fake_mcp(
        monkeypatch,
        [([definition("read_synthetic", {})], None)],
        result({"errors": [graphql_error(500), graphql_error(502)]}),
    )
    with pytest.raises(SourceFailure) as caught:
        await invoke(SourceTools(URL, "", tmp_path), boundary)
    assert caught.value.code == "source_unavailable" and caught.value.retryable is True


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
async def test_conflicting_structured_and_json_error_payloads_are_generic(
    tmp_path, monkeypatch, boundary
):
    mixed = CallToolResult(
        content=[TextContent(type="text", text=json.dumps({"errors": [graphql_error(401)]}))],
        structuredContent={"errors": [graphql_error(404)]},
        isError=True,
    )
    fake_mcp(monkeypatch, [([definition("read_synthetic", {})], None)], mixed)
    with pytest.raises(SourceFailure, match="mcp_tool_error"):
        await invoke(SourceTools(URL, "", tmp_path), boundary)


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
async def test_freetext_is_not_searched_for_status_or_embedded_json(
    tmp_path, monkeypatch, boundary
):
    text = "Error: HTTP 404 " + json.dumps({"errors": [graphql_error(404)]})
    fake_mcp(
        monkeypatch,
        [([definition("read_synthetic", {})], None)],
        CallToolResult(content=[TextContent(type="text", text=text)], isError=True),
    )
    with pytest.raises(SourceFailure, match="mcp_tool_error"):
        await invoke(SourceTools(URL, "", tmp_path), boundary)


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
async def test_nonerror_result_does_not_enter_error_classification(tmp_path, monkeypatch, boundary):
    payload = {"errors": [graphql_error(404)]}
    fake_mcp(
        monkeypatch,
        [([definition("read_synthetic", {})], None)],
        result(payload, is_error=False),
    )
    assert await invoke(SourceTools(URL, "", tmp_path), boundary) == payload


@pytest.mark.parametrize("boundary", ["legacy", "collector"])
async def test_cancellation_still_propagates_through_tool_boundary(tmp_path, monkeypatch, boundary):
    def cancel(*args):
        raise asyncio.CancelledError

    seen = fake_mcp(monkeypatch, [([definition("read_synthetic", {})], None)], cancel)
    with pytest.raises(asyncio.CancelledError):
        await invoke(SourceTools(URL, "", tmp_path), boundary)
    assert seen["closed"]
