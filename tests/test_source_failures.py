"""Check source failure categories at the actual SourceTools boundary."""

import asyncio

import httpx
import pytest

from ati_lscore import sources
from ati_lscore.models import AuthenticationRequired, InvestigationRequest, SourceFailure

REQUEST = InvestigationRequest.parse("CVE-2023-38545 Support Case 00012345")
PRIVATE_URL = "https://private-source.test/mcp?token=private-token"


class HTTPSourceTools(sources.SourceTools):
    """Use HTTPX's real request/error path without a remote MCP server."""

    def __init__(self, tmp_path, handler):
        super().__init__(PRIVATE_URL, PRIVATE_URL, tmp_path)
        self.transport = httpx.MockTransport(handler)

    async def _mcp_call(self, url, name, arguments, *, authenticated=False):
        async with httpx.AsyncClient(transport=self.transport) as client:
            response = await client.post(url, json=arguments)
            response.raise_for_status()
            return response.json()


@pytest.mark.parametrize(
    ("error_type", "code"),
    [
        (httpx.ReadTimeout, "source_timeout"),
        (httpx.ConnectTimeout, "source_timeout"),
        (httpx.ConnectError, "source_unavailable"),
        (httpx.ReadError, "source_unavailable"),
    ],
)
async def test_http_transport_failures_have_safe_retryable_categories(tmp_path, error_type, code):
    calls = []

    def server(request):
        calls.append(request)
        raise error_type("private-token and provider details", request=request)

    tools = HTTPSourceTools(tmp_path, server)
    with pytest.raises(SourceFailure) as caught:
        await tools.call("vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST)
    assert caught.value.code == code
    assert caught.value.retryable is True
    assert str(caught.value) == code
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (401, "source_authentication", False),
        (403, "source_authentication", False),
        (429, "source_rate_limited", True),
        (408, "source_timeout", True),
        (500, "source_unavailable", True),
        (503, "source_unavailable", True),
        (400, "source_http_error", False),
        (404, "source_http_error", False),
    ],
)
async def test_http_status_failures_do_not_publish_the_url_or_response_body(
    tmp_path, status, code, retryable
):
    tools = HTTPSourceTools(
        tmp_path, lambda request: httpx.Response(status, text="private-token provider body")
    )
    with pytest.raises(SourceFailure) as caught:
        await tools.call("vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST)
    assert caught.value.code == code
    assert caught.value.retryable is retryable
    assert str(caught.value) == code
    assert caught.value.__suppress_context__ is True


async def test_vendor_http_failure_is_normalized_after_thread_boundary(tmp_path, monkeypatch):
    vendor_lookup = sources.get_redhat_cve
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(503, text="private body"))
    ) as client:
        monkeypatch.setattr(
            sources, "get_redhat_cve", lambda cve_id: vendor_lookup(cve_id, client=client)
        )
        with pytest.raises(SourceFailure) as caught:
            await sources.SourceTools("", "", tmp_path).call(
                "get_redhat_cve", {"cve_id": REQUEST.cve_id}, REQUEST
            )
    assert caught.value.code == "source_unavailable"
    assert caught.value.retryable is True


@pytest.mark.parametrize("mixed", [False, True])
async def test_nested_mcp_groups_require_unanimous_failure_semantics(tmp_path, mixed):
    leaf = httpx.ConnectError("private URL")
    second = httpx.ReadTimeout("private timeout") if mixed else httpx.ReadError("private URL")
    failure = ExceptionGroup("transport", [leaf, ExceptionGroup("nested", [second])])

    class GroupedTools(sources.SourceTools):
        async def _mcp_call(self, *args, **kwargs):
            raise failure

    tools = GroupedTools(PRIVATE_URL, PRIVATE_URL, tmp_path)
    if mixed:
        with pytest.raises(ExceptionGroup) as caught:
            await tools.call("vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST)
        assert caught.value is failure
    else:
        with pytest.raises(SourceFailure) as caught:
            await tools.call("vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST)
        assert caught.value.code == "source_unavailable"
        assert caught.value.retryable is True


async def test_unknown_mcp_group_leaf_does_not_become_retryable(tmp_path):
    failure = ExceptionGroup(
        "transport", [httpx.ConnectError("private URL"), ValueError("invalid evidence")]
    )

    class GroupedTools(sources.SourceTools):
        async def _mcp_call(self, *args, **kwargs):
            raise failure

    with pytest.raises(ExceptionGroup) as caught:
        await GroupedTools(PRIVATE_URL, PRIVATE_URL, tmp_path).call(
            "vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST
        )
    assert caught.value is failure


async def test_support_authentication_keeps_safe_recovery_priority(tmp_path):
    class ExpiredSupport(sources.SourceTools):
        async def _mcp_call(self, *args, **kwargs):
            raise ExceptionGroup(
                "private context",
                [
                    ValueError("unclassified cleanup"),
                    ExceptionGroup("nested", [AuthenticationRequired("private-token")]),
                ],
            )

    with pytest.raises(AuthenticationRequired) as caught:
        await ExpiredSupport(PRIVATE_URL, PRIVATE_URL, tmp_path).call(
            "GetCaseDetailsByCaseId", {"caseId": REQUEST.case_id}, REQUEST
        )
    assert str(caught.value) == "Run ati-lscore support-login"


async def test_cancellation_is_not_converted_to_source_failure(tmp_path):
    class CancelledTools(sources.SourceTools):
        async def _mcp_call(self, *args, **kwargs):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await CancelledTools(PRIVATE_URL, PRIVATE_URL, tmp_path).call(
            "vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST
        )


async def test_success_keeps_source_evidence_shape(tmp_path):
    tools = HTTPSourceTools(tmp_path, lambda request: httpx.Response(200, json={"count": 0}))
    result = await tools.call("vulnerability__get_cve", {"cve_id": REQUEST.cve_id}, REQUEST)
    assert result["source"] == "vulnerability__get_cve"
    assert result["data"] == {"count": 0}
    assert result["retrieved_at"]
