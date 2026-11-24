"""Request-scoped source allowlist; ATI, not MAS, owns these connections."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .models import AuthenticationRequired, InvestigationRequest, SourceFailure, ToolArgumentsError
from .oauth import support_auth
from .osidb import get_public_osidb_cve
from .security_data import get_redhat_cve


def _source_failure(error: Exception) -> AuthenticationRequired | SourceFailure | None:
    """Normalize known transport failures without losing mixed-group semantics."""
    if isinstance(error, AuthenticationRequired):
        return AuthenticationRequired("Run ati-lscore support-login")
    if isinstance(error, SourceFailure):
        return error
    if isinstance(error, ExceptionGroup):
        normalized = [_source_failure(leaf) for leaf in error.exceptions]
        # Keep the existing Support OAuth recovery action even when cleanup
        # contributes another exception to the task group.
        if any(isinstance(leaf, AuthenticationRequired) for leaf in normalized):
            return AuthenticationRequired("Run ati-lscore support-login")
        if any(leaf is None for leaf in normalized):
            return None
        failures = [leaf for leaf in normalized if isinstance(leaf, SourceFailure)]
        if len({(leaf.code, leaf.retryable) for leaf in failures}) == 1:
            return failures[0]
        return None
    if isinstance(error, httpx.TimeoutException):
        return SourceFailure("source_timeout", retryable=True)
    if isinstance(error, httpx.NetworkError):
        return SourceFailure("source_unavailable", retryable=True)
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        if status in {401, 403}:
            return SourceFailure("source_authentication")
        if status == 429:
            return SourceFailure("source_rate_limited", retryable=True)
        if status == 408:
            return SourceFailure("source_timeout", retryable=True)
        if status >= 500:
            return SourceFailure("source_unavailable", retryable=True)
        return SourceFailure("source_http_error")
    return None


def _mcp_tool_failure(result) -> SourceFailure:
    """Read only root GraphQL error HTTP metadata, never messages or arbitrary paths."""
    fallback = SourceFailure("mcp_tool_error")
    payloads = []
    if result.structuredContent is not None:
        payloads.append(result.structuredContent)
    for block in result.content:
        if block.type == "text":
            try:
                payloads.append(json.loads(block.text))
            except json.JSONDecodeError:
                # MCP often includes a prose rendering alongside structured data.
                # It supplies no trusted status and must never be searched for one.
                continue
    categories = set()
    for payload in payloads:
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if not isinstance(errors, list) or not errors:
            return fallback
        for error in errors:
            extensions = error.get("extensions") if isinstance(error, dict) else None
            http = extensions.get("http") if isinstance(extensions, dict) else None
            status = http.get("status") if isinstance(http, dict) else None
            if type(status) is not int:
                return fallback
            if status == 404:
                category = ("source_not_found", False)
            elif status in {401, 403}:
                category = ("source_authentication", False)
            elif status == 429:
                category = ("source_rate_limited", True)
            elif 500 <= status < 600:
                category = ("source_unavailable", True)
            else:
                return fallback
            categories.add(category)
    if len(categories) != 1:
        return fallback
    code, retryable = categories.pop()
    return SourceFailure(code, retryable=retryable)


class SourceTools:
    def __init__(
        self,
        lightspeed_url: str,
        support_url: str,
        state_dir: Path,
        *,
        environment: str = "connected-organization",
        connection_revision: str = "1",
    ):
        self.lightspeed_url, self.support_url = lightspeed_url, support_url
        self.state_dir = state_dir
        self.environment = environment
        self.connection_fingerprint = hashlib.sha256(
            f"{environment}\n{lightspeed_url}\n{support_url}\n{connection_revision}".encode()
        ).hexdigest()

    def _journey_scope(self, request):
        if not request.journey_mode or request.environment != self.environment:
            raise ToolArgumentsError("Journey environment must match the configured connection")

    async def threat_intel(self, request):
        self._journey_scope(request)
        from .threat_intel import fetch_threat_intel

        return await asyncio.to_thread(fetch_threat_intel, request.cve_id)

    async def inspect_fleet(self, request):
        self._journey_scope(request)
        from .fleet import FleetInspector

        async def inspect(catalog, call):
            return await FleetInspector(catalog, call, source_url=self.lightspeed_url).inspect_cve(
                request.cve_id
            )

        return await self._mcp_collect(self.lightspeed_url, inspect)

    async def search_support(self, request):
        self._journey_scope(request)
        from .support_search import SupportSearch

        async def search(catalog, call):
            return await SupportSearch(catalog, call, source_url=self.support_url).search_cve(
                request.cve_id, max_results=5
            )

        return await self._mcp_collect(self.support_url, search, authenticated=True)

    async def _mcp_collect(self, url, operation, *, authenticated=False):
        """Bind a bounded collector to one catalog and session; never expose arbitrary tools."""
        if not url:
            raise SourceFailure("source_not_configured")
        auth = support_auth(url, self.state_dir / "oauth") if authenticated else None
        try:
            async with streamablehttp_client(url, auth=auth, timeout=25, sse_read_timeout=30) as (
                read,
                write,
                _,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    catalog, cursor = [], None
                    for _ in range(3):
                        page = await session.list_tools(cursor=cursor)
                        catalog.extend(tool.model_dump(mode="json") for tool in page.tools)
                        cursor = page.nextCursor
                        if not cursor:
                            break
                    else:
                        raise SourceFailure("source_catalog_limit")

                    async def call(name, arguments):
                        result = await session.call_tool(name, arguments)
                        if result.isError:
                            raise _mcp_tool_failure(result) from None
                        if result.structuredContent is not None:
                            return result.structuredContent
                        texts = [block.text for block in result.content if block.type == "text"]
                        if len(texts) == 1:
                            try:
                                return json.loads(texts[0])
                            except json.JSONDecodeError:
                                pass
                        raise SourceFailure("source_invalid_response")

                    return await operation(catalog, call)
        except Exception as exc:
            if failure := _source_failure(exc):
                raise failure from None
            raise

    async def call(self, name: str, arguments: dict, request: InvestigationRequest):
        """Enforce request scope and expose safe source failure categories."""
        try:
            return await self._call_source(name, arguments, request)
        except Exception as exc:
            # Unknown errors remain unknown; cancellation is a BaseException
            # and must reach the investigation's deadline/cancellation owner.
            if failure := _source_failure(exc):
                raise failure from None
            raise

    async def _call_source(self, name: str, arguments: dict, request: InvestigationRequest):
        if name == "GetCaseDetailsByCaseId":
            if request.case_id is None or arguments != {"caseId": request.case_id}:
                raise ToolArgumentsError(
                    "Only the exact case explicitly supplied in this request is allowed"
                )
            data = await self._mcp_call(self.support_url, name, arguments, authenticated=True)
        else:
            if name not in {"get_redhat_cve", "get_public_osidb_cve", "vulnerability__get_cve"}:
                raise ToolArgumentsError("Tool is not registered")
            if arguments != {"cve_id": request.cve_id}:
                raise ToolArgumentsError(
                    "Only the CVE explicitly supplied in this request is allowed"
                )
            if name == "get_redhat_cve":
                return await asyncio.to_thread(get_redhat_cve, request.cve_id)
            if name == "get_public_osidb_cve":
                return await asyncio.to_thread(get_public_osidb_cve, request.cve_id)
            data = await self._mcp_call(self.lightspeed_url, name, arguments)
        return {"source": name, "retrieved_at": datetime.now(UTC).isoformat(), "data": data}

    async def _mcp_call(self, url, name, arguments, *, authenticated=False):
        if not url:
            raise ValueError("Source URL is not configured")
        auth = support_auth(url, self.state_dir / "oauth") if authenticated else None
        async with streamablehttp_client(url, auth=auth, timeout=25, sse_read_timeout=30) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # Ask the server for the actual parameter name; the model sees a stable CVE API.
                tools = await session.list_tools()
                tool = next((tool for tool in tools.tools if tool.name == name), None)
                if tool is None:
                    raise ValueError("Expected source tool is unavailable")
                if name == "vulnerability__get_cve":
                    properties = tool.inputSchema.get("properties", {})
                    field = next(
                        (key for key in ("cve_id", "cve", "cveId", "id") if key in properties), None
                    )
                    if field is None:
                        raise ValueError("Lightspeed CVE tool schema is incompatible")
                    arguments = {field: arguments["cve_id"]}
                result = await session.call_tool(name, arguments)
                if result.isError:
                    raise _mcp_tool_failure(result) from None
                if result.structuredContent is not None:
                    return result.structuredContent
                texts = [block.text for block in result.content if block.type == "text"]
                if len(texts) == 1:
                    try:
                        return json.loads(texts[0])
                    except json.JSONDecodeError:
                        pass
                return texts
