"""Request-scoped source allowlist; ATI, not MAS, owns these connections."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .models import AuthenticationRequired, InvestigationRequest
from .oauth import support_auth
from .osidb import get_public_osidb_cve
from .security_data import get_redhat_cve


def schema(name, description, field):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {field: {"type": "string"}},
                "required": [field],
                "additionalProperties": False,
            },
        },
    }


class SourceTools:
    schemas = [
        schema("get_redhat_cve", "Get Red Hat vendor evidence for the requested CVE", "cve_id"),
        schema("get_public_osidb_cve", "Get explicitly public OSIDB evidence", "cve_id"),
        schema(
            "vulnerability__get_cve",
            "Get CVE evidence for the connected Lightspeed organization",
            "cve_id",
        ),
        schema("GetCaseDetailsByCaseId", "Get only the explicitly supplied Support Case", "caseId"),
    ]

    def __init__(self, lightspeed_url: str, support_url: str, state_dir: Path):
        self.lightspeed_url, self.support_url = lightspeed_url, support_url
        self.state_dir = state_dir

    async def call(self, name: str, arguments: dict, request: InvestigationRequest):
        if name == "GetCaseDetailsByCaseId":
            if request.case_id is None or arguments != {"caseId": request.case_id}:
                raise ValueError(
                    "Only the exact case explicitly supplied in this request is allowed"
                )
            try:
                data = await self._mcp_call(self.support_url, name, arguments, authenticated=True)
            except ExceptionGroup as exc:
                if exc.subgroup(AuthenticationRequired) is not None:
                    raise AuthenticationRequired("Run ati-downstream support-login") from None
                raise
        else:
            if name not in {"get_redhat_cve", "get_public_osidb_cve", "vulnerability__get_cve"}:
                raise ValueError("Tool is not registered")
            if arguments != {"cve_id": request.cve_id}:
                raise ValueError("Only the CVE explicitly supplied in this request is allowed")
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
                    raise RuntimeError("Source tool reported an error")
                if result.structuredContent is not None:
                    return result.structuredContent
                texts = [block.text for block in result.content if block.type == "text"]
                if len(texts) == 1:
                    try:
                        return json.loads(texts[0])
                    except json.JSONDecodeError:
                        pass
                return texts
