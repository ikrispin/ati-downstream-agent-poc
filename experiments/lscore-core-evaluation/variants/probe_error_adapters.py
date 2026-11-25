"""Trace installed MCP -> OGX error adapters using only in-memory calls.

No network access, live experiment services, credentials, or source patches.
"""

import asyncio
import json
from types import SimpleNamespace

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from ogx.providers.inline.responses.builtin.responses.tool_executor import ToolExecutor
from ogx.providers.utils.tools.mcp import _parse_mcp_result
from pydantic_ai.exceptions import ModelHTTPError
from utils.agents.error_handler import map_pydantic_agent_run_error


async def main():
    """Exercise real library protocol/adapter functions and print evidence."""
    server = FastMCP("isolated-error-adapter-probe")
    invocations = []

    @server.tool()
    def read_sample(sample_id: str) -> dict:
        """Return a synthetic value or an explicit injected failure."""
        invocations.append(sample_id)
        if sample_id == "FAIL":
            raise ValueError("Injected fixture failure: sample B unavailable")
        return {"sample_id": sample_id, "value": 4}

    executor = ToolExecutor(None, None, None)
    observations = {}
    async with create_connected_server_and_client_session(server) as session:
        for label, arguments in (
            ("success", {"sample_id": "A"}),
            ("tool_failure", {"sample_id": "FAIL"}),
            ("invalid_arguments", {"unexpected": True}),
        ):
            before = len(invocations)
            raw = await session.call_tool("read_sample", arguments)
            parsed = _parse_mcp_result(raw)
            output_message, model_input = await executor._build_result_messages(
                function=SimpleNamespace(name="read_sample", arguments=json.dumps(arguments)),
                tool_call_id="call_probe",
                item_id="fc_probe",
                tool_kwargs=arguments,
                ctx=SimpleNamespace(),
                error_exc=None,
                result=parsed,
                has_error=bool(parsed.error_code),
                mcp_tool_to_server={"read_sample": SimpleNamespace(server_label="neutral-tools")},
            )
            observations[label] = {
                "raw_mcp_result": raw.model_dump(mode="json"),
                "parsed_ogx_result": parsed.model_dump(mode="json"),
                "returned_ogx_output_item": output_message.model_dump(mode="json"),
                "input_sent_back_to_model": model_input.model_dump(mode="json"),
                "tool_function_entries": len(invocations) - before,
            }
    for label in ("tool_failure", "invalid_arguments"):
        assert observations[label]["raw_mcp_result"]["isError"] is True
        assert observations[label]["parsed_ogx_result"]["error_message"] is None
        assert observations[label]["returned_ogx_output_item"]["error"] == "Error (code 1): None"
        assert observations[label]["returned_ogx_output_item"]["output"] is None
        assert observations[label]["input_sent_back_to_model"]["content"][0]["text"]
    assert observations["invalid_arguments"]["tool_function_entries"] == 0
    mapped = map_pydantic_agent_run_error(
        ModelHTTPError(500, "fixture/fixture-model", {"code": "server_error", "message": "Injected local model failure"}),
        "fixture/fixture-model",
    )
    print(json.dumps({
        "probe_kind": "in_memory_mcp_protocol_and_real_ogx_formatter_functions",
        "source_revision": "7693565545044173814b1c5ad5aa66dd329e8b34",
        "observations": observations,
        "mapped_model_http_500": mapped.model_dump(mode="json"),
        "all_assertions_passed": True,
        "limitations": [
            "This isolates protocol and formatter functions; earlier retained HTTP evidence establishes their service use.",
            "It does not reproduce or assign ownership of the asynchronous cancel-scope cleanup error.",
        ],
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
