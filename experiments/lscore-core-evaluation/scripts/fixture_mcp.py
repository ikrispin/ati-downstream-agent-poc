#!/usr/bin/env python3
"""Synthetic streamable-HTTP MCP tools for the bounded LSCore experiment.

Run with the pinned LSCore Python environment (mcp==1.30.0).
No external data, subprocesses, or model calls are used.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

LOG_PATH: Path | None = None
LOG_LOCK = threading.Lock()


def log_record(event: str, **fields: Any) -> None:
    if LOG_PATH is None:
        return
    record = {"event": event, "time": time.time(), "monotonic": time.monotonic(), **fields}
    with LOG_LOCK, LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_server(host: str, port: int) -> FastMCP:
    server = FastMCP("LSCore Neutral Fixture", host=host, port=port, stateless_http=True, json_response=True)

    @server.tool()
    async def read_sample(sample_id: str, delay_seconds: float = 0, request_marker: str = "") -> dict[str, Any]:
        """Read synthetic A=4 or B=7; FAIL/B_FAIL inject an expected error.

        delay_seconds is bounded to 30 seconds and awaits without blocking.
        request_marker is echoed and logged for request-isolation evidence.
        """
        call_id = uuid.uuid4().hex
        fields = {"call_id": call_id, "tool": "read_sample", "sample_id": sample_id, "delay_seconds": delay_seconds, "request_marker": request_marker}
        log_record("tool_start", **fields)
        try:
            if not 0 <= delay_seconds <= 30:
                raise ValueError("delay_seconds must be between 0 and 30")
            await asyncio.sleep(delay_seconds)
            if sample_id.upper() in ("FAIL", "B_FAIL"):
                raise ValueError("Injected fixture failure: sample B unavailable")
            if sample_id not in ("A", "B"):
                raise ValueError(f"Unknown synthetic sample: {sample_id}")
            result = {"sample_id": sample_id, "value": {"A": 4, "B": 7}[sample_id], "request_marker": request_marker}
            log_record("tool_end", **fields, status="success", result=result)
            return result
        except BaseException as error:
            log_record("tool_end", **fields, status="error", error=f"{type(error).__name__}: {error}")
            raise

    @server.tool()
    async def calculate_total(values: list[float], request_marker: str = "") -> dict[str, Any]:
        """Add only the synthetic values supplied by prior successful reads."""
        call_id = uuid.uuid4().hex
        fields = {"call_id": call_id, "tool": "calculate_total", "values": values, "request_marker": request_marker}
        log_record("tool_start", **fields)
        result = {"total": sum(values), "values": values, "request_marker": request_marker}
        log_record("tool_end", **fields, status="success", result=result)
        return result

    return server


def main() -> None:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18142)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    LOG_PATH = args.log
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_record("mcp_fixture_started", host=args.host, port=args.port)
    print(f"Local MCP fixture listening at http://{args.host}:{args.port}/mcp", flush=True)
    build_server(args.host, args.port).run(transport="streamable-http")


if __name__ == "__main__":
    main()
