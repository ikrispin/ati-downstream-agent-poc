#!/usr/bin/env python3
"""Fast isolated comparison of a caller deadline and LSCore stream interruption.

Run with the pinned .local/upstream/.venv/bin/python from this experiment folder.
Only synthetic fixtures are contacted. All services started here are stopped.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".local/deadline-probe"
BASE_URL = "http://127.0.0.1:9140"


def read_log(name: str) -> list[dict[str, Any]]:
    path = PRIVATE / name
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def replace_config(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: replace_config(child) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_config(child) for child in value]
    if isinstance(value, str):
        if value.startswith(".local/state/"):
            return str(PRIVATE / "state" / value.removeprefix(".local/state/"))
        return value.replace("127.0.0.1:18141", "127.0.0.1:19141").replace(
            "127.0.0.1:18142", "127.0.0.1:19142"
        )
    return value


def tool_events(marker: str) -> list[dict[str, Any]]:
    return [
        item
        for item in read_log("tool-calls.jsonl")
        if item.get("request_marker") == marker
    ]


def model_outputs(marker: str) -> list[dict[str, Any]]:
    records = read_log("model-calls.jsonl")
    response_ids = {
        item["response_id"] for item in records if item.get("request_marker") == marker
    }
    return [
        item
        for item in records
        if item.get("response_id") in response_ids and item["event"] == "model_response"
    ]


async def wait_for_tools(
    marker: str, *, terminal: bool, timeout: float
) -> list[dict[str, Any]]:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        records = tool_events(marker)
        if terminal:
            if any(
                item["event"] == "tool_end" and item["tool"] == "calculate_total"
                for item in records
            ):
                return records
        elif any(item["event"] == "tool_start" for item in records):
            return records
        await asyncio.sleep(0.02)
    return tool_events(marker)


async def caller_deadline(client: httpx.AsyncClient) -> dict[str, Any]:
    marker = "caller-deadline-" + uuid.uuid4().hex[:12]
    request = {
        "query": f"[fixture:normal] [request:{marker}] [delay-a:2] Read A and B and calculate their total.",
        "generate_topic_summary": False,
    }
    started = time.monotonic()
    result: dict[str, Any] = {
        "marker": marker,
        "caller_wall_clock_deadline_seconds": 0.3,
        "slow_tool_seconds": 2,
        "request": request,
        "started_monotonic": started,
    }
    try:
        response = await asyncio.wait_for(
            client.post(BASE_URL + "/v1/query", json=request, timeout=None), timeout=0.3
        )
        result.update(
            caller_outcome="response",
            http_status=response.status_code,
            response=response.json(),
        )
    except TimeoutError:
        result["caller_outcome"] = "TimeoutError"
        result["caller_timed_out_monotonic"] = time.monotonic()
        result["caller_elapsed_seconds"] = round(
            result["caller_timed_out_monotonic"] - started, 6
        )
    result["tool_events"] = await wait_for_tools(marker, terminal=True, timeout=5)
    result["model_outputs"] = model_outputs(marker)
    timed_out = result.get("caller_timed_out_monotonic", float("inf"))
    result["successful_tools_finished_after_caller_timeout"] = [
        item["tool"]
        for item in result["tool_events"]
        if item["event"] == "tool_end"
        and item.get("status") == "success"
        and item["monotonic"] > timed_out
    ]
    result["calculation_completed_after_caller_timeout"] = (
        "calculate_total" in result["successful_tools_finished_after_caller_timeout"]
    )
    result["slow_tool_started_before_caller_timeout"] = any(
        item["event"] == "tool_start"
        and item.get("sample_id") == "A"
        and item["monotonic"] < timed_out
        for item in result["tool_events"]
    )
    return result


async def explicit_interrupt(client: httpx.AsyncClient) -> dict[str, Any]:
    marker = "explicit-interrupt-" + uuid.uuid4().hex[:12]
    request = {
        "query": f"[fixture:normal] [request:{marker}] [delay-a:2] Read A and B and calculate their total.",
        "generate_topic_summary": False,
    }
    result: dict[str, Any] = {
        "marker": marker,
        "slow_tool_seconds": 2,
        "request": request,
        "events": [],
    }
    request_id_ready = asyncio.Event()

    async def consume() -> None:
        try:
            async with client.stream(
                "POST", BASE_URL + "/v1/streaming_query", json=request, timeout=None
            ) as response:
                result["stream_http_status"] = response.status_code
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    item = json.loads(line[5:].strip())
                    result["events"].append(
                        {"observed_monotonic": time.monotonic(), **item}
                    )
                    if item.get("event") == "start":
                        result["request_id"] = item["data"]["request_id"]
                        request_id_ready.set()
        except Exception as error:  # noqa: BLE001 - Preserve the observed streaming outcome.
            result["stream_error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }

    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(request_id_ready.wait(), timeout=3)
        await wait_for_tools(marker, terminal=False, timeout=2)
        result["interrupt_requested_monotonic"] = time.monotonic()
        response = await client.post(
            BASE_URL + "/v1/streaming_query/interrupt",
            json={"request_id": result["request_id"]},
            timeout=2,
        )
        result["interrupt_http_status"] = response.status_code
        result["interrupt_response"] = response.json()
        try:
            await asyncio.wait_for(task, timeout=4)
        except TimeoutError:
            result["stream_collection_deadline_exceeded"] = True
        # A local interrupt is distinct from cancelling the MCP server's work.
        # Wait only long enough for the already-started synthetic 2-second tool.
        await asyncio.sleep(2.1)
        result["tool_events"] = tool_events(marker)
        result["model_outputs"] = model_outputs(marker)
        interrupted_at = result["interrupt_requested_monotonic"]
        result["tools_finished_after_interrupt"] = [
            item["tool"]
            for item in result["tool_events"]
            if item["event"] == "tool_end" and item["monotonic"] > interrupted_at
        ]
        result["interrupted_event_observed"] = any(
            item.get("event") == "interrupted" for item in result["events"]
        )
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    return result


async def probes(processes: list[subprocess.Popen[Any]]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=2) as client:
        for url in ("http://127.0.0.1:19141/health", BASE_URL + "/readiness"):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError(
                        "An owned fixture or LSCore process exited during startup"
                    )
                try:
                    if (await client.get(url)).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.2)
            else:
                raise TimeoutError("An owned service did not become ready")
        # Warm imports, SQLite, and MCP discovery before measuring a 0.3-second caller deadline.
        warmup = await client.post(
            BASE_URL + "/v1/query",
            json={
                "query": "[fixture:normal] [request:deadline-warmup] Read A and B and calculate total.",
                "generate_topic_summary": False,
            },
            timeout=10,
        )
        warmup.raise_for_status()
        return {
            "warmup_http_status": warmup.status_code,
            "caller_deadline": await caller_deadline(client),
            "explicit_stream_interrupt": await explicit_interrupt(client),
        }


def main() -> None:
    for port in (9140, 19141, 19142):
        with socket.socket() as check:
            if check.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(
                    f"Experiment port {port} is occupied; no existing process will be stopped"
                )
    PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    (PRIVATE / "state").mkdir(exist_ok=True)
    for name in ("model-calls.jsonl", "tool-calls.jsonl"):
        (PRIVATE / name).write_text("")
    config = replace_config(
        yaml.safe_load((ROOT / "config/lscore-fixture.yaml").read_text())
    )
    config["service"].update(port=9140, base_url=BASE_URL, workers=1)
    config_path = PRIVATE / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    commands = [
        (
            "model",
            [
                sys.executable,
                str(ROOT / "scripts/fixture_server.py"),
                "--port",
                "19141",
                "--log",
                str(PRIVATE / "model-calls.jsonl"),
            ],
        ),
        (
            "mcp",
            [
                sys.executable,
                str(ROOT / "scripts/fixture_mcp.py"),
                "--port",
                "19142",
                "--log",
                str(PRIVATE / "tool-calls.jsonl"),
            ],
        ),
        (
            "lscore",
            [
                str(ROOT / ".local/upstream/.venv/bin/lightspeed-stack"),
                "-c",
                str(config_path),
                "--synthesized-config-output",
                str(PRIVATE / "synthesized.yaml"),
            ],
        ),
    ]
    result: dict[str, Any] = {
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "source_revision": "7693565545044173814b1c5ad5aa66dd329e8b34",
        "scope": "Actual unmodified LSCore service with local deterministic model and MCP fixtures; no ATI code, real model, or external tools.",
        "configured_service": {
            "workers": 1,
            "base_url": BASE_URL,
            "mcp_server_timeout_seconds": 1,
            "ogx_mode": "library",
        },
        "config_path": str(config_path.relative_to(ROOT)),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "supported_whole_run_deadline": {
            "discovery": "No whole-agent-run deadline configuration or enforcement was found in the pinned Configuration model or query/stream/A2A run call sites. No nonexistent server setting was applied. The probe instead tests what a real caller deadline and the supported streaming interrupt do.",
            "source_references": [
                {
                    "path": "src/models/config.py",
                    "line": 42,
                    "fact": "Configuration rejects unknown fields.",
                },
                {
                    "path": "src/utils/agents/query.py",
                    "line": 303,
                    "fact": "agent.run is awaited without a total-deadline wrapper.",
                },
                {
                    "path": "src/utils/agents/streaming.py",
                    "line": 459,
                    "fact": "agent.run_stream_events is awaited without a total-deadline wrapper.",
                },
            ],
        },
        "concurrency_architecture": {
            "classification": "documented built-in service behavior",
            "fact": "service.workers is documented and defaults to 1; LSCore passes it to Uvicorn. No replacement scheduler or custom concurrency hook is needed for non-blocking independent requests.",
            "source_references": [
                {"path": "src/models/config.py", "line": 396},
                {"path": "src/runners/uvicorn.py", "line": 41},
                {"path": "docs/user_doc/config.md", "line": 1153},
            ],
            "limits": "One-worker independent-request overlap does not establish parallel tool calls inside one model turn.",
        },
    }
    processes = []
    try:
        for name, command in commands:
            with (PRIVATE / f"{name}.log").open("w") as log:
                processes.append(
                    subprocess.Popen(
                        command,
                        cwd=ROOT,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                        env={**os.environ, "OTEL_SDK_DISABLED": "true"},
                    )
                )
        result.update(asyncio.run(probes(processes)))
    except Exception as error:  # noqa: BLE001 - Retain bounded experiment failures and clean up.
        result["probe_error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=4)
        result["all_owned_services_stopped"] = all(
            process.poll() is not None for process in processes
        )
        result["ports_closed_after_cleanup"] = {}
        for port in (9140, 19141, 19142):
            with socket.socket() as check:
                result["ports_closed_after_cleanup"][str(port)] = (
                    check.connect_ex(("127.0.0.1", port)) != 0
                )
        result["reproduce_command"] = (
            ".local/upstream/.venv/bin/python scripts/probe_deadline.py"
        )
        result["interpretation"] = (
            "No supported whole-run LSCore deadline setting was found to configure. "
            "Inspect caller timeout, subsequent tool timestamps, final model output, "
            "and explicit-interrupt events separately: caller cancellation, local "
            "stream interruption, and remote tool cancellation are distinct behaviors. "
            "These observations apply to this pinned configuration and synthetic tools."
        )
        output = ROOT / "results/deadline-probe.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "probe_error": result.get("probe_error"),
                "caller_timeout_then_calculation_completed": result.get(
                    "caller_deadline", {}
                ).get("calculation_completed_after_caller_timeout"),
                "stream_interrupted_event": result.get(
                    "explicit_stream_interrupt", {}
                ).get("interrupted_event_observed"),
                "all_owned_services_stopped": result["all_owned_services_stopped"],
            }
        )
    )


if __name__ == "__main__":
    main()
