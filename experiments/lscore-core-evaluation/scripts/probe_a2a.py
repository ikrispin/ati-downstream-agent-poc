#!/usr/bin/env python3
"""Synthetic LSCore A2A wire and native MAS-node compatibility probes.

Direct mode uses only the standard library. Run ``--mode mas-node`` with the
existing isolated MAS virtual environment. The MAS probe invokes the native
node's delegation and outcome conversion methods; it does not save resources,
create a workflow, start a coordinator model, or call an ATI data source.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_PROMPT = (
    "Synthetic neutral evaluation: read sample A and sample B with the available "
    "tools, then calculate their total. Report the observed values and total."
)
TERMINAL = {"completed", "failed", "canceled", "rejected", "input-required"}


def write_record(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def rpc_payload(method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}


def message_payload(prompt: str) -> dict:
    return {
        "message": {
            "messageId": str(uuid.uuid4()),
            "role": "user",
            "parts": [{"kind": "text", "text": prompt}],
        }
    }


def request(base_url: str, path: str, timeout: float, body: dict | None = None) -> dict:
    started = time.monotonic()
    req = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    record: dict = {"method": req.get_method(), "path": path, "request": body}
    try:
        try:
            response = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            record["http_status"] = response.status
            raw = response.read().decode()
            try:
                record["response"] = json.loads(raw)
            except json.JSONDecodeError:
                record["response_text"] = raw
    except (urllib.error.URLError, TimeoutError) as error:
        record["transport_error"] = str(error)
        record["transport_error_type"] = type(error).__name__
    record["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return record


def stream_request(args: argparse.Namespace) -> dict:
    body = rpc_payload("message/stream", message_payload(args.prompt))
    req = urllib.request.Request(
        args.base_url + "/a2a",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
    )
    started = time.monotonic()
    record: dict = {"method": "POST", "path": "/a2a", "request": body, "frames": []}
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as response:
            record["http_status"] = response.status
            record["content_type"] = response.headers.get("content-type")
            data_lines = []
            for raw_line in response:
                line = raw_line.decode().rstrip("\r\n")
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
                elif not line and data_lines:
                    data = "\n".join(data_lines)
                    data_lines.clear()
                    frame = json.loads(data)
                    record["frames"].append(frame)
                    result = frame.get("result", {})
                    if result.get("kind") == "task":
                        record["task_id"] = result["id"]
                    if (
                        args.cancel_in_stream
                        and "cancel_attempt" not in record
                        and record.get("task_id")
                        and result.get("status", {}).get("state") not in TERMINAL
                    ):
                        task_id = record["task_id"]
                        record["task_before_cancel"] = request(
                            args.base_url, "/a2a", args.timeout,
                            rpc_payload("tasks/get", {"id": task_id}),
                        )
                        record["cancel_attempt"] = request(
                            args.base_url, "/a2a", args.timeout,
                            rpc_payload("tasks/cancel", {"id": task_id}),
                        )
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        record["transport_error"] = str(error)
        record["transport_error_type"] = type(error).__name__
    record["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return record


def summarize_task(task: dict) -> dict:
    return {
        "id": task.get("id"),
        "state": task.get("status", {}).get("state"),
        "artifact_part_kinds": [
            part.get("kind")
            for artifact in task.get("artifacts", [])
            for part in artifact.get("parts", [])
        ],
        "artifact_text": [
            part.get("text")
            for artifact in task.get("artifacts", [])
            for part in artifact.get("parts", [])
            if part.get("kind") == "text"
        ],
    }


def direct_probe(args: argparse.Namespace) -> dict:
    records = {
        "health": request(args.base_url, "/a2a/health", args.timeout),
        "agent_card": request(args.base_url, "/.well-known/agent-card.json", args.timeout),
        "legacy_agent_card": request(args.base_url, "/.well-known/agent.json", args.timeout),
    }
    if args.discovery_only:
        return {"records": records}
    records["send"] = request(
        args.base_url, "/a2a", args.timeout,
        rpc_payload("message/send", message_payload(args.prompt)),
    )
    task = records["send"].get("response", {}).get("result", {})
    if task.get("id"):
        records["send_task_lookup"] = request(
            args.base_url, "/a2a", args.timeout,
            rpc_payload("tasks/get", {"id": task["id"], "historyLength": 2}),
        )
    records["stream"] = stream_request(args)
    stream_id = records["stream"].get("task_id")
    if stream_id:
        records["stream_task_lookup"] = request(
            args.base_url, "/a2a", args.timeout,
            rpc_payload("tasks/get", {"id": stream_id}),
        )
    return {
        "records": records,
        "summary": {
            "send": summarize_task(task),
            "stream": summarize_task(
                records.get("stream_task_lookup", {}).get("response", {}).get("result", {})
            ),
            "stream_frame_kinds": [
                frame.get("result", {}).get("kind")
                for frame in records["stream"].get("frames", [])
            ],
            "cancellation": records["stream"].get("cancel_attempt"),
        },
    }


def mas_node_probe(args: argparse.Namespace) -> dict:
    # Imports deliberately occur only in the MAS virtual environment.
    from mas.elements.llms.common.chat.message import ChatMessage, Role
    from mas.elements.nodes.a2a_agent.a2a_agent_node import A2AAgentNode
    from mas.elements.nodes.common.workload import Task
    from mas.graph.models import StepContext
    from pydantic import HttpUrl

    records: dict = {
        "scope": "Native A2AAgentNode delegation and result conversion; no workflow runner",
        "a2a_sdk_version": importlib.metadata.version("a2a-sdk"),
        "inventory_writes": False,
        "coordinator_model_invoked": False,
        "workflow_runner_exercised": False,
        "ui_stream_delivery_exercised": False,
    }
    started = time.monotonic()
    try:
        node = A2AAgentNode(base_url=HttpUrl(args.base_url), retries=0)
        node.set_context(StepContext(uid="lscore-neutral-e8-probe"))
        records["discovery_succeeded"] = True
        records["remote_agent_name"] = node.a2a_provider.agent_card.name
        records["supported_interfaces"] = [
            {
                "url": interface.url,
                "protocol_binding": interface.protocol_binding,
                "protocol_version": interface.protocol_version,
            }
            for interface in node.a2a_provider.agent_card.supported_interfaces
        ]
        if args.discovery_only:
            return {"records": records}
        for method in ("non_streaming", "streaming"):
            task = Task(content=args.prompt, thread_id=str(uuid.uuid4()))
            message = ChatMessage(role=Role.USER, content=args.prompt)
            delegate = (
                node._delegate_without_streaming
                if method == "non_streaming"
                else node._delegate_with_streaming
            )
            method_started = time.monotonic()
            try:
                response, metadata = delegate(message, task)
                outcome = node._create_agent_result(response, metadata)
                records[method] = {
                    "response": response.model_dump(mode="json"),
                    "metadata": metadata,
                    "agent_result": outcome.model_dump(mode="json"),
                    "elapsed_seconds": round(time.monotonic() - method_started, 4),
                }
            except Exception as error:  # noqa: BLE001 — preserve SDK failures as experiment evidence
                records[method] = {"error_type": type(error).__name__, "error": str(error)}
    except Exception as error:  # noqa: BLE001 — preserve setup failures as experiment evidence
        records["error_type"] = type(error).__name__
        records["error"] = str(error)
    records["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return {"records": records}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8140")
    parser.add_argument("--mode", choices=("direct", "mas-node"), default="direct")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--discovery-only", action="store_true")
    parser.add_argument("--cancel-in-stream", action="store_true")
    args = parser.parse_args()
    args.base_url = args.base_url.rstrip("/")
    result = {
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "mode": args.mode,
        "base_url": args.base_url,
        "synthetic_data_only": True,
        **(direct_probe(args) if args.mode == "direct" else mas_node_probe(args)),
    }
    write_record(args.output, result)
    print(json.dumps({"output": str(args.output.resolve()), **result.get("summary", {})}))


if __name__ == "__main__":
    main()
