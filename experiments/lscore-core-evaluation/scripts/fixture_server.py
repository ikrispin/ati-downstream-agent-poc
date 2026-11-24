#!/usr/bin/env python3
"""Local deterministic OpenAI chat fixture; never calls an external service.

User controls: [fixture:normal|parallel|loop|failure|invalid|model_error|skill],
[request:marker], [delay:seconds] (or delay-a/delay-b).
System control: OUTPUT_MARKER=one_word. This verifies prompt transmission only,
not a real model's ability to follow instructions.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

LOG_PATH: Path | None = None
LOG_LOCK = threading.Lock()


def log_record(event: str, **fields: Any) -> None:
    """Keep synthetic request bodies for protocol and prompt evidence."""
    if LOG_PATH is None:
        return
    record = {"event": event, "time": time.time(), "monotonic": time.monotonic(), **fields}
    with LOG_LOCK, LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")


def content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(content_text(item) for item in content)
    if isinstance(content, dict):
        return content_text(content.get("text", content.get("content", "")))
    return str(content) if content is not None else ""


def control(text: str, key: str, default: str = "") -> str:
    match = re.search(r"\[" + re.escape(key) + r":([^\]]+)\]", text, re.IGNORECASE)
    return match.group(1).strip() if match else default


def select_tool(tools: list[dict[str, Any]], suffix: str) -> str | None:
    for item in tools:
        name = item.get("function", item).get("name", "")
        if name.endswith(suffix):
            return name
    return None


def decoded_content(content: Any) -> Any:
    """Decode MCP text content, including the envelope used by OGX."""
    if isinstance(content, str):
        try:
            return decoded_content(json.loads(content))
        except (ValueError, TypeError):
            return content
    if isinstance(content, list):
        decoded = [decoded_content(item) for item in content]
        return decoded[0] if len(decoded) == 1 else decoded
    if isinstance(content, dict):
        if "value" in content or "total" in content:
            return content
        if "structuredContent" in content:
            return decoded_content(content["structuredContent"])
        for key in ("text", "content", "output", "result"):
            if key in content:
                return decoded_content(content[key])
    return content


def make_message(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    messages = body.get("messages", [])
    user_indices = [i for i, message in enumerate(messages) if message.get("role") == "user"]
    controlled_indices = [
        i for i in user_indices
        if re.search(r"\[(?:fixture|request):[^\]]+\]", content_text(messages[i].get("content")), re.IGNORECASE)
    ]
    # Validation feedback is a later user message in the outer agent loop.
    # Retain the experiment controls and tool history from the actual request.
    last_user = max(controlled_indices or user_indices, default=-1)
    user = content_text(messages[last_user].get("content")) if last_user >= 0 else ""
    mode = control(user, "fixture", "normal")
    marker = control(user, "request", "anonymous")
    system = "\n".join(content_text(m.get("content")) for m in messages if m.get("role") in ("system", "developer"))
    tools = body.get("tools", [])
    read_name = select_tool(tools, "read_sample")
    calculate_name = select_tool(tools, "calculate_total")
    calls_by_id: dict[str, dict[str, Any]] = {}
    observations: list[tuple[dict[str, Any], Any, str]] = []
    for message in messages[last_user + 1 :]:
        for call in message.get("tool_calls", []) or []:
            calls_by_id[call.get("id", "")] = call
        if message.get("role") == "tool":
            raw = content_text(message.get("content"))
            observations.append((calls_by_id.get(message.get("tool_call_id", ""), {}), decoded_content(message.get("content")), raw))

    instruction_text = system + "\n" + "\n".join(raw for _, _, raw in observations)
    output_markers = re.findall(r"OUTPUT_MARKER\s*=\s*([A-Za-z0-9_.:-]+)", instruction_text)
    suffix = f" OUTPUT_MARKER={output_markers[-1]}" if output_markers else ""
    skill_tokens = re.findall(r"SKILL_TOKEN\s*=\s*([A-Za-z0-9_.:-]+)", "\n".join(raw for _, _, raw in observations))
    if skill_tokens:
        suffix += f" SKILL_TOKEN={skill_tokens[-1]}"

    facts: dict[str, int | float] = {}
    total: int | float | None = None
    failed = False
    for call, value, raw in observations:
        function = call.get("function", {})
        try:
            arguments = json.loads(function.get("arguments", "{}"))
        except (ValueError, TypeError):
            arguments = {}
        name = function.get("name", "")
        if isinstance(value, dict) and "value" in value:
            sample_id = value.get("sample_id", arguments.get("sample_id", "unknown"))
            facts[sample_id] = value["value"]
        if isinstance(value, dict) and "total" in value:
            total = value["total"]
        if any(word in raw.lower() for word in ("error", "failed", "unavailable", "exception")):
            failed = True
        if name.endswith("calculate_total") and not isinstance(value, dict):
            failed = True

    metadata = {"mode": mode, "request_marker": marker, "observations": len(observations), "facts": facts, "total": total}

    def answer(text: str) -> dict[str, Any]:
        return {"role": "assistant", "content": f"{text} request={marker}.{suffix}"}

    def tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"id": "call_" + uuid.uuid4().hex[:16], "type": "function", "function": {"name": name, "arguments": json.dumps(arguments, separators=(",", ":"))}}

    def read(sample: str) -> dict[str, Any]:
        delay = float(control(user, "delay-" + sample.lower(), control(user, "delay", "0")))
        return tool(read_name or "read_sample", {"sample_id": sample, "delay_seconds": delay, "request_marker": marker})

    if body.get("tool_choice") == "none":
        return answer(f"INCOMPLETE: tools are disabled; observed={json.dumps(facts, sort_keys=True)}; total unverified."), metadata
    if mode == "skill":
        observed_names = {call.get("function", {}).get("name", "") for call, _, _ in observations}
        for skill_tool, arguments in (
            ("list_skills", {}),
            ("load_skill", {"skill_name": "neutral-assessment"}),
            ("read_skill_resource", {"skill_name": "neutral-assessment", "resource_name": "references/outcome.md"}),
        ):
            if not any(name.endswith(skill_tool) for name in observed_names):
                selected = select_tool(tools, skill_tool)
                if selected:
                    return {"role": "assistant", "content": None, "tool_calls": [tool(selected, arguments)]}, metadata
                return answer(f"INCOMPLETE: required skill tool {skill_tool} unavailable."), metadata
        if skill_tokens:
            return answer("COMPLETE: skill listing, loading, and resource read observed."), metadata
        return answer("INCOMPLETE: skill resource token unverified."), metadata
    if mode == "loop":
        if read_name:
            return {"role": "assistant", "content": None, "tool_calls": [read("A")]}, metadata
        return answer("INCOMPLETE: read_sample tool unavailable."), metadata
    if mode == "invalid" and not observations and read_name:
        return {"role": "assistant", "content": None, "tool_calls": [tool(read_name, {"unexpected": True})]}, metadata
    if failed:
        return answer(f"PARTIAL: successful samples={json.dumps(facts, sort_keys=True)}; a tool failed; missing sample unavailable; total unverified."), metadata
    if total is not None:
        return answer(f"COMPLETE: samples={json.dumps(facts, sort_keys=True)}; total={total}."), metadata
    if not read_name or not calculate_name:
        return answer("INCOMPLETE: required fixture tools unavailable."), metadata
    calls = []
    if "A" not in facts:
        calls.append(read("A"))
    if "B" not in facts and (mode == "parallel" or not calls):
        calls.append(read("B_FAIL" if mode == "failure" else "B"))
    if not calls:
        calls.append(tool(calculate_name, {"values": [facts["A"], facts["B"]], "request_marker": marker}))
    return {"role": "assistant", "content": None, "tool_calls": calls}, metadata


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        pass

    def send_json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/models", "/v1/models"):
            self.send_json(200, {"object": "list", "data": [{"id": "neutral-fixture", "object": "model", "created": 0, "owned_by": "local-experiment"}]})
        elif self.path == "/health":
            self.send_json(200, {"status": "ok", "fixture": True})
        else:
            self.send_json(404, {"error": {"message": "Unknown local fixture endpoint"}})

    def do_POST(self) -> None:
        if self.path.rstrip("/") not in ("/chat/completions", "/v1/chat/completions"):
            self.send_json(404, {"error": {"message": "Unknown local fixture endpoint"}})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            message, metadata = make_message(body)
        except (ValueError, TypeError, KeyError) as error:
            self.send_json(400, {"error": {"message": str(error), "type": "invalid_request_error"}})
            return
        response_id = "chatcmpl-fixture-" + uuid.uuid4().hex
        created = int(time.time())
        log_record("model_request", response_id=response_id, body=body, **metadata)
        if metadata["mode"] == "model_error":
            log_record("model_error", response_id=response_id, status=500)
            self.send_json(500, {"error": {"message": "Injected local model failure", "type": "server_error", "code": "fixture_failure"}})
            return
        finish = "tool_calls" if message.get("tool_calls") else "stop"
        common = {"id": response_id, "created": created, "model": body.get("model", "neutral-fixture")}
        log_record("model_response", response_id=response_id, stream=bool(body.get("stream")), message=message, finish_reason=finish)
        if not body.get("stream"):
            self.send_json(200, {**common, "object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def event(delta: dict[str, Any], reason: str | None = None) -> None:
            payload = {**common, "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": reason}]}
            self.wfile.write(("data: " + json.dumps(payload) + "\n\n").encode("utf-8"))
            self.wfile.flush()

        try:
            event({"role": "assistant", "content": ""})
            if message.get("tool_calls"):
                for index, call in enumerate(message["tool_calls"]):
                    # Split arguments to exercise legitimate incremental SSE chunks.
                    arguments = call["function"]["arguments"]
                    split = max(1, len(arguments) // 2)
                    event({"tool_calls": [{"index": index, "id": call["id"], "type": "function", "function": {"name": call["function"]["name"], "arguments": arguments[:split]}}]})
                    event({"tool_calls": [{"index": index, "function": {"arguments": arguments[split:]}}]})
            else:
                content = message["content"]
                for start in range(0, len(content), 48):
                    event({"content": content[start : start + 48]})
            event({}, finish)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            log_record("model_client_disconnected", response_id=response_id)


def main() -> None:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18141)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    LOG_PATH = args.log
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    log_record("model_fixture_started", host=args.host, port=args.port)
    print(f"Local model fixture listening at http://{args.host}:{args.port}/v1", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
