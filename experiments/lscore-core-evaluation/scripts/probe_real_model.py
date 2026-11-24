#!/usr/bin/env python3
"""Run an isolated LSCore round trip against the native ATI PoC model connection.

Execute with ``.local/upstream/.venv/bin/python scripts/probe_real_model.py``
from the LSCore evaluation directory. Existing neutral MCP tools must be running.
Credentials are loaded internally, passed through environment references, and
excluded from sanitized evidence. Only the service process started here is stopped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        stream.write(text)


def replace_state_paths(value: Any, state_dir: Path) -> Any:
    if isinstance(value, dict):
        return {key: replace_state_paths(child, state_dir) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_state_paths(child, state_dir) for child in value]
    if isinstance(value, str) and value.startswith(".local/state/"):
        return str(state_dir / value.removeprefix(".local/state/"))
    return value


def sanitized(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: sanitized(child, replacements) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitized(child, replacements) for child in value]
    if isinstance(value, str):
        for source, replacement in replacements.items():
            if source:
                value = value.replace(source, replacement)
    return value


def http_json(url: str, timeout: float, body: dict | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read().decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw_response": raw}
        return response.status, payload


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8145)
    parser.add_argument("--scenario", choices=("baseline", "failure"), default="baseline")
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--output", type=Path, default=root / ".local/evidence/e1-real.json")
    parser.add_argument("--dotenv", type=Path, default=root.parents[1] / ".env")
    args = parser.parse_args()
    # Preserve an existing service on the requested port, even if it is unhealthy.
    with socket.socket() as check:
        if check.connect_ex(("127.0.0.1", args.port)) == 0:
            raise RuntimeError("The requested experiment port is already occupied")
    settings = dotenv_values(args.dotenv)
    keys = ("LSCORE_MODEL_BASE_URL", "LSCORE_MODEL_NAME", "LSCORE_MODEL_API_KEY")
    if not all(settings.get(key) for key in keys):
        raise RuntimeError("The native model settings are incomplete")
    model_url, model_name, model_key = (str(settings[key]) for key in keys)
    replacements = {
        model_key: "<redacted-api-key>",
        model_url: "<redacted-model-endpoint>",
        urllib.parse.urlparse(model_url).hostname or "": "<redacted-provider-host>",
    }
    source_path = root / "config/lscore-fixture.yaml"
    state_dir = root / ".local/state-real"
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = replace_state_paths(yaml.safe_load(source_path.read_text()), state_dir)
    config["name"] = "LSCore neutral real-model experiment"
    config["service"].update(port=args.port, base_url=f"http://127.0.0.1:{args.port}")
    config["customization"]["system_prompt"] = (
        "You are a neutral sample assessment assistant. Use read_sample to retrieve "
        "samples A and B, then calculate_total with their observed values. Never invent "
        "values. If a lookup fails, report a partial assessment and missing evidence. "
        "Follow the user's request_marker instruction in every tool invocation."
    )
    inference = config["inference"]
    inference.update(default_provider="real", default_model=model_name, max_infer_iters=8, max_tool_calls=8)
    provider = inference["providers"][0]
    provider["id"] = "real"
    provider["config"] = {
        "api_key": "${env.LSCORE_REAL_API_KEY}",
        "base_url": "${env.LSCORE_REAL_BASE_URL}",
    }
    provider["allowed_models"] = [{
        "name": model_name,
        "provider_model_id": model_name,
        "model_type": "llm",
        "metadata": {"context_window": 32768},
    }]
    config["ogx"]["config"]["native_override"]["providers"]["inference"] = [{
        "provider_id": "real",
        "provider_type": "remote::openai",
        "config": {
            "api_key": "${env.LSCORE_REAL_API_KEY}",
            "base_url": "${env.LSCORE_REAL_BASE_URL}",
            "allowed_models": [model_name],
        },
    }]
    private_config = root / ".local/config-real.yaml"
    write_private(private_config, yaml.safe_dump(config, sort_keys=False))
    private_log = root / ".local/logs/lscore-real.log"
    environment = os.environ.copy()
    environment.update(
        LSCORE_REAL_API_KEY=model_key,
        LSCORE_REAL_BASE_URL=model_url,
        OTEL_SDK_DISABLED="true",
    )
    marker = "e1-real-" + uuid.uuid4().hex[:12]
    prompt = (
        "Read A and B using read_sample, calculate their total with calculate_total, "
        "and report the total while citing both observed sample values. "
        f'Pass request_marker="{marker}" in every tool invocation.'
    )
    if args.scenario == "failure":
        prompt = (
            "Perform a synthetic partial-evidence test: read sample A, then attempt "
            "sample B using sample_id B_FAIL (the fixture deliberately makes B unavailable). "
            "Do not substitute another sample ID or invent a value for B. "
            "If B is unavailable, do not calculate a total; report the partial result, "
            "the observed value for A, and the missing evidence. "
            f'Pass request_marker="{marker}" in every tool invocation.'
        )
    request = {"query": prompt, "generate_topic_summary": False}
    evidence: dict[str, Any] = {
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "real_model": True,
        "scenario": args.scenario,
        "model": model_name,
        "provider_endpoint": "<redacted-model-endpoint>",
        "model_call_count": None,
        "model_call_count_note": "No provider-side request recording enabled; do not infer from tool rounds",
        "synthetic_tools_only": True,
        "request_marker": marker,
        "source_config_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "private_config_sha256": hashlib.sha256(private_config.read_bytes()).hexdigest(),
        "configuration_overrides": {
            "service_port": args.port,
            "state_directory": str(state_dir),
            "provider": "real",
            "max_infer_iters": 8,
            "max_tool_calls": 8,
            "endpoint_and_key": "Environment references in typed provider and documented OGX native_override",
        },
        "request": request,
        "expected": (
            {"sample_A": 4, "sample_B": 7, "total": 11}
            if args.scenario == "baseline"
            else {"sample_A": 4, "sample_B": "unavailable", "total": None}
        ),
    }
    service = None
    try:
        private_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with os.fdopen(os.open(private_log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as log:
            command = [
                str(root / ".local/upstream/.venv/bin/lightspeed-stack"),
                "-c", str(private_config),
                "--synthesized-config-output", str(root / ".local/synthesized-ogx-real.yaml"),
            ]
            service = subprocess.Popen(
                command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            evidence["service_pid"] = service.pid
            end = time.monotonic() + 60
            while time.monotonic() < end:
                if service.poll() is not None:
                    raise RuntimeError(f"LSCore exited during startup with code {service.returncode}; private log retained")
                try:
                    status, health = http_json(f"http://127.0.0.1:{args.port}/readiness", 1)
                    if status == 200:
                        evidence["health"] = {"status": status, "response": health}
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.5)
            else:
                raise TimeoutError("Isolated LSCore did not become healthy within 60 seconds")
            started = time.monotonic()
            evidence["http_status"], evidence["response"] = http_json(
                f"http://127.0.0.1:{args.port}/v1/query", args.timeout, request,
            )
            evidence["elapsed_seconds"] = round(time.monotonic() - started, 4)
            response = evidence["response"]
            tool_calls = response.get("tool_calls", []) if isinstance(response, dict) else []
            tool_results = response.get("tool_results", []) if isinstance(response, dict) else []
            actual_calls = [call for call in tool_calls if call.get("type") == "mcp_call"]
            evidence["tool_call_count"] = len(actual_calls)
            evidence["tool_discovery_count"] = len(tool_calls) - len(actual_calls)
            values: dict[str, Any] = {}
            for result in tool_results:
                if result.get("type") != "mcp_call" or result.get("status") != "success":
                    continue
                try:
                    content = json.loads(result.get("content", "{}"))
                except (TypeError, json.JSONDecodeError):
                    continue
                if "sample_id" in content:
                    values[content["sample_id"]] = content.get("value")
                if "total" in content:
                    values["total"] = content["total"]
            evidence["observed_tool_values"] = values
            evidence["verified_expected_tool_results"] = values == {"A": 4, "B": 7, "total": 11}
            if args.scenario == "failure":
                evidence["verified_partial_tool_path"] = (
                    values == {"A": 4}
                    and any(result.get("status") != "success" for result in tool_results)
                    and not any(call.get("name") == "calculate_total" for call in actual_calls)
                )
                evidence["verified_expected_tool_results"] = evidence["verified_partial_tool_path"]
            log_path = root / ".local/evidence/tool-calls.jsonl"
            evidence["fixture_tool_events"] = [
                item for line in log_path.read_text().splitlines()
                if (item := json.loads(line)).get("request_marker") == marker
            ] if log_path.exists() else []
    except Exception as error:  # noqa: BLE001 — record failures before guaranteed service cleanup
        evidence["error_type"] = type(error).__name__
        evidence["error"] = str(error)
    finally:
        if service is not None and service.poll() is None:
            os.killpg(service.pid, signal.SIGTERM)
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(service.pid, signal.SIGKILL)
                service.wait(timeout=5)
        evidence["own_service_stopped"] = service is not None and service.poll() is not None
        cleaned = sanitized(evidence, replacements)
        write_private(args.output, json.dumps(cleaned, indent=2) + "\n")
    print(json.dumps({
        "output": str(args.output.resolve()),
        "http_status": evidence.get("http_status"),
        "elapsed_seconds": evidence.get("elapsed_seconds"),
        "tool_call_count": evidence.get("tool_call_count"),
        "verified_expected_tool_results": evidence.get("verified_expected_tool_results"),
        "verified_partial_tool_path": evidence.get("verified_partial_tool_path"),
        "error_type": evidence.get("error_type"),
        "own_service_stopped": evidence["own_service_stopped"],
    }))


if __name__ == "__main__":
    main()
