#!/usr/bin/env python3
"""Bounded HTTP experiments against an unmodified, locally configured LSCore.

Fixtures and their raw logs are synthetic. This script does not configure or
patch the service, contact real sources, or select a framework.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def events_from_sse(body: str) -> list[dict]:
    events = []
    for line in body.splitlines():
        if line.startswith("data:"):
            try:
                item = json.loads(line[5:].strip())
            except ValueError:
                continue
            if isinstance(item, dict):
                events.append(item)
    return events


def intervals(records: list[dict], marker: str) -> list[dict]:
    starts = {}
    result = []
    for item in records:
        if item.get("request_marker") != marker:
            continue
        if item.get("event") == "tool_start":
            starts[item["call_id"]] = item
        elif item.get("event") == "tool_end" and item["call_id"] in starts:
            start = starts[item["call_id"]]
            result.append({
                "tool": item["tool"],
                "sample_id": item.get("sample_id"),
                "start": start["monotonic"],
                "end": item["monotonic"],
                "duration_seconds": round(item["monotonic"] - start["monotonic"], 4),
                "status": item.get("status"),
            })
    return result


def overlaps(a: dict, b: dict) -> bool:
    return max(a["start"], b["start"]) < min(a["end"], b["end"])


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8140")
    parser.add_argument("--evidence", type=Path, default=Path(".local/evidence"))
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    results = {"started_at": datetime.now(UTC).isoformat(), "base_url": args.base_url,
               "model_kind": "deterministic_fixture", "cases": {}}
    prefix = "probe-" + str(time.time_ns())[-10:]

    async with httpx.AsyncClient(timeout=40) as client:
        async def query(name: str, mode: str = "normal", *, stream=False,
                        controls="", conversation_id=None) -> dict:
            marker = f"{prefix}-{name}"
            payload = {"query": f"Read synthetic samples A and B and calculate their total. "
                       f"[fixture:{mode}] [request:{marker}] {controls}",
                       "generate_topic_summary": False}
            if conversation_id:
                payload["conversation_id"] = conversation_id
            started = time.monotonic()
            try:
                response = await client.post(
                    args.base_url + ("/v1/streaming_query" if stream else "/v1/query"),
                    json=payload,
                )
                events = events_from_sse(response.text) if stream else []
                data = response.json() if not stream else None
                record = {"marker": marker, "http_status": response.status_code,
                          "elapsed_seconds": round(time.monotonic() - started, 4),
                          "request": payload, "response": data, "events": events}
                if stream:
                    record["event_types"] = [e.get("event") for e in events]
                    record["answer"] = "".join(
                        str(e.get("data", {}).get("token", e.get("data", {}).get("text", "")))
                        for e in events if e.get("event") in {"token", "response", "text"}
                    )
                else:
                    record["answer"] = data.get("response", "") if isinstance(data, dict) else ""
                    record["conversation_id"] = data.get("conversation_id") if isinstance(data, dict) else None
            except (httpx.HTTPError, ValueError) as error:
                record = {"marker": marker, "elapsed_seconds": round(time.monotonic() - started, 4),
                          "client_error": type(error).__name__, "request": payload}
            results["cases"][name] = record
            (args.evidence / f"{name}.json").write_text(json.dumps(record, indent=2) + "\n")
            print(name, record.get("http_status", record.get("client_error")),
                  record["elapsed_seconds"], str(record.get("answer", ""))[:160], flush=True)
            return record

        await query("e1-normal")
        await query("e4-parallel-query", "parallel", controls="[delay:0.7]")
        await query("e4-parallel-stream", "parallel", stream=True, controls="[delay:0.7]")
        await asyncio.gather(
            query("e4-concurrent-a", "parallel", controls="[delay:0.7]"),
            query("e4-concurrent-b", "parallel", controls="[delay:0.7]"),
        )
        await query("e5-tool-timeout", "parallel", controls="[delay:1.2]")
        await query("e5-loop", "loop")
        await query("e5-loop-stream", "loop", stream=True)
        await query("e7-failure", "failure")
        await query("e7-invalid", "invalid")
        await query("e7-model-error", "model_error")
        a = await query("e6-isolation-a")
        await query("e6-isolation-b")
        if a.get("conversation_id"):
            await query("e6-followup-a", conversation_id=a["conversation_id"])

    tools = read_jsonl(args.evidence / "tool-calls.jsonl")
    models = read_jsonl(args.evidence / "model-calls.jsonl")
    for record in results["cases"].values():
        record["tool_intervals"] = intervals(tools, record["marker"])
        reads = [i for i in record["tool_intervals"] if i["tool"] == "read_sample"]
        record["sample_reads_overlap"] = any(overlaps(a, b) for i, a in enumerate(reads) for b in reads[i+1:])
        record["fixture_model_requests"] = sum(
            1 for r in models if r.get("event") == "model_request"
            and r.get("request_marker") == record["marker"]
        )
    concurrent = [results["cases"][name] for name in ("e4-concurrent-a", "e4-concurrent-b")]
    results["cross_request_tools_overlap"] = any(
        overlaps(a, b) for a in concurrent[0]["tool_intervals"] for b in concurrent[1]["tool_intervals"]
    )
    a_marker = results["cases"]["e6-isolation-a"]["marker"]
    b_marker = results["cases"]["e6-isolation-b"]["marker"]
    follow_marker = results["cases"].get("e6-followup-a", {}).get("marker")
    def bodies_for(marker):
        return [json.dumps(m.get("body", {})) for m in models
                if m.get("event") == "model_request" and m.get("request_marker") == marker]
    results["state_checks"] = {
        "a_marker_absent_from_b_model_input": all(a_marker not in body for body in bodies_for(b_marker)),
        "b_marker_absent_from_a_model_input": all(b_marker not in body for body in bodies_for(a_marker)),
        "followup_retains_own_prior_marker": any(a_marker in body for body in bodies_for(follow_marker)),
        "followup_excludes_other_conversation": all(b_marker not in body for body in bodies_for(follow_marker)),
        "a_model_requests_observed": len(bodies_for(a_marker)),
        "b_model_requests_observed": len(bodies_for(b_marker)),
        "followup_model_requests_observed": len(bodies_for(follow_marker)),
    }
    results["completed_at"] = datetime.now(UTC).isoformat()
    output = args.evidence / "fixture-results.json"
    output.write_text(json.dumps(results, indent=2) + "\n")
    print("Saved", output, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
