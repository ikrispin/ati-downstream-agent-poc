"""Create a local MAS inventory entry/workflow, optionally submit an investigation."""

import argparse
import json
import time
from pathlib import Path

import httpx
from dotenv import dotenv_values

from ati_downstream.mas_selection import agent_config


def remote_task_id(value):
    if isinstance(value, dict):
        # A chat retains earlier turns. Prefer the newest execution packet
        # before looking through workspace snapshots containing older results.
        for packet in reversed(value.get("inter_packets", [])):
            found = remote_task_id(packet)
            if found:
                return found
        metadata = value.get("execution_metadata", {})
        if metadata.get("remote_agent") and metadata.get("a2a_task_id"):
            return metadata["a2a_task_id"]
        for child in value.values():
            found = remote_task_id(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in reversed(value):
            found = remote_task_id(child)
            if found:
                return found
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8111/api")
    parser.add_argument("--agent-url", default="http://127.0.0.1:8120")
    parser.add_argument("--name", default="ATI independent downstream — four sources")
    parser.add_argument("--prompt")
    args = parser.parse_args()
    token = dotenv_values(".env")["ATI_A2A_TOKEN"]
    with httpx.Client(
        base_url=args.api,
        headers={"Authorization": "Bearer local-poc"},
        timeout=30,
        limits=httpx.Limits(max_keepalive_connections=0),
    ) as client:

        def send(method, path, **kwargs):
            response = client.request(method, args.api + path, **kwargs)
            if response.is_error:
                raise RuntimeError(f"{path}: HTTP {response.status_code}: {response.text[:500]}")
            return response.json()

        with httpx.Client(timeout=10) as discovery:
            config = agent_config(discovery, args.agent_url, token)
        # Keep the saved resource visible in the real UI inventory.
        existing = send("GET", "/resources/resources.list")["resources"]
        match = next((r for r in existing if r["name"] == args.name), None)
        if match:
            resource = send(
                "PUT",
                "/resources/resource.update",
                json={"resourceId": match["rid"], "config": config, "name": args.name},
            )
        else:
            resource = send(
                "POST",
                "/resources/resource.save",
                json={
                    "category": "nodes",
                    "type": "a2a_agent_node",
                    "name": args.name,
                    "config": config,
                },
            )
        rid = resource["rid"]
        blueprint = {
            "name": args.name,
            "description": "Independent ATI through native outbound A2A",
            "nodes": [
                {
                    "rid": "input",
                    "name": "User question",
                    "type": "user_question_node",
                    "config": {"type": "user_question_node"},
                },
                {"rid": f"$ref:{rid}"},
                {
                    "rid": "final",
                    "name": "Final answer",
                    "type": "final_answer_node",
                    "config": {"type": "final_answer_node"},
                },
            ],
            "plan": [
                {"uid": "input", "node": "input"},
                {"uid": "ati", "node": rid, "after": "input"},
                {"uid": "answer", "node": "final", "after": "ati"},
            ],
        }
        blueprints = send("GET", "/blueprints/available.blueprints.summary.get")
        match = next((b for b in blueprints if b.get("name") == args.name), None)
        if match:
            blueprint_id = match["blueprint_id"]
            send(
                "PUT",
                "/blueprints/blueprint.update",
                json={"blueprintId": blueprint_id, "blueprintRaw": json.dumps(blueprint)},
            )
        else:
            blueprint_id = send(
                "POST", "/blueprints/blueprint.save", json={"blueprintRaw": json.dumps(blueprint)}
            )["blueprint_id"]
        outcome = {"blueprint_id": blueprint_id, "resource_id": rid}
        if args.prompt:
            session_id = send(
                "POST", "/sessions/user.session.create", json={"blueprintId": blueprint_id}
            )
            send(
                "POST",
                "/sessions/user.session.submit",
                json={"sessionId": session_id, "inputs": {"user_prompt": args.prompt}},
            )
            outcome["session_id"] = session_id
            print(json.dumps(outcome), flush=True)
            end = time.monotonic() + 300
            while time.monotonic() < end:
                state = send(
                    "GET", "/sessions/session.status.get", params={"sessionId": session_id}
                )
                status = state if isinstance(state, str) else state.get("status")
                if status in {"COMPLETED", "FAILED", "CANCELLED"}:
                    outcome["session_status"] = status
                    chat = send(
                        "GET", "/sessions/session.chat.get", params={"sessionId": session_id}
                    )
                    directory = Path(".local/verification")
                    directory.mkdir(parents=True, exist_ok=True)
                    (directory / f"{session_id}.json").write_text(json.dumps(chat, indent=2))
                    graph = send(
                        "GET", "/sessions/session.state.get", params={"sessionId": session_id}
                    )
                    remote_id = remote_task_id(graph)
                    if remote_id:
                        response = httpx.post(
                            args.agent_url + "/a2a/jsonrpc",
                            headers={"Authorization": f"Bearer {token}", "A2A-Version": "1.0"},
                            json={
                                "jsonrpc": "2.0",
                                "id": "record",
                                "method": "GetTask",
                                "params": {"id": remote_id},
                            },
                            timeout=10,
                        )
                        response.raise_for_status()
                        task = response.json().get("result", {})
                        task = task.get("task", task)
                        for artifact in task.get("artifacts", []):
                            for part in artifact.get("parts", []):
                                record = part.get("data", {})
                                if "run_id" in record:
                                    outcome["investigation_id"] = record["run_id"]
                                    outcome["ati_status"] = record["status"]
                                    outcome["source_status"] = {
                                        key: value["status"]
                                        for key, value in record["sources"].items()
                                    }
                                    record_path = directory / f"{session_id}.ati.json"
                                    record_path.write_text(json.dumps(record, indent=2))
                                    record_path.chmod(0o600)
                    break
                time.sleep(2)
            else:
                raise TimeoutError("MAS session did not reach a terminal status within 300s")
        print(json.dumps(outcome))


if __name__ == "__main__":
    main()
