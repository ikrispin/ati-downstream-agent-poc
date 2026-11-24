"""Register native LSCore with an existing local MAS; optionally exercise its workflow.

Run with the compatible MAS Python environment for its A2A Agent Card parser.
The helper never recovers model-printed JSON as a trusted structured ATI result.
"""

import argparse
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

NAME = "ATI native LSCore assessment"
RETIRED_NAME = "ATI independent downstream — four sources"


def local_api(value):
    url = urlsplit(value)
    if url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1"} or url.username:
        raise ValueError("This helper changes only loopback development services")
    return value.rstrip("/")


def request(client, method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    if response.is_error:
        raise RuntimeError(f"Local MAS returned HTTP {response.status_code}")
    return response.json()


def blueprint(name, resource_id):
    return {
        "name": name,
        "description": "Native LSCore owns the ATI model/tool loop; domain tools are read-only.",
        "nodes": [
            {
                "rid": "input",
                "name": "CVE assessment request",
                "type": "user_question_node",
                "config": {"type": "user_question_node"},
            },
            {"rid": f"$ref:{resource_id}"},
            {
                "rid": "final",
                "name": "Final answer",
                "type": "final_answer_node",
                "config": {"type": "final_answer_node"},
            },
        ],
        "plan": [
            {"uid": "input", "node": "input"},
            {"uid": "ati", "node": resource_id, "after": "input"},
            {"uid": "answer", "node": "final", "after": "ati"},
        ],
    }


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8111/api", type=local_api)
    parser.add_argument("--agent-url", default="http://127.0.0.1:8140", type=local_api)
    parser.add_argument("--prompt")
    parser.add_argument("--output", type=Path, default=Path(".local/reports/mas-native.json"))
    args = parser.parse_args()
    from a2a.client.card_resolver import parse_agent_card
    from google.protobuf.json_format import MessageToDict

    with httpx.Client(timeout=30, limits=httpx.Limits(max_keepalive_connections=0)) as client:
        raw_card = request(client, "GET", args.agent_url + "/.well-known/agent-card.json")
        card = MessageToDict(parse_agent_card(raw_card), preserving_proto_field_name=True)
        config = {
            "type": "a2a_agent_node",
            "base_url": args.agent_url,
            "agent_card": card,
            "retries": 0,
        }
        client.headers["Authorization"] = "Bearer local-poc"
        existing = request(client, "GET", args.api + "/resources/resources.list")["resources"]
        previous = next((x for x in existing if x["name"] in {NAME, RETIRED_NAME}), None)
        if previous:
            resource = request(
                client,
                "PUT",
                args.api + "/resources/resource.update",
                json={
                    "resourceId": previous["rid"],
                    "name": NAME,
                    "config": config,
                },
            )
        else:
            resource = request(
                client,
                "POST",
                args.api + "/resources/resource.save",
                json={
                    "category": "nodes",
                    "type": "a2a_agent_node",
                    "name": NAME,
                    "config": config,
                },
            )
        graph = blueprint(NAME, resource["rid"])
        existing = request(client, "GET", args.api + "/blueprints/available.blueprints.summary.get")
        previous = next((x for x in existing if x.get("name") in {NAME, RETIRED_NAME}), None)
        if previous:
            blueprint_id = previous["blueprint_id"]
            request(
                client,
                "PUT",
                args.api + "/blueprints/blueprint.update",
                json={
                    "blueprintId": blueprint_id,
                    "blueprintRaw": json.dumps(graph),
                },
            )
        else:
            blueprint_id = request(
                client,
                "POST",
                args.api + "/blueprints/blueprint.save",
                json={
                    "blueprintRaw": json.dumps(graph),
                },
            )["blueprint_id"]
        result = {
            "execution_owner": "lscore_native",
            "resource_id": resource["rid"],
            "blueprint_id": blueprint_id,
            "typed_ati_artifact_expected": False,
        }
        if args.prompt:
            session_id = request(
                client,
                "POST",
                args.api + "/sessions/user.session.create",
                json={
                    "blueprintId": blueprint_id,
                },
            )
            request(
                client,
                "POST",
                args.api + "/sessions/user.session.submit",
                json={
                    "sessionId": session_id,
                    "inputs": {"user_prompt": args.prompt},
                },
            )
            end = time.monotonic() + 300
            while time.monotonic() < end:
                state = request(
                    client,
                    "GET",
                    args.api + "/sessions/session.status.get",
                    params={"sessionId": session_id},
                )
                status = state if isinstance(state, str) else state.get("status")
                if status in {"COMPLETED", "FAILED", "CANCELLED"}:
                    result.update(
                        session_status=status,
                        chat=request(
                            client,
                            "GET",
                            args.api + "/sessions/session.chat.get",
                            params={"sessionId": session_id},
                        ),
                    )
                    break
                time.sleep(2)
            else:
                result["session_status"] = "CLIENT_WAIT_EXPIRED"
        private_json(args.output, result)
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in ("execution_owner", "typed_ati_artifact_expected", "session_status")
                    if key in result
                }
            )
        )


if __name__ == "__main__":
    main()
