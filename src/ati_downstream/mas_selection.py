"""Register capability cards and exercise native MAS planning between two A2A agents."""

import argparse
import json
import os
import time
from pathlib import Path

import httpx
from a2a.types import AgentCard
from google.protobuf.json_format import MessageToDict, ParseDict

from .config import Settings

ATI_NAME = "ATI independent downstream — four sources"
ARITHMETIC_NAME = "Arithmetic reference agent"
WORKFLOW_NAME = "Downstream agent selection — ATI and arithmetic"


def request(client, method, path, **kwargs):
    response = client.request(method, path.lstrip("/"), **kwargs)
    if response.is_error:
        raise RuntimeError(f"MAS {method} {path} returned HTTP {response.status_code}")
    return response.json()


def fetch_agent_card(client, base_url):
    response = client.get(base_url.rstrip("/") + "/.well-known/agent-card.json")
    response.raise_for_status()
    card = response.json()
    if not all(card.get(key) for key in ("name", "description", "skills")):
        raise ValueError("Agent Card must describe the agent's capabilities and skills")
    return MessageToDict(ParseDict(card, AgentCard()), preserving_proto_field_name=True)


def agent_config(client, base_url, token):
    return {
        "type": "a2a_agent_node",
        "base_url": base_url.rstrip("/"),
        "bearer_token": token,
        "agent_card": fetch_agent_card(client, base_url),
        "retries": 0,
    }


def save_resource(client, category, kind, name, config):
    items = request(client, "GET", "resources/resources.list")["resources"]
    previous = next((item for item in items if item["name"] == name), None)
    if previous:
        result = request(
            client,
            "PUT",
            "resources/resource.update",
            json={
                "resourceId": previous["rid"],
                "name": name,
                "config": config,
            },
        )
    else:
        result = request(
            client,
            "POST",
            "resources/resource.save",
            json={
                "category": category,
                "type": kind,
                "name": name,
                "config": config,
            },
        )
    return result["rid"]


def build_blueprint(name, ati_rid, arithmetic_rid, llm_rid):
    return {
        "name": name,
        "description": "Native MAS planner selects an independent agent from its capability card.",
        "conditions": [
            {
                "rid": "route",
                "name": "Delegation routing",
                "type": "router_direct",
                "config": {"type": "router_direct"},
            }
        ],
        "nodes": [
            {
                "rid": "input",
                "name": "User question",
                "type": "user_question_node",
                "config": {"type": "user_question_node"},
            },
            {
                "rid": "coordinator",
                "name": "Downstream selection coordinator",
                "type": "orchestrator_node",
                "config": {
                    "type": "orchestrator_node",
                    "llm": f"$ref:{llm_rid}",
                    "retries": 0,
                    "max_rounds": 12,
                    "system_message": (
                        "Select workers using their advertised capabilities. Delegate supported "
                        "requests to the matching worker instead of performing that work yourself. "
                        "Preserve identifiers and the user's current request in delegated tasks. "
                        "Do not assign unrelated work to a specialist. If no capability matches "
                        "or necessary inputs are missing, explain the limitation or ask for them."
                    ),
                },
            },
            {"rid": f"$ref:{ati_rid}"},
            {"rid": f"$ref:{arithmetic_rid}"},
            {
                "rid": "final",
                "name": "Final answer",
                "type": "final_answer_node",
                "config": {"type": "final_answer_node"},
            },
        ],
        "plan": [
            {"uid": "input", "node": "input"},
            {
                "uid": "coordinator",
                "node": "coordinator",
                "after": ["input", "ati", "arithmetic"],
                "exit_condition": "route",
                "branches": {"ati": "ati", "arithmetic": "arithmetic", "finalize": "finalize"},
            },
            {"uid": "ati", "node": ati_rid},
            {"uid": "arithmetic", "node": arithmetic_rid},
            {"uid": "finalize", "node": "final"},
        ],
    }


def remote_dispatches(state):
    found = {}

    def visit(value):
        if isinstance(value, dict):
            metadata = value.get("execution_metadata", {})
            task_id = metadata.get("a2a_task_id")
            if metadata.get("remote_agent") and task_id and value.get("agent_id"):
                item = {
                    "agent_uid": value["agent_id"],
                    "task_id": task_id,
                    "status": metadata.get("a2a_status"),
                }
                found[(item["agent_uid"], task_id)] = item
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(state)
    return sorted(found.values(), key=lambda item: (item["agent_uid"], item["task_id"]))


def require_selection(outcome, expected):
    selected = {task["agent_uid"] for task in outcome["remote_tasks"]}
    wanted = set() if expected == "none" else {expected}
    if (
        outcome["session_status"] != "COMPLETED"
        or selected != wanted
        or not outcome.get("answer_succeeded")
        or any(task.get("status") != "completed" for task in outcome["remote_tasks"])
    ):
        raise RuntimeError(
            f"Agent selection verification failed: expected {expected}, got {selected}"
        )


def final_answer_succeeded(state):
    for packet in reversed(state.get("inter_packets", [])):
        result = packet.get("payload", {}).get("result", {})
        if result.get("agent_id") == "coordinator":
            return result.get("success") is True and bool(state.get("output"))
    return False


def save_blueprint(client, blueprint):
    items = request(client, "GET", "blueprints/available.blueprints.summary.get")
    previous = next((item for item in items if item.get("name") == blueprint["name"]), None)
    if previous:
        request(
            client,
            "PUT",
            "blueprints/blueprint.update",
            json={
                "blueprintId": previous["blueprint_id"],
                "blueprintRaw": json.dumps(blueprint),
            },
        )
        return previous["blueprint_id"]
    return request(
        client, "POST", "blueprints/blueprint.save", json={"blueprintRaw": json.dumps(blueprint)}
    )["blueprint_id"]


def save_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as file:
        json.dump(value, file, indent=2)


def run_session(client, blueprint_id, prompt, timeout):
    session_id = request(
        client, "POST", "sessions/user.session.create", json={"blueprintId": blueprint_id}
    )
    request(
        client,
        "POST",
        "sessions/user.session.submit",
        json={"sessionId": session_id, "inputs": {"user_prompt": prompt}},
    )
    print(json.dumps({"session_id": session_id}), flush=True)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        state = request(
            client, "GET", "sessions/session.status.get", params={"sessionId": session_id}
        )
        status = state if isinstance(state, str) else state.get("status")
        if status in {"COMPLETED", "FAILED", "CANCELLED"}:
            graph = request(
                client, "GET", "sessions/session.state.get", params={"sessionId": session_id}
            )
            chat = request(
                client, "GET", "sessions/session.chat.get", params={"sessionId": session_id}
            )
            directory = Path(".local/verification/selection")
            save_private(directory / f"{session_id}.state.json", graph)
            save_private(directory / f"{session_id}.chat.json", chat)
            return {
                "session_id": session_id,
                "session_status": status,
                "remote_tasks": remote_dispatches(graph),
                "answer_succeeded": final_answer_succeeded(graph),
            }
        time.sleep(2)
    raise TimeoutError(f"MAS selection session {session_id} did not finish within {timeout}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8111/api")
    parser.add_argument("--agent-url", default="http://127.0.0.1:8120")
    parser.add_argument("--arithmetic-url", default="http://127.0.0.1:8123")
    parser.add_argument("--prompt")
    parser.add_argument("--expect-agent", choices=["ati", "arithmetic", "none"])
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    if args.expect_agent and not args.prompt:
        parser.error("--expect-agent requires --prompt")
    settings = Settings.load()
    if not all((settings.token, settings.model_url, settings.model_name, settings.model_key)):
        raise ValueError("Configure ATI_A2A_TOKEN and ATI_LLM_* in the private .env file")
    with httpx.Client(
        base_url=args.api.rstrip("/") + "/",
        timeout=30,
        headers={"Authorization": "Bearer local-poc"},
        limits=httpx.Limits(max_keepalive_connections=0),
    ) as client:
        # Agent discovery is public; never forward the MAS credential to a remote agent.
        with httpx.Client(timeout=10) as discovery:
            ati = agent_config(discovery, args.agent_url, settings.token)
            arithmetic = agent_config(discovery, args.arithmetic_url, settings.token)
        ati_rid = save_resource(client, "nodes", "a2a_agent_node", ATI_NAME, ati)
        arithmetic_rid = save_resource(
            client, "nodes", "a2a_agent_node", ARITHMETIC_NAME, arithmetic
        )
        llm_rid = save_resource(
            client,
            "llms",
            "openai_compatible",
            "Downstream selection planner",
            {
                "type": "openai_compatible",
                "model_name": settings.model_name,
                "base_url": settings.model_url,
                "api_key": settings.model_key,
                "temperature": 0,
                "max_tokens": 4096,
            },
        )
        blueprint_id = save_blueprint(
            client,
            build_blueprint(
                WORKFLOW_NAME,
                ati_rid,
                arithmetic_rid,
                llm_rid,
            ),
        )
        outcome = {
            "blueprint_id": blueprint_id,
            "ati_resource_id": ati_rid,
            "arithmetic_resource_id": arithmetic_rid,
        }
        if args.prompt:
            outcome.update(run_session(client, blueprint_id, args.prompt, args.timeout))
            save_private(
                Path(".local/verification/selection") / f"{outcome['session_id']}.summary.json",
                outcome,
            )
            if args.expect_agent:
                require_selection(outcome, args.expect_agent)
        print(json.dumps(outcome))


if __name__ == "__main__":
    main()
