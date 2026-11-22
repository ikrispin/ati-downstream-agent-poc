import httpx
import pytest

from ati_downstream.mas_selection import (
    agent_config,
    build_blueprint,
    fetch_agent_card,
    final_answer_succeeded,
    remote_dispatches,
    request,
    require_selection,
    run_session,
    save_resource,
)


def card():
    return {
        "name": "ATI",
        "description": "Investigates a supplied vulnerability identifier.",
        "skills": [{"id": "investigate", "name": "Investigation", "description": "CVE research"}],
    }


def test_remote_capabilities_are_saved_in_the_mas_node_configuration():
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=card()))
    ) as client:
        config = agent_config(client, "http://agent/", "private-token")
    assert config["agent_card"] == card()
    assert config["base_url"] == "http://agent"


@pytest.mark.parametrize("value", [{}, {"name": "Agent", "description": "", "skills": []}])
def test_uninformative_agent_card_is_rejected(value):
    with (
        httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json=value))
        ) as client,
        pytest.raises(ValueError, match="capabilit"),
    ):
        fetch_agent_card(client, "http://agent")


def test_http_card_field_names_are_normalized_for_mas_protobuf_configuration():
    advertised = {
        **card(),
        "defaultInputModes": ["text/plain"],
        "supportedInterfaces": [
            {
                "url": "http://agent/a2a/jsonrpc",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
    }
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=advertised))
    ) as client:
        stored = fetch_agent_card(client, "http://agent")
    assert stored["default_input_modes"] == ["text/plain"]
    assert stored["supported_interfaces"][0]["protocol_binding"] == "JSONRPC"


def test_the_planner_can_choose_both_agents_and_receive_their_responses():
    blueprint = build_blueprint("Selection", "ati-resource", "math-resource", "model-resource")
    steps = {step["uid"]: step for step in blueprint["plan"]}
    assert steps["coordinator"]["branches"] == {
        "ati": "ati",
        "arithmetic": "arithmetic",
        "finalize": "finalize",
    }
    assert set(steps["coordinator"]["after"]) == {"input", "ati", "arithmetic"}
    assert steps["ati"].get("after") is None
    assert steps["arithmetic"].get("after") is None
    assert {"rid": "$ref:ati-resource"} in blueprint["nodes"]
    assert {"rid": "$ref:math-resource"} in blueprint["nodes"]
    assert "api_key" not in str(blueprint)


def test_existing_resource_is_updated_without_changing_its_identity():
    calls = []

    def respond(request):
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(200, json={"resources": [{"rid": "original", "name": "ATI"}]})
        return httpx.Response(200, json={"rid": "original"})

    with httpx.Client(base_url="http://mas/api/", transport=httpx.MockTransport(respond)) as client:
        assert save_resource(client, "nodes", "a2a_agent_node", "ATI", {}) == "original"
    assert calls == [
        ("GET", "/api/resources/resources.list"),
        ("PUT", "/api/resources/resource.update"),
    ]


def test_dispatch_evidence_requires_a_remote_task_and_is_not_just_a_planned_branch():
    result = {
        "agent_id": "ati",
        "execution_metadata": {
            "remote_agent": True,
            "a2a_task_id": "task-1",
            "a2a_status": "completed",
        },
    }
    state = {
        "planned_nodes": {"ati": {}, "arithmetic": {}},
        "inter_packets": [{"payload": result}],
        "workspaces": {"copy": result},
    }
    assert remote_dispatches(state) == [
        {"agent_uid": "ati", "task_id": "task-1", "status": "completed"}
    ]
    require_selection(
        {
            "session_status": "COMPLETED",
            "remote_tasks": remote_dispatches(state),
            "answer_succeeded": True,
        },
        "ati",
    )


@pytest.mark.parametrize(
    "tasks",
    [
        [],
        [{"agent_uid": "arithmetic", "task_id": "t"}],
        [{"agent_uid": "ati"}, {"agent_uid": "arithmetic"}],
    ],
)
def test_wrong_or_missing_delegation_fails_verification(tasks):
    with pytest.raises(RuntimeError, match="selection"):
        require_selection({"session_status": "COMPLETED", "remote_tasks": tasks}, "ati")


def test_failed_session_cannot_pass_selection_verification():
    with pytest.raises(RuntimeError, match="selection"):
        require_selection({"session_status": "FAILED", "remote_tasks": []}, "ati")


def test_successful_delegation_with_failed_synthesis_is_not_a_successful_workflow():
    state = {
        "output": "Model rejected synthesis",
        "inter_packets": [
            {"payload": {"result": {"agent_id": "arithmetic", "success": True}}},
            {"payload": {"result": {"agent_id": "coordinator", "success": False}}},
        ],
    }
    assert not final_answer_succeeded(state)
    with pytest.raises(RuntimeError, match="selection"):
        require_selection(
            {
                "session_status": "COMPLETED",
                "answer_succeeded": False,
                "remote_tasks": [
                    {"agent_uid": "arithmetic", "task_id": "t", "status": "completed"}
                ],
            },
            "arithmetic",
        )


def test_successful_coordinator_answer_is_required():
    assert final_answer_succeeded(
        {
            "output": "84",
            "inter_packets": [
                {"payload": {"result": {"agent_id": "coordinator", "success": True}}}
            ],
        }
    )
    assert not final_answer_succeeded({"output": "84", "inter_packets": []})


def test_a_request_without_a_matching_agent_can_finish_without_delegation():
    require_selection(
        {"session_status": "COMPLETED", "answer_succeeded": True, "remote_tasks": []}, "none"
    )


def test_completed_session_records_private_evidence_and_checks_the_final_answer(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    graph = {
        "output": "84",
        "inter_packets": [{"payload": {"result": {"agent_id": "coordinator", "success": True}}}],
    }
    submits = []

    def respond(req):
        if req.url.path.endswith("user.session.create"):
            return httpx.Response(200, json="session-1")
        if req.url.path.endswith("user.session.submit"):
            submits.append(req)
            return httpx.Response(202, json={})
        if req.url.path.endswith("session.status.get"):
            return httpx.Response(200, json="COMPLETED")
        return httpx.Response(200, json=graph)

    with httpx.Client(base_url="http://mas/api/", transport=httpx.MockTransport(respond)) as c:
        result = run_session(c, "workflow", "Calculate 12 * 7", 1)
    assert result["answer_succeeded"] is True
    assert len(submits) == 1
    saved = tmp_path / ".local/verification/selection/session-1.state.json"
    assert saved.stat().st_mode & 0o777 == 0o600


def test_api_errors_do_not_print_response_bodies_that_may_contain_credentials():
    with (
        httpx.Client(
            base_url="http://mas/api/",
            transport=httpx.MockTransport(
                lambda r: httpx.Response(400, text="private credential in server validation output")
            ),
        ) as c,
        pytest.raises(RuntimeError) as error,
    ):
        request(c, "POST", "resources/resource.save", json={})
    assert "private credential" not in str(error.value)
