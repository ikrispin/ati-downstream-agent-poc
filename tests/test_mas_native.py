import importlib.util
from pathlib import Path

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/mas_native.py"


@pytest.fixture
def helper():
    spec = importlib.util.spec_from_file_location("mas_native", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_blueprint_delegates_to_native_a2a_without_an_ati_executor(helper):
    blueprint = helper.blueprint("Native ATI", "agent-resource")
    assert [step["node"] for step in blueprint["plan"]] == ["input", "agent-resource", "final"]
    assert {node["type"] for node in blueprint["nodes"] if "type" in node} == {
        "user_question_node",
        "final_answer_node",
    }


def test_only_loopback_development_services_can_be_changed(helper):
    for url in ("https://external.invalid/api", "http://localhost@external.invalid/api"):
        with pytest.raises(ValueError):
            helper.local_api(url)
    assert helper.local_api("http://127.0.0.1:8111/api") == "http://127.0.0.1:8111/api"


def test_api_failures_do_not_expose_response_bodies(helper):
    with httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(500, text="PRIVATE RESPONSE"))
    ) as client:
        with pytest.raises(RuntimeError) as caught:
            helper.request(client, "GET", "http://localhost/test")
    assert "PRIVATE" not in str(caught.value)
