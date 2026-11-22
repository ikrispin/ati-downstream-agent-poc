import httpx
import pytest

from ati_downstream.selection_reference import calculate, create_app


@pytest.mark.parametrize(
    "question,answer",
    [
        ("Calculate 12 * 7", "84"),
        ("What is 2.5 + 0.5?", "3"),
        ("Compute -2 - 3", "-5"),
        ("Calculate 9 / 2", "4.5"),
    ],
)
def test_reference_agent_performs_only_the_advertised_arithmetic(question, answer):
    assert calculate(question) == answer


@pytest.mark.parametrize(
    "question", ["Investigate CVE-2023-38545", "Calculate 1 / 0", "Calculate 2 ** 1000"]
)
def test_unsupported_reference_tasks_fail_explicitly(question):
    with pytest.raises(ValueError):
        calculate(question)


async def test_reference_agent_has_distinct_discovery_and_a_working_protected_a2a_endpoint():
    app = create_app("http://reference", "secret")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://reference"
    ) as client:
        card = (await client.get("/.well-known/agent-card.json")).json()
        assert "arithmetic" in card["description"].lower()
        assert card["skills"][0]["id"] == "calculate"
        assert (await client.post("/a2a/jsonrpc", json={})).status_code == 401
        result = await client.post(
            "/a2a/jsonrpc",
            headers={"Authorization": "Bearer secret"},
            json={
                "jsonrpc": "2.0",
                "id": "calculate",
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": "math-test",
                        "role": "user",
                        "parts": [{"kind": "text", "text": "Calculate 12 * 7"}],
                    }
                },
            },
        )
        task = result.json()["result"]
        assert task["status"]["state"] == "completed", task
        assert task["artifacts"][0]["parts"][0]["text"] == "84"


def test_reference_service_requires_a_token():
    with pytest.raises(ValueError, match="token"):
        create_app("http://reference", "")
