import httpx
import pytest

from ati_downstream.a2a_service import create_app
from ati_downstream.models import InvestigationResult


class StubInvestigator:
    def __init__(self, status="completed"):
        self.status = status

    async def investigate(self, request):
        return InvestigationResult(
            request.run_id,
            request.cve_id,
            self.status,
            "Known ATI response.",
            {"redhat": {"status": "succeeded"}},
        )


async def test_public_discovery_and_protected_invocation():
    app = create_app(StubInvestigator(), "http://test", "secret")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        card = await c.get("/.well-known/agent-card.json")
        assert card.status_code == 200
        assert card.json()["name"] == "ATI independent downstream lab"
        assert (await c.post("/a2a/jsonrpc", json={})).status_code == 401


@pytest.mark.parametrize("status,expected", [("completed", "completed"), ("failed", "failed")])
async def test_a2a_outcome_is_truthful(status, expected):
    app = create_app(StubInvestigator(status), "http://test", "secret")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.post(
            "/a2a/jsonrpc",
            headers={"Authorization": "Bearer secret"},
            json={
                "jsonrpc": "2.0",
                "id": "test",
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": "msg-test",
                        "role": "user",
                        "parts": [{"kind": "text", "text": "CVE-2023-38545"}],
                    }
                },
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["result"]["status"]["state"] == expected, response.text


def test_missing_service_token_is_rejected():
    with pytest.raises(ValueError, match="token"):
        create_app(StubInvestigator(), "http://test", "")
