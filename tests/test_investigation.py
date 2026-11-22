import asyncio

import pytest

from ati_downstream.engine import Investigator
from ati_downstream.models import AuthenticationRequired, InvestigationRequest
from ati_downstream.store import RunStore


class FakeModel:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    async def complete(self, messages, tools):
        self.calls += 1
        return next(self.replies)


class FakeTools:
    schemas = []

    async def call(self, name, arguments, request):
        if name == "broken":
            raise RuntimeError("unavailable")
        return {"source": name, "value": 0}


def call(name, arguments=None):
    return {
        "id": name,
        "type": "function",
        "function": {"name": name, "arguments": arguments or '{"cve_id":"CVE-2023-38545"}'},
    }


def test_only_current_question_can_authorize_a_case():
    req = InvestigationRequest.parse(
        "CONVERSATION CONTEXT:\ncase 09999999 CVE-2020-1111\n"
        "CURRENT TASK:\nInvestigate CVE-2023-38545 and Support Case 00012345",
        "session",
    )
    assert req.cve_id == "CVE-2023-38545"
    assert req.case_id == "00012345"
    assert InvestigationRequest.parse("CVE-2023-38545", "session").case_id is None


@pytest.mark.parametrize(
    "text", ["hello", "CVE-2023-38545 CVE-2020-1111", "CVE-2023-38545 case 0123 case 0456"]
)
def test_ambiguous_input_is_rejected(text):
    with pytest.raises(ValueError):
        InvestigationRequest.parse(text, "session")


async def test_four_source_completion_and_deduplication(tmp_path):
    request = InvestigationRequest.parse("CVE-2023-38545 Support Case 00012345", "session")
    model = FakeModel(
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    call("get_redhat_cve"),
                    call("get_public_osidb_cve"),
                    call("vulnerability__get_cve"),
                    call("GetCaseDetailsByCaseId", '{"caseId":"00012345"}'),
                ],
            },
            {"role": "assistant", "content": "Evidence-backed answer."},
        ]
    )
    engine = Investigator(model, FakeTools(), RunStore(tmp_path / "runs.sqlite"))
    result = await engine.investigate(request)
    assert result.status == "completed"
    assert len([s for s in result.sources.values() if s["status"] == "succeeded"]) == 4
    repeated = await engine.investigate(request)
    assert repeated.run_id == result.run_id
    assert model.calls == 2


async def test_early_answer_is_partial_not_four_source_success(tmp_path):
    model = FakeModel([{"role": "assistant", "content": "An unsupported answer."}])
    result = await Investigator(model, FakeTools(), RunStore(tmp_path / "runs.sqlite")).investigate(
        InvestigationRequest.parse("CVE-2023-38545", "session")
    )
    assert result.status == "partial"
    assert result.sources["support"]["status"] == "not_requested"
    assert "Missing evidence" in result.answer


async def test_authentication_failure_explains_recovery_without_secret_details(tmp_path):
    class ExpiredSupport(FakeTools):
        async def call(self, name, arguments, request):
            raise AuthenticationRequired("private-token")

    model = FakeModel(
        [
            {"role": "assistant", "tool_calls": [call("GetCaseDetailsByCaseId")]},
            {"role": "assistant", "content": "Support needs sign-in."},
        ]
    )
    result = await Investigator(
        model, ExpiredSupport(), RunStore(tmp_path / "runs.sqlite")
    ).investigate(InvestigationRequest.parse("CVE-2023-38545 Support Case 00012345"))
    support = result.sources["support"]
    assert support["error"] == "AuthenticationRequired"
    assert "support-login" in support["detail"]
    assert "private-token" not in str(result.to_dict())


async def test_round_limit_does_not_make_an_extra_model_call(tmp_path):
    model = FakeModel([{"role": "assistant", "tool_calls": [call("get_redhat_cve")]}])
    result = await Investigator(
        model, FakeTools(), RunStore(tmp_path / "runs.sqlite"), max_rounds=1
    ).investigate(InvestigationRequest.parse("CVE-2023-38545", "session"))
    assert result.status == "partial"
    assert model.calls == 1


async def test_deadline_is_reported(tmp_path):
    class SlowModel:
        async def complete(self, messages, tools):
            await asyncio.sleep(1)

    result = await Investigator(
        SlowModel(), FakeTools(), RunStore(tmp_path / "runs.sqlite"), deadline=0.01
    ).investigate(InvestigationRequest.parse("CVE-2023-38545", "session"))
    assert result.status == "failed"
    assert result.error == "investigation_deadline"


def test_persistent_claim_prevents_retry_after_interrupted_process(tmp_path):
    request = InvestigationRequest.parse("CVE-2023-38545", "session")
    assert RunStore(tmp_path / "runs.sqlite").claim(request) is None
    with pytest.raises(RuntimeError, match="already running|interrupted"):
        RunStore(tmp_path / "runs.sqlite").claim(request)


async def test_tool_call_budget_stops_before_extra_source_access(tmp_path):
    model = FakeModel(
        [
            {
                "role": "assistant",
                "tool_calls": [call("get_redhat_cve"), call("get_public_osidb_cve")],
            }
        ]
    )
    result = await Investigator(
        model, FakeTools(), RunStore(tmp_path / "runs.sqlite"), max_tool_calls=1
    ).investigate(InvestigationRequest.parse("CVE-2023-38545", "session"))
    assert result.tool_calls == 1
    assert result.error == "tool_call_limit"
    assert result.sources["osidb"]["status"] == "not_queried"


def test_same_run_id_cannot_return_evidence_for_a_different_request(tmp_path):
    store = RunStore(tmp_path / "runs.sqlite")
    first = InvestigationRequest.parse("CVE-2023-38545 case 00012345. Investigation ID: same-id")
    store.claim(first)
    second = InvestigationRequest.parse("CVE-2023-38545 case 09999999. Investigation ID: same-id")
    with pytest.raises(ValueError, match="different request"):
        store.claim(second)
