import pytest

from ati_downstream.models import InvestigationRequest
from ati_downstream.sources import SourceTools


@pytest.mark.parametrize(
    "name,args",
    [
        ("GetCaseDetailsByCaseId", {"caseId": "12345"}),
        ("GetCaseDetailsByCaseId", {"caseId": 12345}),
        ("get_redhat_cve", {"cve_id": "CVE-2020-1111"}),
        ("vulnerability__get_cve", {"cve_id": "CVE-2020-1111"}),
        ("ListCases", {}),
    ],
)
async def test_tools_cannot_escape_request_scope(tmp_path, name, args):
    tools = SourceTools("http://example.test/lightspeed", "http://example.test/support", tmp_path)
    request = InvestigationRequest.parse("CVE-2023-38545 case 00012345")
    with pytest.raises(ValueError):
        await tools.call(name, args, request)


async def test_no_case_means_no_support_request(tmp_path):
    tools = SourceTools("http://example.test/lightspeed", "http://example.test/support", tmp_path)
    with pytest.raises(ValueError):
        await tools.call(
            "GetCaseDetailsByCaseId",
            {"caseId": "00012345"},
            InvestigationRequest.parse("CVE-2023-38545"),
        )


async def test_support_keeps_exact_identifier(tmp_path, monkeypatch):
    tools = SourceTools("http://example.test/lightspeed", "http://example.test/support", tmp_path)
    seen = []

    async def remote(url, name, arguments, **kwargs):
        seen.append(arguments)
        return {"status": "open"}

    monkeypatch.setattr(tools, "_mcp_call", remote)
    await tools.call(
        "GetCaseDetailsByCaseId",
        {"caseId": "00012345"},
        InvestigationRequest.parse("CVE-2023-38545 case 00012345"),
    )
    assert seen == [{"caseId": "00012345"}]
