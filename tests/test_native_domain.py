"""Domain tools retain evidence while LSCore alone chooses and executes loop steps."""

import asyncio
import json

import pytest

from ati_lscore.domain import DomainTools
from ati_lscore.models import SourceFailure
from ati_lscore.records import AssessmentStore

CVE = "CVE-2023-38545"


def evidence(name):
    if name == "fleet":
        return {
            "cve_id": CVE,
            "total_affected_systems": 0,
            "systems": [],
            "coverage": {"affected_systems": "complete"},
        }
    if name == "support":
        return {"cve_id": CVE, "cases": [], "coverage": {"case_search": "complete"}}
    if name == "threat_intel":
        return {
            "cve_id": CVE,
            "epss": {"status": "available", "score": 0.15, "stale": False},
            "exploit": {"exploit_available": "yes", "exploited_in_the_wild": "unknown"},
            "sources": {key: {"status": "succeeded"} for key in ("cve_org", "cisa_kev")},
        }
    return {"cve_id": CVE, "redhat_severity": "Important"}


class Sources:
    environment = "demo"
    connection_fingerprint = "synthetic-connection"

    def __init__(self):
        self.calls = []
        self.fail = None

    async def call(self, name, arguments, request):
        source = {
            "get_redhat_cve": "redhat",
            "get_public_osidb_cve": "osidb",
            "vulnerability__get_cve": "lightspeed",
        }[name]
        return await self.collect(source, request)

    async def collect(self, name, request):
        self.calls.append((name, request.cve_id))
        if self.fail == name:
            raise SourceFailure("source_unavailable", retryable=True)
        return evidence(name)

    async def inspect_fleet(self, request):
        return await self.collect("fleet", request)

    async def search_support(self, request):
        return await self.collect("support", request)

    async def threat_intel(self, request):
        return await self.collect("threat_intel", request)


@pytest.fixture
def domain(tmp_path):
    return DomainTools(Sources(), AssessmentStore(tmp_path / "records.sqlite"))


async def collect_all(domain, run_id):
    for name in ("redhat", "osidb", "lightspeed", "fleet", "support", "threat_intel"):
        await domain.collect(run_id, name)


async def test_native_tool_calls_are_explicit_and_finalization_uses_recorded_evidence(domain):
    run = domain.begin(CVE.lower(), "demo")
    assert domain.sources.calls == []  # begin is bookkeeping, never a hidden agent loop
    await collect_all(domain, run["assessment_id"])
    result = domain.finalize(run["assessment_id"])
    assert len(domain.sources.calls) == 6
    assert result["outcome"] == "completed"
    assert result["priority"]["decision"] == "no_affected_systems"
    record = domain.store.read(run["assessment_id"])
    assert record["assessment"]["cve_id"] == CVE
    assert len(record["sources"]) == 6
    assert record["assessment"]["remediation"] == {"status": "not_in_scope"}
    assert "model_calls" not in record and "answer" not in record


async def test_source_failure_is_returned_as_domain_data_and_earlier_evidence_survives(domain):
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    await domain.collect(run_id, "redhat")
    domain.sources.fail = "support"
    failure = await domain.collect(run_id, "support")
    assert failure["status"] == "failed" and failure["error_code"] == "source_unavailable"
    await collect_all(domain, run_id)
    result = domain.finalize(run_id)
    assert result["outcome"] == "partial"
    record = domain.store.read(run_id)
    assert record["sources"]["redhat"]["status"] == "succeeded"
    assert "support_unavailable" in record["assessment"]["missing"]
    assert [name for name, _ in domain.sources.calls].count("redhat") == 1
    assert [name for name, _ in domain.sources.calls].count("support") == 1


async def test_model_cannot_supply_priority_inputs_or_escape_registered_scope(domain):
    with pytest.raises(ValueError):
        domain.begin(CVE, "another-customer")
    with pytest.raises(ValueError):
        domain.begin("CVE OR *", "demo")
    with pytest.raises(ValueError):
        await domain.collect("../secrets", "redhat")
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    with pytest.raises(ValueError):
        await domain.collect(run_id, "execute_remediation")
    with pytest.raises(TypeError):
        domain.finalize(run_id, total_affected_systems=100)
    domain.sources.connection_fingerprint = "changed"
    with pytest.raises(ValueError):
        await domain.collect(run_id, "redhat")


async def test_unfinished_or_premature_native_run_does_not_claim_completion(domain):
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    assert domain.store.read(run_id)["assessment"] is None
    result = domain.finalize(run_id)
    assert result["outcome"] == "failed" and len(result["missing"]) >= 6
    with pytest.raises(ValueError):
        await domain.collect(run_id, "redhat")


async def test_tool_timeout_is_local_to_one_domain_call(domain):
    domain.source_timeout = 0.01

    async def blocked(*args):
        await asyncio.sleep(1)

    domain.sources.inspect_fleet = blocked
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    result = await domain.collect(run_id, "fleet")
    assert result["error_code"] == "source_timeout"
    assert result["retryable"] is True


async def test_mcp_tool_output_excludes_private_case_and_host_details(domain):
    async def private(request):
        return {
            "cve_id": CVE,
            "cases": [{"case_id": "00012345", "cve_mentioned": True}],
            "coverage": {"case_search": "complete"},
            "secret-body": "PRIVATE-CONTENT",
        }

    domain.sources.search_support = private
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    output = await domain.collect(run_id, "support")
    assert output["facts"]["confirmed_related_support_case_count"] == 1
    assert "00012345" not in json.dumps(output) and "PRIVATE" not in json.dumps(output)
    assert "PRIVATE" in json.dumps(domain.store.read(run_id))


async def test_repeated_tool_and_finalize_calls_are_idempotent_and_records_private(domain):
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    await domain.collect(run_id, "redhat")
    await domain.collect(run_id, "redhat")
    first = domain.finalize(run_id)
    assert domain.finalize(run_id) == first
    assert len(domain.sources.calls) == 1
    assert domain.store.path.stat().st_mode & 0o777 == 0o600
    assert domain.store.path.parent.stat().st_mode & 0o077 == 0


async def test_manual_review_policy_never_promotes_an_urgent_action(domain):
    domain.priority_rule = "manual_review"
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    await collect_all(domain, run_id)
    assert domain.finalize(run_id)["priority"]["decision"] == "needs_review"


async def test_invalid_source_identity_is_not_accepted(domain):
    async def wrong(*args):
        return {"cve_id": "CVE-2020-0001"}

    domain.sources.threat_intel = wrong
    run_id = domain.begin(CVE, "demo")["assessment_id"]
    assert (await domain.collect(run_id, "threat_intel"))[
        "error_code"
    ] == "source_identity_mismatch"
