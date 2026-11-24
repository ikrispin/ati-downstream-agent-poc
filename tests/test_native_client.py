"""The headless client invokes native LSCore once per CVE and reports domain truth separately."""

import json

import httpx
import pytest

from ati_lscore.client import assess_batch, save_private_report
from ati_lscore.config import Settings

CVE = "CVE-2023-38545"


async def test_batch_calls_only_native_query_and_does_not_trust_model_claim_of_completion(tmp_path):
    settings = Settings(state_dir=tmp_path, environment="demo")
    seen = []

    def native(request):
        seen.append(request)
        assert request.url.path == "/v1/query"
        body = json.loads(request.content)
        assert "Assessment ID:" in body["query"] and CVE in body["query"]
        return httpx.Response(200, json={"response": "The investigation is completed!"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(native)) as client:
        report = await assess_batch(settings, [CVE], "demo", client=client)
    result = report["results"][0]
    assert len(seen) == 1
    assert result["native_status"] == "request_completed"
    assert result["domain_outcome"] == "not_finalized"
    assert result["record"]["assessment"] is None
    assert report["execution_owner"] == "lscore_native"


@pytest.mark.parametrize(
    "cves,environment,concurrency",
    [
        (["bad"], "demo", 2),
        ([CVE], "other", 2),
        ([], "demo", 2),
        ([CVE], "demo", 0),
        ([CVE], "demo", 11),
    ],
)
async def test_invalid_batch_cannot_make_a_native_request(tmp_path, cves, environment, concurrency):
    with pytest.raises(ValueError):
        await assess_batch(
            Settings(state_dir=tmp_path, environment="demo"),
            cves,
            environment,
            concurrency=concurrency,
        )


@pytest.mark.parametrize("failure", ["timeout", "http", "invalid_json"])
async def test_native_failure_has_safe_code_and_retains_the_domain_record(tmp_path, failure):
    def native(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("PRIVATE CREDENTIAL")
        if failure == "http":
            return httpx.Response(500, json={"error": "PRIVATE CREDENTIAL"})
        return httpx.Response(200, text="PRIVATE CREDENTIAL")

    settings = Settings(state_dir=tmp_path, environment="demo")
    async with httpx.AsyncClient(transport=httpx.MockTransport(native)) as client:
        report = await assess_batch(settings, [CVE], "demo", client=client)
    result = report["results"][0]
    assert result["native_status"] == "request_failed"
    assert result["domain_outcome"] == "not_finalized"
    assert "PRIVATE" not in json.dumps(report)
    assert "assessment_id" in result


def test_report_is_private_and_has_actual_newlines(tmp_path):
    output = tmp_path / "private/report.json"
    save_private_report(output, {"record": "sensitive"})
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(output.read_text()) == {"record": "sensitive"}


async def test_source_fixture_mode_is_explicit_in_both_registry_and_report(tmp_path):
    settings = Settings(state_dir=tmp_path, environment="demo", source_mode="fixture")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"response": "fixture"})
        )
    ) as client:
        report = await assess_batch(settings, [CVE, CVE.lower()], "demo", client=client)
    assert len(report["results"]) == 1
    assert report["data_mode"] == "synthetic_fixture"
    assert report["results"][0]["record"]["data_mode"] == "synthetic_fixture"
