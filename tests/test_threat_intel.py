"""Public catalog evidence must keep probability, PoC and observed attacks separate."""

from datetime import UTC, datetime

import httpx
import pytest

from ati_lscore.threat_intel import fetch_threat_intel

CVE = "CVE-2023-38545"
NOW = datetime(2026, 11, 24, 12, tzinfo=UTC)
CISA_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


def epss_row(score="0.15", percentile="0.9", date="2026-11-23"):
    return {
        "status": "OK",
        "data": [{"cve": CVE, "epss": score, "percentile": percentile, "date": date}],
    }


def cve_record(exploitation="poc", *, org=CISA_ORG, version="2.0.3", state="PUBLISHED"):
    return {
        "cveMetadata": {"cveId": CVE, "state": state, "dateUpdated": "2026-11-20T00:00:00Z"},
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"orgId": org, "shortName": "CISA-ADP"},
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "id": CVE,
                                    "version": version,
                                    "timestamp": "2026-11-20T00:00:00Z",
                                    "options": [{"Exploitation": exploitation}],
                                },
                            }
                        }
                    ],
                }
            ]
        },
    }


def kev_catalog(*, listed=False):
    return {
        "catalogVersion": "2026.11.23",
        "dateReleased": "2026-11-23T18:00:00.000Z",
        "count": int(listed),
        "vulnerabilities": [{"cveID": CVE, "dateAdded": "2026-11-20"}] if listed else [],
    }


def run_lookup(*, epss=None, cve=None, kev=None, fail_host=None, failure=None, **kwargs):
    seen = []

    def respond(request):
        seen.append(request)
        assert request.method == "GET"
        assert "authorization" not in request.headers
        if request.url.host == fail_host:
            if isinstance(failure, Exception):
                raise failure
            return httpx.Response(failure, text="private body /?token=secret")
        if request.url.host == "api.first.org":
            assert request.url.params["cve"] == CVE
            assert request.url.params["limit"] == "1"
            return httpx.Response(200, json=epss if epss is not None else epss_row())
        if request.url.host == "cveawg.mitre.org":
            assert request.url.path == f"/api/cve/{CVE}"
            return httpx.Response(200, json=cve if cve is not None else cve_record())
        assert request.url.host == "www.cisa.gov"
        return httpx.Response(200, json=kev if kev is not None else kev_catalog())

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = fetch_threat_intel(CVE, client=client, now=NOW, **kwargs)
    assert len(seen) == 3
    return result


def test_probability_and_public_poc_are_independent_evidence():
    result = run_lookup()
    assert result["cve_id"] == CVE
    assert result["epss"] | {} == {
        "status": "available",
        "score": 0.15,
        "percentile": 0.9,
        "score_date": "2026-11-23",
        "age_days": 1,
        "stale": False,
        "max_age_days": 2,
        "source_url": f"https://api.first.org/data/v1/epss?cve={CVE}&limit=1",
        "retrieved_at": NOW.isoformat(),
    }
    exploit = result["exploit"]
    assert exploit["exploit_available"] == "yes"
    assert exploit["exploited_in_the_wild"] == "unknown"
    assert exploit["poc_evidence"][0]["evidence_type"] == "cisa_ssvc_poc"
    assert exploit["poc_evidence"][0]["assessment_at"] == "2026-11-20T00:00:00+00:00"
    assert exploit["wild_evidence"] == []
    assert all(s["status"] == "succeeded" for s in result["sources"].values())


def test_zero_score_and_percentile_are_preserved():
    result = run_lookup(epss=epss_row("0", "0"))
    assert result["epss"]["status"] == "available"
    assert result["epss"]["score"] == 0.0
    assert result["epss"]["percentile"] == 0.0


@pytest.mark.parametrize(
    "score_date,age,stale",
    [
        ("2026-11-22", 2, False),
        ("2026-11-21", 3, True),
    ],
)
def test_stale_score_is_retained_and_explicit(score_date, age, stale):
    evidence = run_lookup(epss=epss_row(date=score_date))["epss"]
    assert evidence["score"] == 0.15
    assert evidence["age_days"] == age
    assert evidence["stale"] is stale


def test_staleness_limit_is_configurable():
    assert run_lookup(epss_max_age_days=0)["epss"]["stale"] is True


def test_missing_score_is_unknown_without_losing_poc_evidence():
    result = run_lookup(epss={"status": "OK", "data": []})
    assert result["epss"]["status"] == "unknown"
    assert result["epss"]["score"] is None
    assert result["epss"]["reason"] == "not_found"
    assert result["exploit"]["exploit_available"] == "yes"


@pytest.mark.parametrize("score", [True, "nan", "inf", "-0.01", "1.01", None])
def test_invalid_probability_is_unknown(score):
    result = run_lookup(epss=epss_row(score))
    assert result["epss"]["score"] is None
    assert result["sources"]["epss"]["error_code"] == "invalid_response"


@pytest.mark.parametrize("date", ["2026-11-25", "not-a-date", None])
def test_future_or_invalid_score_date_is_not_current_evidence(date):
    result = run_lookup(epss=epss_row(date=date))
    assert result["epss"]["status"] == "unknown"
    assert result["sources"]["epss"]["error_code"] == "invalid_response"


def test_mismatched_cve_never_supplies_probability():
    epss = epss_row()
    epss["data"][0]["cve"] = "CVE-2024-3094"
    assert run_lookup(epss=epss)["epss"]["score"] is None


def test_kev_is_wild_evidence_not_public_exploit_code():
    result = run_lookup(cve=cve_record("none"), kev=kev_catalog(listed=True))
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["exploit"]["exploited_in_the_wild"] == "yes"
    assert result["exploit"]["wild_evidence"][0]["evidence_type"] == "cisa_kev"


def test_active_ssvc_is_observed_exploitation_not_public_poc():
    result = run_lookup(cve=cve_record("active"))
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["exploit"]["poc_evidence"] == []
    assert result["exploit"]["ssvc_exploitation"][0]["value"] == "active"
    assert result["exploit"]["wild_evidence"][0]["evidence_type"] == "cisa_ssvc_active"
    assert result["exploit"]["exploited_in_the_wild"] == "yes"


def test_other_adp_cannot_impersonate_cisa_by_short_name():
    result = run_lookup(cve=cve_record(org="unrelated-provider"))
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["exploit"]["ssvc_exploitation"] == []


def test_new_ssvc_version_is_recorded_but_not_silently_reinterpreted():
    result = run_lookup(cve=cve_record(version="3.0.0"))
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["sources"]["cve_org"]["unsupported_ssvc_versions"] == ["3.0.0"]


@pytest.mark.parametrize("state", ["REJECTED", "RESERVED"])
def test_nonpublished_cve_cannot_assert_poc(state):
    result = run_lookup(cve=cve_record(state=state))
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["sources"]["cve_org"]["record_state"] == state


@pytest.mark.parametrize(
    "host,source",
    [
        ("api.first.org", "epss"),
        ("cveawg.mitre.org", "cve_org"),
        ("www.cisa.gov", "cisa_kev"),
    ],
)
def test_one_source_failure_does_not_discard_other_evidence(host, source):
    result = run_lookup(fail_host=host, failure=503, kev=kev_catalog(listed=True))
    assert result["sources"][source]["error_code"] == "source_unavailable"
    assert result["sources"][source]["retryable"] is True
    assert "private body" not in str(result)
    assert "token=secret" not in str(result)
    if source != "epss":
        assert result["epss"]["score"] == 0.15
    if source != "cve_org":
        assert result["exploit"]["exploit_available"] == "yes"
    if source != "cisa_kev":
        assert result["exploit"]["exploited_in_the_wild"] == "yes"


@pytest.mark.parametrize(
    "failure,code",
    [
        (httpx.ReadTimeout("private URL"), "source_timeout"),
        (httpx.ConnectError("private URL"), "source_unavailable"),
        (429, "source_rate_limited"),
        (404, "not_found"),
    ],
)
def test_safe_transport_failure_categories(failure, code):
    result = run_lookup(fail_host="api.first.org", failure=failure)
    assert result["sources"]["epss"]["error_code"] == code
    assert "private URL" not in str(result)


def test_invalid_cve_is_rejected_before_network():
    with httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("network called"))) as c:
        with pytest.raises(ValueError):
            fetch_threat_intel("https://untrusted.test/exploit", client=c, now=NOW)


def test_bounded_response_size_does_not_become_evidence():
    result = run_lookup(max_response_bytes=10)
    assert all(v["error_code"] == "response_too_large" for v in result["sources"].values())
    assert result["exploit"]["exploit_available"] == "unknown"


def test_missing_catalog_rows_are_unknown_not_false():
    result = run_lookup(
        cve={"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {}},
        kev=kev_catalog(),
    )
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["exploit"]["exploited_in_the_wild"] == "unknown"
    assert result["sources"]["cisa_kev"]["membership"] == "not_listed"


@pytest.mark.parametrize(
    "payload",
    [
        {"cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"}, "containers": {}},
        {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": []},
    ],
)
def test_invalid_cve_record_cannot_assert_exploitation(payload):
    result = run_lookup(cve=payload)
    assert result["sources"]["cve_org"]["error_code"] == "invalid_response"
    assert result["exploit"]["exploit_available"] == "unknown"
    assert result["exploit"]["wild_evidence"] == []


def test_incomplete_kev_feed_does_not_claim_catalog_was_checked():
    payload = kev_catalog(listed=True)
    payload["count"] = 2
    result = run_lookup(cve=cve_record("none"), kev=payload)
    assert result["sources"]["cisa_kev"]["error_code"] == "invalid_response"
    assert "membership" not in result["sources"]["cisa_kev"]
    assert result["exploit"]["exploited_in_the_wild"] == "unknown"


def test_shared_deadline_stops_remaining_network_calls(monkeypatch):
    current, seen = [0.0], []
    monkeypatch.setattr("ati_lscore.threat_intel.monotonic", lambda: current[0])

    def respond(request):
        seen.append(request)
        current[0] = 26.0
        return httpx.Response(200, json=epss_row())

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = fetch_threat_intel(CVE, client=client, now=NOW, deadline_seconds=25)
    assert len(seen) == 1
    assert all(v["error_code"] == "source_timeout" for v in result["sources"].values())


@pytest.mark.parametrize("deadline", [0, -1, float("nan"), float("inf"), True])
def test_invalid_deadline_is_rejected_before_network(deadline):
    with httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("network called"))) as c:
        with pytest.raises(ValueError):
            fetch_threat_intel(CVE, client=c, now=NOW, deadline_seconds=deadline)
