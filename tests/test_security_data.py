"""Exercise the evidence boundary, including invalid IDs and upstream failures."""

import httpx
import pytest

from ati_lscore.security_data import get_redhat_cve


def test_lookup_keeps_vendor_product_states_and_evidence():
    payload = {
        "name": "CVE-2023-38545",
        "threat_severity": "Important",
        "details": ["A curl flaw."],
        "affected_release": [{"advisory": "RHSA-2023:9999", "product_name": "Example"}],
        "package_state": [{"product_name": "Other", "fix_state": "Not affected"}],
    }

    def respond(request):
        assert request.url.path.endswith("/cve/CVE-2023-38545.json")
        assert request.url.params["isCompressed"] == "false"
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        evidence = get_redhat_cve(" cve-2023-38545 ", client=client)

    assert evidence["cve_id"] == payload["name"]
    assert evidence["redhat_severity"] == "Important"
    assert evidence["affected_release"] == payload["affected_release"]
    assert evidence["package_state"] == payload["package_state"]
    assert evidence["source_url"].startswith("https://access.redhat.com/")
    assert evidence["retrieved_at"].endswith("+00:00")
    assert "exploited_in_the_wild" not in evidence
    assert "affected_systems" not in evidence


@pytest.mark.parametrize("cve_id", ["", "CVE-2023-x", "../../etc/passwd", "https://example.org"])
def test_invalid_identifier_never_reaches_the_network(cve_id):
    def unexpected_request(request):
        pytest.fail("Invalid CVE identifier reached the network")

    with httpx.Client(transport=httpx.MockTransport(unexpected_request)) as client:
        with pytest.raises(ValueError, match="CVE"):
            get_redhat_cve(cve_id, client=client)


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_upstream_errors_remain_errors(status):
    transport = httpx.MockTransport(lambda request: httpx.Response(status))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.HTTPStatusError):
            get_redhat_cve("CVE-2023-38545", client=client)


def test_mismatched_cve_response_is_rejected():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"name": "CVE-2024-3094"})
    )
    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="returned"):
            get_redhat_cve("CVE-2023-38545", client=client)


def test_malformed_response_is_rejected():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[]))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="object"):
            get_redhat_cve("CVE-2023-38545", client=client)
