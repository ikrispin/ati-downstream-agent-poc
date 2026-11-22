"""OSIDB evidence must match the requested CVE and be explicitly public."""

import json
from subprocess import CompletedProcess

import pytest

from ati_downstream.osidb import get_public_osidb_cve


def response(monkeypatch, record, status=200):
    payload = {"results": [record]} if record is not None else {"results": []}

    def run(command, **kwargs):
        assert command[0] == "curl"
        assert "--negotiate" in command
        assert "shell" not in kwargs
        assert command[-1].startswith("https://osidb.prodsec.redhat.com/")
        return CompletedProcess(command, 0, json.dumps(payload) + f"\n{status}", "")

    monkeypatch.setattr("ati_downstream.osidb.subprocess.run", run)


def test_public_record_is_reduced_to_the_selected_evidence(monkeypatch):
    response(
        monkeypatch,
        {
            "cve_id": "CVE-2023-38545",
            "visibility": "PUBLIC",
            "title": "curl issue",
            "impact": "IMPORTANT",
            "internal_comment": "omit me",
            "trackers": [{"private": True}],
        },
    )
    result = get_public_osidb_cve("cve-2023-38545")
    assert result["cve_id"] == "CVE-2023-38545"
    assert result["visibility"] == "PUBLIC"
    assert result["impact"] == "IMPORTANT"
    assert "internal_comment" not in result
    assert "trackers" not in result


@pytest.mark.parametrize("visibility", ["INTERNAL", "EMBARGOED", None])
def test_nonpublic_or_unspecified_visibility_is_rejected(monkeypatch, visibility):
    response(monkeypatch, {"cve_id": "CVE-2023-38545", "visibility": visibility})
    with pytest.raises(ValueError, match="public"):
        get_public_osidb_cve("CVE-2023-38545")


def test_missing_record_is_not_synthesized(monkeypatch):
    response(monkeypatch, None)
    with pytest.raises(LookupError):
        get_public_osidb_cve("CVE-2023-38545")


def test_auth_error_is_reported_without_response_content(monkeypatch):
    response(monkeypatch, None, status=401)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        get_public_osidb_cve("CVE-2023-38545")


def test_invalid_identifier_does_not_run_curl(monkeypatch):
    monkeypatch.setattr(
        "ati_downstream.osidb.subprocess.run",
        lambda *a, **kw: pytest.fail("curl ran"),
    )
    with pytest.raises(ValueError, match="CVE"):
        get_public_osidb_cve("bad; echo unsafe")
