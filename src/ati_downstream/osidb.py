"""A small OSIDB REST lookup using the user's existing Kerberos ticket."""

import json
import subprocess
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from ati_downstream.security_data import normalize_cve_id


def get_public_osidb_cve(cve_id: str) -> dict[str, Any]:
    """Retrieve one explicitly PUBLIC flaw and expose selected fields only."""
    normalized = normalize_cve_id(cve_id)
    url = "https://osidb.prodsec.redhat.com/osidb/api/v1/flaws?" + urlencode(
        {
            "cve_id": normalized,
            "limit": 1,
        }
    )
    response = subprocess.run(
        [
            "curl",
            "--negotiate",
            "-u",
            ":",
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            "--write-out",
            "\n%{http_code}",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )
    if response.returncode:
        raise RuntimeError(
            "OSIDB request failed; check network connectivity and the Kerberos ticket"
        )
    body, _, status = response.stdout.rpartition("\n")
    if status != "200":
        raise RuntimeError(f"OSIDB returned HTTP {status}; check access and the Kerberos ticket")
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("OSIDB response did not contain a results list")
    records = payload["results"]
    if not records:
        raise LookupError("No OSIDB record was returned for this CVE")
    record = records[0]
    if not isinstance(record, dict) or record.get("cve_id") != normalized:
        raise ValueError("OSIDB returned a different or missing CVE identifier")
    if record.get("visibility") != "PUBLIC":
        raise ValueError("The OSIDB record is not explicitly public; no evidence will be exposed")
    evidence: dict[str, Any] = {
        "cve_id": normalized,
        "source": "OSIDB (public flaw only)",
        "source_url": url,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "visibility": "PUBLIC",
    }
    for field in ["title", "impact", "cwe_id", "cvss_scores", "statement", "mitigation"]:
        if field in record:
            evidence[field] = record[field]
    return evidence
