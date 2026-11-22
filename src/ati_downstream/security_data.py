"""Read public Red Hat CVE data without inferring customer fleet impact."""

import re
from datetime import UTC, datetime
from typing import Any

import httpx

SECURITY_DATA_URL = "https://access.redhat.com/hydra/rest/securitydata"


def normalize_cve_id(cve_id: str) -> str:
    """Accept only a CVE identifier, never a URL or shell expression."""
    normalized = cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise ValueError("Expected a CVE identifier such as CVE-2023-38545")
    return normalized


def get_redhat_cve(cve_id: str, *, client: httpx.Client | None = None) -> dict[str, Any]:
    """Return vendor evidence for one CVE; missing records and transport failures raise."""
    normalized = normalize_cve_id(cve_id)

    if client is None:
        with httpx.Client(timeout=20, follow_redirects=True) as owned_client:
            return get_redhat_cve(normalized, client=owned_client)

    url = f"{SECURITY_DATA_URL}/cve/{normalized}.json"
    response = client.get(
        url,
        params={"isCompressed": "false"},
        headers={"Accept": "application/json", "User-Agent": "ATI-MAS-Lab/0.1"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Red Hat CVE response must be a JSON object")
    if payload.get("name") != normalized:
        raise ValueError("Red Hat API returned a different or missing CVE identifier")

    evidence: dict[str, Any] = {
        "cve_id": normalized,
        "source": "Red Hat Security Data API",
        "source_url": url,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "redhat_severity": payload.get("threat_severity"),
    }
    for field in (
        "public_date",
        "details",
        "statement",
        "mitigation",
        "cwe",
        "cvss3",
        "affected_release",
        "package_state",
        "references",
    ):
        if field in payload:
            evidence[field] = payload[field]
    return evidence
