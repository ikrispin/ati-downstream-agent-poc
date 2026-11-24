"""Read public threat catalogs without fetching or running exploit code.

EPSS is a probability, CISA SSVC ``poc`` is a published PoC assessment, and
SSVC ``active`` / KEV membership are observed exploitation evidence. A missing
assertion remains unknown. SSVC PoC can include a well-known exploitation method;
this adapter does not verify a runnable exploit or infer one from reference tags.
"""

import json
import math
import re
from datetime import UTC, date, datetime
from time import monotonic
from typing import Any

import httpx

from .security_data import normalize_cve_id

EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_URL = "https://cveawg.mitre.org/api/cve"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ADP_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


class _CatalogFailure(ValueError):
    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code, self.retryable = code, retryable


def _fetch_json(client: httpx.Client, url: str, max_bytes: int, deadline: float) -> dict:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _CatalogFailure("source_timeout", retryable=True)
    with client.stream(
        "GET",
        url,
        headers={"Accept": "application/json", "User-Agent": "ATI-Threat-Intelligence-Lab/0.1"},
        timeout=min(4.0, remaining),
        follow_redirects=False,
    ) as response:
        response.raise_for_status()
        body = bytearray()
        for block in response.iter_bytes():
            if monotonic() >= deadline:
                raise _CatalogFailure("source_timeout", retryable=True)
            if len(body) + len(block) > max_bytes:
                raise _CatalogFailure("response_too_large")
            body.extend(block)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("Expected a catalog object")
    return value


def _probability(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("Invalid probability")
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ValueError("Invalid probability")
    return number


def _date(value: Any) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid catalog date")
    return date.fromisoformat(value)


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(UTC).isoformat()


def _epss(payload: dict, cve: str, now: datetime, metadata: dict) -> dict:
    rows = payload.get("data")
    if payload.get("status") != "OK" or not isinstance(rows, list) or len(rows) > 1:
        raise ValueError("Invalid EPSS envelope")
    if not rows:
        return {"status": "unknown", "score": None, "percentile": None, "reason": "not_found"}
    row = rows[0]
    if not isinstance(row, dict) or row.get("cve") != cve:
        raise ValueError("Mismatched EPSS CVE")
    score_date = _date(row.get("date"))
    age = (now.date() - score_date).days
    if age < 0:
        raise ValueError("Future EPSS score")
    return {
        "status": "available",
        "score": _probability(row.get("epss")),
        "percentile": _probability(row.get("percentile")),
        "score_date": score_date.isoformat(),
        "age_days": age,
        "stale": age > metadata["max_age_days"],
    }


def _cve_org(payload: dict, cve: str, source: dict) -> list[dict]:
    metadata = payload.get("cveMetadata")
    if not isinstance(metadata, dict) or metadata.get("cveId") != cve:
        raise ValueError("Mismatched CVE record")
    state = metadata.get("state")
    if state not in {"PUBLISHED", "REJECTED", "RESERVED"}:
        raise ValueError("Invalid CVE state")
    source["record_state"] = state
    source["record_updated_at"] = _timestamp(metadata.get("dateUpdated"))
    if state != "PUBLISHED":
        return []
    containers = payload.get("containers")
    if not isinstance(containers, dict):
        raise ValueError("Invalid CVE containers")
    adps = containers.get("adp", [])
    if not isinstance(adps, list):
        raise ValueError("Invalid ADP containers")
    statements = []
    unsupported = set()
    for adp in adps:
        if not isinstance(adp, dict):
            raise ValueError("Invalid ADP object")
        provider = adp.get("providerMetadata", {})
        if not isinstance(provider, dict) or provider.get("orgId") != CISA_ADP_ORG:
            continue
        metrics = adp.get("metrics", [])
        if not isinstance(metrics, list):
            raise ValueError("Invalid CISA metrics")
        for metric in metrics:
            if not isinstance(metric, dict):
                raise ValueError("Invalid CISA metric")
            other = metric.get("other", {})
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict) or content.get("id") != cve:
                raise ValueError("Mismatched SSVC CVE")
            version = content.get("version")
            if not isinstance(version, str) or not re.fullmatch(r"2\.0\.\d+", version):
                unsupported.add(str(version)[:32])
                continue
            options = content.get("options")
            if not isinstance(options, list):
                raise ValueError("Invalid SSVC options")
            for option in options:
                if not isinstance(option, dict):
                    raise ValueError("Invalid SSVC option")
                value = option.get("Exploitation")
                if value in {"none", "poc", "active"}:
                    statements.append(
                        {
                            "value": value,
                            "provider": "CISA-ADP",
                            "provider_org_id": CISA_ADP_ORG,
                            "ssvc_version": version,
                            "assessment_at": _timestamp(content.get("timestamp")),
                            "source_url": source["source_url"],
                            "retrieved_at": source["retrieved_at"],
                        }
                    )
    if unsupported:
        source["unsupported_ssvc_versions"] = sorted(unsupported)
    return statements


def _kev(payload: dict, cve: str, source: dict) -> list[dict]:
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Invalid KEV catalog")
    if type(payload.get("count")) is not int or payload["count"] != len(rows):
        raise ValueError("Incomplete KEV catalog")
    source["catalog_version"] = payload.get("catalogVersion")
    source["catalog_released_at"] = _timestamp(payload.get("dateReleased"))
    matched = [row for row in rows if row.get("cveID") == cve]
    if len(matched) > 1:
        raise ValueError("Duplicate KEV record")
    source["membership"] = "listed" if matched else "not_listed"
    if not matched:
        return []
    return [
        {
            "evidence_type": "cisa_kev",
            "date_added": _date(matched[0].get("dateAdded")).isoformat(),
            "source_url": source["source_url"],
            "retrieved_at": source["retrieved_at"],
        }
    ]


def _failure(exc: Exception) -> tuple[str, bool]:
    if isinstance(exc, _CatalogFailure):
        return exc.code, exc.retryable
    if isinstance(exc, httpx.TimeoutException):
        return "source_timeout", True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 404:
            return "not_found", False
        if status in {401, 403}:
            return "source_access_denied", False
        if status == 429:
            return "source_rate_limited", True
        if status == 408:
            return "source_timeout", True
        return ("source_unavailable", True) if status >= 500 else ("source_http_error", False)
    if isinstance(exc, httpx.HTTPError):
        return "source_unavailable", True
    return "invalid_response", False


def fetch_threat_intel(
    cve_id: str,
    *,
    client: httpx.Client | None = None,
    now: datetime | None = None,
    epss_max_age_days: int = 2,
    max_response_bytes: int = 5_000_000,
    deadline_seconds: float = 25,
) -> dict[str, Any]:
    """Fetch three fixed public catalogs with bounded size/time and no retries.

    Per-source failure is recorded safely without losing another catalog's
    evidence. The shared deadline can overrun by at most one four-second network
    read; the ATI source timeout remains the outer execution boundary.
    """
    cve = normalize_cve_id(cve_id)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(UTC)
    if type(epss_max_age_days) is not int or epss_max_age_days < 0:
        raise ValueError("EPSS maximum age must be a nonnegative integer")
    if (
        type(max_response_bytes) is not int
        or max_response_bytes <= 0
        or type(deadline_seconds) not in {int, float}
        or not math.isfinite(deadline_seconds)
        or deadline_seconds <= 0
    ):
        raise ValueError("Catalog execution bounds must be positive")
    if client is None:
        with httpx.Client() as owned_client:
            return fetch_threat_intel(
                cve,
                client=owned_client,
                now=now,
                epss_max_age_days=epss_max_age_days,
                max_response_bytes=max_response_bytes,
                deadline_seconds=deadline_seconds,
            )
    urls = {
        "epss": f"{EPSS_URL}?cve={cve}&limit=1",
        "cve_org": f"{CVE_URL}/{cve}",
        "cisa_kev": KEV_URL,
    }
    sources = {
        name: {"source_url": url, "retrieved_at": now.isoformat()} for name, url in urls.items()
    }
    epss = {
        "status": "unknown",
        "score": None,
        "percentile": None,
        "max_age_days": epss_max_age_days,
        **sources["epss"],
    }
    statements, wild = [], []
    deadline = monotonic() + deadline_seconds
    for name, source in sources.items():
        try:
            payload = _fetch_json(client, source["source_url"], max_response_bytes, deadline)
            if name == "epss":
                epss.update(_epss(payload, cve, now, epss))
            elif name == "cve_org":
                statements = _cve_org(payload, cve, source)
            else:
                wild = _kev(payload, cve, source)
            source["status"] = "succeeded"
        except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError) as exc:
            code, retryable = _failure(exc)
            source.update(status="failed", error_code=code, retryable=retryable)
            if name == "epss":
                epss["reason"] = code
    poc = [
        {**item, "evidence_type": "cisa_ssvc_poc"} for item in statements if item["value"] == "poc"
    ]
    wild.extend(
        {**item, "evidence_type": "cisa_ssvc_active"}
        for item in statements
        if item["value"] == "active"
    )
    return {
        "cve_id": cve,
        "source": "Public threat intelligence catalogs",
        "retrieved_at": now.isoformat(),
        "epss": epss,
        "exploit": {
            "exploit_available": "yes" if poc else "unknown",
            "exploited_in_the_wild": "yes" if wild else "unknown",
            "poc_evidence": poc,
            "wild_evidence": wild,
            "ssvc_exploitation": statements,
        },
        "sources": sources,
    }
