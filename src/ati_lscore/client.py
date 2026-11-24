"""One native LSCore query per assessment; no model/tool execution loop in this client."""

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from .security_data import normalize_cve_id


def save_private_report(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def assessment_prompt(cve_id, environment, run_id):
    return (
        f"Assess {cve_id} against the configured customer environment.\n"
        f"Environment: {environment}\nAssessment ID: {run_id}\n[request:{run_id}]\n"
        "This assessment already exists. Use exactly this assessment_id; do not begin another. "
        "Use collect_cve_source for each of redhat, osidb, lightspeed, fleet, "
        "support, threat_intel. "
        "Call finalize_cve_assessment only after those six observations, including any failures. "
        "Summarize the recorded outcome, provisional priority and missing evidence. "
        "Do not generate or execute remediation. Preserve the assessment identifier in the answer."
    )


async def assess_batch(settings, cves, environment, *, concurrency=2, client=None):
    if environment != settings.environment:
        raise ValueError("Environment must match the configured connection")
    if not 1 <= concurrency <= 10:
        raise ValueError("Concurrency must be between 1 and 10")
    normalized = list(dict.fromkeys(normalize_cve_id(value) for value in cves))
    if not 1 <= len(normalized) <= 100:
        raise ValueError("Supply between 1 and 100 distinct CVEs")
    if client is None:
        async with httpx.AsyncClient(
            timeout=settings.client_timeout, follow_redirects=False
        ) as owned:
            return await assess_batch(
                settings, normalized, environment, concurrency=concurrency, client=owned
            )
    domain = settings.domain()
    semaphore = asyncio.Semaphore(concurrency)

    async def run(cve_id):
        async with semaphore:
            run_id = domain.begin(cve_id, environment)["assessment_id"]
            result = {"cve_id": cve_id, "assessment_id": run_id}
            try:
                response = await client.post(
                    settings.native_url + "/v1/query",
                    json={
                        "query": assessment_prompt(cve_id, environment, run_id),
                        "generate_topic_summary": False,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Invalid native response")
                result.update(native_status="request_completed", native_response=payload)
            except httpx.TimeoutException:
                result.update(native_status="request_failed", error_code="native_client_timeout")
            except httpx.HTTPError:
                result.update(native_status="request_failed", error_code="native_request_error")
            except ValueError:
                result.update(native_status="request_failed", error_code="native_invalid_response")
            record = domain.store.read(run_id)
            result.update(domain_outcome=record["outcome"], record=record)
            return result

    return {
        "execution_owner": "lscore_native",
        "recorded_at": datetime.now(UTC).isoformat(),
        "environment": environment,
        "data_mode": getattr(domain.sources, "data_mode", "live_sources"),
        "client_timeout_note": "Caller waiting limit only; does not cancel native server work.",
        "results": await asyncio.gather(*(run(cve_id) for cve_id in normalized)),
    }
