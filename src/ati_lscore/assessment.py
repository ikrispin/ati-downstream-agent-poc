"""Pure ATI evidence reduction and priority rules; no model calls or execution loop."""

import math
from datetime import UTC, datetime

SOURCES = ("redhat", "osidb", "lightspeed", "fleet", "support", "threat_intel")


def _count(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
        and int(value) == value
    )


def _decision(fleet, exploit, rule):
    count = fleet.get("total_affected_systems")
    if rule == "affected_and_exploit":
        if (
            _count(count)
            and count > 0
            and (
                exploit.get("exploit_available") == "yes"
                or exploit.get("exploited_in_the_wild") == "yes"
            )
        ):
            return "urgent_review"
        if count == 0 and fleet.get("coverage", {}).get("affected_systems") == "complete":
            return "no_affected_systems"
    return "needs_review"


def validate_assessment(value, cve_id, *, completed=False, sources=None):
    """The same structured assessment must survive persistence and A2A transport."""
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("cve_id") != cve_id
        or not isinstance(value.get("missing"), list)
        or any(not isinstance(item, str) for item in value["missing"])
        or not isinstance(value.get("fleet"), dict)
        or not isinstance(value.get("epss"), dict)
        or not isinstance(value.get("exploit"), dict)
        or not isinstance(value.get("environment"), dict)
        or not isinstance(value["environment"].get("alias"), str)
        or value.get("remediation") != {"status": "not_in_scope"}
    ):
        raise ValueError("Invalid journey assessment")
    priority = value.get("priority", {})
    if (
        not isinstance(priority, dict)
        or priority.get("decision") not in {"urgent_review", "needs_review", "no_affected_systems"}
        or priority.get("provisional") is not True
        or priority.get("rule") not in {"affected_and_exploit", "manual_review"}
    ):
        raise ValueError("Invalid journey assessment priority")
    count = value["fleet"].get("total_affected_systems")
    if count is not None and not _count(count):
        raise ValueError("Invalid journey assessment affected count")
    if priority["decision"] != _decision(value["fleet"], value["exploit"], priority["rule"]):
        raise ValueError("Invalid journey assessment priority evidence")
    epss = value["epss"]
    score = epss.get("score")
    if epss.get("status") == "available" and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 1
    ):
        raise ValueError("Invalid journey assessment EPSS score")
    if completed and value["missing"]:
        raise ValueError("Completed journey assessment has missing evidence")
    if completed and any(
        case.get("cve_mentioned") is not True for case in value.get("support", {}).get("cases", [])
    ):
        raise ValueError("Completed journey assessment has unverified Support relevance")
    if completed and (
        value["fleet"].get("coverage", {}).get("affected_systems") != "complete"
        or value["fleet"].get("active_rhel_coverage") != "complete"
    ):
        raise ValueError("Completed journey assessment has incomplete fleet scope")
    if completed and (
        count is None
        or epss.get("status") != "available"
        or epss.get("stale") is not False
        or value.get("support", {}).get("coverage", {}).get("case_search") != "complete"
        or sources is None
        or any(sources.get(name, {}).get("status") != "succeeded" for name in SOURCES)
        or any(
            sources["threat_intel"]
            .get("evidence", {})
            .get("sources", {})
            .get(name, {})
            .get("status")
            != "succeeded"
            for name in ("cve_org", "cisa_kev")
        )
    ):
        raise ValueError("Completed journey assessment lacks required source evidence")


def _evidence(result, name):
    value = result.sources[name].get("evidence", {})
    return value if isinstance(value, dict) else {}


def _active_fleet(fleet):
    """Active means a RHEL system checked in within 30 days, not proven host uptime."""
    systems = fleet.get("systems", [])
    active, unknown = 0, 0
    for system in systems:
        inventory = system.get("inventory") or {}
        profile_row = system.get("system_profile") or {}
        profile = (
            profile_row.get("system_profile", profile_row) or inventory.get("system_profile") or {}
        )
        os_data = profile.get("operating_system") or {}
        name = str(os_data.get("name", ""))
        vulnerability = system.get("vulnerability") or {}
        attributes = vulnerability.get("attributes", vulnerability)
        # Inventory `updated` is not necessarily a check-in. Use explicit host timestamps.
        last_seen = inventory.get("last_check_in") or attributes.get("last_seen")
        try:
            observed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            age = (datetime.now(UTC) - observed).total_seconds() / 86400
            if observed.tzinfo is None or age < 0:
                raise ValueError("Unknown check-in")
        except (AttributeError, TypeError, ValueError):
            unknown += 1
            continue
        if name not in {"RHEL", "Red Hat Enterprise Linux"}:
            unknown += 1
        elif age <= 30:
            active += 1
    complete = (
        fleet.get("coverage", {}).get("affected_systems") == "complete"
        and _count(fleet.get("total_affected_systems"))
        and len(systems) == fleet["total_affected_systems"]
    )
    return {
        "active_rhel_affected_systems": active if complete and not unknown else None,
        "active_rhel_coverage": "complete" if complete and not unknown else "unknown",
        "active_definition": "RHEL with a recorded check-in within 30 days; not host uptime",
    }


def build_assessment(request, result, *, rule="affected_and_exploit", connection_fingerprint=None):
    fleet = dict(_evidence(result, "fleet"))
    fleet.update(_active_fleet(fleet))
    count = fleet.get("total_affected_systems")
    if not _count(count):
        count = None
    fleet["total_affected_systems"] = count
    intel = _evidence(result, "threat_intel")
    epss = intel.get("epss", {"status": "unknown", "score": None, "stale": True})
    exploit = intel.get(
        "exploit", {"exploit_available": "unknown", "exploited_in_the_wild": "unknown"}
    )
    missing = [
        f"{name}_unavailable" for name in SOURCES if result.sources[name]["status"] != "succeeded"
    ]
    if fleet.get("coverage", {}).get("affected_systems") != "complete":
        missing.append("affected_fleet_incomplete")
    if fleet["active_rhel_coverage"] != "complete":
        missing.append("active_rhel_fleet_unverified")
    support = _evidence(result, "support")
    if support.get("coverage", {}).get("case_search") != "complete":
        missing.append("support_search_incomplete")
    if any(case.get("cve_mentioned") is not True for case in support.get("cases", [])):
        missing.append("support_cve_relevance_unverified")
    if epss.get("status") != "available" or epss.get("stale") is not False:
        missing.append("fresh_epss_unavailable")
    for source in ("cve_org", "cisa_kev"):
        if intel.get("sources", {}).get(source, {}).get("status") != "succeeded":
            missing.append(f"{source}_unavailable")
    decision, reasons = _decision(fleet, exploit, rule), ["Evidence requires analyst review."]
    if decision == "urgent_review":
        reasons = [
            "Connected fleet has confirmed CVE-affected systems.",
            "A source reports a public proof of concept or observed exploitation.",
        ]
    elif decision == "no_affected_systems":
        reasons = ["CVE lookup reports zero affected systems."]
    return {
        "schema_version": 1,
        "cve_id": request.cve_id,
        "assessed_at": datetime.now(UTC).isoformat(),
        "environment": {
            "alias": request.environment,
            "scope": "configured_lightspeed_connection",
            "identity_verified": False,
            "connection_fingerprint": connection_fingerprint,
        },
        "fleet": fleet,
        "epss": epss,
        "exploit": exploit,
        "support": support,
        "vendor": {
            key: _evidence(result, "redhat")[key]
            for key in (
                "redhat_severity",
                "cvss3",
                "mitigation",
                "statement",
                "affected_release",
                "package_state",
                "references",
                "source_url",
                "retrieved_at",
            )
            if key in _evidence(result, "redhat")
        },
        "priority": {
            "decision": decision,
            "rule": rule,
            "provisional": True,
            "reasons": reasons,
            "epss_role": "supporting probability, not proof of attacks",
        },
        "missing": sorted(set(missing)),
        "remediation": {"status": "not_in_scope"},
    }
