"""Read-only ATI business tools. LSCore owns every model call and loop decision."""

import asyncio
from types import SimpleNamespace
from typing import Literal

from .assessment import SOURCES, build_assessment, validate_assessment
from .models import AuthenticationRequired, InvestigationRequest, SourceFailure
from .security_data import normalize_cve_id

SourceName = Literal["redhat", "osidb", "lightspeed", "fleet", "support", "threat_intel"]


def _failure(error):
    if isinstance(error, SourceFailure):
        return error.code, error.retryable
    if isinstance(error, AuthenticationRequired):
        return "authentication_required", False
    if isinstance(error, TimeoutError):
        return "source_timeout", True
    return "source_error", False


class DomainTools:
    def __init__(self, sources, store, *, source_timeout=35, priority_rule="affected_and_exploit"):
        if priority_rule not in {"affected_and_exploit", "manual_review"}:
            raise ValueError("Unknown priority rule")
        if source_timeout <= 0:
            raise ValueError("Source timeout must be positive")
        self.sources, self.store = sources, store
        self.source_timeout, self.priority_rule = source_timeout, priority_rule

    def _scope(self, value):
        if (
            value["connection_fingerprint"] != self.sources.connection_fingerprint
            or value["environment"] != self.sources.environment
            or value["priority_rule"] != self.priority_rule
        ):
            raise ValueError("Assessment connection or policy changed; begin a fresh assessment")

    def begin(self, cve_id, environment):
        cve_id = normalize_cve_id(cve_id)
        if environment != self.sources.environment:
            raise ValueError("Environment must match the configured connection")
        value = self.store.create(
            cve_id,
            environment,
            self.sources.connection_fingerprint,
            self.priority_rule,
            data_mode=getattr(self.sources, "data_mode", "live_sources"),
        )
        return {key: value[key] for key in ("assessment_id", "cve_id", "environment", "data_mode")}

    @staticmethod
    def _summary(run_id, name, observation):
        result = {"assessment_id": run_id, "collector": name, "status": observation["status"]}
        if observation["status"] != "succeeded":
            result.update({key: observation[key] for key in ("error_code", "retryable")})
            return result
        evidence = observation["evidence"]
        facts = {}
        if name == "fleet":
            facts = {key: evidence.get(key) for key in ("total_affected_systems", "coverage")}
        elif name == "support":
            cases = evidence.get("cases", [])
            facts = {
                "support_search_hit_count": len(cases),
                "confirmed_related_support_case_count": sum(
                    case.get("cve_mentioned") is True for case in cases
                ),
                "coverage": evidence.get("coverage"),
            }
        elif name == "threat_intel":
            facts = {key: evidence.get(key) for key in ("epss", "exploit")}
        elif name == "redhat":
            facts = {"redhat_severity": evidence.get("redhat_severity")}
        elif name == "osidb":
            facts = {"impact": evidence.get("impact")}
        result["facts"] = facts
        return result

    async def collect(self, run_id, source):
        if source not in SOURCES:
            raise ValueError("Collector is not registered")

        def reserve(value):
            self._scope(value)
            if value["assessment"] is not None:
                raise ValueError("Assessment is finalized; begin a fresh assessment")
            old = value["sources"].get(source)
            if old is not None:
                if old["status"] == "running":
                    raise ValueError("Collector is already running")
                return old
            value["sources"][source] = {"status": "running"}
            return None

        existing = self.store.change(run_id, reserve)
        if existing is not None:
            return self._summary(run_id, source, existing)
        record = self.store.read(run_id)
        request = InvestigationRequest(
            "", record["cve_id"], None, run_id, True, record["environment"]
        )
        try:
            async with asyncio.timeout(self.source_timeout):
                if source in {"redhat", "osidb", "lightspeed"}:
                    name = {
                        "redhat": "get_redhat_cve",
                        "osidb": "get_public_osidb_cve",
                        "lightspeed": "vulnerability__get_cve",
                    }[source]
                    evidence = await self.sources.call(name, {"cve_id": request.cve_id}, request)
                else:
                    operation = {
                        "fleet": self.sources.inspect_fleet,
                        "support": self.sources.search_support,
                        "threat_intel": self.sources.threat_intel,
                    }[source]
                    evidence = await operation(request)
                if (
                    not isinstance(evidence, dict)
                    or evidence.get("cve_id", request.cve_id) != request.cve_id
                ):
                    raise SourceFailure("source_identity_mismatch")
            observation = {"status": "succeeded", "evidence": evidence}
        except asyncio.CancelledError:
            self.store.change(
                run_id,
                lambda value: value["sources"].update(
                    {source: {"status": "failed", "error_code": "cancelled", "retryable": False}}
                ),
            )
            raise
        except Exception as error:
            code, retryable = _failure(error)
            observation = {"status": "failed", "error_code": code, "retryable": retryable}
        self.store.change(run_id, lambda value: value["sources"].update({source: observation}))
        return self._summary(run_id, source, observation)

    def finalize(self, run_id):
        def finish(value):
            self._scope(value)
            if value["assessment"] is not None:
                return value
            if any(item["status"] == "running" for item in value["sources"].values()):
                raise ValueError("A collector is still running")
            sources = {
                name: value["sources"].get(name, {"status": "not_queried"}) for name in SOURCES
            }
            request = InvestigationRequest(
                "", value["cve_id"], None, run_id, True, value["environment"]
            )
            assessment = build_assessment(
                request,
                SimpleNamespace(sources=sources),
                rule=self.priority_rule,
                connection_fingerprint=value["connection_fingerprint"],
            )
            success = sum(item["status"] == "succeeded" for item in sources.values())
            outcome = (
                "completed" if not assessment["missing"] else "partial" if success else "failed"
            )
            validate_assessment(
                assessment, request.cve_id, completed=outcome == "completed", sources=sources
            )
            value.update(assessment=assessment, outcome=outcome)
            return value

        value = self.store.change(run_id, finish)
        assessment = value["assessment"]
        return {
            "assessment_id": run_id,
            "cve_id": value["cve_id"],
            "environment": value["environment"],
            "outcome": value["outcome"],
            "data_mode": value["data_mode"],
            "priority": assessment["priority"],
            "missing": assessment["missing"],
            "affected_systems": assessment["fleet"]["total_affected_systems"],
            "epss": assessment["epss"],
            "exploit": assessment["exploit"],
            "remediation": assessment["remediation"],
        }
