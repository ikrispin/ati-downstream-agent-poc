"""Explicit synthetic source mode for native LSCore integration checks, no model loop."""

from datetime import UTC, datetime

from .assessment import SOURCES
from .models import SourceFailure


class FixtureSources:
    data_mode = "synthetic_fixture"

    def __init__(self, environment, fail_source=""):
        if fail_source and fail_source not in SOURCES:
            raise ValueError("Unknown fixture failure source")
        self.environment, self.fail_source = environment, fail_source
        self.connection_fingerprint = f"fixture:{environment}:{fail_source}"

    async def collect(self, name, request):
        if name == self.fail_source:
            raise SourceFailure("source_unavailable", retryable=True)
        base = {"cve_id": request.cve_id, "synthetic": True}
        if name == "fleet":
            base.update(
                total_affected_systems=1,
                coverage={"affected_systems": "complete"},
                systems=[
                    {
                        "system_id": "00000000-0000-0000-0000-000000000001",
                        "inventory": {"last_check_in": datetime.now(UTC).isoformat()},
                        "system_profile": {"operating_system": {"name": "RHEL"}},
                    }
                ],
            )
        elif name == "support":
            base.update(
                cases=[{"case_id": "00000001", "cve_mentioned": True}],
                coverage={"case_search": "complete"},
            )
        elif name == "threat_intel":
            base.update(
                epss={"status": "available", "score": 0.15, "stale": False},
                exploit={"exploit_available": "yes", "exploited_in_the_wild": "unknown"},
                sources={key: {"status": "succeeded"} for key in ("cve_org", "cisa_kev")},
            )
        elif name == "redhat":
            base["redhat_severity"] = "Important"
        elif name == "osidb":
            base["impact"] = "IMPORTANT"
        return base

    async def call(self, name, arguments, request):
        return await self.collect(
            {
                "get_redhat_cve": "redhat",
                "get_public_osidb_cve": "osidb",
                "vulnerability__get_cve": "lightspeed",
            }[name],
            request,
        )

    async def inspect_fleet(self, request):
        return await self.collect("fleet", request)

    async def search_support(self, request):
        return await self.collect("support", request)

    async def threat_intel(self, request):
        return await self.collect("threat_intel", request)
