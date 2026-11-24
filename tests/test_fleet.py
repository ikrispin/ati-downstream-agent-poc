"""Bounded CVE-to-host inspection using the discovered Lightspeed MCP schemas."""

import asyncio
from uuid import UUID

import pytest

from ati_lscore.fleet import FleetInspector

HOST_A = str(UUID(int=1))
HOST_B = str(UUID(int=2))
HOST_C = str(UUID(int=3))


def tool(name, properties, required=()):
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        },
    }


def catalog():
    return [
        tool(
            "vulnerability__get_cve_systems",
            {
                "cve": {"type": "string"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
            ("cve",),
        ),
        tool("inventory__get_host_details", {"host_ids": {"type": "string"}}, ("host_ids",)),
        tool("inventory__get_host_system_profile", {"host_ids": {"type": "string"}}),
    ]


async def test_cve_lookup_enriches_only_returned_hosts_and_bounds_profile_batches():
    calls = []

    async def call(name, arguments):
        calls.append((name, arguments))
        if name == "vulnerability__get_cve_systems":
            return {
                "result": {
                    "data": [
                        {"id": host, "attributes": {"status": 0}}
                        for host in (HOST_A, HOST_B, HOST_C)
                    ],
                    "meta": {"total_items": 3},
                }
            }
        ids = arguments["host_ids"].split(",")
        return {"data": [{"id": host, "attributes": {"staleness": "fresh"}} for host in ids]}

    result = await FleetInspector(
        catalog(), call, source_url="https://mcp.invalid/path?key=secret"
    ).inspect_cve("cve-2023-38545")
    assert result["cve_id"] == "CVE-2023-38545"
    assert result["source_url"] == "https://mcp.invalid/path"
    assert result["coverage"]["affected_systems"] == "complete"
    assert result["coverage"]["active_customer_fleet"] == "unverified"
    assert [system["system_id"] for system in result["systems"]] == [HOST_A, HOST_B, HOST_C]
    profile_calls = [args for name, args in calls if name.endswith("system_profile")]
    assert profile_calls == [{"host_ids": HOST_A + "," + HOST_B}, {"host_ids": HOST_C}]
    assert all(system["inventory"] and system["system_profile"] for system in result["systems"])


async def test_bounded_host_list_reports_incomplete_coverage_instead_of_all_fleet():
    async def call(name, arguments):
        return {"data": [{"id": HOST_A}, {"id": HOST_B}], "meta": {"total_items": 100}}

    result = await FleetInspector(
        catalog()[:1], call, source_url="https://mcp.invalid", max_systems=2
    ).inspect_cve("CVE-2023-38545")
    assert result["coverage"]["affected_systems"] == "partial"
    assert result["coverage"]["inventory_details"] == "unavailable"
    assert result["total_affected_systems"] == 100
    assert len(result["systems"]) == 2


async def test_empty_cve_result_is_real_zero_without_asserting_inventory_is_current():
    async def call(name, arguments):
        assert name == "vulnerability__get_cve_systems"
        return {"data": [], "meta": {"total_items": 0}}

    result = await FleetInspector(catalog(), call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["systems"] == []
    assert result["total_affected_systems"] == 0
    assert result["coverage"]["active_customer_fleet"] == "unverified"


async def test_unknown_required_arguments_fail_closed_without_guessing_values():
    unexpected = [
        tool(
            "vulnerability__get_cve_systems",
            {"cve": {"type": "string"}, "tenant": {"type": "string"}},
            ("cve", "tenant"),
        )
    ]

    async def call(*_):
        pytest.fail("An unsupported schema must not reach the server")

    result = await FleetInspector(unexpected, call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["status"] == "unsupported"
    assert result["coverage"]["affected_systems"] == "unknown"


async def test_cve_field_must_be_advertised_even_when_extra_arguments_are_allowed():
    async def call(*_):
        pytest.fail("No CVE parameter may be invented")

    tools = [
        {
            "name": "vulnerability__get_cve_systems",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        }
    ]
    result = await FleetInspector(tools, call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["status"] == "unsupported"


async def test_invalid_cve_never_reaches_a_tool():
    async def call(*_):
        pytest.fail("Invalid CVE must not reach the server")

    with pytest.raises(ValueError):
        await FleetInspector(catalog(), call, source_url="mcp://lightspeed").inspect_cve("all CVEs")


async def test_unexpected_host_id_is_not_used_for_follow_up_queries():
    calls = []

    async def call(name, arguments):
        calls.append(name)
        return {"data": [{"id": "untrusted-not-a-uuid"}], "meta": {"total_items": 1}}

    result = await FleetInspector(catalog(), call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert calls == ["vulnerability__get_cve_systems"]
    assert result["coverage"]["affected_systems"] == "partial"
    assert result["systems"] == []


async def test_late_page_failure_preserves_earlier_hosts_and_total_without_error_body():
    first_page = [{"id": str(UUID(int=i))} for i in range(1, 11)]

    async def call(name, arguments):
        if arguments["offset"]:
            raise RuntimeError("Bearer secret-do-not-return")
        return {"data": first_page, "meta": {"total_items": 100}}

    result = await FleetInspector(
        catalog()[:1], call, source_url="mcp://lightspeed", max_systems=20
    ).inspect_cve("CVE-2023-38545")
    assert result["status"] == "partial"
    assert len(result["systems"]) == 10
    assert result["total_affected_systems"] == 100
    assert result["coverage"]["affected_systems"] == "partial"
    assert result["errors"][0]["code"] == "fleet_page_failed"
    assert "secret" not in str(result)


async def test_failed_inventory_enrichment_preserves_hosts_and_continues_profiles():
    async def call(name, arguments):
        if name == "vulnerability__get_cve_systems":
            return {"data": [{"id": HOST_A}, {"id": HOST_B}], "meta": {"total_items": 2}}
        if name == "inventory__get_host_details":
            raise RuntimeError("https://private.invalid/token")
        return {"data": [{"id": host} for host in arguments["host_ids"].split(",")]}

    result = await FleetInspector(catalog(), call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["status"] == "partial"
    assert result["total_affected_systems"] == 2
    assert len(result["systems"]) == 2
    assert result["coverage"]["affected_systems"] == "complete"
    assert result["coverage"]["inventory_details"] == "partial"
    assert result["coverage"]["system_profiles"] == "complete"
    assert result["errors"][0]["code"] == "fleet_enrichment_failed"
    assert "private.invalid" not in str(result)


async def test_cancellation_during_enrichment_is_not_suppressed():
    async def call(name, arguments):
        if name == "vulnerability__get_cve_systems":
            return {"data": [{"id": HOST_A}], "meta": {"total_items": 1}}
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await FleetInspector(catalog(), call, source_url="mcp://lightspeed").inspect_cve(
            "CVE-2023-38545"
        )


async def test_discarded_rows_are_counted_and_cannot_establish_complete_host_coverage():
    async def call(name, arguments):
        return {
            "data": [{"id": HOST_A}, {"id": "invalid"}, "invalid-row"],
            "meta": {"total_items": 3},
        }

    result = await FleetInspector(catalog()[:1], call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["discarded_system_rows"] == 2
    assert len(result["systems"]) == 1
    assert result["coverage"]["affected_systems"] == "partial"


async def test_positive_total_with_empty_page_is_not_complete_inventory_coverage():
    async def call(name, arguments):
        return {"data": [], "meta": {"total_items": 2}}

    result = await FleetInspector(catalog()[:1], call, source_url="mcp://lightspeed").inspect_cve(
        "CVE-2023-38545"
    )
    assert result["total_affected_systems"] == 2
    assert result["coverage"]["affected_systems"] == "partial"
