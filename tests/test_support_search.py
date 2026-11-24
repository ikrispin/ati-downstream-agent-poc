"""Support search accepts a CVE only and never invents a server query schema."""

import pytest

from ati_lscore.support_search import SearchBinding, SupportSearch


def catalog(properties=None):
    return [
        {
            "name": "SearchCases",
            "inputSchema": {
                "type": "object",
                "properties": properties
                or {"query": {"type": "string"}, "limit": {"type": "integer"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        }
    ]


async def test_explicit_verified_binding_searches_exact_cve_and_caps_results_at_five():
    calls = []

    async def call(name, arguments):
        calls.append((name, arguments))
        return {
            "cases": [
                {"caseNumber": str(i), "summary": "CVE-2023-38545 analysis"} for i in range(10)
            ],
            "total": 10,
        }

    result = await SupportSearch(
        catalog(),
        call,
        source_url="https://mcp.invalid?token=private",
        binding=SearchBinding("SearchCases", "query", "limit"),
    ).search_cve("cve-2023-38545")
    assert calls == [("SearchCases", {"query": "CVE-2023-38545", "limit": 5})]
    assert len(result["cases"]) == 5
    assert result["coverage"]["case_search"] == "partial"
    assert result["source_url"] == "https://mcp.invalid"
    assert all(case["cve_mentioned"] for case in result["cases"])


async def test_unverified_or_missing_binding_never_guesses_a_search_operation():
    async def call(*_):
        pytest.fail("No verified search binding is available")

    result = await SupportSearch(catalog(), call, source_url="mcp://support").search_cve(
        "CVE-2023-38545"
    )
    assert result["status"] == "unverified"
    assert result["coverage"]["case_search"] == "unknown"


async def test_live_verified_filter_binding_uses_cve_keyword_and_private_data_restrictions():
    fields = {
        "keyword": {"type": "string"},
        "maxResults": {"type": "integer"},
        **{
            key: {"type": "boolean"}
            for key in (
                "reducedInformation",
                "includePrivate",
                "includeSecureSupport",
                "includeAllCustomerCases",
            )
        },
    }
    tools = [
        {
            "name": "GetCasesByFilter",
            "inputSchema": {
                "type": "object",
                "properties": {"input": {"$ref": "#/definitions/Filter"}},
                "required": ["input"],
                "definitions": {"Filter": {"type": "object", "properties": fields}},
            },
        }
    ]
    calls = []

    async def call(name, arguments):
        calls.append((name, arguments))
        return {
            "result": {
                "totalCount": 1,
                "cases": [
                    {
                        "caseNumber": "synthetic-case",
                        "summary": "CVE-2023-38545 contains private-name",
                        "description": "private-body",
                        "contactName": "private-person",
                        "comments": ["private"],
                        "status": "Closed",
                        "product": "RHEL",
                        "severity": "3",
                    }
                ],
            }
        }

    result = await SupportSearch(tools, call, source_url="mcp://support").search_cve(
        "CVE-2023-38545"
    )
    assert calls == [
        (
            "GetCasesByFilter",
            {
                "input": {
                    "keyword": "CVE-2023-38545",
                    "maxResults": 5,
                    "reducedInformation": True,
                    "includePrivate": False,
                    "includeSecureSupport": False,
                    "includeAllCustomerCases": False,
                }
            },
        )
    ]
    assert result["coverage"]["case_search"] == "complete"
    assert result["cases"][0]["case_id"] == "synthetic-case"
    assert all(
        sentinel not in str(result)
        for sentinel in ("private-name", "private-body", "private-person")
    )
    assert set(result["cases"][0]) == {
        "case_id",
        "status",
        "severity",
        "product",
        "cve_mentioned",
        "match_basis",
    }


async def test_binding_field_must_exist_even_if_server_schema_allows_extra_properties():
    async def call(*_):
        pytest.fail("The adapter must not invent a server parameter")

    tools = [{"name": "SearchCases", "inputSchema": {"type": "object", "properties": {}}}]
    result = await SupportSearch(
        tools, call, source_url="mcp://support", binding=SearchBinding("SearchCases", "query")
    ).search_cve("CVE-2023-38545")
    assert result["status"] == "unsupported"


async def test_observed_zero_match_support_response_is_zero_without_broad_follow_up():
    async def call(name, arguments):
        return {"data": {"casesFilter": {"totalCount": 0, "cases": None}}}

    result = await SupportSearch(
        catalog(),
        call,
        source_url="mcp://support",
        binding=SearchBinding("SearchCases", "query", "limit"),
    ).search_cve("CVE-2023-38545")
    assert result["status"] == "succeeded"
    assert result["cases"] == []
    assert result["total_matches"] == 0
    assert result["coverage"]["case_search"] == "complete"


async def test_schema_mismatch_does_not_send_extra_or_missing_server_arguments():
    async def call(*_):
        pytest.fail("Unknown required fields must not be guessed")

    value = catalog({"query": {"type": "object"}})
    result = await SupportSearch(
        value, call, source_url="mcp://support", binding=SearchBinding("SearchCases", "query")
    ).search_cve("CVE-2023-38545")
    assert result["status"] == "unsupported"


@pytest.mark.parametrize("value", ["all cases", "CVE-2023-38545 OR *", ""])
async def test_search_rejects_arbitrary_queries(value):
    async def call(*_):
        pytest.fail("Arbitrary search must not be sent")

    with pytest.raises(ValueError):
        await SupportSearch(catalog(), call, source_url="mcp://support").search_cve(value)


@pytest.mark.parametrize("limit", [0, 6, True])
async def test_result_limit_cannot_bypass_the_five_case_cap(limit):
    async def call(*_):
        pytest.fail("Invalid cap must not be sent")

    with pytest.raises(ValueError):
        await SupportSearch(catalog(), call, source_url="mcp://support").search_cve(
            "CVE-2023-38545", max_results=limit
        )
