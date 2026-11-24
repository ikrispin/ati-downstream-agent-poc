"""Offline positive controls; records are synthetic and never query Support."""

import json

import pytest

from ati_lscore.support_search import SupportSearch


def filter_catalog():
    """Relevant fields copied from the recorded GetCasesByFilter input schema."""
    fields = {
        "keyword": {"type": "string"},
        "maxResults": {"type": "integer"},
        "caseNumbers": {"type": "array", "items": {"type": "string"}},
        **{
            key: {"type": "boolean"}
            for key in (
                "includeClosed",
                "reducedInformation",
                "includePrivate",
                "includeSecureSupport",
                "includeAllCustomerCases",
            )
        },
    }
    return [
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


@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2026-115560",
        "CVE-2026-114938",
        "CVE-2026-123633",
        "CVE-2026-123007",
        "CVE-2026-129182",
        "CVE-2026-126714",
        "CVE-2026-129289",
        "CVE-2026-129481",
        "CVE-2026-129496",
        "CVE-2026-129291",
    ],
)
async def test_six_digit_cve_graphql_positive_preserves_leading_zero_number(cve_id):
    async def call(name, arguments):
        assert name == "GetCasesByFilter"
        assert arguments["input"]["keyword"] == cve_id
        return {
            "data": {
                "casesFilter": {
                    "totalCount": 1,
                    "cases": [
                        {
                            "id": "synthetic-internal-id",
                            "caseNumber": "00098765",
                            "status": "Closed",
                            "severity": "3",
                            "product": "RHEL",
                            "summary": "Synthetic assessment",
                            "description": f"https://access.redhat.com/security/cve/{cve_id}",
                            "contactName": "synthetic-contact-not-retained",
                        }
                    ],
                }
            }
        }

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve(cve_id)

    assert result["total_matches"] == 1
    assert result["status"] == "succeeded"
    assert result["coverage"]["case_search"] == "complete"
    assert result["cases"] == [
        {
            "case_id": "00098765",
            "status": "Closed",
            "severity": "3",
            "product": "RHEL",
            "cve_mentioned": True,
            "match_basis": "literal_cve_in_search_result",
        }
    ]
    assert "synthetic-contact" not in json.dumps(result)


@pytest.mark.parametrize("wrapper", ["data", "result", "casesFilter"])
async def test_positive_rows_survive_supported_nested_wrappers(wrapper):
    async def call(*_):
        return {
            wrapper: {
                "data": {
                    "casesFilter": {
                        "totalCount": 1,
                        "cases": [{"caseNumber": "00098765"}],
                    }
                }
            }
        }

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve("CVE-2026-115560")

    assert result["total_matches"] == 1
    assert result["cases"][0]["case_id"] == "00098765"
    assert result["cases"][0]["match_basis"] == "search_query_only"
    assert result["cases"][0]["cve_mentioned"] is False


@pytest.mark.parametrize(
    ("reference", "literal_match"),
    [
        ("https://access.redhat.com/security/cve/CVE-2026-115560", True),
        ("https://example.invalid/advisory?cve=cve-2026-115560&format=json", True),
        ("CVE-2026-115560, CVE-2026-123633", True),
        ("CVE-2026-1155600", False),
        ("CVE-2026-115560-extra", False),
        ("CVE-2026-123633", False),
    ],
)
async def test_url_and_multi_cve_linkage_is_literal_without_discarding_rows(
    reference, literal_match
):
    async def call(*_):
        return {
            "data": {
                "casesFilter": {
                    "totalCount": 1,
                    "cases": [{"caseNumber": "00098765", "description": reference}],
                }
            }
        }

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve("CVE-2026-115560")

    assert len(result["cases"]) == 1
    assert result["cases"][0]["cve_mentioned"] is literal_match


async def test_zero_search_records_effective_scope_without_customer_absence_claim():
    calls = []

    async def call(name, arguments):
        calls.append((name, arguments))
        return {"data": {"casesFilter": {"totalCount": 0, "cases": None}}}

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve("CVE-2026-115560")

    assert calls[0][1]["input"] == {
        "keyword": "CVE-2026-115560",
        "maxResults": 5,
        "includeClosed": True,
        "reducedInformation": True,
        "includePrivate": False,
        "includeSecureSupport": False,
        "includeAllCustomerCases": False,
    }
    assert result["total_matches"] == 0
    assert result["coverage"]["case_search"] == "complete"
    assert result["coverage"]["customer_case_visibility"] == "unverified"
    scope = result["search_scope"]
    assert scope["cve_id"] == "CVE-2026-115560"
    assert scope["result_limit"] == scope["server_result_limit"] == 5
    assert scope["tool_name"] == "GetCasesByFilter"
    assert scope["query_field"] == "input.keyword"
    assert scope["include_closed"] is True
    assert scope["reduced_information"] is True
    assert scope["include_private"] is False
    assert scope["include_secure_support"] is False
    assert scope["include_all_customer_cases"] is False
    assert scope["customer_case_absence_established"] is False
    assert "do not establish absence" in scope["note"]


async def test_unadvertised_scope_flags_remain_unknown_without_guessing_arguments():
    tools = filter_catalog()
    fields = tools[0]["inputSchema"]["definitions"]["Filter"]["properties"]
    for name in (
        "includeClosed",
        "reducedInformation",
        "includePrivate",
        "includeSecureSupport",
        "includeAllCustomerCases",
    ):
        del fields[name]

    async def call(name, arguments):
        assert arguments == {"input": {"keyword": "CVE-2026-115560", "maxResults": 5}}
        return {"data": {"casesFilter": {"totalCount": 0, "cases": None}}}

    result = await SupportSearch(tools, call, source_url="https://support.invalid/mcp").search_cve(
        "CVE-2026-115560"
    )

    scope = result["search_scope"]
    for field in (
        "include_closed",
        "reduced_information",
        "include_private",
        "include_secure_support",
        "include_all_customer_cases",
    ):
        assert scope[field] is None
    assert result["coverage"]["customer_case_visibility"] == "unverified"


async def test_unknown_tool_binding_still_explains_scope_limit_without_sending_a_request():
    async def call(*_):
        pytest.fail("An unknown binding must not issue a query")

    result = await SupportSearch([], call, source_url="https://support.invalid/mcp").search_cve(
        "CVE-2026-115560"
    )

    assert result["status"] == "unverified"
    assert result["coverage"]["customer_case_visibility"] == "unverified"
    assert result["search_scope"]["customer_case_absence_established"] is False
    assert result["search_scope"]["tool_name"] is None


@pytest.mark.parametrize(
    ("summaries", "expected_relevance"),
    [
        (["CVE-2026-115560 assessment"], "verified"),
        (["CVE-2026-115560 assessment", "Synthetic unrelated summary"], "unverified"),
        (["Synthetic unrelated summary"], "unverified"),
    ],
)
async def test_relevance_requires_literal_link_in_every_retained_hit(summaries, expected_relevance):
    async def call(*_):
        return {
            "data": {
                "casesFilter": {
                    "totalCount": len(summaries),
                    "cases": [
                        {"caseNumber": f"0009876{index}", "summary": summary}
                        for index, summary in enumerate(summaries)
                    ],
                }
            }
        }

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve("CVE-2026-115560")

    assert result["coverage"]["cve_relevance"] == expected_relevance
    assert len(result["cases"]) == len(summaries)
    if expected_relevance == "unverified":
        assert any(case["match_basis"] == "search_query_only" for case in result["cases"])
        assert any("not proven related" in note for note in result["unknowns"])


@pytest.mark.parametrize(
    ("total", "expected_relevance"), [(0, "not_applicable"), (2, "unverified")]
)
async def test_empty_case_results_only_make_relevance_inapplicable_when_query_is_complete(
    total, expected_relevance
):
    async def call(*_):
        return {"data": {"casesFilter": {"totalCount": total, "cases": []}}}

    result = await SupportSearch(
        filter_catalog(), call, source_url="https://support.invalid/mcp"
    ).search_cve("CVE-2026-115560")

    assert result["coverage"]["cve_relevance"] == expected_relevance


async def test_relevance_is_unverified_without_an_executed_supported_query():
    async def call(*_):
        pytest.fail("No tool may be called")

    result = await SupportSearch([], call, source_url="https://support.invalid/mcp").search_cve(
        "CVE-2026-115560"
    )

    assert result["coverage"]["cve_relevance"] == "unverified"
