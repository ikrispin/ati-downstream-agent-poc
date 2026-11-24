"""CVE-only Support search; generic query bindings require catalog verification."""

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from .security_data import normalize_cve_id

_FILTER_SCOPE_FLAGS = (
    ("input.includeClosed", "include_closed", True),
    ("input.reducedInformation", "reduced_information", True),
    ("input.includePrivate", "include_private", False),
    ("input.includeSecureSupport", "include_secure_support", False),
    ("input.includeAllCustomerCases", "include_all_customer_cases", False),
)


@dataclass(frozen=True)
class SearchBinding:
    """A tool and fields explicitly verified against the current server catalog."""

    tool_name: str
    query_field: str
    limit_field: str | None = None


def _has_external_ref(value):
    if isinstance(value, dict):
        reference = value.get("$ref")
        return (
            reference is not None
            and not str(reference).startswith("#/")
            or any(_has_external_ref(child) for child in value.values())
        )
    return isinstance(value, list) and any(_has_external_ref(child) for child in value)


def _property(schema, path):
    current = schema
    for field in path.split("."):
        for _ in range(10):
            if "$ref" not in current:
                break
            pointer = current["$ref"]
            if not isinstance(pointer, str) or not pointer.startswith("#/"):
                return None
            current = schema
            for segment in pointer[2:].split("/"):
                current = current.get(segment.replace("~1", "/").replace("~0", "~"), {})
        current = current.get("properties", {}).get(field)
        if not isinstance(current, dict):
            return None
    return current


def _set_field(arguments, path, value):
    fields = path.split(".")
    for field in fields[:-1]:
        arguments = arguments.setdefault(field, {})
    arguments[fields[-1]] = value


def _case_rows(payload):
    for _ in range(6):
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)], None
        if not isinstance(payload, dict):
            break
        if payload.get("errors"):
            break
        meta = payload.get("meta") or {}
        total = payload.get(
            "totalCount", payload.get("total", meta.get("total_items", meta.get("total")))
        )
        if total == 0 and payload.get("cases", "missing") is None:
            return [], 0
        for key in ("cases", "results", "items", "data"):
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)], total
        payload = payload.get("casesFilter", payload.get("result", payload.get("data")))
    return None, None


class SupportSearch:
    def __init__(
        self,
        catalog,
        call_tool: Callable[[str, dict], Awaitable[Any]],
        *,
        source_url: str,
        binding: SearchBinding | None = None,
    ):
        self.catalog = {tool["name"]: tool for tool in catalog}
        self.call_tool = call_tool
        self.binding = binding
        parsed = urlsplit(source_url)
        self.source_url = urlunsplit(
            (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")
        )

    def _binding(self):
        if self.binding is not None:
            return self.binding
        candidates = []
        for name, tool in self.catalog.items():
            schema = tool.get("inputSchema", tool.get("input_schema", {}))
            # Verified against the authenticated 24 November catalog, not inferred from a name.
            if name == "GetCasesByFilter":
                keyword = _property(schema, "input.keyword") or {}
                limit = _property(schema, "input.maxResults") or {}
                if keyword.get("type") == "string" and limit.get("type") == "integer":
                    candidates.append(SearchBinding(name, "input.keyword", "input.maxResults"))
                continue
            if "search" not in name.lower() or "case" not in name.lower():
                continue
            properties = schema.get("properties", {})
            for field in ("cve_id", "cve", "cveId"):
                if properties.get(field, {}).get("type") == "string":
                    limit = next(
                        (key for key in ("limit", "max_results", "pageSize") if key in properties),
                        None,
                    )
                    candidates.append(SearchBinding(name, field, limit))
        return candidates[0] if len(candidates) == 1 else None

    async def search_cve(self, cve_id: str, max_results: int = 5) -> dict[str, Any]:
        cve_id = normalize_cve_id(cve_id)
        if type(max_results) is not int or not 1 <= max_results <= 5:
            raise ValueError("Support search permits between one and five results")
        result = {
            "source": "support_cve_search",
            "source_url": self.source_url,
            "cve_id": cve_id,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "status": "unverified",
            "cases": [],
            "total_matches": None,
            "coverage": {
                "case_search": "unknown",
                "customer_case_visibility": "unverified",
                "cve_relevance": "unverified",
            },
            "search_scope": {
                "cve_id": cve_id,
                "result_limit": max_results,
                "tool_name": None,
                "query_field": None,
                "server_result_limit": None,
                **{field: None for _, field, _ in _FILTER_SCOPE_FLAGS},
                "customer_case_absence_established": False,
                "note": (
                    "Zero matches apply only to this query and its effective filters; "
                    "they do not establish absence of related cases across all customer records."
                ),
            },
            "unknowns": [],
        }
        binding = self._binding()
        if binding is None:
            result["unknowns"].append("No uniquely verified CVE-scoped Support search binding.")
            return result
        definition = self.catalog.get(binding.tool_name, {})
        schema = definition.get("inputSchema", definition.get("input_schema"))
        try:
            if not isinstance(schema, dict) or _has_external_ref(schema):
                raise ValueError("Unsupported MCP input schema")
            Draft202012Validator.check_schema(schema)
            if _property(schema, binding.query_field) is None:
                raise ValueError("CVE search field is not advertised")
            arguments = {}
            _set_field(arguments, binding.query_field, cve_id)
            if binding.limit_field:
                if _property(schema, binding.limit_field) is None:
                    raise ValueError("Search limit field is not advertised")
                _set_field(arguments, binding.limit_field, max_results)
            effective_filters = {}
            if binding.tool_name == "GetCasesByFilter":
                for path, field, value in _FILTER_SCOPE_FLAGS:
                    if _property(schema, path) is not None:
                        _set_field(arguments, path, value)
                        effective_filters[field] = value
            Draft202012Validator(schema).validate(arguments)
        except (ValueError, SchemaError, ValidationError):
            result["status"] = "unsupported"
            result["unknowns"].append(
                "Verified search binding no longer matches the server schema."
            )
            return result
        result["search_scope"].update(
            tool_name=binding.tool_name,
            query_field=binding.query_field,
            server_result_limit=max_results if binding.limit_field else None,
            **effective_filters,
        )
        rows, total = _case_rows(await self.call_tool(binding.tool_name, arguments))
        if rows is None:
            result["unknowns"].append("Support search response structure is unverified.")
            return result
        result["status"] = "succeeded"
        result["total_matches"] = total if type(total) is int and total >= 0 else None
        for row in rows[:max_results]:
            # Examine text for literal CVE linkage, but never retain titles or free text.
            mentioned = bool(
                re.search(
                    r"(?<![A-Z0-9-])" + re.escape(cve_id) + r"(?![A-Z0-9-])",
                    " ".join(str(value) for value in row.values()),
                    re.I,
                )
            )
            item = {
                "cve_mentioned": mentioned,
                "match_basis": "literal_cve_in_search_result" if mentioned else "search_query_only",
            }
            for output, aliases in (
                ("case_id", ("caseNumber", "case_number", "caseId", "id")),
                ("status", ("status",)),
                ("severity", ("severity",)),
                ("product", ("product", "productName")),
            ):
                value = next((row[key] for key in aliases if key in row), None)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    item[output] = str(value)[:200]
            result["cases"].append(item)
        complete = result["total_matches"] is not None and result["total_matches"] <= min(
            max_results, len(rows)
        )
        if total is None and binding.limit_field and len(rows) < max_results:
            complete = True
        result["coverage"]["case_search"] = "complete" if complete else "partial"
        if result["cases"]:
            if all(case["cve_mentioned"] for case in result["cases"]):
                result["coverage"]["cve_relevance"] = "verified"
            else:
                result["unknowns"].append(
                    "Some retained hits have no literal CVE match and are not proven related; "
                    "their CVE relevance remains unverified."
                )
        elif complete and result["total_matches"] in (None, 0):
            result["coverage"]["cve_relevance"] = "not_applicable"
        return result
