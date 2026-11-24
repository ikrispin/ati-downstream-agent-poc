"""Bounded CVE-to-system inspection through discovered, read-only MCP tools."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from .security_data import normalize_cve_id

ToolCall = Callable[[str, dict[str, Any]], Awaitable[Any]]


def _rows(payload: Any) -> tuple[list[Any] | None, int | None]:
    for _ in range(6):
        if isinstance(payload, list):
            return payload, None
        if not isinstance(payload, dict):
            break
        meta = payload.get("meta") or {}
        total = payload.get("total", meta.get("total_items", meta.get("total")))
        total = total if type(total) is int and total >= 0 else None
        for key in ("data", "results", "items"):
            if isinstance(payload.get(key), list):
                return payload[key], total
        if isinstance(payload.get("result"), dict):
            payload = payload["result"]
        elif isinstance(payload.get("data"), dict):
            payload = payload["data"]
        else:
            break
    return None, None


def _system_id(row: dict[str, Any]) -> str | None:
    if not isinstance(row, dict):
        return None
    attributes = row.get("attributes") or {}
    if not isinstance(attributes, dict):
        return None
    value = row.get("id", attributes.get("inventory_id", attributes.get("system_uuid")))
    try:
        return str(UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _has_ref(value: Any) -> bool:
    if isinstance(value, dict):
        return "$ref" in value or any(_has_ref(child) for child in value.values())
    return isinstance(value, list) and any(_has_ref(child) for child in value)


class FleetInspector:
    """Inspect only hosts returned by this CVE lookup; never enumerate other hosts."""

    def __init__(
        self,
        catalog,
        call_tool: ToolCall,
        *,
        source_url: str,
        max_systems: int = 10,
        max_pages: int = 2,
    ):
        if type(max_systems) is not int or not 1 <= max_systems <= 100:
            raise ValueError("max_systems must be between 1 and 100")
        if type(max_pages) is not int or not 1 <= max_pages <= 10:
            raise ValueError("max_pages must be between 1 and 10")
        self.catalog = {tool["name"]: tool for tool in catalog}
        self.call_tool = call_tool
        self.max_systems, self.max_pages = max_systems, max_pages
        parsed = urlsplit(source_url)
        self.source_url = urlunsplit(
            (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")
        )

    def _arguments(self, name: str, required: dict, optional: dict | None = None) -> dict:
        definition = self.catalog.get(name, {})
        schema = definition.get("inputSchema", definition.get("input_schema"))
        if not isinstance(schema, dict) or _has_ref(schema):
            raise ValueError("Unsupported MCP input schema")
        Draft202012Validator.check_schema(schema)
        properties = schema.get("properties", {})
        if any(key not in properties for key in required):
            raise ValueError("Requested MCP parameter is not advertised")
        arguments = {
            **required,
            **{key: value for key, value in (optional or {}).items() if key in properties},
        }
        Draft202012Validator(schema).validate(arguments)
        return arguments

    async def inspect_cve(self, cve_id: str) -> dict[str, Any]:
        cve_id = normalize_cve_id(cve_id)
        result = {
            "source": "lightspeed_fleet",
            "source_url": self.source_url,
            "cve_id": cve_id,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "status": "succeeded",
            "total_affected_systems": None,
            "systems": [],
            "discarded_system_rows": 0,
            "errors": [],
            "coverage": {
                "affected_systems": "unknown",
                "inventory_details": "unavailable",
                "system_profiles": "unavailable",
                "active_customer_fleet": "unverified",
            },
            "unknowns": [
                "Configured connection identity is not independently verified.",
                "Inventory freshness and last check-in do not establish host uptime.",
            ],
        }
        name = "vulnerability__get_cve_systems"
        size = min(10, self.max_systems)
        complete = False
        discarded = False
        try:
            schema = self.catalog.get(name, {}).get("inputSchema", {})
            properties = schema.get("properties", {})
            cve_field = next(
                (field for field in ("cve", "cve_id", "cveId") if field in properties), "cve"
            )
            # Prepare before any call: unknown required fields must never be invented.
            arguments = self._arguments(name, {cve_field: cve_id}, {"limit": size, "offset": 0})
        except (ValueError, SchemaError, ValidationError):
            result["status"] = "unsupported"
            result["unknowns"].append("CVE-to-systems tool or compatible schema unavailable.")
            return result
        systems = {}
        for page in range(self.max_pages):
            if page:
                if "offset" not in arguments:
                    break
                arguments = {**arguments, "offset": page * size}
            try:
                response = await self.call_tool(name, arguments)
            except Exception as error:
                if page == 0:
                    raise
                result["status"] = "partial"
                result["errors"].append(
                    {
                        "code": "fleet_page_failed",
                        "tool": name,
                        "page": page + 1,
                        "error_type": type(error).__name__,
                    }
                )
                result["unknowns"].append("A later CVE system page failed; earlier hosts retained.")
                complete = False
                break
            rows, total = _rows(response)
            if rows is None:
                result["unknowns"].append("CVE system response structure is unverified.")
                result["status"] = "partial" if systems else "unverified"
                complete = False
                break
            if total is not None:
                result["total_affected_systems"] = total
            for row in rows:
                host_id = _system_id(row)
                if host_id is None:
                    discarded = True
                    result["discarded_system_rows"] += 1
                    continue
                if host_id not in systems and len(systems) < self.max_systems:
                    systems[host_id] = {
                        "system_id": host_id,
                        "vulnerability": row,
                        "inventory": None,
                        "system_profile": None,
                    }
            complete = total is not None and page * size + len(rows) >= total
            if total is None and "limit" in arguments and len(rows) < size:
                complete = True
            if complete or len(systems) >= self.max_systems:
                break
        result["systems"] = list(systems.values())
        result["coverage"]["affected_systems"] = (
            "complete"
            if complete
            and not discarded
            and (
                result["total_affected_systems"] is None
                or len(systems) == result["total_affected_systems"]
            )
            else "partial"
        )
        if result["total_affected_systems"] is None and complete and not discarded:
            result["total_affected_systems"] = len(systems)
        if discarded:
            result["unknowns"].append("Some affected systems lacked a usable inventory UUID.")
        if not systems:
            needed = (
                "not_needed" if result["coverage"]["affected_systems"] == "complete" else "unknown"
            )
            result["coverage"].update(inventory_details=needed, system_profiles=needed)
            return result
        for tool_name, field, coverage_name, batch_size in (
            ("inventory__get_host_details", "inventory", "inventory_details", 10),
            ("inventory__get_host_system_profile", "system_profile", "system_profiles", 2),
        ):
            if tool_name not in self.catalog:
                result["unknowns"].append(f"{tool_name} is unavailable in the discovered catalog.")
                continue
            identifiers = list(systems)
            for offset in range(0, len(identifiers), batch_size):
                selected = identifiers[offset : offset + batch_size]
                try:
                    args = self._arguments(tool_name, {"host_ids": ",".join(selected)})
                except (ValueError, SchemaError, ValidationError):
                    result["unknowns"].append(f"{tool_name} input schema is incompatible.")
                    break
                try:
                    response = await self.call_tool(tool_name, args)
                except Exception as error:
                    result["status"] = "partial"
                    result["errors"].append(
                        {
                            "code": "fleet_enrichment_failed",
                            "tool": tool_name,
                            "error_type": type(error).__name__,
                        }
                    )
                    result["unknowns"].append(
                        f"{tool_name} failed; previously collected CVE host evidence retained."
                    )
                    continue
                rows, _ = _rows(response)
                for row in rows or []:
                    host_id = _system_id(row)
                    if host_id in selected:
                        systems[host_id][field] = row
            count = sum(system[field] is not None for system in systems.values())
            result["coverage"][coverage_name] = "complete" if count == len(systems) else "partial"
        return result
