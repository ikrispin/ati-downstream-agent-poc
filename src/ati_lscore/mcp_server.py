"""Documented MCP extension: ATI domain tools with no model or agent loop."""

from mcp.server.fastmcp import FastMCP

from .domain import SourceName


def build_server(domain, *, port=18143):
    server = FastMCP(
        "ATI evidence tools",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True,
    )

    @server.tool()
    async def begin_cve_assessment(cve_id: str, environment: str) -> dict:
        """Begin one read-only CVE assessment in the configured environment; collect nothing yet."""
        try:
            return domain.begin(cve_id, environment)
        except ValueError:
            return {"status": "rejected", "error_code": "invalid_assessment_scope"}

    @server.tool()
    async def collect_cve_source(assessment_id: str, source: SourceName) -> dict:
        """Collect exactly one source for the registered CVE. Repeated calls reuse that observation.

        Call separately for redhat, osidb, lightspeed, fleet, support, threat_intel.
        Domain failures are data with status=failed, not evidence of zero affected systems.
        """
        try:
            return await domain.collect(assessment_id, source)
        except ValueError:
            return {"status": "rejected", "error_code": "invalid_assessment_operation"}

    @server.tool()
    async def finalize_cve_assessment(assessment_id: str) -> dict:
        """Compute provisional priority from recorded evidence, then save the assessment.

        Collect all six sources first. Missing or failed sources remain explicit.
        This never generates or executes remediation and makes no model calls.
        """
        try:
            return domain.finalize(assessment_id)
        except ValueError:
            return {"status": "rejected", "error_code": "invalid_assessment_operation"}

    return server
