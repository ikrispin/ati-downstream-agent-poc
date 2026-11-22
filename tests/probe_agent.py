"""Deterministic interoperability fixture. Never used as ATI source evidence."""

import uvicorn

from ati_downstream.a2a_service import create_app
from ati_downstream.config import Settings
from ati_downstream.models import InvestigationResult


class Probe:
    async def investigate(self, request):
        failed = request.cve_id == "CVE-2020-1111"
        return InvestigationResult(
            request.run_id,
            request.cve_id,
            "failed" if failed else "completed",
            "Intentional interoperability failure." if failed else "Known interoperability result.",
            {},
        )


if __name__ == "__main__":
    settings = Settings.load()
    uvicorn.run(
        create_app(Probe(), "http://127.0.0.1:8122", settings.token), host="127.0.0.1", port=8122
    )
