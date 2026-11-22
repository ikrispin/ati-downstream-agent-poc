"""Transport-independent investigation input and results."""

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any

SOURCE_TOOLS = {
    "get_redhat_cve": "redhat",
    "get_public_osidb_cve": "osidb",
    "vulnerability__get_cve": "lightspeed",
    "GetCaseDetailsByCaseId": "support",
}


class AuthenticationRequired(RuntimeError):
    """A source needs a fresh user sign-in before it can supply evidence."""


@dataclass(frozen=True)
class InvestigationRequest:
    prompt: str
    cve_id: str
    case_id: str | None
    run_id: str

    @classmethod
    def parse(cls, text: str, context_id: str = "direct") -> "InvestigationRequest":
        # Hosted MAS combines previous context with a clearly delimited current task.
        current = text.rsplit("CURRENT TASK:", 1)[-1].strip()
        cves = set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", current.upper()))
        cases = set(
            re.findall(
                r"\b(?:support\s+)?case(?:\s+(?:number|id))?[\s:#]+(\d+)\b", current, re.IGNORECASE
            )
        )
        if len(cves) != 1 or len(cases) > 1:
            raise ValueError("Supply exactly one CVE and at most one explicit Support Case number")
        explicit = re.search(r"\bInvestigation ID:\s*([a-zA-Z0-9_-]{1,100})\b", current)
        run_id = (
            explicit[1]
            if explicit
            else hashlib.sha256(f"{context_id}\n{current}".encode()).hexdigest()[:32]
        )
        return cls(current, next(iter(cves)), next(iter(cases), None), run_id)


@dataclass
class InvestigationResult:
    run_id: str
    cve_id: str
    status: str
    answer: str
    sources: dict[str, dict[str, Any]]
    model_calls: int = 0
    tool_calls: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
