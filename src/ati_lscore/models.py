"""Scoped ATI domain source input and safe failures."""

import hashlib
import re
from dataclasses import dataclass


class AuthenticationRequired(RuntimeError):
    """A source needs a fresh user sign-in before it can supply evidence."""


class ToolArgumentsError(ValueError):
    """The requested source or arguments do not match the authorized investigation."""


class SourceFailure(RuntimeError):
    """A safe source failure category independent of HTTP or MCP transport."""

    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class InvestigationRequest:
    prompt: str
    cve_id: str
    case_id: str | None
    run_id: str
    journey_mode: bool = False
    environment: str | None = None

    def __post_init__(self):
        if self.journey_mode and (
            not isinstance(self.environment, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.environment)
        ):
            raise ValueError("Journey assessment needs an Environment alias")

    @property
    def fingerprint_text(self) -> str:
        if not self.journey_mode and self.environment is None:
            return self.prompt
        return f"{self.prompt}\nATI scope: {self.journey_mode}:{self.environment}"

    @classmethod
    def parse(cls, text: str, context_id: str = "direct") -> "InvestigationRequest":
        # Hosted MAS combines previous context with a clearly delimited current task.
        current = text.rsplit("CURRENT TASK:", 1)[-1].strip()
        journey_mode = bool(re.search(r"(?im)^Assessment mode:\s*journey01\s*$", current))
        environments = re.findall(r"(?im)^Environment:\s*([^\n]+)$", current)
        if journey_mode and len(environments) != 1:
            raise ValueError("Journey assessment needs exactly one Environment alias")
        environment = environments[0].strip() if journey_mode else None
        task_text = re.sub(r"(?im)^Environment:.*$", "", current) if journey_mode else current
        cves = set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", task_text.upper()))
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
        return cls(
            current, next(iter(cves)), next(iter(cases), None), run_id, journey_mode, environment
        )
