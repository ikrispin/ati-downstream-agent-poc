"""Configuration for native LSCore clients and domain MCP tools only."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Settings:
    native_url: str = "http://127.0.0.1:8140"
    mcp_port: int = 18143
    state_dir: Path = Path(".local/state")
    lightspeed_url: str = ""
    support_url: str = ""
    environment: str = "connected-organization"
    connection_revision: str = "1"
    priority_rule: str = "affected_and_exploit"
    source_timeout: float = 35
    client_timeout: float = 240
    source_mode: str = "live"
    fixture_fail_source: str = ""

    @classmethod
    def load(cls):
        load_dotenv(".env")
        env = os.environ
        value = cls(
            native_url=env.get("LSCORE_URL", "http://127.0.0.1:8140").rstrip("/"),
            mcp_port=int(env.get("ATI_MCP_PORT", "18143")),
            state_dir=Path(env.get("ATI_STATE_DIR", ".local/state")),
            lightspeed_url=env.get("ATI_LIGHTSPEED_MCP_URL", ""),
            support_url=env.get("ATI_SUPPORT_MCP_URL", ""),
            environment=env.get("ATI_ENVIRONMENT", "connected-organization"),
            connection_revision=env.get("ATI_CONNECTION_REVISION", "1"),
            priority_rule=env.get("ATI_PRIORITY_RULE", "affected_and_exploit"),
            source_timeout=float(env.get("ATI_SOURCE_TIMEOUT", "35")),
            client_timeout=float(env.get("ATI_CLIENT_TIMEOUT", "240")),
            source_mode=env.get("ATI_SOURCE_MODE", "live"),
            fixture_fail_source=env.get("ATI_FIXTURE_FAIL_SOURCE", ""),
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", value.environment):
            raise ValueError("Invalid configured environment alias")
        if not 1 <= value.mcp_port <= 65535 or value.client_timeout <= 0:
            raise ValueError("Invalid port or client timeout")
        if value.source_mode not in {"live", "fixture"}:
            raise ValueError("ATI_SOURCE_MODE must be live or fixture")
        return value

    def domain(self):
        from .domain import DomainTools
        from .records import AssessmentStore
        from .sources import SourceTools

        if self.source_mode == "fixture":
            from .fixtures import FixtureSources

            sources = FixtureSources(self.environment, self.fixture_fail_source)
        else:
            sources = SourceTools(
                self.lightspeed_url,
                self.support_url,
                self.state_dir,
                environment=self.environment,
                connection_revision=self.connection_revision,
            )
        return DomainTools(
            sources,
            AssessmentStore(self.state_dir / "assessments.sqlite"),
            source_timeout=self.source_timeout,
            priority_rule=self.priority_rule,
        )
