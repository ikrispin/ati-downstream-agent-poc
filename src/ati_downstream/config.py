"""Local experiment configuration; credentials never appear in repr output."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Settings:
    token: str = field(repr=False)
    model_key: str = field(repr=False)
    model_url: str = ""
    model_name: str = ""
    lightspeed_url: str = ""
    support_url: str = ""
    state_dir: Path = Path(".local/state")
    public_url: str = "http://127.0.0.1:8120"
    host: str = "127.0.0.1"
    port: int = 8120
    max_rounds: int = 7
    max_tool_calls: int = 12
    source_timeout: float = 35
    deadline: float = 240

    @classmethod
    def load(cls):
        load_dotenv(".env")
        env = os.environ
        return cls(
            token=env.get("ATI_A2A_TOKEN", ""),
            model_key=env.get("ATI_LLM_API_KEY", ""),
            model_url=env.get("ATI_LLM_BASE_URL", ""),
            model_name=env.get("ATI_LLM_MODEL", ""),
            lightspeed_url=env.get("ATI_LIGHTSPEED_MCP_URL", ""),
            support_url=env.get("ATI_SUPPORT_MCP_URL", ""),
            state_dir=Path(env.get("ATI_STATE_DIR", ".local/state")),
            public_url=env.get("ATI_PUBLIC_URL", "http://127.0.0.1:8120"),
            host=env.get("ATI_HOST", "127.0.0.1"),
            port=int(env.get("ATI_PORT", "8120")),
            max_rounds=int(env.get("ATI_MAX_ROUNDS", "7")),
            max_tool_calls=int(env.get("ATI_MAX_TOOL_CALLS", "12")),
            source_timeout=float(env.get("ATI_SOURCE_TIMEOUT", "35")),
            deadline=float(env.get("ATI_DEADLINE", "240")),
        )

    def investigator(self):
        from .engine import Investigator
        from .model import ChatModel
        from .sources import SourceTools
        from .store import RunStore

        if not all((self.model_url, self.model_name, self.model_key)):
            raise ValueError("Configure ATI_LLM_BASE_URL, ATI_LLM_MODEL and ATI_LLM_API_KEY")
        return Investigator(
            ChatModel(self.model_url, self.model_name, self.model_key),
            SourceTools(self.lightspeed_url, self.support_url, self.state_dir),
            RunStore(self.state_dir / "runs.sqlite"),
            max_rounds=self.max_rounds,
            max_tool_calls=self.max_tool_calls,
            source_timeout=self.source_timeout,
            deadline=self.deadline,
        )
