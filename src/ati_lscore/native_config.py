"""Generate pinned native LSCore configuration using documented extension settings."""

import os
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .client import save_private_report


def _state_paths(value, state_dir):
    if isinstance(value, dict):
        return {key: _state_paths(child, state_dir) for key, child in value.items()}
    if isinstance(value, list):
        return [_state_paths(child, state_dir) for child in value]
    if isinstance(value, str) and value.startswith(".local/state/"):
        return str(state_dir / value.removeprefix(".local/state/"))
    return value


def write_native_config(settings, output: Path):
    names = ("LSCORE_MODEL_NAME", "LSCORE_MODEL_BASE_URL", "LSCORE_MODEL_API_KEY")
    if not all(os.environ.get(name) for name in names):
        raise ValueError(
            "Configure LSCORE_MODEL_NAME, LSCORE_MODEL_BASE_URL and LSCORE_MODEL_API_KEY"
        )
    url = urlsplit(settings.native_url)
    if url.hostname not in {"localhost", "127.0.0.1"} or url.scheme != "http":
        raise ValueError("This no-auth development configuration requires loopback HTTP")
    model = os.environ["LSCORE_MODEL_NAME"]
    config = yaml.safe_load(
        files("ati_lscore").joinpath("templates/native-lscore.yaml").read_text()
    )
    config = _state_paths(config, (settings.state_dir / "lscore").resolve())
    config["name"] = "ATI native LSCore PoC"
    config["service"].update(host="127.0.0.1", port=url.port or 8140, base_url=settings.native_url)
    config["mcp_servers"] = [
        {
            "name": "ati-evidence",
            "url": f"http://127.0.0.1:{settings.mcp_port}/mcp",
            "require_approval": "never",
        }
    ]
    config["customization"]["system_prompt"] = (
        files("ati_lscore").joinpath("templates/ati-system-prompt.txt").read_text()
        + f"\nThe only configured environment alias is {settings.environment}."
    )
    card = config["customization"]["agent_card_config"]
    card.update(
        name="ATI native LSCore agent",
        version="0.2.0",
        description="Read-only CVE and customer fleet assessment through native LSCore MCP tools.",
        skills=[
            {
                "id": "cve_assessment",
                "name": "CVE environment assessment",
                "description": "Gather six evidence sources, compute priority and report gaps.",
                "tags": ["security", "cve", "read-only"],
            }
        ],
    )
    provider = {
        "api_key": "${env.LSCORE_MODEL_API_KEY}",
        "base_url": "${env.LSCORE_MODEL_BASE_URL}",
    }
    config["inference"].update(
        default_provider="ati-model",
        default_model=model,
        max_infer_iters=12,
        max_tool_calls=12,
        providers=[
            {
                "id": "ati-model",
                "type": "openai",
                "skip_model_discovery": True,
                "config": provider,
                "allowed_models": [
                    {
                        "name": model,
                        "provider_model_id": model,
                        "model_type": "llm",
                        "metadata": {"context_window": 32768},
                    }
                ],
            }
        ],
    )
    native = config["ogx"]["config"]["native_override"]["providers"]
    native["inference"] = [
        {
            "provider_id": "ati-model",
            "provider_type": "remote::openai",
            "config": {**provider, "allowed_models": [model]},
        }
    ]
    # JSON is a YAML subset and uses the same private atomic writer as reports.
    save_private_report(output, config)
    return output
