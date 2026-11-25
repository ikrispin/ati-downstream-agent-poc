import pytest
import yaml

from ati_lscore.config import Settings
from ati_lscore.mcp_server import build_server
from ati_lscore.native_config import write_native_config


def test_generated_configuration_uses_native_agent_and_documented_mcp_extension(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LSCORE_MODEL_NAME", "synthetic-model")
    monkeypatch.setenv("LSCORE_MODEL_BASE_URL", "http://127.0.0.1:18141/v1")
    monkeypatch.setenv("LSCORE_MODEL_API_KEY", "PRIVATE-API-KEY")
    path = tmp_path / "native.yaml"
    write_native_config(Settings(state_dir=tmp_path / "state"), path)
    text = path.read_text()
    config = yaml.safe_load(text)
    assert "PRIVATE-API-KEY" not in text
    assert config["mcp_servers"][0]["url"] == "http://127.0.0.1:18143/mcp"
    assert config["ogx"]["use_as_library_client"] is True
    assert config["inference"]["default_model"] == "synthetic-model"
    assert config["inference"]["providers"][0]["config"]["api_key"] == "${env.LSCORE_MODEL_API_KEY}"
    assert "finalize_cve_assessment" in config["customization"]["system_prompt"]
    assert config["customization"]["agent_card_config"]["defaultOutputModes"] == ["text/plain"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_configure_requires_explicit_model_connection(tmp_path, monkeypatch):
    for key in ("LSCORE_MODEL_NAME", "LSCORE_MODEL_BASE_URL", "LSCORE_MODEL_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValueError, match="LSCORE_MODEL"):
        write_native_config(Settings(), tmp_path / "native.yaml")


async def test_mcp_catalog_exposes_only_domain_operations_and_no_model_endpoint(tmp_path):
    domain = Settings(state_dir=tmp_path).domain()
    catalog = await build_server(domain).list_tools()
    tools = {tool.name: tool for tool in catalog}
    assert set(tools) == {"begin_cve_assessment", "collect_cve_source", "finalize_cve_assessment"}
    assert tools["collect_cve_source"].inputSchema["properties"]["source"]["enum"] == [
        "redhat",
        "osidb",
        "lightspeed",
        "fleet",
        "support",
        "threat_intel",
    ]
    assert set(tools["finalize_cve_assessment"].inputSchema["properties"]) == {"assessment_id"}


@pytest.mark.parametrize(
    "updates",
    [
        {"ATI_ENVIRONMENT": "../scope"},
        {"ATI_MCP_PORT": "0"},
        {"ATI_CLIENT_TIMEOUT": "0"},
        {"ATI_SOURCE_MODE": "model"},
    ],
)
def test_invalid_configuration_is_rejected_before_service_start(tmp_path, monkeypatch, updates):
    monkeypatch.chdir(tmp_path)
    for key, value in updates.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        Settings.load()
