"""Privacy, explicit tool dispatch and interrupted-work boundaries."""

import asyncio
import json

import pytest

from ati_lscore import cli
from ati_lscore.config import Settings


def test_cli_assessment_prints_only_summary_and_saves_private_result(tmp_path, monkeypatch, capsys):
    async def native(*args, **kwargs):
        return {
            "data_mode": "synthetic_fixture",
            "results": [
                {
                    "domain_outcome": "partial",
                    "native_status": "request_completed",
                    "record": {"private": "PRIVATE SOURCE TEXT"},
                }
            ],
        }

    monkeypatch.setattr(cli.Settings, "load", lambda: Settings(state_dir=tmp_path))
    monkeypatch.setattr(cli, "assess_batch", native)
    output = tmp_path / "report.json"
    cli.main(
        [
            "assess",
            "--cve",
            "CVE-2023-38545",
            "--environment",
            "connected-organization",
            "--output",
            str(output),
        ]
    )
    assert "PRIVATE" not in capsys.readouterr().out
    assert (
        json.loads(output.read_text())["results"][0]["record"]["private"] == "PRIVATE SOURCE TEXT"
    )
    assert output.stat().st_mode & 0o777 == 0o600


async def test_fixture_sources_exercise_all_six_and_priority_end_to_end(tmp_path):
    domain = Settings(state_dir=tmp_path, source_mode="fixture", environment="demo").domain()
    run_id = domain.begin("CVE-2023-38545", "demo")["assessment_id"]
    for source in ("redhat", "osidb", "lightspeed", "fleet", "support", "threat_intel"):
        assert (await domain.collect(run_id, source))["status"] == "succeeded"
    result = domain.finalize(run_id)
    assert result["data_mode"] == "synthetic_fixture"
    assert result["priority"]["decision"] == "urgent_review"


async def test_failed_fixture_source_is_partial_not_completed(tmp_path):
    domain = Settings(
        state_dir=tmp_path, source_mode="fixture", environment="demo", fixture_fail_source="support"
    ).domain()
    run_id = domain.begin("CVE-2023-38545", "demo")["assessment_id"]
    for source in ("redhat", "osidb", "lightspeed", "fleet", "support", "threat_intel"):
        await domain.collect(run_id, source)
    assert domain.finalize(run_id)["outcome"] == "partial"


async def test_concurrent_duplicate_collection_cannot_duplicate_source_calls(tmp_path):
    domain = Settings(state_dir=tmp_path, source_mode="fixture", environment="demo").domain()
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def blocked(request):
        calls.append(request.cve_id)
        entered.set()
        await release.wait()
        return {"cve_id": request.cve_id}

    domain.sources.inspect_fleet = blocked
    run_id = domain.begin("CVE-2023-38545", "demo")["assessment_id"]
    running = asyncio.create_task(domain.collect(run_id, "fleet"))
    await entered.wait()
    with pytest.raises(ValueError, match="already running"):
        await domain.collect(run_id, "fleet")
    with pytest.raises(ValueError, match="still running"):
        domain.finalize(run_id)
    release.set()
    await running
    assert len(calls) == 1


async def test_cancelled_tool_retains_safe_observation(tmp_path):
    domain = Settings(state_dir=tmp_path, source_mode="fixture", environment="demo").domain()
    entered = asyncio.Event()

    async def blocked(request):
        entered.set()
        await asyncio.sleep(100)

    domain.sources.inspect_fleet = blocked
    run_id = domain.begin("CVE-2023-38545", "demo")["assessment_id"]
    running = asyncio.create_task(domain.collect(run_id, "fleet"))
    await entered.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    observation = domain.store.read(run_id)["sources"]["fleet"]
    assert observation["error_code"] == "cancelled"
    assert domain.store.read(run_id)["outcome"] == "not_finalized"


async def test_actual_mcp_dispatch_reports_invalid_operation_as_safe_data(tmp_path):
    from ati_lscore.mcp_server import build_server

    server = build_server(Settings(state_dir=tmp_path, source_mode="fixture").domain())
    result = await server.call_tool("finalize_cve_assessment", {"assessment_id": "unknown"})
    assert "invalid_assessment_operation" in str(result)


def test_export_command_does_not_call_native_model(tmp_path, monkeypatch, capsys):
    settings = Settings(state_dir=tmp_path, source_mode="fixture")
    record = settings.domain().begin("CVE-2023-38545", settings.environment)
    monkeypatch.setattr(cli.Settings, "load", lambda: settings)
    output = tmp_path / "export.json"
    cli.main(
        ["show-assessment", "--assessment-id", record["assessment_id"], "--output", str(output)]
    )
    assert json.loads(output.read_text())["outcome"] == "not_finalized"
    assert "cve_id" not in capsys.readouterr().out
