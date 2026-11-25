"""Exercise LSCore config/skill extension loading without replacing its engine.

Run from the unchanged pinned source checkout with PYTHONPATH=src, passing
the absolute path to this file to its installed Python interpreter.
"""

import asyncio
import json
from pathlib import Path

from models.config import Customization, SkillsConfiguration
from pydantic import ValidationError
from utils.pydantic_ai_helpers import _skills_capability, get_skills_metadata


async def main():
    """Print JSON evidence from actual configuration and capability factories."""
    root = Path(__file__).resolve().parent
    inline_text = (root / "inline-prompt.txt").read_text()
    inline = Customization(system_prompt=inline_text)
    profile = Customization(profile_path=str(root / "profile.py"))
    candidate = Customization(profile_path=str(root / "flow-hook-candidate.py"))
    skills = SkillsConfiguration(paths=[root / "skills"])
    capability = _skills_capability(skills)
    rejected = {}
    for field in ("after_tool_result", "capabilities", "agent_factory"):
        try:
            Customization.model_validate({field: "probe"})
        except ValidationError as exc:
            rejected[field] = [err["type"] for err in exc.errors()]
    catalog = await capability.toolset.tools["list_skills"].function(None)
    loaded = await capability.toolset.tools["load_skill"].function(
        None, "neutral-assessment"
    )
    resource = await capability.toolset.tools["read_skill_resource"].function(
        None, "neutral-assessment", "references/outcome.md"
    )
    print(json.dumps({
        "probe_kind": "runtime_config_and_capability_loading_no_model",
        "inline_prompt_loaded": inline.system_prompt == inline_text,
        "profile_default_prompt": profile.custom_profile.get_prompts()["default"],
        "profile_topic_summary": profile.custom_profile.get_prompts()["topic_summary"],
        "profile_exposed_fields": sorted(profile.custom_profile.__dataclass_fields__),
        "callback_candidate_prompts": candidate.custom_profile.get_prompts(),
        "callback_candidate_exposed": hasattr(candidate.custom_profile, "after_tool_result"),
        "unknown_customization_fields_rejected": rejected,
        "skills": [item.model_dump() for item in get_skills_metadata(skills)],
        "skill_tools": sorted(capability.toolset.tools),
        "skill_script_tool_excluded": "run_skill_script" not in capability.toolset.tools,
        "skill_tool_schemas": {
            name: tool.function_schema.json_schema
            for name, tool in capability.toolset.tools.items()
        },
        "direct_skill_tool_invocation": {
            "catalog": catalog,
            "load_skill_contains_instructions": "neutral numeric assessment" in loaded,
            "load_skill_lists_resource": "references/outcome.md" in loaded,
            "resource_content": resource,
            "limitation": "Capability tool functions invoked directly; no model or LSCore HTTP request.",
        },
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
