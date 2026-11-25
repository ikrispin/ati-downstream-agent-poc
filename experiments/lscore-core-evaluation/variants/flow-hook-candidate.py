"""Probe whether a profile can register a per-step callback without a patch.

This deliberately supplies a callback-shaped PROFILE_CONFIG entry and a
module-level function. It is not claimed to be a documented extension.
The probe checks that LSCore copies prompt data only and does not expose this
entry through CustomProfile. Import-time Python is not an execution-loop hook.
"""

CALLS = []


def after_tool_result(result):
    """Illustrative rule which must not be mistaken for a registered callback."""
    CALLS.append(result)
    return "partial" if result.get("error") else "continue"


PROFILE_CONFIG = {
    "system_prompts": {"default": "OUTPUT_MARKER=flow-hook-candidate"},
    "after_tool_result": after_tool_result,
}
