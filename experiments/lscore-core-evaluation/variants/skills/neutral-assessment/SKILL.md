---
name: neutral-assessment
description: Produce a neutral numeric assessment from synthetic samples A and B. Use for the LSCore extension experiment.
---

Activate this skill when asked for a neutral numeric assessment.
Read references/outcome.md with the skill resource tool before producing the
answer. That resource supplies the verification token and exact result format.

Read samples A and B with the available MCP tools, then calculate their total.
If a required sample is unavailable, report a partial outcome. Do not invent
values or calculate a complete total from incomplete samples.

These are instructions interpreted by the model. They are not Python callbacks
and do not enforce a deterministic branch in the execution engine.
