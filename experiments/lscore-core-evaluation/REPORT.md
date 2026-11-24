# APPENG 7003 native LSCore findings

**24 November 2026. Native LSCore is the only retained ATI execution path.**
ATI supplies read-only domain MCP tools and private evidence records.
See the [runnable PoC](../../README.md), [current verification](../../verification.json)
and [framework gap table](FRAMEWORK_GAPS.md).

We tested upstream `main` pinned to
[`7693565`](https://github.com/lightspeed-core/lightspeed-stack/tree/7693565545044173814b1c5ad5aa66dd329e8b34),
reporting LSCore `0.8.0rc1`, with frozen OGX `1.2.5` and Python `3.12.16`.
No experiment-authored upstream patches or dependency upgrade were applied.

## Native neutral experiment

| Capability | Observed result and classification |
|---|---|
| Model to tools to answer | **Supported extension.** Real-model run retrieved A=4 and B=7 and calculated 11, with three successful tool calls in 14.61 seconds. |
| Prompts profiles skills | **Supported extension.** Inline prompt, Python prompt profile and skill resource loading worked over HTTP. Skill loading used fixtures; real-model compliance is unverified. |
| Python conditional edges | **No supported documented hook found.** LSCore has a model-driven loop, but prompts/profiles did not register our Python decision code between its steps. Conditions inside an MCP tool remain ordinary domain code. |
| Concurrent separate requests | **Direct.** Two separate requests overlapped and completed in about 1.7 seconds. This does not mean identical completion times. |
| Parallel tools within a request | **Absent on this pinned backend.** Two independent 0.7-second reads ran sequentially in both modes, about 1.72 seconds overall. The tools succeeded; OGX awaited each call before starting the next. |
| Model and tool limits | **Per-response caps with a whole-run gap.** A two-tool cap prevented a third call. An outer retry reset four-model/six-tool allowances, producing eight model calls and eight tool executions before failure. |
| Tool timeout and run deadline | **Native gap.** The MCP timeout field was documented as reserved; a one-second value did not stop 1.2-second calls. A 0.3-second caller deadline did not stop a two-second tool or later calls. Explicit interruption stopped later steps but not active remote work. |
| State | **Tested conversation behavior worked.** Conversations were isolated and their own histories retained; SQLite records were written. Durable arbitrary business-state recovery remains unverified. |
| Failure handling | **Partial support with reporting gaps.** Real-model failure retained A=4 and reported B missing. Pinned OGX returned `Error (code 1): None`. Model outage/unavailable MCP gave generic HTTP 500 errors; readiness did not test MCP reachability. A later fatal model error could omit earlier evidence from its final A2A artifact. |
| A2A and MAS | **Text interoperability worked.** Native output did not supply ATI typed artifacts/outcome metadata. JSON saying failed could still be an A2A completed task. MAS also drops typed artifacts independently. Native cancellation is unsupported in the tested A2A path. |
| Model connection settings | **Documented workaround.** Typed settings alone were not forwarded to OGX; matching `native_override` settings worked without a source patch. |

[Timing and cases](results/summary.json), [concurrency](results/concurrency-origins.json),
[limits](results/limits-origins.json), [deadline](results/deadline-probe.json),
[extensions](variants/http-extension-results.json), [errors](results/error-origins.json),
[native contract](results/structured-contract.json), [configuration](variants/config-forwarding-probe.json).

## Accepted upstream fix

The lost tool-error-text defect was already reported in
[OGX 6744](https://github.com/ogx-ai/ogx/issues/6744) and fixed by
[merged PR 6745](https://github.com/ogx-ai/ogx/pull/6745) on 13 October 2026,
commit `ceda4d4a619c36774f9f9dfe409668a13170c1fb`.
The fix also preserves MCP structured tool content. It does not by itself add
ATI's A2A result schema or domain outcome mapping.

Our dependency pin predates the correction. A compatible packaged release or
supported backport containing it remains unvalidated. Do not count the accepted
fix as a permanent architectural reason to reject LSCore, and do not infer
inclusion from a newer version number alone. No duplicate issue or local patch
was created. [Research receipt](results/upstream-status.json).

## Current ATI native integration

The native agent reaches ATI through the documented MCP extension. It calls
`collect_cve_source` separately for six collector operations, then
`finalize_cve_assessment`. ATI source adapters and deterministic priority rules
contain no model client and no agent loop. Domain evidence is recorded before
final synthesis and exported privately by the headless client.

The four core source families are Security Data, OSIDB, Lightspeed MCP and
Support MCP. Lightspeed supplies both CVE details and affected-fleet inspection
through the same connection. The sixth collector reads additional public HTTP
threat feeds (FIRST EPSS, CVE.org and CISA KEV) for prioritization.

A real-model/native-LSCore run with explicit synthetic sources completed all six
collectors and returned provisional urgent review. A second run used the real
connections: five collectors succeeded, Support failed, and the domain record
remained partial while the native query completed successfully. The current
local MAS workflow also completed using the native A2A endpoint to report an
already-finalized record. This replay did not repeat live source collection.
See [current receipt](../../verification.json).

Source observations and priority are saved in ATI's domain store. That mitigates
lost business evidence without replacing LSCore's loop. If native execution ends
before finalization, the domain outcome remains `not_finalized`.
The 35-second timeout belongs to one
domain collector; the 240-second client timeout only limits waiting.

Native A2A still provides text. A saved domain record is not an automatically
preserved A2A DataPart, and MAS transport success is not proof of complete evidence.
The accepted older Support MCP remains unchanged. Errata and remediation are out
of scope. See [Journey 01](../../JOURNEY01.md).

## Remaining work

Use the observed native gaps as explicit MVP tradeoffs. Retest any supported
upstream upgrade before changing the baseline. A structured A2A/MAS contract,
aggregate run budgets, dependable server cancellation and positive live fleet
coverage remain separate follow-ups. The LangGraph runtime comparison remains
APPENG-7004 work; it is not an additional implementation shipped in this repo.

The original neutral run installed 320 packages, about 2.40 GiB, and required
vector/file providers for startup despite using neither retrieval nor files.
Disconnected operation, full upstream tests and load testing remain unverified.
