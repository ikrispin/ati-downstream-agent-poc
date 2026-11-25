# Observed native LSCore gaps

**Current selection, 24 November 2026:** retain native LSCore as the only PoC
execution path. This table records known tradeoffs; the LangGraph column describes a
future comparison based on official documentation, not an implemented or tested
alternative in this repository.

The observed baseline is upstream `main` pinned to `7693565`, LSCore `0.8.0rc1`,
OGX `1.2.5`. Other revisions/backends have not been replayed here.

| Area | Observed native LSCore gap | Current native PoC treatment | Future LangGraph comparison |
|---|---|---|---|
| Code-controlled routing | No documented extension found for Python conditional edges between native loop steps. | LSCore chooses steps; deterministic priority/business checks remain inside MCP tools. | Conditional edges let application code choose the next node. Domain policies still need implementation/tests. |
| Parallel in-request tools | Independent tools ran sequentially; separate requests overlapped. | Native scheduling; default headless concurrency is two separate native requests. | Parallel nodes/ToolNode can schedule independent work. Dependency order and per-tool concurrency bounds still need design. |
| Whole-run budget | Outer retry reset per-response allowances: four model rounds became eight calls. | Native configuration caps one response; repeated source collection is deduplicated per domain record. Neither is a demonstrated aggregate model/provider-call budget. | A shared allowance must be reserved before dispatch and cover failed attempts, retries and parallel branches. A graph step limit is not a physical-call budget. |
| Timeouts and cancellation | Native MCP timeout field was reserved; caller timeout did not stop server steps or remote work. | One domain collector has a local 35-second timeout. The 240-second headless timeout only bounds waiting. | Async node/workflow-attempt deadlines are documented; absolute deadlines across retries/resumes and remote cancellation remain application/service concerns. |
| Evidence after model failure | Native final artifact could omit earlier success after a fatal model error. | MCP tools persist observations independently. Without finalization the record stays not_finalized; explicit export is possible. | Application state/checkpoints can support retention; domain schema and failure results still require code. |
| Typed A2A/MAS result | Native A2A returned text without ATI typed result/outcome. MAS also loses artifacts independently. | The headless domain JSON export is separate from the native A2A result. | A graph framework does not automatically supply ATI's A2A contract or repair MAS conversion. |
| Lost tool error text | Pinned OGX returned Error code 1 with None as the explanatory text. | **Fixed in upstream source**, not this pin. Domain tool failures are safe data, but generic native tool validation/errors can still use the affected path. | Treat the accepted fix as a dependency-version issue, not a permanent LSCore design gap. |
| Generic model failures/retries | Generic HTTP 500 and underlying provider retry attempts obscure precise error/accounting. | Preserve domain evidence; do not claim those hidden attempts are counted or that the core error contract is fixed. | Reusing the same inference service preserves its limitations; different model bindings need separate evaluation. |
| Model endpoint/key forwarding | Typed settings alone were omitted from OGX. | Documented native_override workaround is applied by the configuration generator. | A working workaround is not an unresolved execution blocker. |

## Evidence and upstream status

See [native findings](REPORT.md), [current ATI verification](../../verification.json),
[concurrency](results/concurrency-origins.json), [limits](results/limits-origins.json),
[errors](results/error-origins.json), and [contract evidence](results/structured-contract.json).

[OGX PR 6745](https://github.com/ogx-ai/ogx/pull/6745) was accepted and merged on
13 October 2026. It restores tool error text and MCP structured tool content.
A compatible packaged version/backport and native runtime retest remain pending;
this correction does not add ATI domain A2A artifacts.

Conversation isolation/history worked. Durable business recovery and restart
semantics remain unverified rather than proven absent. Dependency readiness checks
need explicit policy. The accepted older Support backend and independent MAS
conversion behavior are not LSCore execution-framework defects.

## Documentation for the later comparison

The Python documentation was checked on 24 November 2026; native async node
timeouts require LangGraph 1.2 or later. Pin and run the common neutral scenario
before treating documented behavior as acceptance evidence.

- [Graph API routing and state](https://docs.langchain.com/oss/python/langgraph/graph-api).
- [Parallel branches and joins](https://docs.langchain.com/oss/python/langgraph/graph-api-control-flow).
- [Timeouts retries and handlers](https://docs.langchain.com/oss/python/langgraph/fault-tolerance).
- [Functional workflow-attempt timeout](https://reference.langchain.com/python/langgraph/func/entrypoint/).
- [Checkpoints](https://docs.langchain.com/oss/python/langgraph/checkpointers).
- Higher-level LangChain agents provide [model-call](https://reference.langchain.com/python/langchain/agents/middleware/model_call_limit/ModelCallLimitMiddleware) and [tool-call](https://reference.langchain.com/python/langchain/agents/middleware/tool_call_limit/ToolCallLimitMiddleware) limit middleware; hidden provider calls and nested work still require defined accounting boundaries.
