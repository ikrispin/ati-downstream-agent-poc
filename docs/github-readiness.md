# Native LSCore repository readiness

**25 November 2026.** The PoC uses native LSCore as its agent engine. MAS delegates
to its native A2A endpoint; ATI supplies domain MCP tools and private evidence storage.

## Publication scope

- `src/ati_lscore` contains domain MCP tools, safe source adapters,
  deterministic priority rules, private evidence persistence, the native client,
  frozen dependency lock, setup scripts, tests and local MAS registration helper.
- `experiments/lscore-core-evaluation` retains pinned native capability evidence,
  documented-extension probes, gap table, updated native-only diagrams and Word
  guide. Each result records the tested source revision and experiment scope.
- Root documentation describes this standalone native PoC. Original architecture
  documents are linked to the source ATI project as design references.
- GitHub Actions runs the domain/client tests and publication checks. A full
  authenticated LSCore/model/source deployment is not required or simulated by CI.

No `.env`, OAuth token, key, local runtime, checkout, database, raw private report,
log, editor configuration or local reference PDF belongs in the push set. Those
files are ignored and retained locally. The source pin remains upstream `main`
at `7693565545044173814b1c5ad5aa66dd329e8b34`; OGX remains `1.2.5`.

## Verification

See the [native receipt](../verification.json) for actual
checks and their boundaries. The real configured model drove native LSCore with
both synthetic and real sources. Synthetic positive finalization completed;
real-source finalization remained partial when the accepted Support MCP failed.
Native A2A returned completed with text only, and the local MAS workflow completed
when reporting the finalized record. It did not repeat live collection or prove
typed result preservation.

Local checks cover frozen lock consistency, tests with at least 80 percent
package coverage, lint/format, Python/JSON/YAML/TOML syntax, relative Markdown
links, publication-file exclusions and comparison against existing private
credentials. The Word guide is rendered and visually reviewed; the render files
remain private. Current GitHub-hosted CI results are shown in the PR Checks tab.
The live evidence was captured before relocation into this standalone layout;
source adapters and domain/client code were retained, and standalone installation,
tests, scripts and links were checked separately.

Re-run the publication check from the repository root:

```bash
uv run --locked python scripts/check_repository.py
```

The checker reports filenames and safe failure categories, never credential
values. Its local credential comparison complements pattern checks; it is not
a guarantee that every possible secret format can be detected.

## Known limits of native execution

Native scheduling, nested retry budgets, tool timeout support and cancellation
retain the [recorded gaps](../experiments/lscore-core-evaluation/FRAMEWORK_GAPS.md).
Domain source timeouts and deduplication do not replace a whole-run native budget.
Native answer/task success does not equal complete business evidence. Structured
ATI A2A/MAS artifacts, durable business-run recovery, production identity/deployment
and positive live fleet coverage remain follow-up work.

The accepted upstream OGX error-text fix is recorded without claiming that this
pin contains it. A compatible package or supported backport still needs a native
retest. The existing older Support MCP remains accepted. Errata enrichment and
remediation are excluded.

The publication target is the public `ikrispin/ati-downstream-agent-poc`
repository, branch `feat/APPENG-7003-native-lscore`, with a PR against `main`.
Setup, test and launcher commands do not publish anything themselves.

The [Google Docs guide](https://docs.google.com/document/d/1Ns0PGjMHCFx8Sqwkyp581kU5ecOgG_2nnOz6vndQ2GQ/edit)
is the native-only visual explanation. It retains the document owner's Drive
permissions; placing its URL in a PR does not grant document access.
