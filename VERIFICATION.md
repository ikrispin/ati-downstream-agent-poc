# Verification

## Automated checks

The standalone export passed **87 tests with 83.85% statement coverage** on
22 November 2026. Ruff, shell syntax, local documentation links, and the command
entry point also passed checks. The export was scanned for credentials before
publication; scanner matches were limited to synthetic test credentials.

From a fresh checkout:

```bash
uv sync --locked --extra test --extra ui
uv run --locked --extra test --extra ui ruff check src tests scripts
uv run --locked --extra test --extra ui pytest --cov=ati_downstream --cov-fail-under=80
```

The tests exercise investigation bounds, evidence status, duplicate submissions,
source validation, case restrictions, OAuth renewal, A2A success/failure and
cancellation handling, capability-card registration, selection verification,
and development certificate behavior. Source and model interactions are mocked.
They do not require a live MAS installation or user credentials.

## Historical live lab evidence

Before this standalone export, the development lab demonstrated:

- Direct A2A and MAS-delegated investigations retrieving all four configured
  sources after source access and Support sign-in were available.
- Direct ATI invocation with the lab's MAS API and worker stopped.
- MAS selecting ATI for a supplied CVE and the reference agent for arithmetic.
- No worker invocation for an unsupported request or a request missing required
  investigation details.
- Successful final coordinator answers for the four selection scenarios.
- Five native A2A compatibility scenarios and four model-adapter compatibility
  scenarios against the patched, separately installed MAS baseline.

The four-source runs were performed on 18 November 2026; the selection runs were
performed on 22 November 2026 through the MAS session API and Temporal worker.
The selection workflow has not been verified through a browser chat.

Raw case data, model settings, resource IDs, session records, OAuth tokens, and
local infrastructure details are not part of this repository. These historical
results depend on the configured remote services and do not constitute a fresh
live-source verification of every checkout.

## Remaining limits

MAS-to-agent cancellation propagation, checkpoint-based restart recovery,
production identity delegation, registry-wide selection, and disconnected
deployment are not established by this PoC. ATI's persisted completed results
and MAS's own saved workflow state do not replace execution checkpoints.
