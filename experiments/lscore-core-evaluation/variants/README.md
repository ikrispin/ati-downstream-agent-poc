# Variant reproduction

The [baseline configuration](../config/lscore-fixture.yaml) and
[configuration overrides](configuration-overrides.json) specify every change
used for the extension, tool-limit, and unavailable-MCP service instances.
Override keys use JSON Pointer paths: `/service/port` means the `port` field
inside `service`. Replace `<evaluation-directory>` with this directory's absolute
path, apply the values to a baseline copy, and start it using the same LSCore
command as the baseline with the new `-c` path. Keep the two fixture servers running.
The limit and unavailable-MCP variants both use 8143, so run them sequentially.

The HTTP request bodies, expected results, configuration hashes, and raw evidence
locations are recorded in [http-extension-results.json](http-extension-results.json)
and [tool-limit-results.json](tool-limit-results.json). Extension requests are:

```json
{"query":"Assess samples A and B. [fixture:normal] [request:e2-inline]","system_prompt":"Use the neutral sample tools. OUTPUT_MARKER=inline","generate_topic_summary":false}
```

Send the inline request to the baseline `/v1/query`. Send the following to the
extension instance on 8144, which loads the Python profile and skill directory:

```json
{"query":"Assess samples A and B. [fixture:normal] [request:e2-profile]","generate_topic_summary":false}
```

```json
{"query":"Load neutral-assessment and its reference. [fixture:skill] [request:e2-skill]","generate_topic_summary":false}
```

These synthetic controls tell the fixture exactly what to request. They verify
that LSCore forwards prompts and tools; they do not establish real-model skill
compliance. `probe_extensions.py` also checks loading and rejected callback
settings without a model:

```bash
cd .local/upstream
PYTHONPATH=src .venv/bin/python ../../variants/probe_extensions.py
PYTHONPATH=src .venv/bin/python ../../variants/probe_config_forwarding.py
```

The real-model normal and failure checks have a separate launcher. From the
evaluation directory, with the neutral MCP fixture running:

```bash
.local/upstream/.venv/bin/python scripts/probe_real_model.py --scenario baseline
.local/upstream/.venv/bin/python scripts/probe_real_model.py --scenario failure
```

For MAS compatibility, run `scripts/probe_a2a.py --mode mas-node --output
.local/evidence/e8-mas-node.json` with the existing MAS environment's Python and
the MAS source directory in `PYTHONPATH`. The probe invokes the native node in
isolation; it does not register an agent or run a platform workflow.
