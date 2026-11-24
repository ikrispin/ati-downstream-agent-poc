"""Private evidence records for MCP tools, never an agent executor or task store."""

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class AssessmentStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS assessments (id TEXT PRIMARY KEY, data TEXT)")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, cve_id, environment, fingerprint, priority_rule, *, data_mode="live_sources"):
        run_id = uuid4().hex
        value = {
            "assessment_id": run_id,
            "cve_id": cve_id,
            "environment": environment,
            "connection_fingerprint": fingerprint,
            "priority_rule": priority_rule,
            "data_mode": data_mode,
            "created_at": datetime.now(UTC).isoformat(),
            "sources": {},
            "assessment": None,
            "outcome": "not_finalized",
        }
        with self.connection() as db:
            db.execute("INSERT INTO assessments VALUES (?, ?)", (run_id, json.dumps(value)))
        return value

    @staticmethod
    def _read(db, run_id):
        if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("Invalid assessment identifier")
        row = db.execute("SELECT data FROM assessments WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown assessment identifier")
        return json.loads(row[0])

    def read(self, run_id):
        with self.connection() as db:
            return self._read(db, run_id)

    def change(self, run_id, operation):
        """Reserve/update one observation atomically, with no network work under the lock."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            value = self._read(db, run_id)
            result = operation(value)
            db.execute("UPDATE assessments SET data = ? WHERE id = ?", (json.dumps(value), run_id))
            return result
