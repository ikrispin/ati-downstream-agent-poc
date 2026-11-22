"""Persistent claims prevent retries from silently repeating model/source calls."""

import hashlib
import json
import os
import sqlite3
from pathlib import Path

from .models import InvestigationRequest, InvestigationResult


class RunStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connection() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS runs "
                "(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT)"
            )
        os.chmod(path, 0o600)

    def _connection(self):
        return sqlite3.connect(self.path, timeout=5)

    def claim(self, request: InvestigationRequest) -> InvestigationResult | None:
        fingerprint = hashlib.sha256(request.prompt.encode()).hexdigest()
        with self._connection() as db:
            try:
                db.execute("INSERT INTO runs VALUES (?, ?, NULL)", (request.run_id, fingerprint))
            except sqlite3.IntegrityError:
                row = db.execute(
                    "SELECT fingerprint, result FROM runs WHERE id=?", (request.run_id,)
                ).fetchone()
                if row[0] != fingerprint:
                    raise ValueError(
                        "Investigation ID already belongs to a different request"
                    ) from None
                if row[1] is None:
                    raise RuntimeError(
                        "Investigation already running or interrupted; use a new "
                        "Investigation ID to explicitly retry"
                    ) from None
                return InvestigationResult(**json.loads(row[1]))
        return None

    def finish(self, result: InvestigationResult) -> None:
        with self._connection() as db:
            db.execute(
                "UPDATE runs SET result=? WHERE id=?", (json.dumps(result.to_dict()), result.run_id)
            )
