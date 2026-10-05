import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, version INTEGER NOT NULL,
  document TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(project_id, version), FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
  status TEXT NOT NULL, accepted_entries INTEGER NOT NULL, rejected_entries INTEGER NOT NULL,
  created_at TEXT NOT NULL, UNIQUE(project_id, sha256),
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, artifact_id TEXT NOT NULL, locator TEXT NOT NULL,
  kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
  evidence_id TEXT NOT NULL, UNIQUE(project_id, method, path),
  FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, finding_type TEXT NOT NULL, claim TEXT NOT NULL,
  evidence_refs TEXT NOT NULL, missing_information TEXT NOT NULL, suggested_manual_check TEXT NOT NULL,
  confidence REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, finding_id TEXT NOT NULL, status TEXT NOT NULL,
  reviewer TEXT NOT NULL, actual_result TEXT NOT NULL, tested_identity TEXT NOT NULL,
  tested_object TEXT NOT NULL, stop_reason TEXT NOT NULL, policy_version INTEGER NOT NULL,
  created_at TEXT NOT NULL, FOREIGN KEY(project_id) REFERENCES projects(id),
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, action TEXT NOT NULL,
  object_type TEXT NOT NULL, object_id TEXT NOT NULL, result TEXT NOT NULL,
  policy_version INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_contexts (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, alias TEXT NOT NULL, role TEXT NOT NULL,
  ownership_notes TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id, alias),
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS model_runs (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
  input_digest TEXT NOT NULL, evidence_count INTEGER NOT NULL, output_count INTEGER NOT NULL,
  status TEXT NOT NULL, error TEXT, duration_ms INTEGER NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def rows(rows: list[sqlite3.Row]) -> list[dict]:
        result = []
        for row in rows:
            item = dict(row)
            for field in ("document", "payload", "evidence_refs"):
                if field in item:
                    item[field] = json.loads(item[field])
            result.append(item)
        return result
