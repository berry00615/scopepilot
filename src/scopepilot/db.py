import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from .sanitize import sanitize_url, target_identity


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
  created_at TEXT NOT NULL, origin_key TEXT NOT NULL, UNIQUE(project_id, origin_key),
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, artifact_id TEXT NOT NULL, locator TEXT NOT NULL,
  kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
  evidence_id TEXT NOT NULL, target TEXT NOT NULL, target_key TEXT NOT NULL,
  scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER,
  UNIQUE(project_id, method, target_key),
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


def artifact_origin_key(sha256: str, tool: str | None = None, version: str = "", source_root: str = "source") -> str:
    if tool is None:
        return "har:" + sha256
    context = json.dumps([tool, version, source_root, sha256], ensure_ascii=False, separators=(",", ":"))
    return "tool:" + hashlib.sha256(context.encode()).hexdigest()


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            conn.execute("BEGIN")
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Additive, repeatable migration; legacy HTTP targets come from retained evidence."""
        if "origin_key" not in {row["name"] for row in conn.execute("PRAGMA table_info(artifacts)")}:
            artifacts = []
            for row in conn.execute("SELECT * FROM artifacts").fetchall():
                key = artifact_origin_key(row["sha256"])
                evidence = conn.execute("SELECT payload FROM evidence WHERE project_id=? AND artifact_id=? AND kind='tool_result' ORDER BY created_at,id LIMIT 1",
                                        (row["project_id"], row["id"])).fetchone()
                if evidence:
                    payload = json.loads(evidence["payload"])
                    key = artifact_origin_key(row["sha256"], payload.get("tool", "unknown"),
                                              payload.get("tool_version", "unknown"), payload.get("source_root", "source"))
                artifacts.append((*tuple(row), key))
            # Keep foreign-key enforcement on: defer validation to this transaction's
            # commit while recreating the parent table and restoring the same IDs.
            for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                table_name = table["name"].replace('"', '""')
                for foreign_key in conn.execute(f'PRAGMA foreign_key_list("{table_name}")'):
                    if foreign_key["table"] == "artifacts" and foreign_key["on_delete"] not in {"NO ACTION", "RESTRICT"}:
                        raise sqlite3.IntegrityError("artifact migration cannot preserve custom cascading references")
            conn.execute("PRAGMA defer_foreign_keys=ON")
            conn.execute("DROP TABLE artifacts")
            conn.execute("""CREATE TABLE artifacts (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
                status TEXT NOT NULL, accepted_entries INTEGER NOT NULL, rejected_entries INTEGER NOT NULL,
                created_at TEXT NOT NULL, origin_key TEXT NOT NULL, UNIQUE(project_id,origin_key),
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )""")
            conn.executemany("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?)", artifacts)
            if conn.execute("PRAGMA foreign_key_check").fetchone():
                raise sqlite3.IntegrityError("artifact migration found invalid foreign-key references")
        additions = {
            "findings": {
                "target": "TEXT NOT NULL DEFAULT ''", "method": "TEXT NOT NULL DEFAULT ''",
                "severity": "TEXT NOT NULL DEFAULT 'unrated'",
                "original_severity": "TEXT NOT NULL DEFAULT 'unrated'",
                "severity_reason": "TEXT NOT NULL DEFAULT 'Evidence has not been rated.'",
                "original_severity_reason": "TEXT NOT NULL DEFAULT 'Legacy finding; original rating unavailable.'",
                "category": "TEXT NOT NULL DEFAULT 'vulnerability'",
                "remediation": "TEXT NOT NULL DEFAULT ''", "dedup_key": "TEXT",
                "updated_at": "TEXT NOT NULL DEFAULT ''",
            },
            "reviews": {
                "success_criteria": "TEXT NOT NULL DEFAULT ''", "criteria_met": "INTEGER NOT NULL DEFAULT 0",
                "evidence_refs": "TEXT NOT NULL DEFAULT '[]'", "control_required": "INTEGER NOT NULL DEFAULT 0",
                "control_result": "TEXT NOT NULL DEFAULT ''", "control_passed": "INTEGER",
                "severity": "TEXT", "severity_reason": "TEXT NOT NULL DEFAULT ''",
            },
        }
        for table, fields in additions.items():
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in fields.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        # Earlier adapters mislabeled this reviewed configuration-only template.
        # Correct its category while preserving all human ratings and decisions.
        conn.execute("UPDATE findings SET category='hardening' WHERE finding_type='nuclei:http-missing-security-headers'")
        conn.execute("""CREATE TABLE IF NOT EXISTS finding_sources (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL, finding_id TEXT NOT NULL,
            source_kind TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
            original_severity TEXT NOT NULL, severity_reason TEXT NOT NULL,
            evidence_refs TEXT NOT NULL, hint_kind TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(finding_id) REFERENCES findings(id),
            UNIQUE(finding_id,source_kind,name,version)
        )""")
        endpoint_columns = {row["name"] for row in conn.execute("PRAGMA table_info(endpoints)")}
        if "target_key" not in endpoint_columns:
            conn.execute("DROP TABLE endpoints")
            conn.execute("""CREATE TABLE endpoints (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
                evidence_id TEXT NOT NULL, target TEXT NOT NULL, target_key TEXT NOT NULL,
                scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER,
                UNIQUE(project_id,method,target_key),
                FOREIGN KEY(project_id) REFERENCES projects(id),
                FOREIGN KEY(evidence_id) REFERENCES evidence(id)
            )""")
            # Rebuild from every exchange: the old unique path key could have hidden hosts.
            for row in conn.execute("SELECT * FROM evidence WHERE kind='http_exchange' ORDER BY created_at,id"):
                payload = json.loads(row["payload"])
                target = sanitize_url(row["project_id"], payload["url"]) if payload.get("url") else ""
                if not target:
                    continue
                parsed = urlsplit(target)
                conn.execute("INSERT OR IGNORE INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?)", (
                    "ep_" + hashlib.sha256(row["id"].encode()).hexdigest()[:16], row["project_id"],
                    payload.get("method", "GET"), parsed.path or "/", row["id"], target,
                    target_identity(target), parsed.scheme,
                    parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80),
                ))
        for row in conn.execute("SELECT * FROM findings WHERE dedup_key IS NULL").fetchall():
            refs = json.loads(row["evidence_refs"])
            evidence = conn.execute("SELECT payload FROM evidence WHERE project_id=? AND id=?",
                                    (row["project_id"], refs[0] if refs else "")).fetchone()
            payload = json.loads(evidence["payload"]) if evidence else {}
            target = sanitize_url(row["project_id"], payload["url"]) if payload.get("url") else "legacy:" + row["id"]
            method = payload.get("method", "")
            identity = [target_identity(target), method, row["finding_type"]]
            key = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()
            # Preserve legacy duplicate rows and their reviews, but reserve the stable key for the first.
            if conn.execute("SELECT id FROM findings WHERE project_id=? AND dedup_key=?", (row["project_id"], key)).fetchone():
                key = "legacy:" + row["id"]
            conn.execute("UPDATE findings SET target=?,method=?,dedup_key=?,updated_at=created_at WHERE id=?",
                         (target, method, key, row["id"]))
            conn.execute("INSERT OR IGNORE INTO finding_sources VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                "src_" + row["id"], row["project_id"], row["id"], "rule", "legacy", "unknown",
                row["original_severity"], row["original_severity_reason"], row["evidence_refs"],
                "legacy", row["created_at"],
            ))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS findings_dedup ON findings(project_id,dedup_key)")
        # An old confirmation did not record the success criterion or controls; never export it as verified.
        conn.execute("""UPDATE findings SET status='needs_evidence' WHERE status='confirmed' AND NOT EXISTS (
            SELECT 1 FROM reviews r WHERE r.finding_id=findings.id AND r.project_id=findings.project_id
            AND r.status='confirmed' AND r.criteria_met=1 AND r.success_criteria<>'' AND r.evidence_refs<>'[]'
        )""")
        conn.execute("PRAGMA user_version=2")

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
