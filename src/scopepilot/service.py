import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .db import Database
from .har import HarError, parse_har
from .schemas import FindingStatus, PolicyCreate, ProjectCreate, ReviewCreate


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


class ValidationError(ValueError):
    pass


class ScopePilotService:
    def __init__(self, database: Database):
        self.db = database

    def create_project(self, data: ProjectCreate) -> dict:
        project_id = new_id("prj")
        created = utcnow()
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO projects(id,name,owner,created_at) VALUES(?,?,?,?)",
                (project_id, data.name, data.owner, created),
            )
            conn.execute(
                "INSERT INTO policies(project_id,version,document,created_at) VALUES(?,?,?,?)",
                (project_id, 1, data.policy.model_dump_json(), created),
            )
            self._audit(conn, project_id, "project.create", "project", project_id, "ok", 1)
        return {"id": project_id, "name": data.name, "owner": data.owner, "policy_version": 1}

    def list_projects(self) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT p.*, (SELECT MAX(version) FROM policies WHERE project_id=p.id) policy_version "
                "FROM projects p ORDER BY created_at DESC"
            ).fetchall()
        return self.db.rows(rows)

    def get_project(self, project_id: str) -> dict:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
            if not row:
                raise NotFoundError("project not found")
            policy = conn.execute(
                "SELECT version,document FROM policies WHERE project_id=? ORDER BY version DESC LIMIT 1",
                (project_id,),
            ).fetchone()
        result = dict(row)
        result["policy_version"] = policy["version"]
        result["policy"] = json.loads(policy["document"])
        return result

    def current_policy(self, conn: sqlite3.Connection, project_id: str) -> tuple[int, PolicyCreate]:
        row = conn.execute(
            "SELECT version,document FROM policies WHERE project_id=? ORDER BY version DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        if not row:
            raise NotFoundError("project or policy not found")
        return row["version"], PolicyCreate.model_validate_json(row["document"])

    def add_policy(self, project_id: str, policy: PolicyCreate) -> dict:
        with self.db.connection() as conn:
            current_version, _ = self.current_policy(conn, project_id)
            version = current_version + 1
            conn.execute(
                "INSERT INTO policies(project_id,version,document,created_at) VALUES(?,?,?,?)",
                (project_id, version, policy.model_dump_json(), utcnow()),
            )
            self._audit(conn, project_id, "policy.create", "policy", str(version), "ok", version)
        return {"project_id": project_id, "policy_version": version, "status": policy.status.value}

    def import_har(self, project_id: str, filename: str, content: bytes) -> dict:
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = new_id("art")
        created = utcnow()
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            duplicate = conn.execute(
                "SELECT * FROM artifacts WHERE project_id=? AND sha256=?", (project_id, digest)
            ).fetchone()
            if duplicate:
                raise ConflictError(f"identical artifact already imported as {duplicate['id']}")
            try:
                entries = parse_har(project_id, content, policy)
            except HarError as exc:
                self._audit(conn, project_id, "artifact.import", "artifact", artifact_id, f"rejected:{exc}", policy_version)
                raise ValidationError(str(exc)) from exc
            accepted = [entry for entry in entries if entry.allowed]
            rejected = [entry for entry in entries if not entry.allowed]
            status = "accepted" if accepted and not rejected else "partial" if accepted else "rejected"
            conn.execute(
                "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?)",
                (artifact_id, project_id, Path(filename).name, digest, status, len(accepted), len(rejected), created),
            )
            for entry in accepted:
                evidence_id = new_id("ev")
                payload = {
                    "method": entry.method,
                    "url": entry.normalized_url,
                    "path": entry.path,
                    "request_headers": entry.request_headers,
                    "query": entry.query,
                    "request_body": entry.request_body,
                    "response_status": entry.response_status,
                    "response_body": entry.response_body,
                }
                conn.execute(
                    "INSERT INTO evidence VALUES(?,?,?,?,?,?,?)",
                    (evidence_id, project_id, artifact_id, f"HAR entry {entry.entry_index}", "http_exchange", json.dumps(payload), created),
                )
                endpoint_id = new_id("ep")
                conn.execute(
                    "INSERT OR IGNORE INTO endpoints VALUES(?,?,?,?,?)",
                    (endpoint_id, project_id, entry.method, entry.path, evidence_id),
                )
            self._audit(conn, project_id, "artifact.import", "artifact", artifact_id, status, policy_version)
        return {
            "artifact_id": artifact_id,
            "status": status,
            "accepted_entries": len(accepted),
            "rejected_entries": len(rejected),
            "rejections": [
                {"entry_index": e.entry_index, "reason": e.scope_reason, "url": e.normalized_url}
                for e in rejected
            ],
            "raw_retained": False,
        }

    def analyze(self, project_id: str) -> dict:
        """Create evidence-backed hypotheses. This method performs no network access."""
        created_ids: list[str] = []
        created = utcnow()
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "analysis")
            evidence_rows = conn.execute(
                "SELECT * FROM evidence WHERE project_id=? ORDER BY created_at,id", (project_id,)
            ).fetchall()
            for row in evidence_rows:
                payload = json.loads(row["payload"])
                query_keys = {key.lower() for key in payload.get("query", {})}
                body = payload.get("request_body")
                body_keys = {key.lower() for key in body} if isinstance(body, dict) else set()
                object_keys = sorted(key for key in query_keys | body_keys if key == "id" or key.endswith("id") or key.endswith("_id"))
                if object_keys:
                    refs_json = json.dumps([row["id"]])
                    duplicate = conn.execute(
                        "SELECT id FROM findings WHERE project_id=? AND finding_type=? AND evidence_refs=?",
                        (project_id, "object_authorization_review", refs_json),
                    ).fetchone()
                    if duplicate:
                        continue
                    finding_id = new_id("find")
                    conn.execute(
                        "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            finding_id,
                            project_id,
                            "object_authorization_review",
                            f"接口包含对象标识参数（{', '.join(object_keys)}），需要使用自有 A/B 账号核查对象授权。",
                            refs_json,
                            "缺少服务端行为、账号角色和对象归属信息。",
                            "仅使用自有账号及自建对象，比较对象所有者与非所有者的授权结果；出现第三方数据立即停止。",
                            0.45,
                            FindingStatus.PENDING.value,
                            created,
                        ),
                    )
                    created_ids.append(finding_id)
            self._audit(conn, project_id, "analysis.run", "project", project_id, f"created:{len(created_ids)}", policy_version)
        return {"created": len(created_ids), "finding_ids": created_ids, "engine": "deterministic-mvp"}

    def list_endpoints(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE project_id=? ORDER BY path,method", (project_id,)
            ).fetchall()
        return self.db.rows(rows)

    def list_findings(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,)
            ).fetchall()
        return self.db.rows(rows)

    def review_finding(self, project_id: str, finding_id: str, review: ReviewCreate) -> dict:
        review_id = new_id("rev")
        with self.db.connection() as conn:
            policy_version, _ = self.current_policy(conn, project_id)
            finding = conn.execute(
                "SELECT * FROM findings WHERE id=? AND project_id=?", (finding_id, project_id)
            ).fetchone()
            if not finding:
                raise NotFoundError("finding not found in project")
            refs = json.loads(finding["evidence_refs"])
            existing = conn.execute(
                f"SELECT COUNT(*) count FROM evidence WHERE project_id=? AND id IN ({','.join('?' for _ in refs)})",
                (project_id, *refs),
            ).fetchone()["count"]
            if existing != len(refs):
                raise ValidationError("finding references missing or cross-project evidence")
            conn.execute(
                "INSERT INTO reviews VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    review_id, project_id, finding_id, review.status.value, review.reviewer,
                    review.actual_result, review.tested_identity, review.tested_object,
                    review.stop_reason, policy_version, utcnow(),
                ),
            )
            conn.execute("UPDATE findings SET status=? WHERE id=?", (review.status.value, finding_id))
            self._audit(conn, project_id, "finding.review", "finding", finding_id, review.status.value, policy_version)
        return {"review_id": review_id, "finding_id": finding_id, "status": review.status.value}

    def report_markdown(self, project_id: str) -> str:
        project = self.get_project(project_id)
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "report export")
            rows = conn.execute(
                "SELECT f.*,r.reviewer,r.actual_result,r.tested_identity,r.tested_object,r.stop_reason,r.created_at review_time "
                "FROM findings f JOIN reviews r ON r.finding_id=f.id AND r.project_id=f.project_id "
                "WHERE f.project_id=? AND f.status=? ORDER BY r.created_at",
                (project_id, FindingStatus.CONFIRMED.value),
            ).fetchall()
            if not rows:
                raise ValidationError("no human-confirmed findings are available for export")
            evidence: dict[str, dict] = {}
            for row in rows:
                for ref in json.loads(row["evidence_refs"]):
                    ev = conn.execute(
                        "SELECT id,locator,payload FROM evidence WHERE id=? AND project_id=?", (ref, project_id)
                    ).fetchone()
                    if not ev:
                        raise ValidationError("report evidence is missing or belongs to another project")
                    evidence[ref] = {"locator": ev["locator"], "payload": json.loads(ev["payload"])}
            self._audit(conn, project_id, "report.export", "project", project_id, "ok", policy_version)

        lines = [
            f"# {project['name']}：人工确认发现报告",
            "",
            f"- 项目编号：{project_id}",
            f"- 授权引用：{policy.authorization_reference}",
            f"- Scope 版本：{policy_version}",
            f"- 导出时间：{utcnow()}",
            "- 状态说明：仅包含人工确认且证据完整的发现；本报告不会自动提交。",
        ]
        for index, row in enumerate(rows, 1):
            lines += [
                "", f"## {index}. {row['claim']}", "",
                f"- 类型：{row['finding_type']}",
                f"- 审核人：{row['reviewer']}",
                f"- 测试身份：{row['tested_identity']}",
                f"- 测试对象：{row['tested_object']}",
                f"- 实际结果：{row['actual_result']}",
                f"- 停止原因：{row['stop_reason']}",
                "", "### 证据", "",
            ]
            for ref in json.loads(row["evidence_refs"]):
                ev = evidence[ref]
                payload = ev["payload"]
                lines.append(f"- `{ref}` · {ev['locator']} · {payload.get('method')} {payload.get('path')} · HTTP {payload.get('response_status')}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _audit(conn: sqlite3.Connection, project_id: str, action: str, object_type: str, object_id: str, result: str, policy_version: int | None) -> None:
        conn.execute(
            "INSERT INTO audit_events(project_id,action,object_type,object_id,result,policy_version,created_at) VALUES(?,?,?,?,?,?,?)",
            (project_id, action, object_type, object_id, result, policy_version, utcnow()),
        )

    @staticmethod
    def _ensure_policy_usable(policy: PolicyCreate, operation: str) -> None:
        now = datetime.now(timezone.utc)
        if policy.status.value != "active":
            raise ValidationError(f"{operation} requires an active policy")
        if not policy.valid_from <= now <= policy.valid_until:
            raise ValidationError(f"{operation} requires a currently valid policy")
