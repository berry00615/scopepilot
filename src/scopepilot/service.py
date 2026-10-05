import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit

from .db import Database, artifact_origin_key
from .har import HarError, parse_har
from .llm import LocalLlmGateway
from .sanitize import sanitize_path, sanitize_text, sanitize_url, target_identity
from .schemas import FindingStatus, IdentityCreate, ModelFinding, PolicyCreate, ProjectCreate, ReviewCreate, Severity


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
        name, owner = sanitize_text(data.name), sanitize_text(data.owner)
        policy = data.policy.model_copy(update={"authorization_reference": sanitize_text(data.policy.authorization_reference)})
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO projects(id,name,owner,created_at) VALUES(?,?,?,?)",
                (project_id, name, owner, created),
            )
            conn.execute(
                "INSERT INTO policies(project_id,version,document,created_at) VALUES(?,?,?,?)",
                (project_id, 1, policy.model_dump_json(), created),
            )
            self._audit(conn, project_id, "project.create", "project", project_id, "ok", 1)
        return {"id": project_id, "name": name, "owner": owner, "policy_version": 1}

    def list_projects(self) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT p.*, (SELECT MAX(version) FROM policies WHERE project_id=p.id) policy_version "
                "FROM projects p ORDER BY created_at DESC"
            ).fetchall()
        projects = self.db.rows(rows)
        for project in projects:
            project["name"], project["owner"] = sanitize_text(project["name"]), sanitize_text(project["owner"])
        return projects

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
        result["name"], result["owner"] = sanitize_text(result["name"]), sanitize_text(result["owner"])
        result["policy"]["authorization_reference"] = sanitize_text(result["policy"]["authorization_reference"])
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
        policy = policy.model_copy(update={"authorization_reference": sanitize_text(policy.authorization_reference)})
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
        origin_key = artifact_origin_key(digest)
        artifact_id = new_id("art")
        created = utcnow()
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            duplicate = conn.execute(
                "SELECT * FROM artifacts WHERE project_id=? AND origin_key=?", (project_id, origin_key)
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
                "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?)",
                (artifact_id, project_id, sanitize_text(Path(filename).name), digest, status, len(accepted), len(rejected), created, origin_key),
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
                    "response_headers": entry.response_headers,
                    "response_cookies": entry.response_cookies,
                    "signals": entry.signals,
                }
                conn.execute(
                    "INSERT INTO evidence VALUES(?,?,?,?,?,?,?)",
                    (evidence_id, project_id, artifact_id, f"HAR entry {entry.entry_index}", "http_exchange", json.dumps(payload), created),
                )
                self._add_endpoint(conn, project_id, entry.method, entry.normalized_url, evidence_id)
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

    def import_tool_results(self, project_id: str, tool: str, filename: str, content: bytes,
                            tool_version: str, source_root: str = "source", *, reuse_existing: bool = False) -> dict:
        from .adapters import parse_tool_results

        artifact_id, created = new_id("art"), utcnow()
        digest = hashlib.sha256(content).hexdigest()
        origin_key = artifact_origin_key(digest, tool, tool_version, source_root)
        created_ids: list[str] = []
        finding_ids: list[str] = []
        with self.db.connection() as conn:
            # Serialize the identity check and insert, including concurrent task retries.
            conn.execute("BEGIN IMMEDIATE")
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "tool result import")
            duplicate = conn.execute("SELECT * FROM artifacts WHERE project_id=? AND origin_key=?", (project_id, origin_key)).fetchone()
            if duplicate and not reuse_existing:
                raise ConflictError("identical artifact already imported")
            try:
                candidates = parse_tool_results(tool, content, project_id, policy, tool_version,
                                                source_root=source_root, filename=Path(filename).name)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            if duplicate:
                refs = {row["id"] for row in conn.execute("SELECT id FROM evidence WHERE artifact_id=? AND project_id=?",
                                                         (duplicate["id"], project_id))}
                finding_ids = [row["id"] for row in conn.execute("SELECT id,evidence_refs FROM findings WHERE project_id=?", (project_id,))
                               if refs.intersection(json.loads(row["evidence_refs"]))]
                return {"artifact_id": duplicate["id"], "status": duplicate["status"], "accepted_entries": duplicate["accepted_entries"],
                        "rejected_entries": duplicate["rejected_entries"], "created": 0, "finding_ids": finding_ids,
                        "raw_retained": False, "tool": tool, "tool_version": tool_version, "reused": True}
            conn.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?)", (
                artifact_id, project_id, sanitize_text(Path(filename).name), digest, "accepted", len(candidates), 0, created, origin_key,
            ))
            for candidate in candidates:
                candidate.setdefault("original_severity_reason", f"{tool} {tool_version} 上游输出声明 {candidate.get('original_severity', 'unrated')}；该声明尚未独立验证。")
                evidence_id = new_id("ev")
                conn.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?)", (
                    evidence_id, project_id, artifact_id, sanitize_text(candidate["locator"]),
                    "tool_result", json.dumps({**candidate["evidence"], "target": candidate["target"],
                                               "method": candidate.get("method", ""), "source_root": source_root}), created,
                ))
                self._add_endpoint(conn, project_id, candidate.get("method", ""), candidate["target"], evidence_id)
                finding_id, is_new = self._upsert_finding(
                    conn, project_id, candidate, [evidence_id], "tool", tool, tool_version,
                )
                finding_ids.append(finding_id)
                if is_new:
                    created_ids.append(finding_id)
            self._audit(conn, project_id, "artifact.import_tool", "artifact", artifact_id,
                        f"{tool}:accepted:{len(candidates)}", policy_version)
        return {"artifact_id": artifact_id, "status": "accepted", "accepted_entries": len(candidates),
                "rejected_entries": 0, "created": len(created_ids), "finding_ids": list(dict.fromkeys(finding_ids)),
                "raw_retained": False, "tool": tool, "tool_version": tool_version}

    @staticmethod
    def _target_key(target: str) -> str:
        return target_identity(target)

    def _add_endpoint(self, conn: sqlite3.Connection, project_id: str, method: str, target: str,
                      evidence_id: str) -> None:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"}:
            return
        target = sanitize_url(project_id, target)
        parsed = urlsplit(target)
        conn.execute("INSERT OR IGNORE INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?)", (
            new_id("ep"), project_id, method, parsed.path or "/", evidence_id, target,
            self._target_key(target), parsed.scheme, parsed.hostname or "",
            parsed.port or (443 if parsed.scheme == "https" else 80),
        ))

    def _upsert_finding(self, conn: sqlite3.Connection, project_id: str, candidate: dict, refs: list[str],
                        source_kind: str, source_name: str, source_version: str) -> tuple[str, bool]:
        target, method = candidate["target"], candidate.get("method", "")
        if target.lower().startswith(("http://", "https://")):
            target = sanitize_url(project_id, target)
        source_name, source_version = sanitize_text(source_name), sanitize_text(source_version)
        identity = [self._target_key(target), method, candidate["finding_type"]]
        if target.startswith("source://"):
            identity.append(candidate.get("locator", ""))
        dedup_key = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()
        existing = conn.execute("SELECT * FROM findings WHERE project_id=? AND dedup_key=?",
                                (project_id, dedup_key)).fetchone()
        created = utcnow()
        severity = candidate.get("severity", "unrated")
        original = candidate.get("original_severity", severity)
        reason = sanitize_text(candidate.get("severity_reason", "Evidence has not been rated."))
        if severity not in {item.value for item in Severity} or original not in {item.value for item in Severity}:
            raise ValidationError("invalid finding severity")
        if existing:
            finding_id = existing["id"]
            merged = list(dict.fromkeys(json.loads(existing["evidence_refs"]) + refs))
            conn.execute("UPDATE findings SET evidence_refs=?,updated_at=? WHERE id=?", (json.dumps(merged), created, finding_id))
        else:
            finding_id = new_id("find")
            conn.execute("""INSERT INTO findings (
                id,project_id,finding_type,claim,evidence_refs,missing_information,suggested_manual_check,
                confidence,status,created_at,target,method,severity,original_severity,severity_reason,
                original_severity_reason,category,remediation,dedup_key,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                finding_id, project_id, sanitize_text(candidate["finding_type"]), sanitize_text(candidate["claim"]),
                json.dumps(list(dict.fromkeys(refs))), sanitize_text(candidate.get("missing_information", "需要人工复核和成功判据。")),
                sanitize_text(candidate.get("suggested_manual_check", "仅在已授权范围内使用自有合成材料验证。")),
                candidate.get("confidence", 0.4), FindingStatus.PENDING.value, created, target, method,
                severity, original, reason, sanitize_text(candidate.get("original_severity_reason", reason)),
                candidate.get("category", "vulnerability"), sanitize_text(candidate.get("remediation", "")), dedup_key, created,
            ))
        source = conn.execute("""SELECT * FROM finding_sources WHERE finding_id=? AND source_kind=?
                              AND name=? AND version=?""", (finding_id, source_kind, source_name, source_version)).fetchone()
        if source:
            merged = list(dict.fromkeys(json.loads(source["evidence_refs"]) + refs))
            conn.execute("UPDATE finding_sources SET evidence_refs=? WHERE id=?", (json.dumps(merged), source["id"]))
        else:
            conn.execute("INSERT INTO finding_sources VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                new_id("src"), project_id, finding_id, source_kind, sanitize_text(source_name), sanitize_text(source_version),
                original, sanitize_text(candidate.get("original_severity_reason", reason)), json.dumps(refs),
                sanitize_text(candidate.get("hint_kind", candidate["finding_type"])), created,
            ))
        return finding_id, existing is None

    def list_artifacts(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE project_id=? ORDER BY created_at DESC", (project_id,)
            ).fetchall()
        return self.db.rows(rows)

    def delete_artifact(self, project_id: str, artifact_id: str) -> dict:
        with self.db.connection() as conn:
            policy_version, _ = self.current_policy(conn, project_id)
            artifact = conn.execute(
                "SELECT id FROM artifacts WHERE id=? AND project_id=?", (artifact_id, project_id)
            ).fetchone()
            if not artifact:
                raise NotFoundError("artifact not found in project")
            evidence_ids = [row["id"] for row in conn.execute(
                "SELECT id FROM evidence WHERE artifact_id=? AND project_id=?", (artifact_id, project_id)
            ).fetchall()]
            finding_ids: list[str] = []
            if evidence_ids:
                evidence_set = set(evidence_ids)
                for row in conn.execute(
                    "SELECT id,evidence_refs,status FROM findings WHERE project_id=?", (project_id,)
                ).fetchall():
                    old_refs = json.loads(row["evidence_refs"])
                    if not evidence_set.intersection(old_refs):
                        continue
                    remaining = [ref for ref in old_refs if ref not in evidence_set]
                    if not remaining:
                        finding_ids.append(row["id"])
                    else:
                        status = "needs_evidence" if row["status"] == "confirmed" else row["status"]
                        conn.execute("UPDATE findings SET evidence_refs=?,status=?,updated_at=? WHERE id=?",
                                     (json.dumps(remaining), status, utcnow(), row["id"]))
                for source in conn.execute("SELECT id,evidence_refs FROM finding_sources WHERE project_id=?", (project_id,)).fetchall():
                    remaining = [ref for ref in json.loads(source["evidence_refs"]) if ref not in evidence_set]
                    if remaining:
                        conn.execute("UPDATE finding_sources SET evidence_refs=? WHERE id=?", (json.dumps(remaining), source["id"]))
                    else:
                        conn.execute("DELETE FROM finding_sources WHERE id=?", (source["id"],))
                if finding_ids:
                    placeholders = ",".join("?" for _ in finding_ids)
                    conn.execute(f"DELETE FROM reviews WHERE project_id=? AND finding_id IN ({placeholders})", (project_id, *finding_ids))
                    conn.execute(f"DELETE FROM finding_sources WHERE project_id=? AND finding_id IN ({placeholders})", (project_id, *finding_ids))
                    conn.execute(f"DELETE FROM findings WHERE project_id=? AND id IN ({placeholders})", (project_id, *finding_ids))
                placeholders = ",".join("?" for _ in evidence_ids)
                conn.execute(f"DELETE FROM endpoints WHERE project_id=? AND evidence_id IN ({placeholders})", (project_id, *evidence_ids))
                conn.execute(f"DELETE FROM evidence WHERE project_id=? AND id IN ({placeholders})", (project_id, *evidence_ids))
                for ev in conn.execute("SELECT id,payload FROM evidence WHERE project_id=? ORDER BY created_at,id", (project_id,)).fetchall():
                    payload = json.loads(ev["payload"])
                    target = payload.get("url") or payload.get("target")
                    if target:
                        self._add_endpoint(conn, project_id, payload.get("method", ""), target, ev["id"])
            conn.execute("DELETE FROM artifacts WHERE id=? AND project_id=?", (artifact_id, project_id))
            self._audit(conn, project_id, "artifact.delete", "artifact", artifact_id, "ok", policy_version)
        return {"artifact_id": artifact_id, "deleted_evidence": len(evidence_ids), "deleted_findings": len(finding_ids)}

    def create_identity(self, project_id: str, data: IdentityCreate) -> dict:
        identity_id = new_id("ident")
        fields = {key: sanitize_text(value) for key, value in data.model_dump().items()}
        with self.db.connection() as conn:
            policy_version, _ = self.current_policy(conn, project_id)
            try:
                conn.execute(
                    "INSERT INTO identity_contexts VALUES(?,?,?,?,?,?)",
                    (identity_id, project_id, fields["alias"], fields["role"], fields["ownership_notes"], utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("identity alias already exists in project") from exc
            self._audit(conn, project_id, "identity.create", "identity", identity_id, "ok", policy_version)
        return {"id": identity_id, "project_id": project_id, **fields}

    def list_identities(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM identity_contexts WHERE project_id=? ORDER BY alias", (project_id,)
            ).fetchall()
        return self.db.rows(rows)

    def delete_identity(self, project_id: str, identity_id: str) -> dict:
        with self.db.connection() as conn:
            policy_version, _ = self.current_policy(conn, project_id)
            cursor = conn.execute(
                "DELETE FROM identity_contexts WHERE id=? AND project_id=?", (identity_id, project_id)
            )
            if cursor.rowcount != 1:
                raise NotFoundError("identity not found in project")
            self._audit(conn, project_id, "identity.delete", "identity", identity_id, "ok", policy_version)
        return {"identity_id": identity_id, "deleted": True}

    def analyze(self, project_id: str) -> dict:
        """Create evidence-backed hypotheses without performing any network access."""
        from .passive_checks import check_payload

        created_ids: list[str] = []
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "analysis")
            evidence_rows = conn.execute(
                "SELECT * FROM evidence WHERE project_id=? AND kind='http_exchange' ORDER BY created_at,id", (project_id,)
            ).fetchall()
            for row in evidence_rows:
                payload = json.loads(row["payload"])
                for candidate in check_payload(payload):
                    candidate = {**candidate, "target": payload["url"], "method": payload["method"]}
                    finding_id, is_new = self._upsert_finding(
                        conn, project_id, candidate, [row["id"]], "rule", "scopepilot-passive", "1",
                    )
                    if is_new:
                        created_ids.append(finding_id)
            self._audit(conn, project_id, "analysis.run", "project", project_id, f"created:{len(created_ids)}", policy_version)
        return {"created": len(created_ids), "finding_ids": created_ids, "engine": "deterministic-mvp"}

    def analyze_with_local_llm(self, project_id: str, gateway: LocalLlmGateway) -> dict:
        run_id = new_id("run")
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "local model analysis")
            rows = conn.execute(
                "SELECT id,payload FROM evidence WHERE project_id=? ORDER BY created_at,id LIMIT 100", (project_id,)
            ).fetchall()
        evidence = [self._model_evidence(row["id"], json.loads(row["payload"])) for row in rows]
        if not evidence:
            raise ValidationError("local model analysis requires accepted evidence")
        input_digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
        try:
            output, duration_ms = gateway.analyze(evidence)
            created_ids = self._store_model_findings(project_id, policy_version, output.findings, {item["id"] for item in evidence}, gateway.settings.model)
        except Exception as exc:
            error = "Local model output or transport validation failed."
            with self.db.connection() as conn:
                conn.execute(
                    "INSERT INTO model_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, project_id, "local-openai-compatible", gateway.settings.model, input_digest, len(evidence), 0, "failed", error, 0, utcnow()),
                )
                self._audit(conn, project_id, "analysis.local_llm", "model_run", run_id, "failed", policy_version)
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError(f"local model analysis failed: {error}") from exc
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO model_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, project_id, "local-openai-compatible", gateway.settings.model, input_digest, len(evidence), len(created_ids), "succeeded", None, duration_ms, utcnow()),
            )
            self._audit(conn, project_id, "analysis.local_llm", "model_run", run_id, f"created:{len(created_ids)}", policy_version)
        return {"run_id": run_id, "created": len(created_ids), "finding_ids": created_ids, "engine": "local-llm", "duration_ms": duration_ms}

    def _store_model_findings(self, project_id: str, expected_policy_version: int, findings: list[ModelFinding],
                              allowed_refs: set[str], model_name: str = "unknown") -> list[str]:
        created_ids: list[str] = []
        with self.db.connection() as conn:
            current_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "local model result storage")
            if current_version != expected_policy_version:
                raise ValidationError("policy changed while local model analysis was running")
            for finding in findings:
                refs = list(dict.fromkeys(finding.evidence_refs))
                if not set(refs).issubset(allowed_refs):
                    raise ValidationError("local model referenced missing or cross-project evidence")
                evidence = self._validated_evidence(conn, project_id, refs)
                targets: dict[tuple[str, str], list[str]] = {}
                for ev in evidence:
                    payload = ev["payload"]
                    key = (payload.get("url") or payload.get("target") or "evidence:" + ev["id"], payload.get("method", ""))
                    targets.setdefault(key, []).append(ev["id"])
                for (target, method), target_refs in targets.items():
                    candidate = {**finding.model_dump(), "target": target, "method": method,
                                 "severity": "unrated", "severity_reason": "Model output remains an unverified hypothesis without reviewed impact evidence."}
                    finding_id, is_new = self._upsert_finding(
                        conn, project_id, candidate, target_refs, "model", model_name, "unknown",
                    )
                    if is_new:
                        created_ids.append(finding_id)
        return created_ids

    @staticmethod
    def _model_evidence(evidence_id: str, payload: dict) -> dict:
        request_body = payload.get("request_body")
        response_body = payload.get("response_body")
        return {
            "id": evidence_id,
            "method": payload.get("method"),
            "path": sanitize_path("model", payload["path"]) if payload.get("path") else None,
            "query_keys": sorted((payload.get("query") or {}).keys()),
            "request_body_keys": sorted(request_body.keys()) if isinstance(request_body, dict) else [],
            "response_status": payload.get("response_status"),
            "response_body_keys": sorted(response_body.keys()) if isinstance(response_body, dict) else [],
        }

    def list_endpoints(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE project_id=? ORDER BY path,method", (project_id,)
            ).fetchall()
        return self.db.rows(rows)

    @staticmethod
    def _rating(finding: dict, reviews: list[dict] | None = None) -> dict:
        reviewed = next((review for review in (reviews or []) if review.get("severity")), None)
        return {"original": finding["original_severity"], "original_reason": finding["original_severity_reason"],
                "current": finding["severity"], "reason": finding["severity_reason"],
                "reviewed": reviewed["severity"] if reviewed else None,
                "reviewed_reason": reviewed["severity_reason"] if reviewed else None}

    def list_findings(self, project_id: str, status: str | None = None, severity: str | None = None,
                      category: str | None = None, source: str | None = None, q: str | None = None) -> list[dict]:
        clauses, params = ["f.project_id=?"], [project_id]
        for field, value in (("status", status), ("severity", severity), ("category", category)):
            if value:
                clauses.append(f"f.{field}=?")
                params.append(value)
        if source:
            clauses.append("EXISTS (SELECT 1 FROM finding_sources s WHERE s.finding_id=f.id AND (s.source_kind=? OR s.name=?))")
            params.extend((source, source))
        if q:
            clauses.append("(instr(lower(f.claim),lower(?))>0 OR instr(lower(f.target),lower(?))>0 OR instr(lower(f.finding_type),lower(?))>0)")
            params.extend((q, q, q))
        with self.db.connection() as conn:
            self.current_policy(conn, project_id)
            rows = conn.execute("SELECT f.* FROM findings f WHERE " + " AND ".join(clauses) + " ORDER BY f.created_at DESC,f.id", params).fetchall()
            findings = self.db.rows(rows)
            for finding in findings:
                finding["sources"] = self.db.rows(conn.execute(
                    "SELECT * FROM finding_sources WHERE project_id=? AND finding_id=? ORDER BY created_at,id",
                    (project_id, finding["id"])).fetchall())
                finding["evidence_count"] = len(finding["evidence_refs"])
                rating_review = conn.execute("SELECT severity,severity_reason FROM reviews WHERE finding_id=? AND project_id=? "
                                             "AND severity IS NOT NULL ORDER BY created_at DESC,rowid DESC LIMIT 1",
                                             (finding["id"], project_id)).fetchone()
                finding["rating"] = self._rating(finding, [dict(rating_review)] if rating_review else [])
        return findings

    def get_finding(self, project_id: str, finding_id: str) -> dict:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE project_id=? AND id=?", (project_id, finding_id)).fetchone()
            if not row:
                raise NotFoundError("finding not found in project")
            finding = self.db.rows([row])[0]
            finding["sources"] = self.db.rows(conn.execute(
                "SELECT * FROM finding_sources WHERE project_id=? AND finding_id=? ORDER BY created_at,id",
                (project_id, finding_id)).fetchall())
            finding["evidence"] = self._validated_evidence(conn, project_id, finding["evidence_refs"])
            finding["reviews"] = self.db.rows(conn.execute(
                "SELECT * FROM reviews WHERE project_id=? AND finding_id=? ORDER BY created_at DESC,rowid DESC",
                (project_id, finding_id)).fetchall())
            finding["rating"] = self._rating(finding, finding["reviews"])
            finding["evidence_count"] = len(finding["evidence"])
        return finding

    def list_evidence(self, project_id: str) -> list[dict]:
        with self.db.connection() as conn:
            self.current_policy(conn, project_id)
            return self.db.rows(conn.execute(
                "SELECT e.*,a.filename,a.sha256 FROM evidence e JOIN artifacts a ON a.id=e.artifact_id "
                "WHERE e.project_id=? ORDER BY e.created_at,e.id", (project_id,)).fetchall())

    def _validated_evidence(self, conn: sqlite3.Connection, project_id: str, refs: list[str]) -> list[dict]:
        if not refs:
            return []
        refs = list(dict.fromkeys(refs))
        rows = conn.execute(
            "SELECT e.*,a.filename,a.sha256 FROM evidence e JOIN artifacts a ON a.id=e.artifact_id "
            f"WHERE e.project_id=? AND e.id IN ({','.join('?' for _ in refs)})",
            (project_id, *refs)).fetchall()
        if len(rows) != len(refs):
            raise ValidationError("finding references missing or cross-project evidence")
        evidence = {row["id"]: row for row in self.db.rows(rows)}
        return [evidence[ref] for ref in refs]

    @staticmethod
    def _confirmation_valid(finding_type: str, review: dict) -> bool:
        needs_control = review.get("control_required") or finding_type in {"object_authorization_review", "cors_origin_review", "cors_wildcard_credentials"}
        return bool(review.get("criteria_met") and str(review.get("success_criteria", "")).strip()
                    and review.get("evidence_refs") and review.get("control_passed") not in (False, 0)
                    and (not needs_control or (review.get("control_passed") in (True, 1)
                                               and str(review.get("control_result", "")).strip())))

    def review_finding(self, project_id: str, finding_id: str, review: ReviewCreate) -> dict:
        review_id = new_id("rev")
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            finding = conn.execute("SELECT * FROM findings WHERE id=? AND project_id=?", (finding_id, project_id)).fetchone()
            if not finding:
                raise NotFoundError("finding not found in project")
            review_data = review.model_dump(mode="json")
            review_data["evidence_refs"] = list(dict.fromkeys(review.evidence_refs))
            for key, value in review_data.items():
                if isinstance(value, str):
                    review_data[key] = sanitize_text(value)
            refs = json.loads(finding["evidence_refs"])
            self._validated_evidence(conn, project_id, refs + review_data["evidence_refs"])
            if review.status == FindingStatus.CONFIRMED:
                self._ensure_policy_usable(policy, "finding confirmation")
                if not self._confirmation_valid(finding["finding_type"], review_data):
                    raise ValidationError("confirmed requires a satisfied success criterion, evidence references and passing required controls")
            if review.severity is not None and not review.severity_reason.strip():
                raise ValidationError("a reviewed severity requires a rating reason")
            required_control = review.control_required or finding["finding_type"] in {"object_authorization_review", "cors_origin_review", "cors_wildcard_credentials"}
            conn.execute("""INSERT INTO reviews (
                id,project_id,finding_id,status,reviewer,actual_result,tested_identity,tested_object,
                stop_reason,policy_version,created_at,success_criteria,criteria_met,evidence_refs,
                control_required,control_result,control_passed,severity,severity_reason
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                review_id, project_id, finding_id, review.status.value, review_data["reviewer"],
                review_data["actual_result"], review_data["tested_identity"], review_data["tested_object"],
                review_data["stop_reason"], policy_version, utcnow(), review_data["success_criteria"],
                review.criteria_met, json.dumps(review_data["evidence_refs"]), required_control,
                review_data["control_result"], review.control_passed,
                review.severity.value if review.severity else None, review_data["severity_reason"],
            ))
            merged = list(dict.fromkeys(refs + review_data["evidence_refs"]))
            conn.execute("UPDATE findings SET status=?,evidence_refs=?,updated_at=? WHERE id=?",
                         (review.status.value, json.dumps(merged), utcnow(), finding_id))
            if review.severity is not None:
                conn.execute("UPDATE findings SET severity=?,severity_reason=? WHERE id=?",
                             (review.severity.value, review_data["severity_reason"], finding_id))
            if review_data["evidence_refs"]:
                conn.execute("INSERT INTO finding_sources VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                    new_id("src"), project_id, finding_id, "human", review_data["reviewer"], review_id,
                    review.severity.value if review.severity else "unrated", review_data["severity_reason"],
                    json.dumps(review_data["evidence_refs"]), "manual_review", utcnow(),
                ))
            self._audit(conn, project_id, "finding.review", "finding", finding_id, review.status.value, policy_version)
        return {"review_id": review_id, "finding_id": finding_id, "status": review.status.value}

    def report_markdown(self, project_id: str) -> str:
        project = self.get_project(project_id)
        with self.db.connection() as conn:
            policy_version, policy = self.current_policy(conn, project_id)
            self._ensure_policy_usable(policy, "report export")
            rows = conn.execute("SELECT * FROM findings WHERE project_id=? AND status='confirmed' ORDER BY created_at,id", (project_id,)).fetchall()
            if not rows:
                raise ValidationError("no human-confirmed findings are available for export")
            details = []
            for row in rows:
                finding = self.db.rows([row])[0]
                review_row = conn.execute("SELECT * FROM reviews WHERE project_id=? AND finding_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1",
                                          (project_id, finding["id"])).fetchone()
                if not review_row:
                    raise ValidationError("report confirmation is missing")
                review = self.db.rows([review_row])[0]
                if review["status"] != "confirmed" or not self._confirmation_valid(finding["finding_type"], review):
                    raise ValidationError("report confirmation has no satisfied success criterion or passing controls")
                evidence = self._validated_evidence(conn, project_id, list(dict.fromkeys(finding["evidence_refs"] + review["evidence_refs"])))
                sources = self.db.rows(conn.execute("SELECT * FROM finding_sources WHERE project_id=? AND finding_id=? ORDER BY created_at,id",
                                                    (project_id, finding["id"])).fetchall())
                details.append((finding, review, evidence, sources))
            self._audit(conn, project_id, "report.export", "project", project_id, "ok", policy_version)

        def clean(value: object) -> str:
            return sanitize_text(str(value)).replace("\r", " ").replace("\n", " ").replace("`", "'")

        def clean_target(value: str) -> str:
            return clean(sanitize_url(project_id, value) if value.lower().startswith(("http://", "https://")) else value)

        lines = [f"# {clean(project['name'])}：人工确认发现报告", "", f"- 项目编号：{project_id}",
                 f"- 授权引用：{clean(policy.authorization_reference)}", f"- Scope 版本：{policy_version}",
                 f"- 导出时间：{utcnow()}", "- 状态说明：仅包含人工确认且证据完整的发现；本报告不会自动提交。"]
        details.sort(key=lambda item: item[0]['category'] == 'hardening')
        previous_category = None
        for index, (finding, review, evidence, sources) in enumerate(details, 1):
            if finding['category'] != previous_category:
                lines += ['', '## 配置加固（独立列示，不计为已确认漏洞）' if finding['category'] == 'hardening' else '## 已确认漏洞']
                previous_category = finding['category']
            lines += ["", f"### {index}. {clean(finding['claim'])}", "",
                      f"- 目标：{clean(finding['method'])} {clean_target(finding['target'])}",
                      f"- 类型：{clean(finding['finding_type'])}；分类：{clean(finding['category'])}",
                      f"- 原始评级：{clean(finding['original_severity'])}；理由：{clean(finding['original_severity_reason'])}",
                      f"- 当前评级：{clean(finding['severity'])}；理由：{clean(finding['severity_reason'])}",
                      f"- 审核人：{clean(review['reviewer'])}", f"- 测试身份：{clean(review['tested_identity'])}",
                      f"- 复核 Scope 版本：{review['policy_version']}",
                      f"- 测试对象：{clean(review['tested_object'])}", f"- 成功判据：{clean(review['success_criteria'])}",
                      f"- 实际结果：{clean(review['actual_result'])}", f"- 对照结果：{clean(review['control_result'])}",
                      f"- 停止原因：{clean(review['stop_reason'])}", f"- 修复建议：{clean(finding['remediation'])}",
                      "", "#### 来源", ""]
            for source in sources:
                lines.append(f"- {clean(source['source_kind'])} · {clean(source['name'])} · 版本 {clean(source['version'])} · 原始评级 {clean(source['original_severity'])} · {clean(source['severity_reason'])}")
            lines += ["", "#### 证据", ""]
            for ev in evidence:
                payload = ev["payload"]
                target = payload.get("url") or payload.get("target") or ""
                lines.append(f"- `{ev['id']}` · {clean(ev['filename'])} · {clean(ev['locator'])} · {clean(payload.get('method', ''))} {clean_target(target)} · HTTP {clean(payload.get('response_status', 'n/a'))}")
            lines.append("- 复核引用：" + ", ".join(review["evidence_refs"]))
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
