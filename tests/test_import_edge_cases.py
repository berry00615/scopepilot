"""Only synthetic imports; no scanners, downloaded templates or target requests."""
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from scopepilot.adapters import parse_tool_results
from scopepilot.db import Database, SCHEMA, artifact_origin_key
from scopepilot.schemas import PolicyCreate, ProjectCreate, ScopeRule
from scopepilot.service import ConflictError, ScopePilotService, ValidationError


def policy():
    now = datetime.now(timezone.utc)
    return PolicyCreate(authorization_reference="self-owned synthetic records", valid_from=now-timedelta(minutes=1),
                        valid_until=now+timedelta(days=1), status="active",
                        allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000)])


@pytest.fixture
def lab(tmp_path):
    service = ScopePilotService(Database(tmp_path / "imports.db"))
    project = service.create_project(ProjectCreate(name="Synthetic imports", owner="researcher", policy=policy()))
    return service, project["id"]


def nuclei(*, rule="http-missing-security-headers", severity="info", matcher="x-frame-options", **extra):
    return {"template-id": rule, "type": "http", "matched-at": "http://127.0.0.1:3000/status", "method": "GET",
            "info": {"name": "Synthetic observation", "severity": severity}, "matcher-name": matcher, **extra}


def gitleaks(**extra):
    return {"RuleID": "synthetic-rule", "File": "src/config.py", "StartLine": 8, "EndLine": 8,
            "Description": "Synthetic credential", "Secret": "copied-credential-value", "Match": "secret=copied-credential-value", **extra}


@pytest.mark.parametrize("rule,severity,category", [
    ("http-missing-security-headers", "info", "hardening"),
    ("http-missing-security-headers", "HIGH", "hardening"),
    ("synthetic-exposure", "info", "vulnerability"),
    ("synthetic-missing-security-headers", "info", "vulnerability"),
])
def test_classification_uses_reviewed_template_id_not_severity(lab, rule, severity, category):
    service, pid = lab
    result = service.import_tool_results(pid, "nuclei", "result.json", json.dumps(nuclei(rule=rule, severity=severity)).encode(), "3.11.1")
    finding = service.get_finding(pid, result["finding_ids"][0])
    assert finding["category"] == category
    assert finding["status"] == "pending_review"
    assert finding["severity"] == "unrated"


@pytest.mark.parametrize("tool,raw,normalized", [("nuclei", "UNKNOWN", "unrated"), ("nuclei", "HIGH", "high"),
                                                  ("gitleaks", "unknown", "unrated"), ("gitleaks", "Medium", "medium")])
def test_raw_declared_rating_is_preserved_while_enum_is_normalized(lab, tool, raw, normalized):
    service, pid = lab
    record = nuclei(severity=raw) if tool == "nuclei" else [gitleaks(Severity=raw)]
    result = service.import_tool_results(pid, tool, "result.json", json.dumps(record).encode(), "1.0")
    finding = service.get_finding(pid, result["finding_ids"][0])
    assert finding["original_severity"] == normalized
    assert finding["evidence"][0]["payload"]["original_severity_raw"] == raw
    assert raw in finding["original_severity_reason"]


def test_same_content_distinguishes_tool_version_and_source_root_without_changing_sha(lab):
    service, pid = lab
    content = json.dumps([gitleaks()]).encode()
    first = service.import_tool_results(pid, "gitleaks", "first.json", content, "8.30.1", "backend")
    second = service.import_tool_results(pid, "gitleaks", "second.json", content, "8.30.2", "backend")
    third = service.import_tool_results(pid, "gitleaks", "third.json", content, "8.30.1", "frontend")
    assert len({result["artifact_id"] for result in (first, second, third)}) == 3
    assert (first["created"], second["created"], third["created"]) == (1, 0, 1)
    assert {row["sha256"] for row in service.list_artifacts(pid)} == {hashlib.sha256(content).hexdigest()}
    assert len({row["origin_key"] for row in service.list_artifacts(pid)}) == 3
    detail = service.get_finding(pid, first["finding_ids"][0])
    assert {source["version"] for source in detail["sources"]} == {"8.30.1", "8.30.2"}
    assert len(detail["evidence"]) == 2
    with pytest.raises(ConflictError):
        service.import_tool_results(pid, "gitleaks", "renamed.json", content, "8.30.1", "backend")
    assert len(service.list_artifacts(pid)) == 3


def test_empty_result_imports_still_have_source_identity(lab):
    service, pid = lab
    first = service.import_tool_results(pid, "gitleaks", "zero.json", b"[]", "8.30.1")
    second = service.import_tool_results(pid, "nuclei", "zero.json", b"[]", "3.11.1")
    assert first["artifact_id"] != second["artifact_id"]
    assert len(service.list_artifacts(pid)) == 2
    with pytest.raises(ConflictError):
        service.import_tool_results(pid, "nuclei", "zero.json", b"[]", "3.11.1")


def test_har_duplicate_identity_remains_content_based(lab):
    service, pid = lab
    content = json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "http://127.0.0.1:3000/status", "headers": []},
                                              "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}}}]}}).encode()
    service.import_har(pid, "one.har", content)
    with pytest.raises(ConflictError):
        service.import_har(pid, "two.har", content)
    assert service.list_artifacts(pid)[0]["sha256"] == hashlib.sha256(content).hexdigest()


def test_nuclei_matchers_merge_without_losing_either_observation(lab):
    service, pid = lab
    content = json.dumps([nuclei(matcher="x-frame-options"), nuclei(matcher="content-security-policy")]).encode()
    result = service.import_tool_results(pid, "nuclei", "headers.json", content, "3.11.1")
    assert result["created"] == 1
    finding = service.get_finding(pid, result["finding_ids"][0])
    assert len(finding["evidence"]) == 2
    assert {row["payload"]["matcher_name"] for row in finding["evidence"]} == {"x-frame-options", "content-security-policy"}


def test_gitleaks_same_rule_at_distinct_lines_remains_distinct(lab):
    service, pid = lab
    content = json.dumps([gitleaks(), gitleaks(StartLine=19, EndLine=19)]).encode()
    result = service.import_tool_results(pid, "gitleaks", "lines.json", content, "8.30.1")
    assert result["created"] == 2
    assert len({finding["dedup_key"] for finding in service.list_findings(pid)}) == 2


@pytest.mark.parametrize("field,value", [("File", "src/copied-credential-value.py"),
                                          ("File", "src/%63opied-credential-value.py"),
                                          ("RuleID", "prefix-copied-credential-value")])
def test_known_secret_in_identity_metadata_rejects_whole_import(lab, field, value):
    service, pid = lab
    content = json.dumps([gitleaks(Secret="other-credential", Match="other-credential"), gitleaks(**{field: value})]).encode()
    with pytest.raises(ValidationError, match="sensitive material") as exc:
        service.import_tool_results(pid, "gitleaks", "source.json", content, "8.30.1")
    assert "copied-credential-value" not in str(exc.value)
    assert service.list_artifacts(pid) == [] and service.list_findings(pid) == []
    assert b"copied-credential-value" not in service.db.path.read_bytes()


@pytest.mark.parametrize("metadata", [{"filename": "copied-credential-value.json"},
                                       {"tool_version": "copied-credential-value"},
                                       {"source_root": "copied-credential-value"}])
def test_known_secret_in_import_metadata_is_rejected(lab, metadata):
    service, pid = lab
    args = {"filename": "source.json", "tool_version": "8.30.1", "source_root": "source"} | metadata
    with pytest.raises(ValidationError, match="sensitive material"):
        service.import_tool_results(pid, "gitleaks", content=json.dumps([gitleaks()]).encode(), **args)
    assert service.list_artifacts(pid) == []


def test_cross_record_secret_copy_is_rejected_and_unused_description_is_discarded(lab):
    service, pid = lab
    content = json.dumps([gitleaks(), gitleaks(Secret="different-value", Match="different-value", File="copied-credential-value.py")]).encode()
    with pytest.raises(ValidationError, match="sensitive material"):
        service.import_tool_results(pid, "gitleaks", "cross.json", content, "8.30.1")
    safe = json.dumps([gitleaks(Description="copied-credential-value")]).encode()
    service.import_tool_results(pid, "gitleaks", "safe.json", safe, "8.30.1")
    assert "copied-credential-value" not in json.dumps(service.list_findings(pid))
    assert b"copied-credential-value" not in service.db.path.read_bytes()


def test_extracted_nuclei_secret_is_removed_from_titles_and_rejected_from_ids():
    secret = "copy/opaque+credential"
    record = nuclei(**{"info": {"name": "Copied " + quote(secret, safe=""), "severity": "info"}, "extracted-results": [secret]})
    finding = parse_tool_results("nuclei", json.dumps(record), "p", policy(), "3.11.1")[0]
    assert secret not in json.dumps(finding) and quote(secret, safe="") not in json.dumps(finding)
    record = nuclei(matcher="opaque-credential", **{"extracted-results": ["opaque-credential"]})
    with pytest.raises(ValueError, match="sensitive material"):
        parse_tool_results("nuclei", json.dumps(record), "p", policy(), "3.11.1")


def test_metadata_secret_comparisons_are_bounded():
    rows = [nuclei(**{"extracted-results": [f"opaque-value-{batch}-{index}" for index in range(500)]}) for batch in range(9)]
    with pytest.raises(ValueError, match="sanitization budget"):
        parse_tool_results("nuclei", json.dumps(rows), "p", policy(), "3.11.1")


def test_origin_key_migration_preserves_actual_foreign_keys_and_raw_hash(tmp_path):
    db_path = tmp_path / "legacy.db"
    content = json.dumps([gitleaks()]).encode()
    digest = hashlib.sha256(content).hexdigest()
    legacy_schema = SCHEMA.replace("created_at TEXT NOT NULL, origin_key TEXT NOT NULL, UNIQUE(project_id, origin_key)",
                                   "created_at TEXT NOT NULL, UNIQUE(project_id, sha256)")
    with sqlite3.connect(db_path) as conn:
        conn.executescript(legacy_schema)
        conn.execute("INSERT INTO projects VALUES('p','legacy','owner','time')")
        conn.execute("INSERT INTO policies(project_id,version,document,created_at) VALUES('p',1,?,'time')", (policy().model_dump_json(),))
        conn.execute("INSERT INTO artifacts VALUES('a','p','old.json',?,'accepted',1,0,'time')", (digest,))
        payload = json.dumps({"tool": "gitleaks", "tool_version": "8.30.1", "source_root": "backend"})
        conn.execute("INSERT INTO evidence VALUES('e','p','a','config.py:8','tool_result',?,'time')", (payload,))
        conn.execute("INSERT INTO endpoints VALUES('ep','p','GET','/status','e','http://127.0.0.1:3000/status','http://127.0.0.1:3000/status','http','127.0.0.1',3000)")
    database = Database(db_path)
    Database(db_path)
    with database.connection() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM endpoints").fetchone()[0] == 1
        artifact = conn.execute("SELECT * FROM artifacts").fetchone()
        assert artifact["sha256"] == digest
        assert artifact["origin_key"] == artifact_origin_key(digest, "gitleaks", "8.30.1", "backend")
    service = ScopePilotService(database)
    with pytest.raises(ConflictError):
        service.import_tool_results("p", "gitleaks", "same.json", content, "8.30.1", "backend")
    service.import_tool_results("p", "gitleaks", "new-version.json", content, "8.30.2", "backend")
    assert len(service.list_artifacts("p")) == 2


def test_migration_corrects_only_known_hardening_category_and_keeps_rating(lab):
    service, pid = lab
    result = service.import_tool_results(pid, "nuclei", "headers.json", json.dumps(nuclei()).encode(), "3.11.1")
    with service.db.connection() as conn:
        conn.execute("UPDATE findings SET category='vulnerability',severity='high',severity_reason='Preserve human context' WHERE id=?",
                     (result["finding_ids"][0],))
    Database(service.db.path)
    finding = service.get_finding(pid, result["finding_ids"][0])
    assert finding["category"] == "hardening"
    assert finding["severity"] == "high" and finding["severity_reason"] == "Preserve human context"


def test_migration_refuses_custom_cascade_without_removing_evidence(tmp_path):
    db_path = tmp_path / "custom-cascade.db"
    legacy_schema = SCHEMA.replace("created_at TEXT NOT NULL, origin_key TEXT NOT NULL, UNIQUE(project_id, origin_key)",
                                   "created_at TEXT NOT NULL, UNIQUE(project_id, sha256)")
    legacy_schema = legacy_schema.replace("REFERENCES artifacts(id)", "REFERENCES artifacts(id) ON DELETE CASCADE")
    with sqlite3.connect(db_path) as conn:
        conn.executescript(legacy_schema)
        conn.execute("INSERT INTO projects VALUES('p','legacy','owner','time')")
        conn.execute("INSERT INTO artifacts VALUES('a','p','old.json','digest','accepted',1,0,'time')")
        conn.execute("INSERT INTO evidence VALUES('e','p','a','HAR entry 0','http_exchange','{}','time')")
    with pytest.raises(sqlite3.IntegrityError, match="custom cascading"):
        Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 1
        assert "origin_key" not in {row[1] for row in conn.execute("PRAGMA table_info(artifacts)")}
