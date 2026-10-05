from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scopepilot.db import Database
from scopepilot.schemas import FindingStatus, IdentityCreate, PolicyCreate, PolicyStatus, ProjectCreate, ReviewCreate, ScopeRule
from scopepilot.service import ScopePilotService, ValidationError


FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


def make_service(tmp_path: Path) -> ScopePilotService:
    return ScopePilotService(Database(tmp_path / "test.db"))


def make_project(service: ScopePilotService) -> dict:
    now = datetime.now(timezone.utc)
    return service.create_project(ProjectCreate(
        name="Synthetic Lab",
        owner="local researcher",
        policy=PolicyCreate(
            authorization_reference="self-owned synthetic fixture",
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(days=1),
            status=PolicyStatus.ACTIVE,
            allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000, path_prefix="/")],
        ),
    ))


def test_full_offline_workflow(tmp_path: Path):
    service = make_service(tmp_path)
    project = make_project(service)
    raw = FIXTURE.read_bytes()

    imported = service.import_har(project["id"], "sample.har", raw)
    assert imported["accepted_entries"] == 1
    assert imported["rejected_entries"] == 1
    assert imported["raw_retained"] is False

    endpoints = service.list_endpoints(project["id"])
    assert [(e["method"], e["path"]) for e in endpoints] == [("GET", "/api/orders")]

    analysis = service.analyze(project["id"])
    assert analysis["created"] == 1
    assert service.analyze(project["id"])["created"] == 0
    finding = service.list_findings(project["id"])[0]
    assert finding["status"] == FindingStatus.PENDING.value

    with pytest.raises(ValidationError, match="no human-confirmed"):
        service.report_markdown(project["id"])

    service.review_finding(project["id"], finding["id"], ReviewCreate(
        status=FindingStatus.NEEDS_EVIDENCE,
        reviewer="researcher",
        actual_result="first review needs more synthetic evidence",
        tested_identity="synthetic-account-b",
        tested_object="synthetic-order-a",
        stop_reason="stopped before drawing a conclusion",
    ))
    service.review_finding(project["id"], finding["id"], ReviewCreate(
        status=FindingStatus.CONFIRMED,
        reviewer="researcher",
        actual_result="自有账号 B 无法访问账号 A 的对象；本合成演示将该项人工标记为已确认。",
        tested_identity="synthetic-account-b",
        tested_object="synthetic-order-a",
        stop_reason="完成单一合成假设验证后停止",
    ))
    report = service.report_markdown(project["id"])
    assert "人工确认发现报告" in report
    assert "不会自动提交" in report
    assert "synthetic-secret-token" not in report
    assert "alice@example.test" not in report
    assert "first review needs more synthetic evidence" not in report


def test_import_does_not_persist_raw_secret(tmp_path: Path):
    service = make_service(tmp_path)
    project = make_project(service)
    service.import_har(project["id"], "sample.har", FIXTURE.read_bytes())
    database_bytes = (tmp_path / "test.db").read_bytes()
    assert b"synthetic-secret-token" not in database_bytes
    assert b"never-store-me" not in database_bytes
    assert b"alice@example.test" not in database_bytes
    assert b"synthetic-order-17" not in database_bytes


def test_identity_metadata_and_artifact_deletion(tmp_path: Path):
    service = make_service(tmp_path)
    project = make_project(service)
    identity = service.create_identity(project["id"], IdentityCreate(
        alias="account-a", role="member", ownership_notes="owns synthetic order A",
    ))
    assert service.list_identities(project["id"])[0]["alias"] == "account-a"
    assert service.delete_identity(project["id"], identity["id"])["deleted"] is True

    imported = service.import_har(project["id"], "sample.har", FIXTURE.read_bytes())
    service.analyze(project["id"])
    deleted = service.delete_artifact(project["id"], imported["artifact_id"])
    assert deleted["deleted_evidence"] == 1
    assert deleted["deleted_findings"] == 1
    assert service.list_artifacts(project["id"]) == []
    assert service.list_endpoints(project["id"]) == []
    assert service.list_findings(project["id"]) == []
