import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from scopepilot.db import Database
from scopepilot.llm import LocalLlmGateway, LocalLlmSettings
from scopepilot.schemas import PolicyCreate, PolicyStatus, ProjectCreate, ScopeRule
from scopepilot.service import ScopePilotService, ValidationError


FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


def project(service: ScopePilotService) -> str:
    now = datetime.now(timezone.utc)
    return service.create_project(ProjectCreate(
        name="Local model lab", owner="researcher",
        policy=PolicyCreate(
            authorization_reference="self-owned fixture",
            valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(days=1),
            status=PolicyStatus.ACTIVE,
            allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000, path_prefix="/")],
        ),
    ))["id"]


def test_settings_reject_non_loopback_and_wrong_path():
    with pytest.raises(ValueError, match="loopback"):
        LocalLlmSettings("https://api.example.com/v1/chat/completions", "model").validate()
    with pytest.raises(ValueError, match="path"):
        LocalLlmSettings("http://127.0.0.1:11434/api/generate", "model").validate()


def test_local_model_output_is_structured_and_remains_pending(tmp_path: Path):
    service = ScopePilotService(Database(tmp_path / "llm.db"))
    project_id = project(service)
    service.import_har(project_id, "sample.har", FIXTURE.read_bytes())

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        evidence = json.loads(payload["messages"][1]["content"].split("\n", 1)[1])
        assert set(evidence[0]) == {"id", "method", "path", "query_keys", "request_body_keys", "response_status", "response_body_keys"}
        content = json.dumps({"findings": [{
            "finding_type": "local_model_hypothesis",
            "claim": "对象标识符需要核查授权边界。",
            "evidence_refs": [evidence[0]["id"]],
            "missing_information": "缺少两个自有账号的对照结果。",
            "suggested_manual_check": "用自有 A/B 账号和自建对象进行一次最小对照。",
            "confidence": 0.4,
        }]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    gateway = LocalLlmGateway(
        LocalLlmSettings("http://127.0.0.1:11434/v1/chat/completions", "synthetic-model"),
        transport=httpx.MockTransport(handler),
    )
    result = service.analyze_with_local_llm(project_id, gateway)
    assert result["created"] == 1
    finding = service.list_findings(project_id)[0]
    assert finding["status"] == "pending_review"
    assert finding["finding_type"] == "local_model_hypothesis"


def test_local_model_cannot_invent_evidence_reference(tmp_path: Path):
    service = ScopePilotService(Database(tmp_path / "bad-ref.db"))
    project_id = project(service)
    service.import_har(project_id, "sample.har", FIXTURE.read_bytes())

    def handler(_: httpx.Request) -> httpx.Response:
        content = json.dumps({"findings": [{
            "finding_type": "bad",
            "claim": "Invented reference",
            "evidence_refs": ["ev_other_project"],
            "missing_information": "unknown",
            "suggested_manual_check": "Use self-owned data only.",
            "confidence": 0.9,
        }]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    gateway = LocalLlmGateway(
        LocalLlmSettings("http://127.0.0.1:11434/v1/chat/completions", "synthetic-model"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ValidationError, match="cross-project evidence"):
        service.analyze_with_local_llm(project_id, gateway)
    assert service.list_findings(project_id) == []
