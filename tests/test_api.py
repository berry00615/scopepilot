from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import scopepilot.api as api
from scopepilot.db import Database
from scopepilot.service import ScopePilotService


def test_http_api_smoke(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "service", ScopePilotService(Database(tmp_path / "api.db")))
    client = TestClient(api.app)
    now = datetime.now(timezone.utc)
    project_response = client.post("/projects", json={
        "name": "API synthetic lab",
        "owner": "local researcher",
        "policy": {
            "authorization_reference": "self-owned fixture",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "status": "active",
            "allow": [{"scheme": "http", "host": "127.0.0.1", "port": 3000, "path_prefix": "/"}],
            "deny": [],
            "external_model_egress": False,
        },
    })
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]

    fixture = __import__("pathlib").Path(__file__).parent / "fixtures" / "sample.har"
    with fixture.open("rb") as handle:
        imported = client.post(
            f"/projects/{project_id}/imports/har",
            files={"file": ("sample.har", handle, "application/json")},
        )
    assert imported.status_code == 201
    assert imported.json()["raw_retained"] is False

    analysis = client.post(f"/projects/{project_id}/analysis-runs")
    assert analysis.status_code == 201
    assert analysis.json()["created"] == 1
    assert client.post(f"/projects/{project_id}/reports").status_code == 422
    assert client.get("/health").json()["target_execution"] is False


def test_foreign_origin_cannot_change_state():
    client = TestClient(api.app)
    response = client.post("/projects", headers={"Origin": "https://attacker.example"}, json={})
    assert response.status_code == 403
    same_origin = client.post("/projects", headers={"Origin": "http://testserver"}, json={})
    assert same_origin.status_code == 422
