"""Real official-SDK stdio round trips; all input is local synthetic evidence."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from scopepilot.db import Database
from scopepilot.mcp_server import MAX_IMPORT_BYTES, database_path
from scopepilot.schemas import ReviewCreate
from scopepilot.service import ScopePilotService


ROOT = Path(__file__).resolve().parents[1]
HAR = (ROOT / "tests" / "fixtures" / "sample.har").read_text(encoding="utf-8")
SECRETS = ("synthetic-secret-token", "never-store-me", "alice@example.test", "synthetic-order-17")


def project_data(name="MCP Synthetic Lab"):
    now = datetime.now(timezone.utc)
    return {
        "name": name, "owner": "synthetic local researcher",
        "policy": {
            "authorization_reference": "self-owned synthetic MCP fixture only",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "status": "active",
            "allow": [{"scheme": "http", "host": "127.0.0.1", "port": 3000, "path_prefix": "/"}],
        },
    }


@pytest.fixture
def mcp_database():
    # Production startup deliberately rejects a database outside the project.
    root = ROOT / ".cache" / "mcp-tests"
    root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="stdio-", dir=root) as folder:
        yield Path(folder) / "mcp.sqlite3"


@asynccontextmanager
async def session(database):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "scopepilot.mcp_server", "--db", str(database)],
        cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as client:
            initialized = await client.initialize()
            assert initialized.serverInfo.name == "scopepilot"
            assert initialized.capabilities.tools is not None
            yield client


async def call(client, name, arguments=None, *, error=False):
    result = await client.call_tool(name, arguments or {})
    assert bool(result.isError) is error, result
    assert result.structuredContent is not None, result
    data = result.structuredContent
    assert data["ok"] is not error
    assert json.loads(result.content[0].text) == data
    serialized = result.model_dump_json()
    for secret in SECRETS:
        assert secret not in serialized
    return data["error"] if error else data["data"]


def test_official_stdio_offline_workflow(mcp_database):
    async def exercise():
        async with session(mcp_database) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert set(tools) == {
                "capabilities", "list_projects", "get_project", "create_project", "import_har_text",
                "import_tool_result_text", "analyze", "list_findings", "get_finding", "export_report",
                "list_tasks", "get_task",
            }
            assert all(tool.inputSchema.get("additionalProperties") is False for tool in tools.values())
            assert tools["get_finding"].annotations.readOnlyHint is True
            assert tools["import_har_text"].annotations.readOnlyHint is False
            assert all(tool.annotations.openWorldHint is False for tool in tools.values())
            caps = await call(client, "capabilities")
            assert caps["offline"] and not caps["task_execution"] and not caps["human_confirmation_via_mcp"]
            assert (await call(client, "list_projects"))["projects"] == []
            project = await call(client, "create_project", {"project": project_data()})
            project_id = project["id"]
            other = await call(client, "create_project", {"project": project_data("Other project")})
            assert (await call(client, "get_project", {"project_id": project_id}))["policy"]["status"] == "active"

            imported = await call(client, "import_har_text", {"project_id": project_id, "content": HAR})
            assert imported["accepted_entries"] == 1 and imported["rejected_entries"] == 1
            assert imported["raw_retained"] is False
            duplicate = await call(client, "import_har_text", {"project_id": project_id, "content": HAR}, error=True)
            assert duplicate["code"] == "conflict"
            analysis = await call(client, "analyze", {"project_id": project_id})
            assert analysis["created"] >= 1
            assert (await call(client, "analyze", {"project_id": project_id}))["created"] == 0
            findings = (await call(client, "list_findings", {"project_id": project_id, "status": "pending_review"}))["findings"]
            assert findings and all(finding["project_id"] == project_id for finding in findings)
            finding = await call(client, "get_finding", {"project_id": project_id, "finding_id": findings[0]["id"]})
            assert finding["evidence"] and finding["sources"] and finding["reviews"] == []
            assert finding["rating"]["current"] == finding["severity"]
            assert (await call(client, "list_findings", {"project_id": other["id"]}))["findings"] == []
            crossed = await call(client, "get_finding", {"project_id": other["id"], "finding_id": finding["id"]}, error=True)
            assert crossed["code"] == "not_found"
            assert (await call(client, "export_report", {"project_id": project_id}, error=True))["code"] == "operation_rejected"
            assert (await call(client, "review_finding", {"project_id": project_id, "finding_id": finding["id"], "status": "confirmed"}, error=True))["code"] == "unknown_tool"

            tool_result = json.dumps([{
                "RuleID": "synthetic-secret-rule", "File": "fixture.env", "StartLine": 1, "EndLine": 1,
                "Secret": "EXAMPLE_FAKE_VALUE", "Match": "password=EXAMPLE_FAKE_VALUE",
                "Description": "Synthetic fixture only",
            }])
            imported_tool = await call(client, "import_tool_result_text", {
                "project_id": project_id, "tool": "gitleaks", "tool_version": "8.30.1",
                "source_root": "synthetic-lab", "content": tool_result,
            })
            assert imported_tool["created"] == 1
            filtered = (await call(client, "list_findings", {
                "project_id": project_id, "source": "gitleaks", "severity": "info", "category": "hardening",
            }))["findings"]
            assert len(filtered) == 1
            assert "EXAMPLE_FAKE_VALUE" not in json.dumps(await call(client, "get_finding", {
                "project_id": project_id, "finding_id": filtered[0]["id"],
            }))

            # Simulate a human record from the separate review UI/service, never
            # through MCP; export must observe this independently recorded review.
            service = ScopePilotService(Database(mcp_database))
            service.review_finding(project_id, finding["id"], ReviewCreate(
                status="confirmed", reviewer="synthetic human reviewer",
                actual_result="Synthetic controlled review meets the recorded criterion.",
                tested_identity="synthetic-account-b", tested_object="synthetic object",
                stop_reason="Single synthetic check completed", success_criteria="Synthetic fixture criterion is met",
                criteria_met=True, evidence_refs=finding["evidence_refs"],
                control_required=True, control_result="Synthetic authorized control passed", control_passed=True,
            ))
            report = await call(client, "export_report", {"project_id": project_id})
            assert report["mime_type"] == "text/markdown" and "人工确认发现报告" in report["markdown"]
            assert "Synthetic controlled review" in report["markdown"]

        for secret in SECRETS:
            assert secret.encode() not in mcp_database.read_bytes()

    asyncio.run(exercise())


def test_stdio_rejects_unsafe_or_invalid_arguments(mcp_database):
    async def exercise():
        async with session(mcp_database) as client:
            project = await call(client, "create_project", {"project": project_data()})
            pid = project["id"]
            bad_project = project_data()
            bad_project["policy"]["shell"] = "password=never-store-me"
            assert (await call(client, "create_project", {"project": bad_project}, error=True))["code"] == "invalid_arguments"
            assert (await call(client, "list_projects", {"command": "password=never-store-me"}, error=True))["code"] == "invalid_arguments"
            for invalid in (
                {"project_id": pid, "content": "{ password=never-store-me"},
                {"project_id": pid, "content": HAR, "filename": "../private.har"},
                {"project_id": pid, "path": "C:/private.har"},
            ):
                await call(client, "import_har_text", invalid, error=True)
            large = "界" * (MAX_IMPORT_BYTES // 3 + 1)
            assert (await call(client, "import_har_text", {"project_id": pid, "content": large}, error=True))["code"] == "import_too_large"
            assert (await call(client, "get_project", {"project_id": "prj_0000000000000000"}, error=True))["code"] == "not_found"
            assert (await call(client, "list_projects"))["projects"][0]["id"] == pid
    asyncio.run(exercise())


def test_task_queries_do_not_recover_or_change_running_tasks(mcp_database):
    async def exercise():
        async with session(mcp_database) as client:
            project = await call(client, "create_project", {"project": project_data()})
            other = await call(client, "create_project", {"project": project_data("Other task project")})
            assert (await call(client, "list_tasks", {"project_id": project["id"]}))["tasks"] == []
            # Only the fixed columns read by the adapter are needed for this probe.
            with Database(mcp_database).connection() as conn:
                conn.execute("CREATE TABLE local_tasks (id TEXT PRIMARY KEY, project_id TEXT, status TEXT, log TEXT, created_at TEXT)")
                conn.execute("INSERT INTO local_tasks VALUES(?,?,?,?,?)", (
                    "task_0123456789abcdef", project["id"], "running", "synthetic task", datetime.now(timezone.utc).isoformat(),
                ))
            task = await call(client, "get_task", {"project_id": project["id"], "task_id": "task_0123456789abcdef"})
            assert task["status"] == "running"
            assert (await call(client, "list_tasks", {"project_id": other["id"]}))["tasks"] == []
            await call(client, "get_task", {"project_id": other["id"], "task_id": task["id"]}, error=True)
        # Starting another MCP server must not mark an existing task interrupted.
        async with session(mcp_database) as client:
            task = await call(client, "get_task", {"project_id": project["id"], "task_id": "task_0123456789abcdef"})
            assert task["status"] == "running"
    asyncio.run(exercise())


def test_database_is_confined_to_project(tmp_path):
    root = tmp_path / "repo"
    (root / "src" / "scopepilot").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="scopepilot"\n')
    assert database_path(str(root / "runtime" / "db.sqlite3"), root) == root / "runtime" / "db.sqlite3"
    with pytest.raises(ValueError, match="absolute"):
        database_path("runtime/db.sqlite3", root)
    with pytest.raises(ValueError, match="inside"):
        database_path(str(tmp_path / "outside.sqlite3"), root)
    with pytest.raises(ValueError, match="inside"):
        database_path(str(root / ".." / "outside.sqlite3"), root)
    with pytest.raises(ValueError, match="project root"):
        database_path(str(tmp_path / "db.sqlite3"), tmp_path)
