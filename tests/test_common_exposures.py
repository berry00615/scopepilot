"""Synthetic captured responses only: no HTTP servers or target requests."""
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

from scopepilot.db import Database
from scopepilot.har import parse_har
from scopepilot.passive_checks import check_payload
from scopepilot.schemas import PolicyCreate, ProjectCreate, ScopeRule
from scopepilot.service import ScopePilotService


DIRECTORY = '<html><title>Index of /downloads/</title><h1>Index of /downloads/</h1><pre><a href="../">Parent Directory</a><a href="private-person-file.txt">PRIVATE-FILENAME-SENTINEL</a></pre></html>'
GIT = '[core]\nrepositoryformatversion = 0\nfilemode = true\n[remote "origin"]\nurl = https://internal-private-origin.invalid/repository\n'
ENV = 'APP_ENV=production\nDB_HOST=private-internal-host-sentinel\nDB_PASSWORD=opaque-value-not-for-storage\nUNUSUAL_FIELD=another-unrecognized-private-value\n'
KINDS = {"directory_index_review", "git_config_exposure_review", "env_config_exposure_review"}
CASES = [("/downloads/", DIRECTORY, "text/html", "directory_index_review"),
         ("/.git/config", GIT, "text/plain", "git_config_exposure_review"),
         ("/.env", ENV, "text/plain", "env_config_exposure_review")]


def policy():
    now = datetime.now(timezone.utc)
    return PolicyCreate(authorization_reference="self-owned captured synthetic materials", status="active",
                        valid_from=now-timedelta(minutes=1), valid_until=now+timedelta(hours=1),
                        allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000)])


def har(path, body, mime="text/plain", status=200, method="GET", headers=None):
    return json.dumps({"log": {"entries": [{"request": {"url": "http://127.0.0.1:3000"+path, "method": method, "headers": []},
                     "response": {"status": status, "headers": headers or [], "content": {"mimeType": mime, "text": body}}}]}}).encode()


def parse(path, body, mime="text/plain", **kwargs):
    entry = parse_har("p", har(path, body, mime, **kwargs), policy())[0]
    payload = asdict(entry) | {"url": entry.normalized_url}
    candidates = [item for item in check_payload(payload) if item["finding_type"] in KINDS]
    return entry, candidates


@pytest.mark.parametrize("path,body,mime,kind", CASES)
def test_realistic_captured_structure_yields_only_unconfirmed_clues(path, body, mime, kind):
    entry, candidates = parse(path, body, mime)
    assert [item["finding_type"] for item in candidates] == [kind]
    assert candidates[0]["severity"] == ("info" if kind == "directory_index_review" else "unrated")
    assert candidates[0]["category"] == ("hardening" if kind == "directory_index_review" else "vulnerability")
    assert "status" not in candidates[0] and "cvss" not in json.dumps(candidates).lower()
    assert entry.response_body in {"[SENSITIVE_FILE_BODY_OMITTED]", "[DIRECTORY_INDEX_BODY_OMITTED]"}
    serialized = json.dumps(asdict(entry))
    for value in ("PRIVATE-FILENAME-SENTINEL", "private-person-file.txt", "internal-private-origin", "private-internal-host-sentinel", "opaque-value-not-for-storage", "another-unrecognized-private-value"):
        assert value not in serialized


@pytest.mark.parametrize("status", [0, 204, 302, 401, 403, 404, 500])
@pytest.mark.parametrize("path,body,mime,kind", CASES)
def test_non_success_responses_do_not_claim_exposure(path, body, mime, kind, status):
    entry, candidates = parse(path, body, mime, status=status)
    assert candidates == []
    assert "private" not in json.dumps(asdict(entry)).lower()


@pytest.mark.parametrize("path,body,mime,kind", CASES)
def test_head_and_post_do_not_count_as_observed_file_fetch(path, body, mime, kind):
    for method in ("HEAD", "POST"):
        assert parse(path, body, mime, method=method)[1] == []


@pytest.mark.parametrize("path,body,mime", [
    ("/", '<html><title>Home</title><ul><li><a href="about">About</a></li><li><a href="contact">Contact</a></li></ul></html>', "text/html"),
    ("/docs/", '<html><h1>Documentation</h1><pre>Example: Index of /</pre><a href="one">one</a><a href="two">two</a></html>', "text/html"),
    ("/docs/", '<html><h1>Index of /</h1><pre><code>directory listing example</code><a href="one">one</a><a href="two">two</a></pre></html>', "text/html"),
    ("/login", DIRECTORY.replace('</html>', '<form><input type="password"></form></html>'), "text/html"),
    ("/", '<html><h1>Home</h1><!-- <title>Index of /</title> --><pre><a href="one">one</a><a href="two">two</a></pre></html>', "text/html"),
    ("/", '<html><h1>Home</h1><script>const value="Index of /"</script><pre><a href="one">one</a><a href="two">two</a></pre></html>', "text/html"),
    ("/.git/config", '<html><h1>Login</h1><pre>'+GIT+'</pre></html>', "text/html"),
    ("/.env", '<html><title>Not found</title><pre>'+ENV+'</pre></html>', "text/html"),
    ("/.env", 'Documentation example\n```dotenv\n'+ENV+'```', "text/plain"),
    ("/.git/config", 'Example git configuration:\n```ini\n'+GIT+'```', "text/plain"),
    ("/.env.example", ENV, "text/plain"),
    ("/.env.sample", ENV, "text/plain"),
    ("/.env", 'APP_KEY=example\nDB_PASSWORD="changeme"\n', "text/plain"),
    ("/.env", 'APP_NAME=Example\nAPP_ENV=local\n', "text/plain"),
    ("/docs/config.txt", GIT, "text/plain"),
    ("/docs/env.txt", ENV, "text/plain"),
    ("/.git/config", '[unrelated]\nkey = value\n', "text/plain"),
    ("/.env", json.dumps({"example": ENV}), "application/json"),
])
def test_normal_login_documentation_placeholder_and_soft_404_controls(path, body, mime):
    assert parse(path, body, mime)[1] == []


def test_content_type_header_can_reject_env_even_if_har_mime_is_plain():
    assert parse("/.env", ENV, headers=[{"name": "Content-Type", "value": "text/html"}])[1] == []


def test_large_or_unrecognized_sensitive_file_body_is_omitted_without_guessing():
    for path in ("/.env", "/.git/config"):
        entry, candidates = parse(path, "unknown-field-opaque-private-value\n" * 3000)
        assert candidates == [] and entry.response_body == "[SENSITIVE_FILE_BODY_OMITTED]"


def test_python_directory_listing_and_nested_config_paths():
    body = '<html><title>Directory listing for /</title><h1>Directory listing for /</h1><ul><li><a href="one">one</a></li><li><a href="two">two</a></li></ul></html>'
    assert parse("/", body, "text/html")[1][0]["finding_type"] == "directory_index_review"
    assert parse("/app/.git/config", GIT)[1][0]["finding_type"] == "git_config_exposure_review"
    assert parse("/app/.env.production", ENV)[1][0]["finding_type"] == "env_config_exposure_review"


def test_saved_findings_stay_pending_and_evidence_contains_no_new_raw_values(tmp_path):
    service = ScopePilotService(Database(tmp_path / "synthetic.db"))
    project = service.create_project(ProjectCreate(name="Synthetic exposures", owner="local test", policy=policy()))
    pid = project["id"]
    for index, (path, body, mime, _) in enumerate(CASES):
        service.import_har(pid, f"synthetic-{index}.har", har(path, body, mime))
    service.analyze(pid)
    findings = [item for item in service.list_findings(pid) if item["finding_type"] in KINDS]
    assert len(findings) == 3
    assert all(item["status"] == "pending_review" for item in findings)
    stored = json.dumps(service.list_evidence(pid))
    for value in ("PRIVATE-FILENAME-SENTINEL", "private-person-file.txt", "internal-private-origin", "private-internal-host-sentinel", "opaque-value-not-for-storage", "another-unrecognized-private-value"):
        assert value not in stored
    assert service.analyze(pid)["created"] == 0
