import base64
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

from scopepilot.adapters import parse_tool_results
from scopepilot.har import HarError, parse_har
from scopepilot.passive_checks import check_payload
from scopepilot.sanitize import load_json_limited, sanitize_body, sanitize_text, sanitize_url, target_identity
from scopepilot.schemas import PolicyCreate, ScopeRule


@pytest.fixture
def policy():
    now = datetime.now(timezone.utc)
    return PolicyCreate(authorization_reference="self-owned synthetic material", valid_from=now - timedelta(hours=1), valid_until=now + timedelta(hours=1), status="active", allow=[ScopeRule(scheme="https", host="lab.example.test", port=443, path_prefix="/")])


def har_bytes(url="https://lab.example.test/api/orders/123?orderId=123&token=NEVER-STORE-TOKEN", *, response=None, request=None):
    req = {"method": "GET", "url": url, "headers": []}
    req.update(request or {})
    return json.dumps({"log": {"entries": [{"request": req, "response": response or {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}}}]}}).encode()


def nuclei_row(**overrides):
    row = {"template-id": "test-exposure", "info": {"name": "Synthetic exposure", "severity": "high"}, "type": "http", "matched-at": "https://lab.example.test/api/orders/123?token=NEVER-STORE-TOKEN"}
    row.update(overrides)
    return row


def gitleaks_row(**overrides):
    row = {"RuleID": "generic-api-key", "Description": "Synthetic", "File": "src/config.py", "StartLine": 12, "EndLine": 12, "Secret": "NEVER-STORE-CREDENTIAL", "Match": 'token="NEVER-STORE-CREDENTIAL"'}
    row.update(overrides)
    return row


def test_har_keeps_origin_and_pseudonymizes_objects(policy):
    one = parse_har("project-a", har_bytes(), policy)[0]
    two = parse_har("project-a", har_bytes("https://lab.example.test/api/orders/456?orderId=456"), policy)[0]
    assert one.normalized_url.startswith("https://lab.example.test:443/api/orders/obj_")
    assert one.query["token"] == "[REDACTED]"
    assert one.query["orderId"].startswith("obj_")
    assert target_identity(one.normalized_url) == target_identity(two.normalized_url)
    assert "NEVER-STORE" not in json.dumps(asdict(one))
    assert target_identity(one.normalized_url) != target_identity(one.normalized_url.replace(":443", ":8443"))


def test_har_headers_cookie_attributes_and_no_values(policy):
    entry = parse_har("p", har_bytes(response={"status": 200, "headers": [
        {"name": "Set-Cookie", "value": "session=NEVER-STORE-COOKIE; HttpOnly; SameSite=None; Path=/"},
        {"name": "Set-Cookie", "value": "theme=NEVER-STORE-THEME; Secure; SameSite=Lax"},
        {"name": "Content-Type", "value": "text/html"},
    ], "content": {"text": "<html>synthetic</html>", "mimeType": "text/html"}}), policy)[0]
    assert entry.response_headers["Set-Cookie"] == "[REDACTED]"
    assert entry.response_cookies[0]["httpOnly"] is True
    assert entry.response_cookies[0]["secure"] is False
    assert entry.response_cookies[0]["sameSite"] == "none"
    serialized = json.dumps(asdict(entry))
    assert "NEVER-STORE" not in serialized
    payload = asdict(entry) | {"url": entry.normalized_url}
    checks = {item["finding_type"]: item for item in check_payload(payload)}
    assert {"cookie_missing_secure", "cookie_missing_httponly", "cookie_samesite_none_without_secure", "missing_content_security_policy", "missing_hsts", "object_authorization_review"} <= checks.keys()
    assert all("cvss" not in item and "status" not in item for item in checks.values())


@pytest.mark.parametrize("document", [[], {"log": []}, {"log": {"entries": {}}}, {"log": {"entries": [None]}}, {"log": {"entries": [{"request": []}]}}, {"log": {"entries": [{"request": {"method": "GET", "url": 42}}]}}])
def test_har_rejects_wrong_shapes(policy, document):
    with pytest.raises(HarError):
        parse_har("p", json.dumps(document).encode(), policy)


@pytest.mark.parametrize("bad_response", [{"status": True}, {"status": 1000}, {"headers": ["not-header"]}, {"headers": [{"name": "bad\nheader", "value": "x"}]}, {"content": {"text": []}}, {"cookies": [{"name": "id", "secure": "false"}]}])
def test_har_rejects_bad_nested_fields(policy, bad_response):
    with pytest.raises(HarError):
        parse_har("p", har_bytes(response=bad_response), policy)


def test_har_rejects_limits_and_json_ambiguity(policy):
    with pytest.raises(HarError):
        parse_har("p", b" " * (10 * 1024 * 1024 + 1), policy)
    for text in ('{"log":{},"log":{}}', "[" * 40 + "0" + "]" * 40, '{"x":NaN}'):
        with pytest.raises(ValueError):
            load_json_limited(text)
    with pytest.raises(HarError):
        parse_har("p", har_bytes("https://lab.example.test/?" + "&".join(f"k{i}=x" for i in range(501))), policy)


def test_response_base64_is_sanitized_and_signals_survive(policy):
    body = '{"password":"NEVER-STORE-PASSWORD","error":"Traceback (most recent call last):"}'
    entry = parse_har("p", har_bytes(response={"status": 500, "content": {"text": base64.b64encode(body.encode()).decode(), "encoding": "base64", "mimeType": "application/json"}}), policy)[0]
    assert "NEVER-STORE" not in json.dumps(asdict(entry))
    assert {"debug_error_detail", "suspected_sensitive_content"} <= set(entry.signals)


def test_passive_rules_do_not_mislabel_cors_or_basic_object_ids():
    rows = check_payload({"query": {"orderId": "obj_abc"}, "response_headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}})
    rows = {item["finding_type"]: item for item in rows}
    assert rows["object_authorization_review"]["severity"] == "unrated"
    assert rows["cors_wildcard_credentials"]["category"] == "hardening"
    assert "阻止" in rows["cors_wildcard_credentials"]["claim"]
    assert check_payload({"response_status": 200, "response_body": {"normal": "json"}}) == []


def test_sanitizer_report_and_body_forms():
    text = '''{"password":"SECRET-ONE", "api_key": "SECRET-TWO"}
Authorization: Basic U0VDUkVU
Cookie: sid=SECRET-THREE; preference=SECRET-FOUR
https://alice:SECRET-FIVE@lab.example.test/?token=SECRET-SIX'''
    assert "SECRET-" not in sanitize_text(text)
    assert "U0VDUkVU" not in sanitize_text(text)
    assert sanitize_body("p", "password=SECRET-SEVEN&orderId=123", "application/x-www-form-urlencoded")["password"] == "[REDACTED]"
    assert "SECRET" not in sanitize_url("p", "https://a:SECRET@lab.example.test:8443/token/SECRET?id=123&token=SECRET", include_query=True)


def test_gitleaks_whitelist_and_sample_distinction(policy):
    rows = parse_tool_results("gitleaks", json.dumps([gitleaks_row(Description="NEVER-STORE-CREDENTIAL"), gitleaks_row(Secret="your_api_key_here", File="tests/example.py")]), "p", policy, "8.30.1")
    assert rows[0]["target"] == "source://source/src/config.py"
    assert rows[0]["locator"] == "src/config.py:12"
    assert rows[0]["hint_kind"] == "suspected_credential"
    assert rows[0]["severity"] == "unrated"
    assert rows[1]["hint_kind"] == "example"
    assert rows[1]["severity"] == "info"
    assert "NEVER-STORE" not in json.dumps(rows)
    assert "your_api_key_here" not in json.dumps(rows)


@pytest.mark.parametrize("path", ["../secret.txt", "a/../../secret", "C:\\users\\secret.txt", "/etc/passwd", "\\\\host\\share\\x", "a/%2e%2e/b", "a/%252e%252e/b", "a//b"])
def test_gitleaks_rejects_unsafe_paths(policy, path):
    with pytest.raises(ValueError):
        parse_tool_results("gitleaks", json.dumps([gitleaks_row(File=path)]), "p", policy, "8.30.1")


def test_nuclei_json_jsonl_and_original_rating(policy):
    record = nuclei_row(request="GET / HTTP/1.1\r\nAuthorization: Bearer NEVER-STORE-REQUEST", response="NEVER-STORE-RESPONSE", **{"extracted-results": ["NEVER-STORE-EXTRACTED"]})
    for content in (json.dumps(record), json.dumps([record]), json.dumps(record) + "\n" + json.dumps(record)):
        rows = parse_tool_results("nuclei", content, "p", policy, "3.11.1")
        assert rows[0]["target"].startswith("https://lab.example.test:443/")
        assert rows[0]["original_severity"] == "high"
        assert rows[0]["severity"] == "unrated"
        assert "NEVER-STORE" not in json.dumps(rows)


@pytest.mark.parametrize("record", [nuclei_row(type="dns"), nuclei_row(**{"matched-at": "https://outside.example.test/"}), nuclei_row(info={"name": "x", "severity": "extreme"}), nuclei_row(info=[]), nuclei_row(**{"extracted-results": {"secret": "x"}}), nuclei_row(host="https://outside.example.test/")])
def test_nuclei_rejects_unsupported_or_scope_bypass(policy, record):
    with pytest.raises(ValueError):
        parse_tool_results("nuclei", json.dumps([nuclei_row(), record]), "p", policy, "3.11.1")


def test_result_json_requires_exact_structure(policy):
    for tool, content in (("gitleaks", "{}"), ("gitleaks", "[null]"), ("nuclei", "[[]]"), ("nuclei", '{"info":{},"info":{}}')):
        with pytest.raises(ValueError):
            parse_tool_results(tool, content, "p", policy, "1.0")


def test_encoded_path_identity_and_form_params_are_preserved(policy):
    entry = parse_har("p", har_bytes("https://lab.example.test/api/a%3Fb%23c", request={"postData": {"mimeType": "application/x-www-form-urlencoded", "params": [{"name": "orderId", "value": "123"}, {"name": "password", "value": "NEVER-STORE"}]}}), policy)[0]
    assert entry.normalized_url == "https://lab.example.test:443/api/a%3Fb%23c"
    assert entry.request_body["orderId"].startswith("obj_")
    assert "NEVER-STORE" not in json.dumps(asdict(entry))


def test_free_text_quoted_cookie_and_encoded_query_are_redacted():
    for text in ('{"cookie": "sid=NEVER-STORE"}', 'https://lab.example.test/?%74oken=NEVER-STORE', 'https://lab.example.test/?api%5Fkey=NEVER-STORE', 'https://lab.example.test/?code=NEVER-STORE', '{"access_key":"NEVER-STORE"}'):
        assert "NEVER-STORE" not in sanitize_text(text)
    text = "Review https://lab.example.test:8443/users/alice?email=owner@example.test and https://lab.example.test/orders/12345"
    clean = sanitize_text(text)
    assert "https://lab.example.test:8443/users/obj_" in clean
    assert "alice" not in clean and "12345" not in clean and "owner" not in clean


@pytest.mark.parametrize('hidden', ['REDACTED', '[REDACTED]', '<redacted>', '********', ''])
def test_redacted_gitleaks_secret_is_not_mistaken_for_safe_example(policy, hidden):
    row = parse_tool_results('gitleaks', json.dumps([gitleaks_row(Secret=hidden)]), 'p', policy, '8.30.1')[0]
    assert row['hint_kind'] == 'suspected_credential'
    assert row['category'] == 'vulnerability'
    assert row['severity'] == 'unrated'


def test_nuclei_preserves_request_method_or_marks_unknown(policy):
    row = parse_tool_results("nuclei", json.dumps(nuclei_row(request="POST / HTTP/1.1\r\nCookie: NEVER-STORE")), "p", policy, "3.11.1")[0]
    assert row["method"] == "POST"
    unknown = parse_tool_results("nuclei", json.dumps(nuclei_row()), "p", policy, "3.11.1")[0]
    assert unknown["method"] == "HTTP"


def test_har_sanitized_origin_still_matches_cors_origin(policy):
    entry = parse_har("p", har_bytes(request={"headers": [{"name": "Origin", "value": "https://owned-origin.example.test"}]}, response={"status": 200, "headers": [
        {"name": "Access-Control-Allow-Origin", "value": "https://owned-origin.example.test"},
        {"name": "Access-Control-Allow-Credentials", "value": "true"},
    ]}), policy)[0]
    kinds = {row["finding_type"] for row in check_payload(asdict(entry) | {"url": entry.normalized_url})}
    assert "cors_origin_review" in kinds
