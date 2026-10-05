from scopepilot.sanitize import sanitize_body, sanitize_headers, sanitize_text


def test_headers_and_nested_json_are_minimized():
    headers = sanitize_headers([
        {"name": "Authorization", "value": "Bearer secret"},
        {"name": "X-Trace", "value": "owner@example.test"},
    ])
    body = sanitize_body("prj_test", '{"user_id":42,"password":"bad","nested":{"token":"bad"}}', "application/json")
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["X-Trace"] == "[EMAIL]"
    assert body["password"] == "[REDACTED]"
    assert body["nested"]["token"] == "[REDACTED]"
    assert body["user_id"].startswith("obj_")


def test_pseudonyms_are_stable_within_project_and_different_across_projects():
    first = sanitize_body("one", '{"order_id":"17"}', "application/json")["order_id"]
    second = sanitize_body("one", '{"order_id":"17"}', "application/json")["order_id"]
    third = sanitize_body("two", '{"order_id":"17"}', "application/json")["order_id"]
    assert first == second
    assert first != third


def test_free_text_key_value_secrets_are_removed():
    clean = sanitize_text("password=hunter2&token=abc123 owner@example.test")
    assert "hunter2" not in clean
    assert "abc123" not in clean
    assert "owner@example.test" not in clean
