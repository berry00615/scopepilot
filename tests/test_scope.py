from datetime import datetime, timedelta, timezone

from scopepilot.schemas import PolicyCreate, PolicyStatus, ScopeRule
from scopepilot.scope import evaluate_url


def active_policy(**overrides) -> PolicyCreate:
    now = datetime.now(timezone.utc)
    values = dict(
        authorization_reference="self-owned local lab",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        status=PolicyStatus.ACTIVE,
        allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000, path_prefix="/api/")],
        deny=[],
    )
    values.update(overrides)
    return PolicyCreate(**values)


def test_exact_scope_allows_expected_url():
    decision = evaluate_url(active_policy(), "http://127.0.0.1:3000/api/orders?id=1")
    assert decision.allowed is True
    assert decision.normalized_url == "http://127.0.0.1:3000/api/orders"


def test_host_suffix_and_wrong_port_are_rejected():
    policy = active_policy()
    assert not evaluate_url(policy, "http://127.0.0.1.example.test:3000/api/orders").allowed
    assert not evaluate_url(policy, "http://127.0.0.1:3001/api/orders").allowed


def test_deny_wins_and_draft_never_allows():
    denied = ScopeRule(scheme="http", host="127.0.0.1", port=3000, path_prefix="/api/admin")
    policy = active_policy(deny=[denied])
    assert not evaluate_url(policy, "http://127.0.0.1:3000/api/admin/users").allowed
    draft = active_policy(status=PolicyStatus.DRAFT)
    assert not evaluate_url(draft, "http://127.0.0.1:3000/api/orders").allowed


def test_ambiguous_encoded_separator_is_rejected():
    assert not evaluate_url(active_policy(), "http://127.0.0.1:3000/api%2Fadmin").allowed
    assert not evaluate_url(active_policy(), "http://127.0.0.1:3000/api/../admin").allowed


def test_path_prefix_uses_segment_boundary():
    policy = active_policy(allow=[ScopeRule(scheme="http", host="127.0.0.1", port=3000, path_prefix="/api")])
    assert evaluate_url(policy, "http://127.0.0.1:3000/api/orders").allowed
    assert not evaluate_url(policy, "http://127.0.0.1:3000/api-v2/orders").allowed


def test_normalization_preserves_encoded_path_identity():
    policy = active_policy()
    for suffix in ('report%3Fadmin', 'report%23admin', 'hello%20world'):
        decision = evaluate_url(policy, 'http://127.0.0.1:3000/api/' + suffix)
        assert decision.allowed
        assert decision.normalized_url == 'http://127.0.0.1:3000/api/' + suffix
    assert evaluate_url(policy, 'http://127.0.0.1:3000/api/report?admin').normalized_url != (
        evaluate_url(policy, 'http://127.0.0.1:3000/api/report%3Fadmin').normalized_url)


def test_nested_encoding_and_control_characters_cannot_bypass_scope():
    policy = active_policy()
    for suffix in ('%252e%252e/admin', 'orders%252fadmin', 'orders%255cadmin',
                   'orders\\admin', 'orders\nadmin', 'orders\tadmin'):
        assert not evaluate_url(policy, 'http://127.0.0.1:3000/api/' + suffix).allowed


def test_policy_and_target_use_same_path_canonicalization():
    rule = ScopeRule(scheme='http', host='127.0.0.1', port=3000, path_prefix='/api/%61dmin')
    assert rule.path_prefix == '/api/admin'
    policy = active_policy(deny=[rule])
    assert not evaluate_url(policy, 'http://127.0.0.1:3000/api/admin').allowed
    assert not evaluate_url(policy, 'http://127.0.0.1:3000/api/%61dmin').allowed
    assert not evaluate_url(policy, 'http://127.0.0.1:3000/api/%00orders').allowed
    policy = active_policy(allow=[ScopeRule(scheme='http',host='127.0.0.1',port=80,path_prefix='/')])
    assert not evaluate_url(policy, 'http://127.0.0.1:0/api/orders').allowed
