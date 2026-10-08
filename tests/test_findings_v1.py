"""Synthetic regression coverage for attribution, review gates and database upgrades."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scopepilot.db import Database
from scopepilot.schemas import ModelFinding, PolicyCreate, ProjectCreate, ReviewCreate, ScopeRule
from scopepilot.service import NotFoundError, ScopePilotService, ValidationError


def project(service, *, name="Synthetic lab"):
    now = datetime.now(timezone.utc)
    return service.create_project(ProjectCreate(name=name, owner="researcher", policy=PolicyCreate(
        authorization_reference="self-owned synthetic records", valid_from=now-timedelta(minutes=1),
        valid_until=now+timedelta(days=1), status="active", allow=[
            ScopeRule(scheme=scheme, host=host, port=port)
            for scheme, host, port in (("http", "127.0.0.1", 3000), ("http", "localhost", 3000),
                                       ("http", "127.0.0.1", 3001), ("https", "127.0.0.1", 3000))
        ])))['id']


@pytest.fixture
def lab(tmp_path):
    service = ScopePilotService(Database(tmp_path / "findings.db"))
    return service, project(service)


def har(urls, marker="first", statuses=None):
    entries = []
    for index, url in enumerate(urls):
        entries.append({"request": {"method": "GET", "url": url, "headers": [{"name": "X-Synthetic", "value": marker}]},
                        "response": {"status": (statuses or [200] * len(urls))[index], "content": {
                            "mimeType": "application/json", "text": '{"owner":"self-owned-a"}'}}})
    return json.dumps({"log": {"entries": entries}}).encode()


def object_finding(service, project_id):
    service.import_har(project_id, "object.har", har(["http://127.0.0.1:3000/orders?orderId=owned-a"]))
    service.analyze(project_id)
    return next(item for item in service.list_findings(project_id) if item['finding_type'] == 'object_authorization_review')


def confirmation(finding, **overrides):
    data = dict(status="confirmed", reviewer="synthetic reviewer", actual_result="Non-owner B read A's self-owned object.",
                tested_identity="self-owned-b", tested_object="self-owned-a", stop_reason="one synthetic comparison completed",
                success_criteria="Non-owner B reads owner A's object despite expected rejection.", criteria_met=True,
                evidence_refs=finding["evidence_refs"], control_required=True,
                control_result="Owner A baseline succeeds; unauthenticated control is denied; B incorrectly succeeds.",
                control_passed=True, severity="medium", severity_reason="Synthetic impact limited to one self-owned object.")
    return ReviewCreate(**(data | overrides))


def test_target_identity_preserves_protocol_host_and_port(lab):
    service, pid = lab
    urls = ["http://127.0.0.1:3000/orders?id=1", "http://localhost:3000/orders?id=1",
            "http://127.0.0.1:3001/orders?id=1", "https://127.0.0.1:3000/orders?id=1"]
    service.import_har(pid, "targets.har", har(urls))
    endpoints = service.list_endpoints(pid)
    assert len(endpoints) == 4
    assert {(e['scheme'], e['host'], e['port']) for e in endpoints} == {
        ('http', '127.0.0.1', 3000), ('http', 'localhost', 3000),
        ('http', '127.0.0.1', 3001), ('https', '127.0.0.1', 3000)}
    service.analyze(pid)
    assert len([f for f in service.list_findings(pid) if f['finding_type'] == 'object_authorization_review']) == 4


def test_repeated_import_merges_evidence_but_not_projects(lab):
    service, pid = lab
    first = object_finding(service, pid)
    service.import_har(pid, "second.har", har(["http://127.0.0.1:3000/orders?orderId=owned-b"], "second"))
    assert service.analyze(pid)['created'] == 0
    detail = service.get_finding(pid, first['id'])
    assert len(detail['evidence']) == 2
    assert len(detail['sources']) == 1
    assert len(detail['sources'][0]['evidence_refs']) == 2
    other = project(service)
    other_finding = object_finding(service, other)
    assert other_finding['id'] != first['id']
    with pytest.raises(NotFoundError):
        service.get_finding(other, first['id'])


@pytest.mark.parametrize("overrides", [
    {"success_criteria": ""}, {"criteria_met": False}, {"evidence_refs": []},
    {"control_result": ""}, {"control_passed": False}, {"control_passed": None, "control_required": False},
])
def test_failed_or_incomplete_verification_cannot_confirm(lab, overrides):
    service, pid = lab
    finding = object_finding(service, pid)
    with pytest.raises(ValidationError, match="success criterion"):
        service.review_finding(pid, finding['id'], confirmation(finding, **overrides))
    assert service.get_finding(pid, finding['id'])['status'] == 'pending_review'
    assert service.get_finding(pid, finding['id'])['reviews'] == []
    with pytest.raises(ValidationError, match="no human-confirmed"):
        service.report_markdown(pid)


def test_denied_non_owner_result_is_rejected_and_excluded_from_report(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    service.review_finding(pid, finding['id'], confirmation(
        finding, status="rejected", actual_result="B cannot access A's object: HTTP 403 as expected.", criteria_met=False,
        severity="info", severity_reason="The expected authorization boundary was enforced."))
    assert service.get_finding(pid, finding['id'])['status'] == 'rejected'
    with pytest.raises(ValidationError, match="no human-confirmed"):
        service.report_markdown(pid)


def test_cross_project_review_evidence_fails_atomically(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    other = project(service)
    foreign = object_finding(service, other)
    with pytest.raises(ValidationError, match="cross-project"):
        service.review_finding(pid, finding['id'], confirmation(finding, evidence_refs=foreign['evidence_refs']))
    assert service.get_finding(pid, finding['id'])['reviews'] == []


def test_reviewed_rating_keeps_original_and_filters(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    service.review_finding(pid, finding['id'], confirmation(finding))
    detail = service.get_finding(pid, finding['id'])
    assert detail['rating']['original'] == 'unrated'
    assert detail['rating']['current'] == detail['rating']['reviewed'] == 'medium'
    assert detail['rating']['original_reason'] != detail['rating']['reviewed_reason']
    assert {s['source_kind'] for s in detail['sources']} == {'rule', 'human'}
    assert len(service.list_findings(pid, status='confirmed', severity='medium', category='vulnerability', source='human', q='orders')) == 1
    assert service.list_findings(pid)[0]['rating']['reviewed'] == 'medium'
    assert service.list_findings(pid, source='tool') == []
    with pytest.raises(ValidationError, match="rating reason"):
        service.review_finding(pid, finding['id'], confirmation(finding, severity_reason=''))


def test_equivalent_model_and_rule_findings_preserve_both_sources(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    output = ModelFinding(finding_type=finding['finding_type'], claim='Model repeats the same object authorization hypothesis.',
                          evidence_refs=finding['evidence_refs'], missing_information='Need actual behavior.',
                          suggested_manual_check='Compare self-owned accounts.', confidence=0.5)
    created = service._store_model_findings(pid, 1, [output], set(finding['evidence_refs']), 'synthetic-model-v1')
    assert created == []
    detail = service.get_finding(pid, finding['id'])
    assert {source['source_kind'] for source in detail['sources']} == {'rule', 'model'}
    assert len(detail['evidence']) == 1
    assert detail['severity'] == 'unrated'


def test_report_sanitizes_all_free_text_including_legacy_content(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    secret_text = ' token=report-secret email@example.test {"password":"json-secret"} '
    service.review_finding(pid, finding['id'], confirmation(
        finding, reviewer=secret_text, actual_result=secret_text, tested_identity=secret_text, tested_object=secret_text,
        stop_reason=secret_text, success_criteria=secret_text, control_result=secret_text, severity_reason=secret_text))
    # Simulate pre-upgrade text that bypassed sanitization on write.
    with service.db.connection() as conn:
        conn.execute('UPDATE projects SET name=? WHERE id=?', (secret_text, pid))
        conn.execute('UPDATE findings SET claim=?,remediation=? WHERE id=?', (secret_text, secret_text, finding['id']))
        policy_row = conn.execute('SELECT document FROM policies WHERE project_id=?', (pid,)).fetchone()
        policy_data = json.loads(policy_row['document'])
        policy_data['authorization_reference'] = secret_text
        conn.execute('UPDATE policies SET document=? WHERE project_id=?', (json.dumps(policy_data), pid))
        conn.execute('UPDATE evidence SET locator=? WHERE project_id=?', (secret_text, pid))
        conn.execute('UPDATE artifacts SET filename=? WHERE project_id=?', (secret_text, pid))
        conn.execute('UPDATE findings SET target=? WHERE id=?', ('http://127.0.0.1:3000/users/legacy-private-object', finding['id']))
    report = service.report_markdown(pid)
    for secret in ('report-secret', 'email@example.test', 'json-secret', 'legacy-private-object'):
        assert secret not in report
    assert '[REDACTED]' in report


def test_delete_one_artifact_retains_other_evidence_and_revokes_confirmation(lab):
    service, pid = lab
    finding = object_finding(service, pid)
    first_artifact = service.list_artifacts(pid)[0]['id']
    service.import_har(pid, 'second.har', har(['http://127.0.0.1:3000/orders?orderId=owned-b'], 'second'))
    service.analyze(pid)
    finding = service.get_finding(pid, finding['id'])
    service.review_finding(pid, finding['id'], confirmation(finding))
    result = service.delete_artifact(pid, first_artifact)
    assert result['deleted_findings'] == 0
    detail = service.get_finding(pid, finding['id'])
    assert detail['status'] == 'needs_evidence'
    assert len(detail['evidence']) == 1
    assert all(len(source['evidence_refs']) == 1 for source in detail['sources'])
    assert len(service.list_endpoints(pid)) == 1
    with pytest.raises(ValidationError, match='no human-confirmed'):
        service.report_markdown(pid)


def nuclei_record(url='http://127.0.0.1:3000/status', title='Synthetic template'):
    return {'template-id': 'synthetic-rule', 'info': {'name': title, 'severity': 'high'},
            'type': 'http', 'matched-at': url}


def test_report_separates_confirmed_hardening_from_vulnerabilities(lab):
    service, pid = lab
    hardening = nuclei_record(title='Synthetic header observation')
    hardening['template-id'] = 'http-missing-security-headers'
    service.import_tool_results(pid, 'nuclei', 'headers.json', json.dumps(hardening).encode(), '3.11.1')
    clue = object_finding(service, pid)
    for finding in service.list_findings(pid):
        service.review_finding(pid, finding['id'], confirmation(finding))
    report = service.report_markdown(pid)
    assert '## 已确认漏洞' in report and '## 配置加固（独立列示，不计为已确认漏洞）' in report
    vulnerability_section, hardening_section = report.split('## 配置加固（独立列示，不计为已确认漏洞）')
    assert clue['claim'] in vulnerability_section
    assert 'Synthetic header observation' not in vulnerability_section
    assert 'Synthetic header observation' in hardening_section


def test_tool_version_sources_and_merged_evidence_are_retained(lab):
    service, pid = lab
    first = service.import_tool_results(pid, 'nuclei', 'one.json', json.dumps(nuclei_record()).encode(), '3.11.1')
    second = service.import_tool_results(pid, 'nuclei', 'two.json', json.dumps(nuclei_record(title='Second observation')).encode(), '3.11.2')
    assert first['created'] == 1 and second['created'] == 0
    detail = service.get_finding(pid, first['finding_ids'][0])
    assert len(detail['evidence']) == 2
    assert {source['version'] for source in detail['sources']} == {'3.11.1', '3.11.2'}
    assert detail['severity'] == 'unrated'
    assert detail['original_severity'] == 'high'
    assert detail['status'] == 'pending_review'
    assert detail['original_severity_reason'] != detail['severity_reason']


def test_out_of_scope_tool_import_is_atomic(lab):
    service, pid = lab
    content = json.dumps([nuclei_record(), nuclei_record('https://outside.example.test/admin')]).encode()
    with pytest.raises(ValidationError, match='scope'):
        service.import_tool_results(pid, 'nuclei', 'mixed.json', content, '3.11.1')
    assert service.list_artifacts(pid) == []
    assert service.list_evidence(pid) == []
    assert service.list_findings(pid) == []


def test_source_line_locations_do_not_collapse(lab):
    service, pid = lab
    records = [{'RuleID': 'generic-api-key', 'Description': 'Synthetic secret', 'File': 'src/settings.py',
                'StartLine': line, 'EndLine': line, 'Secret': 'EXAMPLE_PLACEHOLDER', 'Match': 'token=EXAMPLE_PLACEHOLDER'}
               for line in (3, 9)]
    result = service.import_tool_results(pid, 'gitleaks', 'source.json', json.dumps(records).encode(), '8.30.1')
    assert result['created'] == 2
    assert len({f['dedup_key'] for f in service.list_findings(pid)}) == 2
    assert service.list_endpoints(pid) == []


def test_legacy_database_upgrade_recovers_hosts_and_demotes_unqualified_confirmation(tmp_path):
    path = tmp_path / 'legacy.db'
    conn = sqlite3.connect(path)
    conn.executescript('''
      CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT NOT NULL,owner TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE artifacts(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,filename TEXT NOT NULL,sha256 TEXT NOT NULL,status TEXT NOT NULL,accepted_entries INTEGER NOT NULL,rejected_entries INTEGER NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE evidence(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,artifact_id TEXT NOT NULL,locator TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE endpoints(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,evidence_id TEXT NOT NULL,UNIQUE(project_id,method,path));
      CREATE TABLE findings(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,finding_type TEXT NOT NULL,claim TEXT NOT NULL,evidence_refs TEXT NOT NULL,missing_information TEXT NOT NULL,suggested_manual_check TEXT NOT NULL,confidence REAL NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE reviews(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,finding_id TEXT NOT NULL,status TEXT NOT NULL,reviewer TEXT NOT NULL,actual_result TEXT NOT NULL,tested_identity TEXT NOT NULL,tested_object TEXT NOT NULL,stop_reason TEXT NOT NULL,policy_version INTEGER NOT NULL,created_at TEXT NOT NULL);
      INSERT INTO projects VALUES('p','legacy','owner','2026-10-05');
      INSERT INTO artifacts VALUES('a','p','legacy.har','digest','accepted',2,0,'2026-10-05');
      INSERT INTO endpoints VALUES('ep','p','GET','/same','e1');
      INSERT INTO findings VALUES('f','p','object_authorization_review','Legacy hypothesis','["e1"]','missing','check',0.4,'confirmed','2026-10-05');
      INSERT INTO reviews VALUES('r','p','f','confirmed','old','B was denied','B','A','done',1,'2026-10-05');
    ''')
    for evidence_id, host in [('e1', '127.0.0.1'), ('e2', 'localhost')]:
        conn.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)', (evidence_id, 'p', 'a', 'HAR', 'http_exchange',
            json.dumps({'url': f'http://{host}:3000/same', 'method': 'GET', 'path': '/same'}), '2026-10-05'))
    conn.commit()
    conn.close()
    db = Database(path)
    Database(path)  # Reopening must not duplicate migrated data or fail.
    with db.connection() as conn:
        assert conn.execute('SELECT count(*) FROM endpoints').fetchone()[0] == 2
        row = conn.execute('SELECT * FROM findings').fetchone()
        assert row['target'] == 'http://127.0.0.1:3000/same'
        assert row['status'] == 'needs_evidence'
        assert row['severity'] == 'unrated'
        assert conn.execute('SELECT count(*) FROM finding_sources').fetchone()[0] == 1
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
