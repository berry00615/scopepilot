import os
import asyncio
import hashlib
import json
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from scopepilot.tasks import TaskManager, ProcessResult, HEADER_MATCHERS, OUTPUT_LIMIT, PINNED, TERMINAL, deny_proxy, run_bounded
from scopepilot.service import ValidationError, NotFoundError, ConflictError
from test_workflow import make_service, make_project


def run_case(tmp_path, source, **kwargs):
    # Only this test-created synthetic helper can be executed here.
    helper = tmp_path / 'worker.py'
    helper.write_text(source)
    return run_bounded([sys.executable, str(helper)], cwd=tmp_path, env=dict(os.environ),
                       cancel=kwargs.pop('cancel', threading.Event()), **kwargs)


def test_bounded_success_nonzero_and_missing(tmp_path):
    result = run_case(tmp_path, 'print("synthetic-ok")')
    assert result.status == 'succeeded' and result.exit_code == 0
    assert result.stdout.strip() == b'synthetic-ok'
    result = run_case(tmp_path, 'raise SystemExit(7)')
    assert result.status == 'failed' and result.exit_code == 7
    with pytest.raises(FileNotFoundError):
        run_bounded([str(tmp_path / 'missing.exe')], cwd=tmp_path, env={}, cancel=threading.Event())


def test_timeout_cancel_and_output_limit(tmp_path):
    assert run_case(tmp_path, 'import time; time.sleep(10)', timeout=.3).status == 'timed_out'
    event = threading.Event()
    timer = threading.Timer(.2, event.set)
    timer.start()
    assert run_case(tmp_path, 'import time; time.sleep(10)', cancel=event).status == 'cancelled'
    timer.join()
    result = run_case(tmp_path, 'import sys; sys.stdout.write("X"*1000000)', output_limit=4096)
    assert result.status == 'output_limit' and len(result.stdout) <= 4096


def test_proxy_refuses_every_upstream_without_connecting():
    with deny_proxy() as proxy:
        with httpx.Client(proxy=proxy, timeout=2, trust_env=False) as client:
            assert client.get('http://outside.invalid/redirect').status_code == 403
            assert client.get('http://192.0.2.1/').status_code == 403
            assert client.get('http://127.0.0.1:65534/').status_code == 403
            with pytest.raises(httpx.ProxyError):
                client.get('https://outside.invalid/')


def test_task_cancellation_scope_and_missing_tool(tmp_path):
    service = make_service(tmp_path)
    project = make_project(service)['id']
    other = make_project(service)['id']
    manager = TaskManager(service, tmp_path)
    try:
        with pytest.raises(ValidationError):
            manager.start(project, 'nuclei')
        with pytest.raises(ValidationError):
            manager.start(project, 'arbitrary-shell')
        task = manager.start(project, 'simulation', 'slow')
        with pytest.raises(NotFoundError):
            manager.cancel(other, task['id'])
        manager.cancel(project, task['id'])
        deadline = time.monotonic() + 3
        while manager.get(project, task['id'])['status'] != 'cancelled' and time.monotonic() < deadline:
            time.sleep(.05)
        assert manager.get(project, task['id'])['status'] == 'cancelled'
        assert service.list_findings(project) == []
        manager.enabled = True
        missing = manager.start(project, 'nuclei')
        deadline = time.monotonic() + 3
        while manager.get(project, missing['id'])['status'] not in {'failed'} and time.monotonic() < deadline:
            time.sleep(.05)
        assert manager.get(project, missing['id'])['status'] == 'failed'
        assert '工具缺失' in manager.get(project, missing['id'])['log']
        assert manager.capabilities()['os_network_isolation_verified'] is False
    finally:
        manager.close()


@pytest.mark.parametrize('previous_status', ['queued', 'running', 'cancelling', 'importing'])
def test_restart_does_not_fabricate_success(tmp_path, previous_status):
    service = make_service(tmp_path)
    project = make_project(service)['id']
    manager = TaskManager(service, tmp_path)
    with service.db.connection() as conn:
        conn.execute('INSERT INTO local_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                     ('interrupted-task', project, 'simulation', 'slow', previous_status, 40, '', None, 0, None, 'now', 'now'))
    recovered = TaskManager(service, tmp_path)
    assert recovered.get(project, 'interrupted-task')['status'] == 'interrupted'


def wait_task(manager, pid, task_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        task = manager.get(pid, task_id)
        if task['status'] in TERMINAL:
            return task
        time.sleep(.02)
    raise AssertionError('synthetic task did not finish')


def nuclei_output(cwd, **change):
    rows = [{'template-id': 'http-missing-security-headers', 'type': '',
             'matched-at': str(cwd / 'synthetic-response.txt'),
             'info': {'name': 'HTTP Missing Security Headers', 'severity': 'info'}, 'matcher-name': matcher}
            for matcher in sorted(HEADER_MATCHERS)]
    rows[0].update(change)
    return b'\n'.join(json.dumps(item).encode() for item in rows)


def synthetic_manager(tmp_path, monkeypatch, tool='nuclei'):
    import scopepilot.tasks as tasks_module
    binary = tmp_path / '.tools' / tool / f'{tool}.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'Synthetic marker; this file is never executed')
    monkeypatch.setitem(PINNED, tool, ('test-version', hashlib.sha256(binary.read_bytes()).hexdigest()))

    def fake_run(argv, *, cwd, **kwargs):
        content = nuclei_output(cwd, timestamp=time.monotonic())
        return ProcessResult('succeeded', 0, content, len(content))

    monkeypatch.setattr(tasks_module, 'run_bounded', fake_run)
    service = make_service(tmp_path)
    pid = make_project(service)['id']
    return TaskManager(service, tmp_path, enabled=True), service, pid


def test_repeated_tool_task_reuses_existing_import(tmp_path, monkeypatch):
    manager, service, pid = synthetic_manager(tmp_path, monkeypatch)
    try:
        first = wait_task(manager, pid, manager.start(pid, 'nuclei')['id'])
        second = wait_task(manager, pid, manager.start(pid, 'nuclei')['id'])
        assert first['status'] == second['status'] == 'succeeded'
        first_result, second_result = json.loads(first['result']), json.loads(second['result'])
        assert first_result['artifact_id'] == second_result['artifact_id']
        assert second_result['created'] == 0 and second_result['reused'] is True
        assert len(service.list_artifacts(pid)) == 1
        assert len(service.list_findings(pid)) == 1
        assert len(service.list_evidence(pid)) == len(HEADER_MATCHERS)
    finally:
        manager.close()


def test_cancel_accepted_during_result_parsing_prevents_commit(tmp_path, monkeypatch):
    manager, service, pid = synthetic_manager(tmp_path, monkeypatch)
    entered, resume = threading.Event(), threading.Event()
    normalize = manager._normalize_results

    def paused_normalize(*args):
        result = normalize(*args)
        entered.set()
        assert resume.wait(3)
        return result

    monkeypatch.setattr(manager, '_normalize_results', paused_normalize)
    try:
        task = manager.start(pid, 'nuclei')
        assert entered.wait(3)
        cancelled = manager.cancel(pid, task['id'])
        assert cancelled['cancel_accepted'] is True and cancelled['status'] == 'cancelling'
        resume.set()
        assert wait_task(manager, pid, task['id'])['status'] == 'cancelled'
        assert service.list_artifacts(pid) == [] and service.list_findings(pid) == []
    finally:
        resume.set()
        manager.close()


def test_cancel_after_commit_boundary_returns_explicit_conflict(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import scopepilot.api as api
    manager, service, pid = synthetic_manager(tmp_path, monkeypatch)
    entered, resume = threading.Event(), threading.Event()
    import_results = service.import_tool_results

    def paused_import(*args, **kwargs):
        entered.set()
        assert resume.wait(3)
        return import_results(*args, **kwargs)

    monkeypatch.setattr(service, 'import_tool_results', paused_import)
    monkeypatch.setattr(api, 'service', service)
    monkeypatch.setattr(api, '_task_manager', manager)
    try:
        task = manager.start(pid, 'nuclei')
        assert entered.wait(3)
        with pytest.raises(ConflictError, match='原子结果提交'):
            manager.cancel(pid, task['id'])
        response = TestClient(api.app).post(f"/projects/{pid}/tasks/{task['id']}/cancel")
        assert response.status_code == 409 and '原子结果提交' in response.text
        assert manager.get(pid, task['id'])['status'] == 'importing'
        resume.set()
        assert wait_task(manager, pid, task['id'])['status'] == 'succeeded'
        assert len(service.list_findings(pid)) == 1
    finally:
        resume.set()
        manager.close()


def test_file_output_and_streams_share_one_budget(tmp_path):
    result_path = tmp_path / 'result.json'
    result = run_case(tmp_path, "from pathlib import Path\nimport sys\nPath('result.json').write_bytes(b'X'*4096)\nsys.stdout.write('Y'*2048)",
                      output_limit=5000, output_paths=(result_path,))
    assert result.status == 'output_limit'
    assert result.output_bytes > 5000


def test_fast_file_output_is_checked_after_process_exit(tmp_path):
    result_path = tmp_path / 'result.json'
    result = run_case(tmp_path, "from pathlib import Path\nimport os\nPath('result.json').write_bytes(b'X'*4097)\nos._exit(0)",
                      output_limit=4096, output_paths=(result_path,))
    assert result.status == 'output_limit' and result.output_bytes == 4097


def test_file_growth_after_runner_check_never_uses_unbounded_read(tmp_path, monkeypatch):
    import scopepilot.tasks as tasks_module
    manager, service, pid = synthetic_manager(tmp_path, monkeypatch, tool='gitleaks')

    def fake_run(argv, **kwargs):
        Path(argv[argv.index('--report-path') + 1]).write_bytes(b'X' * (OUTPUT_LIMIT + 1))
        return ProcessResult('succeeded', 0, b'', 0)

    read_bytes = Path.read_bytes

    def forbid_report_read(path):
        assert path.name != 'result.json', 'result files must be read with a size bound'
        return read_bytes(path)

    monkeypatch.setattr(tasks_module, 'run_bounded', fake_run)
    monkeypatch.setattr(Path, 'read_bytes', forbid_report_read)
    try:
        result = wait_task(manager, pid, manager.start(pid, 'gitleaks')['id'])
        assert result['status'] == 'output_limit'
        assert service.list_artifacts(pid) == []
    finally:
        manager.close()


@pytest.mark.parametrize('change', [
    {'matched-at': 'https://outside.example.test/'}, {'host': 'https://outside.example.test/'},
    {'type': 'http'}, {'type': 'offline-http'}, {'template-id': 'unexpected-template'}, {'matcher-name': 'unknown-matcher'},
])
def test_unexpected_nuclei_provenance_is_rejected_before_mapping(tmp_path, change):
    with pytest.raises(ValidationError):
        TaskManager._normalize_results('nuclei', nuclei_output(tmp_path, **change), tmp_path, 'positive')


def test_incomplete_positive_nuclei_matchers_do_not_pass(tmp_path):
    partial = nuclei_output(tmp_path).splitlines()[0]
    with pytest.raises(ValidationError, match='未完整命中'):
        TaskManager._normalize_results('nuclei', partial, tmp_path, 'positive')


def test_api_task_manager_initializes_once_under_concurrent_requests(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import scopepilot.api as api
    created = []

    class FakeManager:
        def __init__(self, service, root, enabled):
            time.sleep(.025)
            self.service = service
            created.append(self)

    monkeypatch.setattr(api, '_task_manager', None)
    monkeypatch.setattr(api, 'TaskManager', FakeManager)
    barrier = threading.Barrier(8)

    def request():
        barrier.wait()
        return api.tasks()

    with ThreadPoolExecutor(max_workers=8) as pool:
        managers = list(pool.map(lambda _: request(), range(8)))
    assert len(created) == 1
    assert all(manager is created[0] for manager in managers)


@pytest.mark.parametrize('declared', [None, b'5', b'1000'])
def test_oversized_request_is_rejected_before_downstream_parser(declared):
    from scopepilot.api import BoundedRequestBodyMiddleware
    called, sent = [], []

    async def parser(*args):
        called.append(True)

    messages = iter([{'type': 'http.request', 'body': b'A' * 20, 'more_body': True},
                     {'type': 'http.request', 'body': b'B' * 20, 'more_body': False}])

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    scope = {'type': 'http', 'method': 'POST', 'headers': [] if declared is None else [(b'content-length', declared)]}
    asyncio.run(BoundedRequestBodyMiddleware(parser, 32)(scope, receive, send))
    assert called == []
    assert sent[0]['status'] == 413


def test_valid_multipart_still_reaches_endpoint_under_receive_limit():
    from fastapi import FastAPI, File, UploadFile
    from fastapi.testclient import TestClient
    from scopepilot.api import BoundedRequestBodyMiddleware
    app = FastAPI()
    app.add_middleware(BoundedRequestBodyMiddleware, max_body=1024)

    @app.post('/upload')
    async def upload(file: UploadFile = File(...)):
        try:
            return {'size': len(await file.read())}
        finally:
            await file.close()

    with TestClient(app) as client:
        response = client.post('/upload', files={'file': ('synthetic.txt', b'synthetic', 'text/plain')})
        assert response.status_code == 200 and response.json() == {'size': 9}
