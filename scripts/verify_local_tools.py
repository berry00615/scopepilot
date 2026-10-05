"""Real binaries, built-in synthetic input only; does not claim OS egress isolation."""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from scopepilot.db import Database
from scopepilot.schemas import ProjectCreate, PolicyCreate, ScopeRule
from scopepilot.service import ScopePilotService
from scopepilot.tasks import TaskManager, TERMINAL

root = Path(__file__).resolve().parents[1]
(root / 'runtime').mkdir(exist_ok=True)
results = []
with TemporaryDirectory(prefix='tool-verification-', dir=root / 'runtime') as folder:
    service = ScopePilotService(Database(Path(folder) / 'test.db'))
    now = datetime.now(timezone.utc)
    project = service.create_project(ProjectCreate(name='SYNTHETIC TOOL VERIFICATION', owner='local test', policy=PolicyCreate(
        authorization_reference='self-owned built-in synthetic files; no target requests', status='active',
        valid_from=now-timedelta(minutes=1), valid_until=now+timedelta(hours=1),
        allow=[ScopeRule(scheme='http',host='127.0.0.1',port=3000,path_prefix='/')])))
    manager = TaskManager(service, root, enabled=True)
    try:
        for tool in ('nuclei', 'gitleaks'):
            for scenario in ('positive', 'negative', 'positive'):
                task = manager.start(project['id'], tool, scenario)
                deadline = time.monotonic() + 45
                while task['status'] not in TERMINAL and time.monotonic() < deadline:
                    time.sleep(.1)
                    task = manager.get(project['id'], task['id'])
                task.pop('id')
                task.pop('project_id')
                results.append(task)
                print(tool, scenario, task['status'], task['log'], flush=True)
            first, negative, repeated = results[-3:]
            if all(row['status'] == 'succeeded' for row in (first, negative, repeated)):
                first_result, repeated_result = json.loads(first['result']), json.loads(repeated['result'])
                assert first_result['artifact_id'] == repeated_result['artifact_id']
                assert repeated_result['created'] == 0 and repeated_result['reused'] is True
    finally:
        manager.close()
document = {'verified_at': datetime.now(timezone.utc).isoformat(), 'input': 'built-in synthetic files only',
            'os_network_isolation_verified': False, 'results': results}
(root/'docs'/'tool-verification.json').write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
if any(r['status'] != 'succeeded' for r in results):
    raise SystemExit(1)
