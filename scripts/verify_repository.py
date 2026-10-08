"""Scan only non-ignored project text with pinned Gitleaks; never scan the host."""
import hashlib
import json
import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from scopepilot.tasks import PINNED, TaskManager, deny_proxy, run_bounded

root = Path(__file__).resolve().parents[1]
binary = root / '.tools' / 'gitleaks' / 'gitleaks.exe'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == PINNED['gitleaks'][1]
paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root).decode().split('\0')
files = sorted(set(name for name in paths if name))
findings = []
with TemporaryDirectory(prefix='repository-audit-', dir=root / 'runtime') as folder:
    work = Path(folder)
    source = work / 'source'
    source.mkdir()
    copied = 0
    for name in files:
        original = (root / name).resolve()
        assert original.is_relative_to(root) and not original.is_symlink()
        if not original.is_file() or original.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.ico'}:
            continue
        assert original.stat().st_size < 2 * 1024**2, 'Unexpected large source file'
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        copied += 1
    config = work / 'gitleaks.toml'
    config.write_text('[extend]\nuseDefault = true\n')
    report = work / 'redacted.json'
    with deny_proxy() as proxy:
        env = TaskManager._environment(work)
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy)
        execution = run_bounded([str(binary), 'dir', str(source), '--config', str(config),
                                 '--report-format', 'json', '--report-path', str(report),
                                 '--redact=100', '--no-banner', '--no-color', '--exit-code', '0',
                                 '--max-target-megabytes', '2', '--timeout', '20'],
                                cwd=work, env=env, cancel=threading.Event(), output_paths=(report,))
    assert execution.status == 'succeeded', execution.status
    with report.open('rb') as handle:
        content = handle.read(262145)
    assert len(content) <= 262144
    for item in json.loads(content):
        path = Path(item['File'])
        if path.is_absolute():
            path = path.relative_to(source)
        findings.append({'file': path.as_posix(), 'line': item['StartLine'], 'rule': item['RuleID']})
result = {'verified_at': datetime.now(timezone.utc).isoformat(), 'scope': 'non-ignored project text only',
          'tool': 'Gitleaks 8.30.1, official binary hash verified, --redact=100',
          'files_scanned': copied, 'matches': findings,
          'note': 'A match requires manual classification; zero matches is not a proof that all secrets are absent.'}
(root / 'docs' / 'repository-review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
