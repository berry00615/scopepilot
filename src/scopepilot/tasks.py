"""Bounded local task lifecycle. No caller-supplied command, URL, or template.

Real tools only process built-in synthetic files. This is deliberately not an OS
network sandbox: capabilities explicitly report that limitation.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from .service import ScopePilotService, ValidationError, NotFoundError, ConflictError, new_id, utcnow
from .sanitize import load_json_limited, sanitize_text

TERMINAL = {'succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'interrupted'}
OUTPUT_LIMIT = 262144
HEADER_MATCHERS = {'strict-transport-security', 'content-security-policy', 'permissions-policy', 'x-frame-options',
                   'x-content-type-options', 'x-permitted-cross-domain-policies', 'referrer-policy',
                   'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy'}
PINNED = {
    'nuclei': ('3.11.1', '73d5e5b0dde9ea5d5fc15dcc34c756148ccae20dc431a21e611af11b8649b480'),
    'gitleaks': ('8.30.1', '17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c'),
}


@contextmanager
def deny_proxy():
    """Reject every HTTP/CONNECT request without opening any upstream socket."""
    class Handler(BaseHTTPRequestHandler):
        def reject(self):
            self.send_response(403)
            self.send_header('Content-Length', '0')
            self.end_headers()
        do_GET = do_POST = do_CONNECT = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = reject
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@dataclass
class ProcessResult:
    status: str
    exit_code: int | None
    stdout: bytes
    output_bytes: int
    stderr: bytes = b''


def run_bounded(argv: list[str], *, cwd: Path, env: dict[str, str], cancel: threading.Event,
                timeout: float = 30, output_limit: int = 262144,
                output_paths: tuple[Path, ...] = ()) -> ProcessResult:
    """Internal primitive, never exposed through HTTP or MCP as a command tool."""
    if cancel.is_set():
        return ProcessResult('cancelled', None, b'', 0)

    def file_bytes():
        size = 0
        for path in set(output_paths):
            try:
                size += path.stat().st_size
            except FileNotFoundError:
                pass
        return size

    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                               start_new_session=os.name != 'nt')
    chunks: queue.Queue = queue.Queue(maxsize=32)
    stop_reading = threading.Event()

    def read(stream, is_stdout):
        try:
            while chunk := stream.read(4096):
                while not stop_reading.is_set():
                    try:
                        chunks.put((is_stdout, chunk), timeout=.05)
                        break
                    except queue.Full:
                        continue
                if stop_reading.is_set():
                    break
        finally:
            stream.close()

    readers = [threading.Thread(target=read, args=(stream, stdout), daemon=True)
               for stream, stdout in ((process.stdout, True), (process.stderr, False))]
    for thread in readers:
        thread.start()
    start = time.monotonic()
    count, output, errors, state = 0, bytearray(), bytearray(), None
    try:
        while process.poll() is None or any(t.is_alive() for t in readers) or not chunks.empty():
            if cancel.is_set():
                state = 'cancelled'
                break
            if time.monotonic() - start >= timeout:
                state = 'timed_out'
                break
            if count + file_bytes() > output_limit:
                state = 'output_limit'
                break
            try:
                is_stdout, chunk = chunks.get(timeout=.025)
                count += len(chunk)
                if count + file_bytes() > output_limit:
                    state = 'output_limit'
                    break
                if is_stdout:
                    output.extend(chunk)
                else:
                    errors.extend(chunk)
            except queue.Empty:
                pass
    finally:
        stop_reading.set()
        if process.poll() is None:
            if os.name == 'nt':
                # Only the exact process this function created and its children.
                subprocess.run([os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'taskkill.exe'),
                                '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=5,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        for thread in readers:
            thread.join(timeout=2)
    count += file_bytes()
    if state is None and count > output_limit:
        state = 'output_limit'
    return ProcessResult(state or ('succeeded' if process.returncode == 0 else 'failed'),
                         process.returncode, bytes(output), count, bytes(errors))


class TaskManager:
    def __init__(self, service: ScopePilotService, root: Path, enabled: bool = False):
        self.service, self.root, self.enabled = service, root.resolve(), enabled
        self.running: dict[str, tuple[threading.Event, threading.Thread]] = {}
        self.lock = threading.RLock()
        with service.db.connection() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS local_tasks (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, tool TEXT NOT NULL, scenario TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL, log TEXT NOT NULL, exit_code INTEGER, output_bytes INTEGER NOT NULL, result TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)')
            conn.execute("UPDATE local_tasks SET status='interrupted',log='服务重启：上次执行未完成，不能视为成功',updated_at=? WHERE status IN ('queued','running','cancelling','importing')", (utcnow(),))

    def capabilities(self) -> dict:
        return {
            'target_requests': False, 'arbitrary_commands': False, 'os_network_isolation_verified': False,
            'execution_scope': '仅内置合成文件，Nuclei 被动模式；不运行用户目标或上传脚本',
            'limitations': '尚未完成系统级禁止外联验收；不支持主动靶场扫描。',
            'tools': {name: {'version': spec[0], 'installed': self._binary(name).is_file(),
                             'enabled': self.enabled and self._binary(name).is_file()}
                      for name, spec in PINNED.items()},
            'simulation': True,
        }

    def _binary(self, tool: str) -> Path:
        return self.root / '.tools' / tool / f'{tool}.exe'

    def list(self, project_id: str) -> list[dict]:
        self.service.get_project(project_id)
        with self.service.db.connection() as conn:
            return [dict(row) for row in conn.execute('SELECT * FROM local_tasks WHERE project_id=? ORDER BY created_at DESC LIMIT 100', (project_id,))]

    def get(self, project_id: str, task_id: str) -> dict:
        with self.service.db.connection() as conn:
            row = conn.execute('SELECT * FROM local_tasks WHERE project_id=? AND id=?', (project_id, task_id)).fetchone()
            if not row:
                raise NotFoundError('task not found in project')
            return dict(row)

    def start(self, project_id: str, tool: str, scenario: str = 'positive') -> dict:
        if tool not in {*PINNED, 'simulation'} or scenario not in {'positive', 'negative', 'slow'}:
            raise ValidationError('只允许内置工具与合成场景')
        if tool != 'simulation' and not self.enabled:
            raise ValidationError('真实工具默认关闭；请先阅读受限执行说明并显式配置')
        if tool != 'simulation' and scenario == 'slow':
            raise ValidationError('慢任务仅用于模拟取消验收')
        with self.service.db.connection() as conn:
            _, policy = self.service.current_policy(conn, project_id)
            self.service._ensure_policy_usable(policy, 'local synthetic task')
        with self.lock:
            if len(self.running) >= 2:
                raise ValidationError('最多同时运行两个本地任务')
            task_id = new_id('task')
            now = utcnow()
            with self.service.db.connection() as conn:
                conn.execute('INSERT INTO local_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                             (task_id, project_id, tool, scenario, 'queued', 0,
                              '合成数据演示；模拟结果不代表真实工具验证' if tool == 'simulation' else '内置合成文件；未进行系统级网络隔离验收',
                              None, 0, None, now, now))
            event = threading.Event()
            thread = threading.Thread(target=self._run, args=(project_id, task_id, tool, scenario, event), daemon=True)
            self.running[task_id] = (event, thread)
            thread.start()
        return self.get(project_id, task_id)

    def cancel(self, project_id: str, task_id: str) -> dict:
        with self.lock:
            task = self.get(project_id, task_id)
            if task['status'] == 'importing':
                raise ConflictError('任务已进入原子结果提交，无法再取消；请等待提交结果')
            if task['status'] in TERMINAL:
                return {**task, 'cancel_accepted': False}
            if task_id in self.running:
                self.running[task_id][0].set()
                self._update(task_id, status='cancelling', log='取消已接受；结果提交尚未开始')
                return {**self.get(project_id, task_id), 'cancel_accepted': True}
            raise ConflictError('任务没有可取消的活动执行器')

    def close(self):
        with self.lock:
            running = list(self.running.values())
        for event, _ in running:
            event.set()
        for _, thread in running:
            thread.join(timeout=8)

    def _update(self, task_id, **values):
        with self.lock, self.service.db.connection() as conn:
            conn.execute('UPDATE local_tasks SET ' + ','.join(f'{k}=?' for k in values) + ',updated_at=? WHERE id=?',
                         (*values.values(), utcnow(), task_id))

    def _run(self, project_id, task_id, tool, scenario, cancel):
        try:
            with self.lock:
                if cancel.is_set():
                    self._update(task_id, status='cancelled', progress=0, log='启动前已取消；未执行工具')
                    return
                self._update(task_id, status='running', progress=10)
            if tool == 'simulation':
                for _ in range(150 if scenario == 'slow' else 8):
                    if cancel.wait(.1):
                        self._update(task_id, status='cancelled', progress=0, log='模拟任务已取消；无工具结果')
                        return
                with self.lock:
                    if cancel.is_set():
                        self._update(task_id, status='cancelled', progress=0, log='模拟任务已取消；无工具结果')
                    else:
                        self._update(task_id, status='succeeded', progress=100, exit_code=0,
                                     log='模拟生命周期完成；没有运行扫描器，也没有创建漏洞发现')
                return
            binary = self._binary(tool)
            if not binary.is_file():
                raise ValidationError('工具缺失，未执行')
            if hashlib.sha256(binary.read_bytes()).hexdigest() != PINNED[tool][1]:
                raise ValidationError('工具文件与已验证官方发布版本不一致，拒绝执行')
            work = self.root / 'runtime' / 'tasks'
            work.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix=task_id + '-', dir=work) as folder, deny_proxy() as proxy:
                cwd = Path(folder)
                env = self._environment(cwd)
                env.update({'HTTP_PROXY': proxy, 'HTTPS_PROXY': proxy, 'ALL_PROXY': proxy})
                if tool == 'nuclei':
                    argv, result_path = self._nuclei(binary, cwd, scenario)
                    argv.extend(['-proxy', proxy, '-proxy-internal'])
                else:
                    argv, result_path = self._gitleaks(binary, cwd, scenario)
                result = run_bounded(argv, cwd=cwd, env=env, cancel=cancel,
                                     output_paths=(result_path,) if result_path else ())
                state = result.status
                self._update(task_id, progress=80, exit_code=result.exit_code, output_bytes=result.output_bytes)
                if state != 'succeeded':
                    diagnostic = sanitize_text(result.stderr.decode('utf-8', errors='replace'))[:2000]
                    self._update(task_id, status=state, log=f'真实工具执行结束：{state}；退出码 {result.exit_code}；不导入部分输出\n{diagnostic}')
                    return
                if cancel.is_set():
                    self._update(task_id, status='cancelled', log='导入前取消，不保存发现')
                    return
                remaining = OUTPUT_LIMIT - len(result.stdout) - len(result.stderr)
                if result_path is None:
                    raw_content = result.stdout
                else:
                    with result_path.open('rb') as handle:
                        if os.fstat(handle.fileno()).st_size > remaining:
                            self._update(task_id, status='output_limit', log='合计输出超过 256KiB，不导入')
                            return
                        raw_content = handle.read(remaining + 1)
                if len(raw_content) > (OUTPUT_LIMIT if result_path is None else remaining):
                    self._update(task_id, status='output_limit', log='结果超过 256KiB，不导入')
                    return
                content = raw_content
                content, expected_count = self._normalize_results(tool, content, cwd, scenario)
                with self.lock:
                    if cancel.is_set():
                        self._update(task_id, status='cancelled', log='提交前取消，不保存发现')
                        return
                    # This is the cancellation linearization point: cancel() now
                    # reports a conflict rather than pretending to stop a commit.
                    self._update(task_id, status='importing', progress=90, log='原子提交结果中；已越过取消边界')
                imported = (self.service.import_tool_results(project_id, tool, f'synthetic-{tool}-{scenario}.json',
                            content, PINNED[tool][0], source_root='synthetic-lab', reuse_existing=True) if expected_count else
                            {'accepted_entries': 0, 'created': 0, 'finding_ids': [], 'artifact_id': None})
                imported['execution_mode'] = 'offline-synthetic'
                imported['tool_output_sha256'] = hashlib.sha256(raw_content).hexdigest()
                self._update(task_id, status='succeeded', progress=100, result=json.dumps(imported),
                             log='真实工具处理内置合成文件完成；结果仅为待验证线索；无主动目标请求')
        except Exception as exc:
            # Avoid reflecting scanner output, arbitrary paths, or secrets in task logs.
            message = str(exc) if isinstance(exc, ValidationError) else type(exc).__name__
            self._update(task_id, status='failed', log=f'任务失败：{message[:200]}；未标记成功')
        finally:
            with self.lock:
                self.running.pop(task_id, None)

    @staticmethod
    def _normalize_results(tool: str, content: bytes, cwd: Path, scenario: str) -> tuple[bytes, int]:
        if tool == 'nuclei':
            records = []
            expected_input = (cwd / 'synthetic-response.txt').resolve()
            for line in content.splitlines():
                if not line.strip():
                    continue
                item = load_json_limited(line, max_bytes=OUTPUT_LIMIT)
                # Pinned v3.11.1 passive output has an empty type and no host;
                # matched-at carries the absolute input file. Do not invent an
                # offline protocol label or accept a live HTTP result here.
                if not isinstance(item, dict) or item.get('template-id') != 'http-missing-security-headers' or item.get('type') != '':
                    raise ValidationError('Nuclei 返回了非预期模板或非离线结果；拒绝映射')
                if item.get('matcher-name') not in HEADER_MATCHERS:
                    raise ValidationError('Nuclei 返回了不属于合成样本预期的 matcher')
                location = item.get('matched-at')
                if item.get('host') not in (None, '') or not isinstance(location, str) or not Path(location).is_absolute() or Path(location).resolve() != expected_input:
                    raise ValidationError('Nuclei 原始输出来源不是本次内置合成文件；拒绝映射')
                info = item.get('info')
                if not isinstance(info, dict) or info.get('severity') != 'info' or not isinstance(info.get('name'), str):
                    raise ValidationError('Nuclei 固定模板的元数据不符合预期')
                # Only after validating provenance do we assign a stable synthetic
                # HTTP display target. It is a fixture label, not a fetched URL.
                records.append({'template-id': item['template-id'], 'matcher-name': item['matcher-name'],
                                'info': {'name': '内置合成数据：' + info['name'], 'severity': info['severity']},
                                'matched-at': 'http://127.0.0.1:3000/synthetic-headers',
                                'host': 'http://127.0.0.1:3000', 'type': 'http', 'method': 'GET'})
            if scenario == 'positive' and (len(records) != len(HEADER_MATCHERS) or
                                           {row['matcher-name'] for row in records} != HEADER_MATCHERS):
                raise ValidationError('异常合成样本未完整命中预期安全头；执行成功不能代替检测验收')
            records.sort(key=lambda item: item['matcher-name'])
        else:
            records = load_json_limited(content, max_bytes=OUTPUT_LIMIT)
            if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
                raise ValidationError('Gitleaks 返回了非预期结果结构')
            for item in records:
                if not isinstance(item.get('File'), str):
                    raise ValidationError('Gitleaks 结果没有有效文件位置')
                file = Path(item['File'])
                file = file if file.is_absolute() else cwd / 'source' / file
                if file.resolve() != (cwd / 'source' / 'synthetic-example.txt').resolve():
                    raise ValidationError('Gitleaks 结果来源不是本次内置合成文件')
                item['File'] = 'synthetic-example.txt'
            retained = ('RuleID', 'File', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 'Secret', 'Match', 'Description', 'Severity')
            records = [{key: item[key] for key in retained if key in item} for item in records]
        if scenario == 'positive' and not records:
            raise ValidationError('异常合成样本未命中；执行成功不能代替检测验收')
        if scenario == 'negative' and records:
            raise ValidationError('正常对照样本意外命中；不能作为检测通过')
        return json.dumps(records, sort_keys=True).encode(), len(records)

    @staticmethod
    def _environment(cwd: Path) -> dict[str, str]:
        env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'COMSPEC') if k in os.environ}
        for name in ('USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'):
            env[name] = str(cwd)
        env.update({'DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD': 'true',
                    'DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD': 'true',
                    'DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD': 'true',
                    'DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD': 'true',
                    'DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD': 'true', 'NO_PROXY': ''})
        return env

    @staticmethod
    def _nuclei(binary: Path, cwd: Path, scenario: str):
        response = cwd / 'synthetic-response.txt'
        headers = ['Content-Type: text/html; charset=utf-8']
        if scenario == 'negative':
            headers += [f'{h}: enabled' for h in ('Strict-Transport-Security', 'Content-Security-Policy', 'Permissions-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy')]
        response.write_bytes(('HTTP/1.1 200 OK\r\n' + '\r\n'.join(headers) + '\r\nContent-Length: 20\r\n\r\n<p>Synthetic lab</p>\n').encode())
        template = Path(__file__).parent / 'resources' / 'scopepilot-offline-headers.yaml'
        normalized = template.read_text(encoding='utf-8').replace('\r\n', '\n').encode()
        if hashlib.sha256(normalized).hexdigest() != '36740e559e937e93ac64f092a90f98b33a4f3912339803cfa7e969b3629348ed':
            raise ValidationError('模板与审查版本不一致，拒绝执行')
        config = cwd / 'nuclei-config.yaml'
        config.write_text('{}\n')
        return [str(binary), '-passive', '-u', str(response), '-t', str(template), '-config', str(config),
                '-duc', '-ni', '-dr', '-nh', '-no-stdin', '-jsonl', '-silent', '-nc', '-omit-raw', '-omit-template',
                '-c', '1', '-bs', '1', '-timeout', '3', '-retries', '0'], None

    @staticmethod
    def _gitleaks(binary: Path, cwd: Path, scenario: str):
        source = cwd / 'source'
        source.mkdir()
        # Explicit synthetic value, never a usable credential.
        value = 'ghp_' + 'ScopePilotSyntheticFixtureOnly1234567' if scenario == 'positive' else 'example-placeholder'
        (source / 'synthetic-example.txt').write_text(f'github_token = "{value}"\n')
        config = cwd / 'gitleaks.toml'
        config.write_text('[extend]\nuseDefault = true\n')
        report = cwd / 'result.json'
        return [str(binary), 'dir', str(source), '--config', str(config), '--report-format', 'json',
                '--report-path', str(report), '--redact=100', '--no-banner', '--no-color', '--exit-code', '0',
                '--max-target-megabytes', '1', '--timeout', '20'], report
