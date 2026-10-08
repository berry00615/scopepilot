"""Real Chromium + installed CLI, exclusively on a disposable synthetic database."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
from playwright.sync_api import sync_playwright, expect


ROOT = Path(__file__).resolve().parents[1]


def main():
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    screenshots = ROOT / 'docs' / 'images'
    screenshots.mkdir(exist_ok=True)
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(ROOT / '.tools' / 'browsers')
    with TemporaryDirectory(prefix='browser-test-', dir=runtime) as folder:
        work = Path(folder)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        env = dict(os.environ, SCOPEPILOT_DB=str(work / 'test.db'),
                   SCOPEPILOT_ENABLE_LOCAL_TOOLS='0', SCOPEPILOT_ENABLE_LOCAL_LLM='0',
                   TEMP=str(work), TMP=str(work))
        log = (work / 'server.log').open('wb')
        # Use the installed entry point; no source-only in-process server shortcut.
        executable = Path(sys.executable).parent / ('scopepilot.exe' if os.name == 'nt' else 'scopepilot')
        server = subprocess.Popen([str(executable), '--host', '127.0.0.1', '--port', str(port)],
                                  cwd=ROOT, env=env, stdout=log, stderr=log,
                                  creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        checks = []
        try:
            with httpx.Client(base_url=base, trust_env=False, timeout=2) as client:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError('Installed CLI stopped before startup')
                    try:
                        if client.get('/health').status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError('Startup timeout')
            checks.append('installed CLI starts on loopback with disposable DB')
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(viewport={'width': 1440, 'height': 1000}, locale='zh-CN')
                failures, forbidden = [], []
                # All browser follow-up requests are restricted to this exact preview origin.
                def route(request):
                    if request.request.url.startswith(base + '/'):
                        request.continue_()
                    else:
                        forbidden.append(request.request.url)
                        request.abort()
                context.route('**/*', route)
                page = context.new_page()
                page.on('pageerror', lambda error: failures.append(str(error)))
                page.goto(base)
                expect(page.locator('#projects-empty')).to_be_visible()
                page.goto(base + '/docs')
                expect(page.locator('.endpoint')).not_to_have_count(0)
                expect(page.locator('#schemas')).to_be_visible()
                page.goto(base)
                checks.append('offline API reference renders without CDN or external requests')
                page.locator('#project-name').fill('合成演示 · ScopePilot v1')
                page.locator('#create-project').click()
                page.wait_for_url('**/workspace/**')
                workspace = page.url
                expect(page.locator('#count-confirmed')).to_have_text('0')
                expect(page.locator('#llm-analysis')).to_be_disabled()
                page.locator('#import-file').set_input_files(ROOT / 'tests' / 'fixtures' / 'sample.har')
                with page.expect_navigation():
                    page.locator('#import-submit').click()
                with page.expect_navigation():
                    page.locator('#rule-analysis').click()
                expect(page.locator('#count-pending')).to_have_text('1')
                expect(page.locator('.finding-open')).to_have_count(1)
                checks.append('UI project creation, HAR upload, offline analysis and real counts')

                # Exercise a negative filter and then all four combined positive filters.
                page.locator('#filter-severity').select_option('critical')
                with page.expect_navigation():
                    page.locator('#filter-form button').click()
                expect(page.locator('.finding-open')).to_have_count(0)
                for key, value in [('severity', 'unrated'), ('status', 'pending_review'),
                                   ('source', 'rule'), ('category', 'vulnerability')]:
                    page.locator('#filter-' + key).select_option(value)
                with page.expect_navigation():
                    page.locator('#filter-form button').click()
                expect(page.locator('.finding-open')).to_have_count(1)
                checks.append('severity/status/source/category filters, including empty result')
                page.goto(workspace)
                with page.expect_response('**/reports') as denied:
                    page.locator('#report').click()
                assert denied.value.status == 422
                expect(page.locator('#global-error')).not_to_be_empty()
                checks.append('report refused before evidence-backed review')

                page.locator('#task-scenario').select_option('slow')
                page.locator('#start-task').click()
                expect(page.locator('.cancel-task')).to_have_count(1)
                page.locator('.cancel-task').click()
                expect(page.locator('#task-list')).to_contain_text('已取消', timeout=10000)
                expect(page.locator('.cancel-task')).to_have_count(0)
                expect(page.locator('#count-total')).to_have_text('1')
                checks.append('task progress/log rendering and cancellation; simulation creates no findings')

                page.locator('.finding-open').click()
                expect(page.locator('#detail-content')).to_contain_text('原始评级')
                expect(page.locator('#detail-content')).to_contain_text('脱敏证据')
                body = page.locator('#detail-content').inner_text()
                for secret in ('never-store-me', 'synthetic-secret-token', 'alice@example.test'):
                    assert secret not in body
                page.locator('#review-section summary').click()
                page.locator('#review-status').select_option('confirmed')
                for name, value in {
                    'reviewer': '合成测试操作者', 'identity': '合成角色 B', 'object': '合成对象 A',
                    'result': '仅验证复核表单：合成结果声明 B 可以读取 A；没有实际目标请求。',
                    'success': '合成流程断言：有证据引用且支持结论的对照字段完整。',
                    'control': '合成对照声明：所有者 A 能读取，修复版 B 被拒绝。仅用于表单测试。',
                    'severity-reason': '合成测试演示；不代表真实漏洞评级。',
                    'stop': '合成浏览器流程结束，不进行任何实际漏洞验证。',
                }.items():
                    page.locator('#review-' + name).fill(value)
                page.locator('#review-criteria-met').check()
                page.locator('[name=evidence_refs]').first.check()
                page.locator('#review-control-passed').select_option('true')
                page.locator('#review-severity').select_option('low')
                with page.expect_navigation():
                    page.locator('#save-review').click()
                expect(page.locator('#count-confirmed')).to_have_text('1')
                page.locator('#report').click()
                expect(page.locator('#report-download')).to_be_visible()
                with page.expect_download() as download:
                    page.locator('#report-download').click()
                report = work / 'synthetic-report.md'
                download.value.save_as(report)
                report_text = report.read_text(encoding='utf-8')
                assert '合成测试' in report_text
                for secret in ('never-store-me', 'synthetic-secret-token', 'alice@example.test'):
                    assert secret not in report_text
                checks.append('synthetic human-review form, evidence references, report preview/download and redaction')
                page.goto(workspace)
                page.screenshot(path=str(screenshots / 'desktop.png'), full_page=True)
                page.set_viewport_size({'width': 390, 'height': 844})
                page.screenshot(path=str(screenshots / 'narrow.png'), full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.locator('.finding-open').click()
                expect(page.locator('#finding-detail')).to_be_visible()
                page.locator('#close-detail').click()
                page.locator('#report').click()
                expect(page.locator('#report-download')).to_be_visible()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                checks.append('1440px desktop and 390px narrow layout; narrow details/export; no horizontal overflow')
                assert not failures, failures
                assert not forbidden, 'Page attempted non-preview requests'
                checks.append('no browser JavaScript errors or external resource requests')
                context.close()
                browser.close()
        finally:
            if os.name == 'nt':
                subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32' / 'taskkill.exe'),
                                '/PID', str(server.pid), '/T', '/F'], capture_output=True, timeout=10,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                server.terminate()
            server.wait(timeout=10)
            log.close()
        (ROOT / 'docs' / 'browser-verification.json').write_text(json.dumps({
            'verified_at': datetime.now(timezone.utc).isoformat(), 'status': 'passed',
            'browser': 'Chromium headless shell 145.0.7632.6 / Playwright 1.58.0',
            'data': 'synthetic only; confirmation tests form semantics, not vulnerability exploitation',
            'checks': checks, 'server_stopped': server.poll() is not None,
        }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': 'passed', 'checks': len(checks), 'server_stopped': True}))


if __name__ == '__main__':
    main()
