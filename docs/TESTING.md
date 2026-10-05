# 验证与复现

所有示例与测试数据均为本任务创建的合成材料。人工确认测试验证字段、证据引用与状态门槛，不证明真实目标存在漏洞。不要用测试数代替真实工具或隔离验收。

## 单元、服务与协议回归

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp runtime\pytest-final --junitxml=runtime\pytest-final.xml
```

包含原有回归、完整目标身份、证据跨项目拒绝、去重、秘密脱敏、正常/异常 HAR、CORS 误报边界、工具格式校验、数据库迁移、评级、确认/排除/待补证据和报告。MCP 测试会真正启动 stdio 服务子进程，但不调用模型。

任务单元测试会运行测试临时目录中的合成 Python 助手，检查非零退出、超时、取消、标准输出与文件总量超限、异常结果与提交竞争；这部分不等于真实 Nuclei/Gitleaks 检测验收。HTTP 接收层在 multipart 解析写临时文件前限制总量，另验证分块与声明长度异常。

## 官方工具真实集成

```powershell
.venv\Scripts\python.exe scripts\fetch_tools.py
.venv\Scripts\python.exe scripts\verify_local_tools.py
```

固定官方 Windows Nuclei 3.11.1 / Gitleaks 8.30.1；运行前检查二进制哈希。每个工具执行阳性、阴性、重复阳性三个流程：阳性必须满足预期命中，阴性必须零命中，重复执行复用已有材料且不重复新增发现。执行日志、退出状态和原始输出哈希记录于 [tool-verification.json](tool-verification.json)。Nuclei 对内置 HTTP 响应文本做被动解析；显示的 localhost URL 是明确的合成标签，没有向该 URL 请求。

拒绝代理测试向本任务创建的代理发送 HTTP/CONNECT，实测返回拒绝；代理实现不创建上游连接。**它只证明代理路径被阻止，不能证明任意进程无法绕过代理。** 系统级网络隔离、主动靶场和任意子进程树退出清理仍未验收；应用不提供对应能力。CLI 固定单 Web 进程，MCP 仅查询任务。

## 真实浏览器端到端

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\.tools\browsers"
.venv\Scripts\python.exe -m playwright install chromium --only-shell
.venv\Scripts\python.exe scripts\verify_browser.py
```

使用已安装的 ScopePilot CLI，在随机回环端口启动专用空数据库，用 Chromium 操作创建、上传、分析、四类筛选、详情、脱敏证据、模拟取消、合成复核与报告下载。浏览器额外拦截非预览来源的后续请求。1440px 桌面和 390px 窄屏检查无横向溢出，截图人工查看；记录见 [browser-verification.json](browser-verification.json)。退出停止本次服务进程树并清理测试库。

## 本机 Codex 客户端

```powershell
.venv\Scripts\python.exe scripts\verify_codex_client.py
```

本机 Codex app-server 实際识别 12 工具并调用两项只读工具，使用进程内配置与短暂协议会话；零模型轮次、零付费模型调用，不修改既有聊天或全局配置。详见 [Codex 接入](CODEX.md) 和 [codex-verification.json](codex-verification.json)。

## 交付检查

```powershell
.venv\Scripts\python.exe scripts\verify_repository.py
.venv\Scripts\python.exe scripts\measure_disk.py
git diff --check
```

前者仅把仓库非忽略文本复制到本项目临时目录，由已校验的官方 Gitleaks 扫描，输出脱敏定位信息；不读取用户主目录或扫描整机。未命中不等于保证不存在任何秘密。磁盘计量包含项目内依赖、浏览器、工具、压缩包、缓存、测试输出和 Git；系统盘同期增长作为保守余量而非全部归因本任务。

Windows 上当前执行环境可能限制 Python 的本地 socket pair，需要允许本机进程通信才能运行异步测试；不要求管理员、不更改系统防火墙或安全设置。
