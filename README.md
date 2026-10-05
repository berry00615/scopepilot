# ScopePilot v1

[![Tests](https://github.com/berry00615/scopepilot/actions/workflows/tests.yml/badge.svg)](https://github.com/berry00615/scopepilot/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ScopePilot 是本地、离线优先的授权安全研究工作台：导入已有材料，整理脱敏证据，生成待复核线索，再由研究者记录验证结果和导出报告。网页和 Codex MCP 共用业务服务与 SQLite 数据库。

**主动目标请求关闭；真实工具与本地模型默认关闭。** 工具命中、模型输出和合成演示都不会自动确认漏洞，不生成 CVSS，也不会自动提交或发送报告。

## 已实现的能力

- 版本化授权策略：精确协议、主机、端口和路径范围；拒绝规则优先，过期或未启用的策略拒绝处理。
- HAR 导入：逐条范围检查，保留完整目标身份、请求/响应结构、响应头和不含值的 Cookie 属性；脱敏常见秘密、邮箱和对象标识。
- 离线检查：安全响应头、Cookie 属性、CORS 配置疑点、调试错误、疑似敏感内容和对象授权线索。配置加固与漏洞线索分开计数。
- Nuclei JSON/JSONL 与 Gitleaks JSON 导入：保留工具名称、版本、定位和原始评级；原始请求/响应、Secret、Match 等不直接写入证据。Gitleaks 区分明显示例值和疑似凭据。
- 发现去重与追溯：区分项目和完整目标，合并相同发现的多条证据；详情包含来源、原始/当前/人工评级、修复建议和复核历史。
- 中文工作区：真实计数、严重性/状态/来源/分类筛选、证据预览、身份管理、材料删除、接口目录和 Markdown 下载。
- 有限制的本地任务：状态、日志、进度、退出码、输出限制、超时、取消和重启后中断标记。模拟任务不创建发现。
- 本地 stdio MCP：供 Codex 查询、导入已有文本、分析和导出符合条件的报告，详见 [Codex 配置与能力边界](docs/CODEX.md)。

## Windows 安装与启动

需要 Python 3.11 或更高版本。在仓库根目录的 PowerShell 中运行，无需激活虚拟环境或修改执行策略：

~~~powershell
py -3 -m venv .venv
$env:PIP_CACHE_DIR = "$PWD\.cache\pip"
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\.venv\Scripts\scopepilot.exe
~~~

打开 [本地工作区](http://127.0.0.1:8000) 或 [离线 API 参考](http://127.0.0.1:8000/docs)。服务仅绑定回环地址，固定单 Web 进程运行；不要另外启动多个 Web worker 共享任务库。默认数据库为仓库内的 runtime/scopepilot.db；请始终从同一个仓库目录启动。可用 SCOPEPILOT_DB 指定另一个数据库路径。

依赖版本和哈希见 [requirements.lock](requirements.lock)。网页运行不需要下载浏览器、扫描器或模型。其他系统可使用虚拟环境 bin 目录中的对应命令；当前真实工具安装脚本针对 Windows 二进制。

本次交付已在当前项目安装官方固定工具。可双击 [start-workbench.cmd](start-workbench.cmd) 启动网页并启用**内置合成材料**的工具任务；开关只影响这个启动进程，关闭窗口即结束服务，不修改系统配置。默认 CLI 的真实工具开关仍为关闭，启动器不会下载缺失组件。

## 第一次使用

1. 在首页创建“合成材料项目”，或填写实际授权来源、精确范围与有效期创建普通项目。
2. 导入 [sample.har](tests/fixtures/sample.har)。默认合成范围 http://127.0.0.1:3000 下，一条请求接受，外部域名条目拒绝。
3. 点击“离线分析”，打开发现详情，检查完整目标、脱敏证据、来源和缺少的信息。
4. 在独立、明确授权的人工流程中使用自有账号及对象验证，再记录复核结论。
5. 满足确认条件后生成并下载报告。删除材料会撤销其证据依赖，相关发现可能删除或回到待补证据状态。

[创建项目示例](examples/project.json) 的有效期需要按实际情况更新；它不产生对第三方目标的授权。[复核示例](examples/review.json) 故意使用“待补证据”，可直接提交结构，但必须按实际观察替换描述。

### 工具结果导入

在网页“导入材料”中选择类型，填写产生结果的工具版本并上传。无需安装或启用扫描器。

| 接口 | 文件与字段 | 校验 |
|---|---|---|
| POST /projects/{id}/imports/har | multipart 的 file | HAR 逐条范围检查，支持部分接受 |
| POST /projects/{id}/imports/nuclei | file、tool_version | HTTP 类型结果；每条目标必须处于授权范围 |
| POST /projects/{id}/imports/gitleaks | file、tool_version、source_root（默认 source） | source_root 是逻辑标签；文件位置必须为无穿越的相对源码路径，不读取这些文件 |

HTTP 默认上传上限为 5 MiB；HAR 最多 2,000 条，另有 JSON 深度和结构限制。Nuclei/Gitleaks 导入采用整批校验：任何无效结构、越界目标或非法路径都会拒绝整批，不保留部分结果。Gitleaks 不以“位于 tests 目录”作为凭据无害的依据。

### 严格人工复核

确认必须记录复核人、测试身份、测试对象、实际结果、停止原因，并同时满足：

- success_criteria 写明可观察的成功判据，criteria_met 为 true；
- evidence_refs 至少引用一条当前项目中仍存在的证据；
- 对象授权、CORS 或主动标记需要对照的发现，必须有 control_result，且 control_passed 为 true；
- 修改 severity 时必须填写 severity_reason，原始评级不会被覆盖。

没有足够证据时使用 needs_evidence；不支持结论时可排除或标记重复。报告会重新检查当前策略、最新确认记录、判据、必要对照和证据完整性，不能通过只修改状态跳过检查。

## 可选执行能力

**真实工具只处理程序内置的合成离线文件，不接受用户目标、任意命令、上传脚本或自定义模板。** Nuclei 3.11.1 使用固定模板的被动模式，Gitleaks 8.30.1 检查临时合成源码；工具版本和哈希固定。它们不是主动靶场扫描入口。

需要本地开发验证时，可显式下载经官方哈希校验的 Windows 工具，再在当前 PowerShell 会话启用：

~~~powershell
.\.venv\Scripts\python.exe scripts\fetch_tools.py
$env:SCOPEPILOT_ENABLE_LOCAL_TOOLS = "1"
.\.venv\Scripts\scopepilot.exe
~~~

安装脚本访问官方发布站点；应用本身不会自动下载工具。启用后仍仅支持内置阳性/阴性合成场景。慢任务只用于模拟取消演示。任务功能状态可在网页或 GET /capabilities 查看。

**系统级禁止外联隔离尚未完成验收。** 固定参数、临时环境和拒绝代理是应用层限制，不能替代操作系统网络沙盒；现有合成工具运行记录不证明主动目标测试或系统隔离已通过。

本地模型同样需要显式启用，并自行提供兼容服务：

~~~powershell
$env:SCOPEPILOT_ENABLE_LOCAL_LLM = "1"
$env:SCOPEPILOT_LOCAL_LLM_URL = "http://127.0.0.1:11434/v1/chat/completions"
$env:SCOPEPILOT_LOCAL_LLM_MODEL = "your-local-model"
.\.venv\Scripts\scopepilot.exe
~~~

仅接受数值回环 HTTP 地址，禁用重定向和系统代理；模型只接收脱敏结构摘要，不能自行确认。项目不捆绑或下载模型。通过 MCP 向 Codex 提交的文本会先进入 Codex 上下文，请仅提交合成或已脱敏材料；详见 [MCP 数据边界](docs/CODEX.md)。

## 测试与限制

~~~powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .cache\pytest
~~~

当前不支持 Burp XML、OpenAPI、JS AST、自动角色比较、主动靶场扫描、SRC 自动提交或经过验收的系统网络沙盒。脱敏是数据最小化措施，不保证识别任意格式的秘密；上传原件不写入应用证据库。

实现状态与独立验证记录见 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)，组件选择见 [开源复用决策](docs/OPEN_SOURCE.md)。这些说明不代表整体验收或合并已完成。

浏览器合成流程预览：[桌面](docs/images/desktop.png)、[窄屏](docs/images/narrow.png)。截图中的确认数来自显著标注的合成表单验收，不能视为真实漏洞数量。

贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；ScopePilot 自身的安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。
