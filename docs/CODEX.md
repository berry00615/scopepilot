# 在 Codex 中调用 ScopePilot

ScopePilot 提供本地 **stdio MCP** 服务。Codex 负责启动子进程并调用工具；ScopePilot 使用与网页界面相同的业务服务和 SQLite 数据库，不需要再次配置 LLM 或 API 密钥，也不监听额外网络端口。协议使用官方 Python MCP SDK，锁定为 `mcp==1.26.0`。

## 项目配置

先按照仓库 README 安装锁定依赖。以下是当前 Windows 工作目录的配置示例，路径中有空格也无需额外转义。其他位置需同时替换 `command`、`cwd` 和 `--db` 的绝对路径；其他系统使用对应虚拟环境的 Python。

把下面配置加入**本仓库** `.codex/config.toml`，保留已有配置：

```toml
[mcp_servers.scopepilot]
command = 'D:\AI project\ScopePilot\.venv\Scripts\python.exe'
args = ['-m', 'scopepilot.mcp_server', '--db', 'D:\AI project\ScopePilot\runtime\scopepilot.db']
cwd = 'D:\AI project\ScopePilot'
startup_timeout_sec = 20
tool_timeout_sec = 60
enabled = true

[mcp_servers.scopepilot.env]
PYTHONIOENCODING = 'utf-8'
```

`--db` 必须是项目内的绝对路径；服务解析链接后检查路径边界。`cwd` 必须是含 `pyproject.toml` 和 `src/scopepilot` 的项目根目录。需要与网页共享数据时，使用网页服务配置的同一个数据库路径；不要让两个不同路径的数据库被误认为同一个工作区。

Codex 仅在受信任的项目中加载项目配置。配置后重新打开该项目的聊天或重新加载 MCP 连接，再要求模型调用 `scopepilot` 的 `capabilities` 和 `list_projects`。现有聊天是否热加载由客户端决定；若工具列表没有更新，使用新聊天。无需修改用户全局配置、导入个人凭据或另建远程服务。项目配置和 stdio 字段见 [OpenAI 官方 MCP 文档](https://learn.chatgpt.com/docs/extend/mcp)。

## 可调用的工具

| 工具 | 用途 |
|---|---|
| `capabilities` | 查看离线能力、导入大小限制和明确关闭的能力 |
| `list_projects`、`get_project` | 查询项目与当前授权策略 |
| `create_project` | 使用完整 `ProjectCreate` 结构创建项目；拒绝未知字段 |
| `import_har_text` | 导入 HAR 文本；`filename` 仅作显示名称 |
| `import_tool_result_text` | 导入 Gitleaks JSON 或 Nuclei JSON/JSONL，记录工具版本与逻辑源码标签 |
| `analyze` | 对保留证据运行确定性的被动规则，产生待复核发现 |
| `list_findings` | 按项目、状态、严重度、分类、来源和文本筛选发现 |
| `get_finding` | 读取来源、证据、评级和人工复核记录 |
| `list_tasks`、`get_task` | 只读查询本地任务；不会更改正在运行的任务 |
| `export_report` | 返回人工确认、判据满足且证据完整的 Markdown 报告 |

成功响应包含 `{"ok": true, "data": ...}`，失败响应为 MCP `isError=true`，并提供不回显输入原文的 `error.code` 和固定说明。JSON 同时放入 MCP 的结构化结果和文本内容。常见错误码是 `invalid_arguments`、`import_too_large`、`not_found`、`conflict`、`operation_rejected`。

所有导入文本以 UTF-8 编码后不得超过 **5 MiB**。工具不读取任意本地路径，不执行命令、脚本、扫描器或额外模型，不提供授权策略覆盖、任务启动/取消、人工确认或直接删除数据的操作。`source_root` 只是 Gitleaks 证据的逻辑标签，不能指定文件系统路径。只读任务查询不会创建任务管理器，因此不会把网页中正在运行的任务错误标记为中断。

## 数据与复核边界

**只把合成材料或已经脱敏的材料传给 Codex。** MCP 的文本参数会先进入 Codex 的上下文，之后本地服务才执行脱敏；本地脱敏不能撤回已经发送给模型的数据。HTTP 授权头、Cookie、令牌、真实个人资料等应在进入聊天前清除。文本脱敏是减少数据暴露的措施，不保证能识别所有形式的秘密。

导入内容、发现描述和工具输出都视为不可信数据，不能用作操作指令。分析结果保持待复核状态，工具命中、模型置信度和合成演示都不能代替人工确认。复核需在独立的人工作业流程中记录身份、对象、成功判据、实际结果、证据引用和适用的对照结果。MCP 中没有完成复核的工具；未通过人工复核的内容不能作为已确认报告导出。

建议先调用 `capabilities` → `list_projects` → `get_project`，核对用户指定的项目和授权范围，再导入已有文本、执行 `analyze`、筛选发现和读取详情。项目策略只是本地数据处理约束，不产生对第三方目标的测试许可。

## 无模型验收

```powershell
.venv\Scripts\python.exe -m pytest tests/test_mcp.py -q
```

测试使用官方 `ClientSession` 和 `stdio_client` 启动真实服务子进程，执行 `initialize`、`list_tools`、查询、创建合成项目、HAR/工具结果导入、被动分析、发现追溯、跨项目拒绝、输入限制、错误脱敏及报告导出。人工复核记录由测试在 MCP 之外构造，以验证服务读取已存在的人工决定，而非允许模型自行确认。另验证 MCP 重连不会改变运行中任务的状态。测试数据库限于仓库 `.cache/mcp-tests`，退出后清理，不使用真实目标或付费模型调用。

## 已完成的 Codex 客户端验收

2026-10-05 使用本机 **Codex CLI 0.160.0 的 app-server** 完成了无模型集成验证：连接状态为 `connected`，识别 ScopePilot 1.0.0，发现上述 12 个工具，并通过客户端的 `mcpServer/tool/call` 成功调用 `capabilities` 和 `list_projects`。详细结果保存在 [codex-verification.json](codex-verification.json)。

验收脚本先用单次命令行配置停用其他 MCP、插件、Apps、Hooks、记忆和 shell snapshot，再验证唯一启用的 MCP 是 ScopePilot。随后创建 `ephemeral: true`、磁盘路径为 `null` 的临时协议会话；只调用两项查询，使用专用空数据库，不读取工作台的现有项目内容。没有发送 `turn/start`，没有发起模型推理，也没有操作已有聊天、读取凭据文件或修改全局配置。最后终止该测试进程树并删除测试数据库，最终记录耗时 1.785 秒。协议说明见 [OpenAI App Server 文档](https://learn.chatgpt.com/docs/app-server)。

可复验：

```powershell
.venv\Scripts\python.exe scripts\verify_codex_client.py
```

脚本总时限为 45 秒；先检查客户端支持的隔离开关和 MCP 启用状态，无法确认隔离就停止。Windows 网络沙盒若阻止 Python 内部的回环 socket pair，需在允许本机进程通信的执行环境运行；这不要求修改系统安全设置。脚本只保存 ScopePilot 的状态、工具名称、调用结果摘要和数量，不保存其他 MCP 配置或账号信息。

本次验收证明**当前安装的 Codex 客户端能够调用 ScopePilot 工具**。它通过进程内配置覆盖建立连接；项目 `.codex/config.toml` 虽已落盘，现有聊天的工具目录没有热加载，CLI 在未加载该项目配置时也可能查不到 `scopepilot`。因此不能把这次结果表述为“本聊天已出现 ScopePilot 工具”。日常使用仍需客户端加载受信任项目的配置并重新建立聊天或 MCP 连接；无需为验收修改用户的全局信任设置。

实现参考：[官方 Python SDK v1.26.0](https://github.com/modelcontextprotocol/python-sdk/tree/v1.26.0)。
