# ScopePilot v0.2

[![Tests](https://github.com/berry00615/scopepilot/actions/workflows/tests.yml/badge.svg)](https://github.com/berry00615/scopepilot/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ScopePilot 是一个本地、离线优先的授权安全研究工作台。当前可用闭环：

1. 创建项目和版本 1 授权策略；
2. 导入 HAR，逐条执行精确主机、协议、端口和路径检查；
3. 删除凭据、稳定假名化对象 ID，只保存脱敏后的必要证据；
4. 生成接口目录和带证据引用的待审核线索；
5. 由研究者保存验证结论；
6. 只为人工确认的发现生成 Markdown 报告。

该版本没有向研究目标发送请求的代码，也不自动提交报告。它可选连接数值回环地址上的 OpenAI 兼容本地模型；规则和模型都只能提出核查假设，不能确认漏洞。

## 能做什么

- 将明确授权范围写成版本化策略，按精确协议、主机、端口和路径检查每条材料。
- 导入 HAR，拒绝超范围条目，提取接口方法、路径和证据位置。
- 删除常见凭据和邮箱，对对象标识符做项目内稳定假名化。
- 根据带对象 ID 的请求生成权限核查线索，并保留证据引用和未知项。
- 保存人工验证使用的测试身份、测试对象、实际结果和停止原因。
- 仅为人工确认且证据仍然存在的发现生成 Markdown 报告草稿。
- 记录项目、策略、导入、分析、审核和报告操作，便于追溯。
- 通过完整网页工作台创建项目、导入、管理测试身份、分析、审核和生成报告。
- 可选使用 OpenAI 兼容的本地模型；只发送证据编号、方法、路径、字段名和响应状态。

它是研究工作台，不是漏洞扫描器。请只处理自己拥有或得到明确授权的系统和材料。

## 运行

需要 Python 3.11 或更高版本。建议使用独立虚拟环境：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/scopepilot
```

打开 `http://127.0.0.1:8000` 使用完整工作台，打开 `http://127.0.0.1:8000/docs` 使用交互式 API。

### 可选本地模型

ScopePilot 支持提供 `/v1/chat/completions` 的 OpenAI 兼容本地服务，例如启用了兼容接口的本地推理程序。地址必须是数值回环 IP，重定向和系统代理均被禁用：

```bash
export SCOPEPILOT_LOCAL_LLM_URL=http://127.0.0.1:11434/v1/chat/completions
export SCOPEPILOT_LOCAL_LLM_MODEL=your-local-model
.venv/bin/scopepilot
```

不设置这两个变量时，本地模型按钮保持禁用，规则分析仍可使用。模型只接收结构摘要，但材料本身仍应先按项目规定处理。

运行测试：

```bash
.venv/bin/pytest
```

## 第一次演示

在 `/docs` 依次调用：

1. `POST /projects`，策略状态使用 `active`，范围仅填自己的本地靶场地址。
2. `POST /projects/{project_id}/imports/har`，可先使用 `tests/fixtures/sample.har`。
3. `GET /projects/{project_id}/endpoints` 查看接口目录。
4. `POST /projects/{project_id}/analysis-runs` 生成待审核线索。
5. `GET /projects/{project_id}/findings` 取得 finding id。
6. 在实际获准环境中完成最小化人工验证，再调用 reviews 接口记录结果。
7. `POST /projects/{project_id}/reports` 生成报告草稿。

测试夹具只含合成数据，其中一条本地请求应通过、一个外部域名应被拒绝。

`examples/project.json` 和 `examples/review.json` 可直接作为创建本地合成项目和保存人工审核记录的请求体。创建项目示例中的有效期只用于演示，过期后应创建新策略版本，不能通过修改系统时间绕过。

## 当前限制

- 只支持 HAR；不支持 Burp XML、OpenAPI 或 JS AST。
- Scope 只支持精确主机，不支持通配域名。
- 本地 LLM 适配器已提供，但项目不捆绑或自动下载模型；模型质量取决于用户选择和固定评估。
- 身份档案只保存别名、角色和对象归属说明，不保存登录凭据，也不会代替人工验证工具。
- 直接在普通本机进程运行适合合成数据开发，尚未提供经过验证的解析/分析网络隔离容器配置；真实材料不得据此视为完成安全验收。
- P0 不保留上传原件；API 将文件读入有限内存并只写脱敏后的结构化记录。生产级故障隔离和重启清理仍需后续容器部署阶段验证。

准确的实现进度和下一步见 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)。

## 公开开发

欢迎针对授权边界、数据最小化、证据追踪和报告流程提交问题或改进。提交前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；ScopePilot 自身的安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。
