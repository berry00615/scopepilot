# ScopePilot v1 交接

## 交付与边界

已在现有 ScopePilot 基础上完成轻量工作台：完整目标身份与多来源去重、HAR 被动检查、Nuclei/Gitleaks 结构化导入、严格人工复核、中文桌面/窄屏 UI、报告、受限任务和 Codex MCP。先检索并复用官方开源组件，未引入大型扫描平台或前端框架。

真实工具仅处理固定内置合成文件。用户目标、上传脚本、任意命令、自动公网扫描和付费模型调用不可用。系统级禁止外联、主动靶场、任意后代进程清理尚未验收；因此整体验收仍有缺项，不执行合并。开发分支已推送；PR 创建被连接器 403 权限错误阻止，不能声称已创建。用户允许按需开启功能后，增加本地启动器启用已验证的合成工具流程；这不等于放开目标或系统安全边界。

## 检查类型与确认

支持响应安全头、Cookie 属性、调试/错误信息、疑似敏感内容、CORS 疑点、对象授权线索，以及官方 Nuclei HTTP 结果和 Gitleaks 相对源码结果导入。缺头与 Cookie 配置归为加固；对象 ID、CORS 反射和工具命中均为待验证线索。

按追加要求，先检索官方 GitHub 规则，再添加目录索引、`.git/config`、`.env` 三项已有 HAR 检查；只使用响应结构，不请求新地址或使用疑似凭据。配置正文和命中的目录正文整段省略，避免保留未知秘密或文件名。目录为信息级加固，配置线索未评级、待复核；公开下载目录可能合理，200 状态不等于漏洞。固定来源与误报边界见 [COMMON_CHECKS.md](COMMON_CHECKS.md)。

保留原始评级、当前评级与人工评级依据。Gitleaks 的 REDACTED 标记仍按疑似凭据处理，不能据此降为无害示例。确认必须有当前项目证据、明确成功判据与适用对照；没有可信依据不生成 CVSS。报告把加固独立列示，不能把演示确认计为真实漏洞。

## 实际验证

| 验证 | 结果与范围 |
|---|---|
| 原仓库基线回归 | 17 通过，单独使用原提交源码运行 |
| 最终本地 pytest | 187 通过；1 条上游 TestClient 弃用提示，无失败；含原有回归、解析、授权、多目标、跨项目、迁移、去重、状态、任务边界、真实 MCP stdio 及新增 49 项部署暴露检查 |
| v1 GitHub CI | [Actions 37337619810](https://github.com/berry00615/scopepilot/actions/runs/37337619810) 在 Python 3.11/3.13 均通过，提交 ae8f5d0；最初 YAML 冒号解析失败已修正，无跳过检查 |
| 新增检查 GitHub CI | [Actions 37340431129](https://github.com/berry00615/scopepilot/actions/runs/37340431129) 在 Python 3.11/3.13 均通过，功能提交 711c2e7；后续仅整理交接记录 |
| 官方工具真实集成 | Nuclei 3.11.1 与 Gitleaks 8.30.1，各阳性、阴性、重复阳性，共 6 轮通过；重复复用材料，不新增重复发现 |
| 浏览器端到端 | Chromium 9 组检查通过：安装后真实启动、项目/导入/分析、四类筛选、详情、取消、合成复核、下载和离线 API 文档；桌面 1440px 与窄屏 390px 已查看截图 |
| Codex 客户端 | 本机 CLI 0.160.0 app-server connected，识别 12 工具，成功调用 capabilities/list_projects；0 模型轮次，无全局配置修改 |
| 禁止外联 | 自建拒绝代理的 HTTP/CONNECT 路径实测拒绝；系统级隔离未验证，不能据此声称全部外联不可行 |
| 交付源码检查 | 官方 Gitleaks 扫描仓库非忽略文本无命中；不代表能识别所有未知秘密格式 |

测试中的人工确认只验证表单、引用和状态规则，没有进行真实漏洞利用。详细记录与复现方式见 [TESTING.md](TESTING.md)、[工具结果](tool-verification.json)、[浏览器结果](browser-verification.json)、[Codex 结果](codex-verification.json)。

## 来源与磁盘

49 个 Python 包固定版本和官方 PyPI wheel 哈希；Nuclei/Gitleaks 对照官方 GitHub 发布资产 digest 与 checksums。只引入一个官方安全头模板，固定提交，保留原件/许可证；离线派生规则明确标注修改。Playwright 1.58.0 只安装 Chromium Headless Shell 145.0.7632.6 及必需辅助工具。依赖来源、许可证、实际下载体积见 [开源决策](OPEN_SOURCE.md)、[Python 清单](python-dependencies.json)、[工具安装清单](tool-installation.json)。

项目内逻辑文件约 **0.83GB**；计入系统盘同期增长的保守余量后约 **1.16GB**，远低于 35/40/50GB 门槛。系统盘同期增长不全部归因本任务；不重复累计项目占用与工作盘增长。精确字节与可用空间见 [disk-usage.json](disk-usage.json)。未安装 Docker/WSL、创建容器/VHDX、修改防火墙/注册表/系统代理或读取个人凭据。额度重置使用 **0 次**。

## 启动与预览

当前项目已安装依赖与固定工具。双击仓库根目录 [start-workbench.cmd](../start-workbench.cmd)，打开 `http://127.0.0.1:8000`。窗口关闭或 Ctrl+C 停止服务；仅这个启动进程启用合成工具，本地模型保持关闭。缺组件按 [README](../README.md) 安装；没有自动下载安装脚本执行。

Codex 项目配置已写入本地 `.codex/config.toml`，不会提交绝对路径。重新打开受信任项目聊天或重建 MCP 连接后使用；本聊天没有热加载工具。详见 [CODEX.md](CODEX.md)。

预览：[桌面截图](images/desktop.png)、[窄屏截图](images/narrow.png)。截图显著标注合成演示，确认数量仅为测试表单生成。测试服务、工具进程与临时数据库在验收后停止/清理，保留项目依赖、工具和必要记录用于复现。

限制：固定单 Web 进程；无生产多用户认证/多 worker 任务协调；文本脱敏不保证识别任意秘密；本地模型适配仅有模拟响应测试，没有真实模型验证；无主动靶场或 XSS 浏览器利用验证、Semgrep/依赖扫描器。

## GitHub 状态

基线 `4c6904bc3edf27a1ed92065cbd36cb03007d8c3e`，唯一开发分支 [codex/scopepilot-v1-20261005](https://github.com/berry00615/scopepilot/tree/codex/scopepilot-v1-20261005)。上游 main 已复核仍为该基线。功能里程碑 `90562ef`，CI 修正 `ae8f5d0`，追加检查 `711c2e7`；最终文档提交在交付消息中列明。

PR **尚未创建**：连接器返回 `403 Resource not accessible by integration`；本机没有 gh CLI，备用浏览器停在登录页，未读取或提取凭据。可从 [创建 PR 页面](https://github.com/berry00615/scopepilot/pull/new/codex/scopepilot-v1-20261005) 使用 [已准备的正文](PR_DRAFT.md) 创建草稿。未合并：系统级隔离仍缺独立证据，不能由模拟成功或较多单元测试替代。

## 下一步三件事

1. 使用有仓库 PR 写权限的 GitHub 连接创建草稿，保留现有分支；不要提交凭据到聊天。
2. 在已有、经授权的隔离运行环境验证禁止外联与进程清理，完成受限执行器的系统级验收后再考虑合并。
3. 在日常 Codex 聊天中加载项目 MCP，结合已脱敏的授权材料继续验证常见检查的误报与复核流程，保持人工确认独立于模型工具。
