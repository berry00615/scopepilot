# 开源复用决策（2026-10-05）

在实现前通过官方 GitHub 仓库、发布页和许可证完成比较。只引入必要组件，不整合大型扫描平台。

| 仓库 | 决定 | 依据与边界 |
|---|---|---|
| https://github.com/projectdiscovery/nuclei | 官方 v3.11.1 独立工具适配；JSONL 导入 | MIT；官方 Windows 包 46,067,128 字节，有发布 SHA-256 和 checksums。仅固定、审查过的有限模板；关闭更新、Interactsh、重定向及非 HTTP 能力，未验证隔离前不运行危险测试。 |
| https://github.com/projectdiscovery/nuclei-templates | 只挑选所需官方模板，固定提交并保留许可证 | MIT；不下载完整模板库，不启用任意模板或自动更新。 |
| https://github.com/gitleaks/gitleaks | 官方 v8.30.1 结果适配，必要时单独运行合成材料 | MIT；官方 Windows 包 8,438,883 字节，有发布 SHA-256。仅处理用户指定项目或合成材料。上游现已宣告功能冻结、继续安全补丁；不自动迁移到新工具。 |
| https://github.com/microsoft/playwright-python | 用于浏览器验收，至多一种浏览器 | Apache-2.0；不成为应用运行依赖；使用隔离测试浏览器资料。 |
| https://github.com/DefectDojo/django-DefectDojo | 参考发现/来源/去重组织方式，不导入平台 | BSD-3-Clause；独立 Django 平台和依赖规模不符合现有轻量 FastAPI 架构。 |
| https://github.com/Markfesenk0/har-analyzer | 不复用 | 仓库未标明许可证，且核心方式是 LLM 驱动流量重放/变异，与离线优先和默认关闭目标请求不符。 |

安全头/Cookie/CORS 检查需要在现有 HAR 脱敏流程内完成，采用 Python 标准库解析，少量规则补充。外部扫描检测能力优先交给成熟工具；本项目仅承担范围、证据、去重、复核和展示。所有工具命中保持待验证；无证据的严重性为未评级，不生成 CVSS。

## 实际固定版本与改动

- 官方模板固定于 `projectdiscovery/nuclei-templates` 提交 `6fe741cf4df683674c78b85d99b31109f5ed34c4`，仅取 `http/misconfiguration/http-missing-security-headers.yaml`，原件与 MIT 许可证保留在包资源中。
- `scopepilot-offline-headers.yaml` 是明确标注的派生规则：离线 Nuclei 使用 `all_headers` 而非原在线规则的 `header`；禁用重定向，移除不再适用的原签名。运行前校验派生规则固定 SHA-256，不把修改后的规则冒充上游签名版本。
- Playwright Python `1.58.0`，仅安装 Chromium Headless Shell `145.0.7632.6`（build 1208），由官方 Microsoft 包指定的 `cdn.playwright.dev/chrome-for-testing-public` 分发；附带其必需的 FFmpeg/Winldd 辅助工具。没有另装 Firefox/WebKit。未发现独立上游浏览器校验文件，不把自行计算哈希当来源证明。
- Codex 使用官方 [Python MCP SDK v1.26.0](https://github.com/modelcontextprotocol/python-sdk/tree/v1.26.0)，不手写 MCP 传输协议。
- v1 后按追加要求，再查阅固定提交的官方目录索引、Git 与环境配置模板，只参考其响应判据增补 HAR 离线检查，不执行原模板请求或秘密值提取器；来源、哈希和比较见 [COMMON_CHECKS.md](COMMON_CHECKS.md)。
- Python 包锁文件保留官方 PyPI 各平台 wheel SHA-256；`docs/python-dependencies.json` 记录本次下载对应版本、来源、许可证与体积。Nuclei/Gitleaks 官方档案同时核对 GitHub 发布资产 digest 与上游 checksums 文件，见 `tool-lock.json` 和 `docs/tool-installation.json`。
