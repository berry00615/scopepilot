# 常见部署暴露：纯 HAR 离线检查

更新：2026-10-06。新增目录索引、Git 配置和环境配置三项检查。它们只分析用户已经导入、且通过范围检查的 HAR；不会发现新 URL、读取源码路径、跟随链接、执行脚本、下载目录或向研究目标发送请求。

选择依据是现有响应材料能够支持较清楚的内容判据，以及有成熟开源定义可参考。OWASP 分类排名不等于命中率，也不说明容易获得漏洞奖励；这里不推测频率数字。

## 官方来源与固定版本

2026-10-06 通过 GitHub 官方 API 读取 nuclei-templates 的 main 引用，再仅在内存中读取以下小文件，固定提交为 **a638cbe6c48f164725ec31fd6fd90eebfd063037**。未下载模板库或新的执行器。

| 官方定义 | 借鉴内容 | 原文件 SHA-256 |
|---|---|---|
| [dir-listing.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/a638cbe6c48f164725ec31fd6fd90eebfd063037/http/miscellaneous/dir-listing.yaml) | 目录索引标题特征；本实现另要求 HTML 列表结构，避免仅凭字符串命中 | 616275a73fd26c454f3cd3f4304641975b7609dedf61c5255ebae42f4650706c |
| [git-config.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/a638cbe6c48f164725ec31fd6fd90eebfd063037/http/exposures/configs/git-config.yaml) | 对应路径、200 响应、非 HTML、Git 配置节名 | bd8bdfa0b5ed5bf4d3712edb793adfd0987d9282e51c6f7d673bf14b9e4dd524 |
| [laravel-env.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/a638cbe6c48f164725ec31fd6fd90eebfd063037/http/exposures/configs/laravel-env.yaml) | 环境配置路径、200 响应、非 HTML、APP_/DB_ 字段特征 | 37566f5fb1764be65072836390d4ff3f40af4917ecf00bdb08dbfcf862bb09c7 |

上游使用 [MIT 许可证](https://github.com/projectdiscovery/nuclei-templates/blob/a638cbe6c48f164725ec31fd6fd90eebfd063037/LICENSE.md)，版权标记为 Copyright (c) 2025 ProjectDiscovery, Inc.；许可证文件 SHA-256 为 5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c。这里只参考检测定义并独立实现更严格的离线结构检查，不复制或执行上游请求、路径枚举或秘密值提取器，也不沿用上游 CVSS。

[OWASP WSTG-CONF-04](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/) 明确指出，自定义 404 可能返回 200，文件名及状态码不能单独证明敏感内容暴露。本实现因此同时检查路径和内容结构，并保留人工复核要求。

比较后暂不新增 source map 规则：只有 sourceMappingURL 引用不足以证明对应映射文件可访问或包含非预期敏感源码；这类判断依赖材料完整性与发布意图。[OWASP WSTG-INFO-05](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/) 也要求结合敏感性和上下文评估。另核实 [ZAP Directory Browsing](https://www.zaproxy.org/docs/alerts/0/) 属于主动规则，未将其误称为被动规则或引入执行。

## 最小判据与误报对照

三项检查共同要求已有 GET / HTTP 200 响应。缺少响应正文、HEAD、POST、重定向、401、403、404、500 均不据此产生新的暴露候选。

| 检查 | 最小内容定义 | 误报对照与边界 | 本地候选 |
|---|---|---|---|
| 目录索引 | title/h1 以已知目录索引标题开头；存在 table/pre/ul 列表容器；至少两个相对链接；不包含 form 或 code 元素 | 普通导航、仅提及目录索引的文档、注释/脚本字符串、登录表单均不命中。公开下载目录仍可能是合理配置，不能确认文件泄露。未实现所有 IIS 或自定义索引变体 | directory_index_review；hardening / info |
| Git 配置 | 路径以 /.git/config 结束；正文由 INI 节与赋值组成；core 节含典型 Git 属性，或 credential/credentials 节含对应属性；拒绝 HTML、JSON、XML 和正文夹杂说明文本 | 单独节名、其他 INI、登录页、带 Markdown 围栏的配置示例、不对应的文档路径均不命中。不能由此推出完整仓库可下载或未认证访问 | git_config_exposure_review；vulnerability / unrated |
| 环境配置 | 文件名为 .env 或受支持的点/下划线/短横线后缀；全体非注释行均为环境变量赋值；至少两个已知配置字段，且至少一个已知秘密字段不是空值或明确占位值 | .env.example/.sample/.template、仅非敏感元数据、明确占位值、登录/错误 HTML、文档围栏与不对应的文档路径不命中。不会据此宣称 Laravel 框架或秘密有效 | env_config_exposure_review；vulnerability / unrated |

环境配置已知秘密字段包括 APP_KEY、APP_PASSWORD、DB_PASSWORD、MAIL_PASSWORD、REDIS_PASSWORD。为空或明确的 example、changeme、占位变量引用等不满足秘密内容条件；此判断只减少误报，不验证凭据。引号跨行值、复杂 Git 多行配置或其他框架格式可能漏检。

目录结构只检查正文前 65,536 字符；配置正文超过该限制时不推断结构。目录仅有一个链接、其他语言标题或包含表单的自定义目录页也可能漏检。没有命中不能证明目标不存在这些问题。

## 数据保留与复核

- 在临时内存中识别内容，只输出 directory_index_observed、git_config_observed、env_config_observed 等固定信号，不保存提取值。
- **所有受支持的 Git/.env 路径响应**，无论是否命中或 HTTP 状态如何，正文均替换为固定省略标记；因此不会保存 Git remote URL、任意数据库字段或未知环境变量值。
- **匹配目录结构的响应**整体省略 HTML 正文，不保存目录文件名、链接或行内容。既有请求目标、状态和脱敏响应头仍保留用于追溯。
- 新候选均由现有服务存为 pending_review；目录只作为配置加固，配置内容线索保持未评级。规则不会自动确认或生成 CVSS。
- 后续复核需要检查已有授权身份、部署意图、生产/示例属性和实际影响。不自动读取目录内文件、重建仓库，或使用疑似凭据登录任何服务。
- 历史证据不恢复原始正文；这些信号在新 HAR 导入时生成。现有通用安全头、调试错误或敏感内容规则独立运行，可能另有其自身线索。

## 合成测试

[tests/test_common_exposures.py](../tests/test_common_exposures.py) 包含正常页面、结构阳性、非 200 状态、登录页、软 404、文档示例、示例文件与占位值、正文大小界限、持久化无原值、待复核状态及重复分析对照。全部材料在测试中构造，不启动服务、不访问研究目标。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_common_exposures.py tests/test_parsers_v1.py tests/test_sanitize.py -q --basetemp .cache\pytest-common
```

该组合定向运行通过 96 项测试；这只是本次离线增补的验证，不代表主动测试或系统网络隔离验收。
