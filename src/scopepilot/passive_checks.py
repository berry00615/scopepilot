"""Offline clues only: no requests, automatic confirmation, or CVSS scores."""
import re
from urllib.parse import urlsplit


def _candidate(kind: str, claim: str, *, category: str = "hardening", severity: str = "low", reason: str | None = None, remediation: str, missing: str, manual: str) -> dict:
    return {"finding_type": kind, "claim": claim, "severity": severity,
            "severity_reason": reason or "仅依据导入响应的配置观察给出加固优先级，尚无可利用性与影响证据。",
            "category": category, "remediation": remediation,
            "missing_information": missing, "suggested_manual_check": manual}


def _object_keys(value, depth: int = 0) -> set[str]:
    if depth > 16:
        return set()
    if isinstance(value, dict):
        result = {str(key) for key in value if str(key).lower() == "id" or str(key).lower().endswith("id") or str(key).lower().endswith("_id")}
        for item in list(value.values())[:100]:
            result.update(_object_keys(item, depth + 1))
        return result
    if isinstance(value, list):
        return set().union(*(_object_keys(item, depth + 1) for item in value[:100])) if value else set()
    return set()


def _origin_key(value: str):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def check_payload(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    headers = {str(key).lower(): str(value) for key, value in (payload.get("response_headers") or {}).items()}
    request_headers = {str(key).lower(): str(value) for key, value in (payload.get("request_headers") or {}).items()}
    signals = set(payload.get("signals") or [])
    result = []
    html = "html_response" in signals or "text/html" in headers.get("content-type", "").lower()
    status = payload.get("response_status")
    response_observed = type(status) is int and status > 0
    if html and response_observed:
        if not headers.get("content-security-policy"):
            result.append(_candidate("missing_content_security_policy", "HTML 响应未观察到执行型 Content-Security-Policy，需核查页面级策略。",
                remediation="根据页面资源制定 CSP，先观察兼容性再启用执行策略。", missing="页面是否包含内联 CSP、动态资源与浏览器实际执行策略。", manual="检查完整页面、响应头及浏览器策略；缺少头本身不能证明 XSS。"))
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            result.append(_candidate("missing_content_type_options", "HTML 响应未观察到有效 X-Content-Type-Options: nosniff。",
                remediation="返回正确 Content-Type，并配置 X-Content-Type-Options: nosniff。", missing="实际内容类型与浏览器内容嗅探行为。", manual="在自有页面检查实际响应类型及浏览器行为。"))
        if headers.get("x-frame-options", "").lower().strip() not in {"deny", "sameorigin"} and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            result.append(_candidate("missing_frame_protection", "HTML 响应未观察到 X-Frame-Options 或 CSP frame-ancestors。",
                remediation="按业务嵌入需求配置 CSP frame-ancestors。", missing="页面敏感操作、预期嵌入来源与浏览器行为。", manual="用自有测试页面确认是否允许跨源嵌入；仅缺少头不确认点击劫持。"))
    if response_observed and str(payload.get("url", "")).startswith("https://") and not headers.get("strict-transport-security"):
        result.append(_candidate("missing_hsts", "HTTPS 响应未观察到 Strict-Transport-Security。",
            remediation="确认域名全站 HTTPS 兼容后配置合适的 HSTS 策略。", missing="域名其他响应、既有浏览器 HSTS 状态与子域 HTTPS 兼容性。", manual="检查自有域名的代表性响应和 HTTPS 策略；单个 HAR 响应不能证明降级攻击。"))
    for flag, kind, label in (("secure", "cookie_missing_secure", "Secure"), ("httpOnly", "cookie_missing_httponly", "HttpOnly"), ("sameSite", "cookie_missing_samesite", "SameSite")):
        cookies = [cookie for cookie in (payload.get("response_cookies") or []) if isinstance(cookie, dict) and (cookie.get(flag) is False if flag != "sameSite" else cookie.get("source") == "set-cookie" and cookie.get(flag) not in {"lax", "strict", "none"})]
        if cookies:
            result.append(_candidate(kind, f"观察到 {len(cookies)} 个响应 Cookie 未设置有效 {label} 属性；未保存 Cookie 值。",
                remediation=f"按 Cookie 用途配置 {label}，区分会话 Cookie 与需要脚本访问的非敏感 Cookie。", missing="Cookie 的用途、认证关联、传输条件和浏览器版本。", manual="只使用自有会话确认 Cookie 用途与浏览器属性；属性缺失本身不确认凭据泄露。"))
    if any(isinstance(cookie, dict) and cookie.get("sameSite") == "none" and cookie.get("secure") is False for cookie in payload.get("response_cookies") or []):
        result.append(_candidate("cookie_samesite_none_without_secure", "Cookie 声明 SameSite=None 但缺少 Secure，现代浏览器可能拒绝该 Cookie。",
            remediation="确有跨站需求时配合 Secure 使用 SameSite=None，否则评估 Lax/Strict。", missing="目标浏览器及业务跨站依赖。", manual="在自有测试环境检查浏览器是否接收 Cookie 与认证流程是否受影响。"))
    if "cookie_parse_incomplete" in signals:
        result.append(_candidate("cookie_attributes_unparsed", "部分 Set-Cookie 格式无法可靠解析，属性检查可能不完整。", severity="info",
            remediation="检查服务器输出是否符合 Cookie 格式。", missing="无法解析的 Cookie 属性；原始值未留存。", manual="在授权浏览器中检查实际接收到的 Cookie 属性。"))
    origin, credentials = headers.get("access-control-allow-origin", "").strip(), headers.get("access-control-allow-credentials", "").lower().strip()
    if origin == "*" and credentials == "true":
        result.append(_candidate("cors_wildcard_credentials", "CORS 同时声明通配来源与允许凭据；浏览器通常阻止这种组合，不据此确认跨源数据读取。",
            remediation="使用经过验证的精确来源白名单并按需允许凭据。", missing="浏览器实际响应、请求凭据模式及响应敏感性。", manual="使用自有两个来源验证浏览器行为，记录控制请求与测试请求。"))
    elif credentials == "true" and origin and (origin == "null" or (_origin_key(origin) is not None and _origin_key(origin) == _origin_key(request_headers.get("origin", "")))):
        result.append(_candidate("cors_origin_review", "观察到允许凭据的 CORS 来源响应，需要核查来源是否经过严格白名单验证。", category="vulnerability", severity="unrated",
            reason="单个响应无法区分固定白名单与不安全的来源反射；尚无跨源读取或影响证据。", remediation="对来源做精确白名单验证，谨慎处理 null 来源。", missing="来源白名单、对照来源响应、浏览器跨源读取结果与数据敏感性。", manual="仅用自有来源及数据比较允许来源和不允许来源；记录浏览器实际读取结果。"))
    for signal, kind, claim, remediation in (
        ("debug_error_detail", "debug_error_detail", "响应包含调试堆栈或数据库错误特征，需要人工评估暴露内容。", "生产环境关闭详细错误回显，保留受控服务端日志。"),
        ("suspected_sensitive_content", "suspected_sensitive_content", "响应包含疑似敏感字段或凭据格式特征；已脱敏，未确认凭据有效性或非预期暴露。", "核对字段用途、访问控制与返回最小化；如确认秘密泄露则轮换并撤销。"),
    ):
        if signal in signals:
            result.append(_candidate(kind, claim, category="vulnerability", severity="unrated", reason="只有离线内容特征，缺少可访问性、有效性与影响证据。",
                remediation=remediation, missing="响应的预期用途、访问身份、数据真实性与影响范围。", manual="人工检查脱敏证据及自有测试数据；不要使用疑似凭据访问第三方服务。"))
    object_keys = _object_keys(payload.get("query")) | _object_keys(payload.get("request_body"))
    if object_keys or re.search(r"/obj_[0-9a-f]{12}(?:/|$)", str(payload.get("path", ""))):
        result.append(_candidate("object_authorization_review", "接口包含对象标识线索，需要使用自有 A/B 账号核查对象授权。", category="vulnerability", severity="unrated",
            reason="对象标识只构成测试线索，缺少非所有者成功访问及业务影响证据。", remediation="服务端逐对象校验当前身份与对象的访问权限。", missing="账号角色、对象归属、预期拒绝结果及所有者/非所有者对照。", manual="仅使用自有 A/B 账号及自建对象，比较所有者与非所有者结果；出现第三方数据立即停止。"))
    return result
