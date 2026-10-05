"""Strict, offline result adapters for Nuclei v3 and Gitleaks v8.

Imports are atomic: a malformed or out-of-scope row rejects the whole input.
Unknown fields are discarded, never stored. No source path is opened and no
tool, script, template, request, response, or credential is executed.
"""
import re
from pathlib import PurePosixPath
from urllib.parse import quote, unquote

from .sanitize import load_json_limited, sanitize_text, sanitize_url
from .scope import evaluate_url

MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_RESULTS = 2000
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown", "unrated"}
# Classification is based on an explicitly reviewed template identity, never on
# an informational severity or user-controlled title/tag.
HARDENING_TEMPLATES = {"http-missing-security-headers"}
EXAMPLE = re.compile(r"(?i)(?:^\[?redacted\]?$|^<[^<>]+>$|^(?:your[_-]|replace[_-]|insert[_-])|(?:^|[_-])(?:example|sample|dummy|placeholder|changeme|testonly|notareal)(?:[_-]|$)|^x{6,}$)")


def _string(record: dict, key: str, *, required: bool = False, limit: int = 2000) -> str:
    value = record.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"{key} must be a bounded{' nonempty' if required else ''} string")
    return value


def _identifier(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", value):
        raise ValueError(f"{label} is not a supported identifier")
    return value


def _severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in SEVERITIES:
        raise ValueError("unsupported original severity")
    return "unrated" if normalized == "unknown" else normalized


def _relative_path(raw: str) -> str:
    path = raw.replace("\\", "/")
    decoded = unquote(path)
    if any(ord(c) < 32 for c in path) or ":" in decoded or decoded.startswith("/"):
        raise ValueError("source file must be a relative path without drive or absolute prefix")
    if any(part in {"", ".", ".."} for part in decoded.split("/")):
        raise ValueError("source file path contains empty or traversal segments")
    if PurePosixPath(decoded).is_absolute():
        raise ValueError("absolute source paths are not accepted")
    # Encoded separators would make the logical and displayed locator disagree.
    if re.search(r"%(?:2f|5c|25)", path, re.I):
        raise ValueError("encoded source path separators are not accepted")
    return sanitize_text(path)


def _redact_known(value: str, secrets: list[str]) -> str:
    # A copied value may have been URL-encoded in a title or path. Decode before
    # comparing so encoding cannot turn discarded secrets into retained text.
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return sanitize_text(value)


def _reject_known_metadata(values: list[str], secrets: set[str]) -> None:
    """Identity fields cannot safely be replaced without changing their meaning."""
    for value in values:
        decoded = unquote(unquote(value))
        if any(secret in value or secret in decoded for secret in secrets):
            raise ValueError("sensitive material was repeated in retained metadata")


def _gitleaks(record: dict, index: int, source_root: str, version: str) -> dict:
    rule = _identifier(_string(record, "RuleID", required=True, limit=160), "RuleID")
    relative = _relative_path(_string(record, "File", required=True, limit=1024))
    start, end = record.get("StartLine"), record.get("EndLine", record.get("StartLine"))
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 100_000_000:
        raise ValueError("source line positions must be positive ordered integers")
    for key in ("StartColumn", "EndColumn"):
        if key in record and (type(record[key]) is not int or not 0 <= record[key] <= 100_000_000):
            raise ValueError("source column position must be a nonnegative integer")
    secret = _string(record, "Secret", limit=1024 * 1024)
    match = _string(record, "Match", limit=1024 * 1024)
    _string(record, "Description", limit=8000)
    original_raw = _string(record, "Severity", limit=20)
    original = _severity(original_raw or "unrated")
    # A scanner's redaction marker is not evidence that the underlying value was
    # a harmless example. Treat a hidden or omitted value as unverified.
    redacted = bool(re.fullmatch(r'(?i)(?:\[redacted\]|redacted|<redacted>|\*{3,})', secret.strip()))
    example = bool(secret and not redacted and EXAMPLE.search(secret))
    hint = "example" if example else "suspected_credential"
    # Do not infer that test/fixture paths imply a harmless value: real secrets
    # are often accidentally checked into precisely those locations.
    target = f"source://{source_root}/{quote(relative, safe='/-._~')}"
    locator = f"{relative}:{start}" + (f"-{end}" if end != start else "")
    return {"target": target, "method": "SOURCE", "finding_type": f"gitleaks:{rule}",
            "claim": "Gitleaks 标记了示例或占位凭据线索，需要人工核对用途。" if example else "Gitleaks 标记了疑似凭据，需要人工核对有效性、归属与暴露范围。",
            "original_severity": original, "severity": "info" if example else "unrated",
            "original_severity_reason": f"Gitleaks 输出声明 {original_raw}；尚未独立验证。" if original_raw else "Gitleaks 输出未提供原始评级。",
            "severity_reason": "值具有明显示例或脱敏占位特征，未确认实际凭据。" if example else "工具命中不代表凭据真实或有效，尚无影响证据；原始工具评级单独保留。",
            "category": "hardening" if example else "vulnerability", "locator": locator, "hint_kind": hint,
            "evidence": {"tool": "gitleaks", "tool_version": version, "record_index": index,
                         "rule_id": _redact_known(rule, [secret, match]), "source_root": source_root,
                         "original_severity": original, "original_severity_raw": original_raw or None,
                         "file": relative, "start_line": start, "end_line": end,
                         "secret_retained": False, "match_retained": False, "upstream_redacted": redacted, "hint_kind": hint},
            "remediation": "核查凭据用途；若确认为有效秘密则撤销、轮换并清理版本历史，采用秘密管理服务。示例值应明确标注。"}


def _nuclei(record: dict, index: int, project_id: str, policy, version: str, known_values: set[str]) -> dict:
    rule = _identifier(_string(record, "template-id", required=True, limit=160), "template-id")
    info = record.get("info")
    if not isinstance(info, dict):
        raise ValueError("info must be an object")
    title = _string(info, "name", required=True, limit=2000)
    original_raw = _string(info, "severity", required=True, limit=20)
    original = _severity(original_raw)
    protocol = _string(record, "type", required=True, limit=20).lower()
    if protocol != "http":
        raise ValueError("only scoped HTTP Nuclei results are accepted")
    candidates = [_string(record, key, limit=16384) for key in ("matched-at", "url", "host")]
    url = next((item for item in candidates if item), "")
    if not url:
        raise ValueError("HTTP result requires matched-at, url, or host")
    decision = evaluate_url(policy, url)
    if not decision.allowed or not decision.normalized_url:
        raise ValueError(f"Nuclei result is outside authorized scope: {decision.reason}")
    # Host is occasionally a hostname without a scheme; if another URL field
    # contains an explicit origin it must independently satisfy the policy.
    for alternative in candidates:
        if alternative and alternative.lower().startswith(("http://", "https://")) and not evaluate_url(policy, alternative).allowed:
            raise ValueError("Nuclei result contains an out-of-scope URL field")
    raw_request = _string(record, "request", limit=2 * 1024 * 1024)
    request_line = re.match(r"^([A-Z]{1,24}) [^\r\n]* HTTP/\d(?:\.\d)?(?:\r?\n|$)", raw_request)
    # Nuclei does not always export a method. Do not invent GET when a raw
    # exchange was omitted; retain HTTP as an explicitly unknown method.
    method = _string(record, "method", limit=24).upper() or (request_line.group(1) if request_line else "HTTP")
    if not re.fullmatch(r"[A-Z]{1,24}", method):
        raise ValueError("HTTP method is invalid")
    extracted = record.get("extracted-results", [])
    if not isinstance(extracted, list) or len(extracted) > 500 or any(not isinstance(item, str) or len(item) > 1024 * 1024 for item in extracted):
        raise ValueError("extracted-results must be a bounded list of strings")
    for key in ("request", "response", "curl-command"):
        _string(record, key, limit=2 * 1024 * 1024)
    matcher = _string(record, "matcher-name", limit=160)
    if matcher:
        _identifier(matcher, "matcher-name")
    target = sanitize_url(project_id, url)
    safe_title = _redact_known(title, sorted(known_values, key=len, reverse=True))
    hardening = rule in HARDENING_TEMPLATES
    return {"target": target, "method": method, "finding_type": f"nuclei:{rule}",
            "claim": f"Nuclei 模板命中待复核：{safe_title}", "original_severity": original,
            "original_severity_reason": f"Nuclei 模板输出声明 {original_raw}；尚未独立验证。",
            "severity": "unrated", "severity_reason": "仅观察到安全响应头配置加固项；缺少可利用性和影响证据。" if hardening else "原始模板评级已保留；尚缺独立复核、成功判据、对照和实际影响证据。",
            "category": "hardening" if hardening else "vulnerability", "locator": f"Nuclei record {index}; template {rule}", "hint_kind": "configuration_observation" if hardening else "tool_match",
            "evidence": {"tool": "nuclei", "tool_version": version, "record_index": index,
                         "template_id": rule, "template_name": safe_title, "matcher_name": matcher or None,
                         "url": target, "method": method, "original_severity": original, "original_severity_raw": original_raw,
                         "raw_exchange_retained": False, "extracted_results_retained": False},
            "remediation": "审查对应固定版本模板与业务上下文；仅在授权范围内用自有数据复核并依据确认根因修复。"}


def parse_tool_results(tool: str, content: bytes | str, project_id: str, policy, tool_version: str,
                       source_root: str = "source", *, filename: str = "") -> list[dict]:
    """Return safe candidates or reject the complete input with ValueError."""
    if tool not in {"gitleaks", "nuclei"}:
        raise ValueError("unsupported tool; expected gitleaks or nuclei")
    if not isinstance(tool_version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}", tool_version):
        raise ValueError("tool version must be a short explicit version identifier")
    if not isinstance(source_root, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", source_root):
        raise ValueError("source_root must be a short logical source identifier")
    if not isinstance(content, (str, bytes)) or len(content) > MAX_IMPORT_BYTES:
        raise ValueError("tool input exceeds size limit or is not text")
    try:
        text = content.decode("utf-8-sig") if isinstance(content, bytes) else content
    except UnicodeError as exc:
        raise ValueError("tool input must be UTF-8") from exc
    if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("tool input exceeds size limit")
    if tool == "gitleaks":
        rows = load_json_limited(text, max_bytes=MAX_IMPORT_BYTES)
        if not isinstance(rows, list):
            raise ValueError("Gitleaks JSON must be an array")
    else:
        try:
            document = load_json_limited(text, max_bytes=MAX_IMPORT_BYTES)
            rows = document if isinstance(document, list) else [document]
        except ValueError as exc:
            lines = [line for line in text.splitlines() if line.strip()]
            if len(lines) <= 1 or len(lines) > MAX_RESULTS:
                raise ValueError("invalid bounded Nuclei JSON/JSONL") from exc
            rows = [load_json_limited(line, max_bytes=2 * 1024 * 1024) for line in lines]
    if len(rows) > MAX_RESULTS:
        raise ValueError(f"tool input contains more than {MAX_RESULTS} results")
    known_values: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"record {index} must be an object")
        if tool == "gitleaks":
            known_values.update(value for value in (_string(row, "Secret", limit=1024 * 1024),
                                                    _string(row, "Match", limit=1024 * 1024)) if value)
        else:
            extracted = row.get("extracted-results", [])
            if not isinstance(extracted, list) or len(extracted) > 500 or any(not isinstance(value, str) or len(value) > 1024 * 1024 for value in extracted):
                raise ValueError(f"record {index}: extracted-results must be a bounded list of strings")
            known_values.update(value for value in extracted if value)
        if len(known_values) > MAX_RESULTS * 2:
            raise ValueError("tool output exceeds the bounded metadata sanitization budget")
    _reject_known_metadata([tool, tool_version, source_root, filename], known_values)
    result = []
    for index, row in enumerate(rows):
        try:
            fields = ("File", "RuleID", "Severity") if tool == "gitleaks" else ("template-id", "matcher-name", "matched-at", "url", "host", "method")
            _reject_known_metadata([value for field in fields if isinstance(value := row.get(field), str)], known_values)
            if tool == "nuclei" and isinstance(row.get("info"), dict) and isinstance(row["info"].get("severity"), str):
                _reject_known_metadata([row["info"]["severity"]], known_values)
            result.append(_gitleaks(row, index, source_root, tool_version) if tool == "gitleaks" else _nuclei(row, index, project_id, policy, tool_version, known_values))
        except ValueError as exc:
            raise ValueError(f"record {index}: {exc}") from exc
    return result
