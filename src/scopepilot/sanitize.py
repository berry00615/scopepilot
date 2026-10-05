import hashlib
import json
import re
from typing import Any


SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
SECRET_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|session|credential)")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
KEY_VALUE_SECRET = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|session)=([^&\s]+)")


def pseudonym(project_id: str, value: str) -> str:
    digest = hashlib.sha256(f"{project_id}:{value}".encode()).hexdigest()[:12]
    return f"obj_{digest}"


def sanitize_headers(headers: list[dict[str, Any]]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for header in headers:
        name = str(header.get("name", "")).strip()
        value = str(header.get("value", ""))
        clean[name] = "[REDACTED]" if name.lower() in SECRET_HEADERS else sanitize_text(value)
    return clean


def sanitize_text(value: str) -> str:
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = KEY_VALUE_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    value = EMAIL.sub("[EMAIL]", value)
    return value[:8000]


def sanitize_json(project_id: str, value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_KEYS.search(str(key)):
                result[str(key)] = "[REDACTED]"
            elif re.search(r"(?i)(^|_)(user|account|order|object)?_?id$", str(key)) and isinstance(item, (str, int)):
                result[str(key)] = pseudonym(project_id, str(item))
            else:
                result[str(key)] = sanitize_json(project_id, item)
        return result
    if isinstance(value, list):
        return [sanitize_json(project_id, item) for item in value[:100]]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def sanitize_body(project_id: str, text: str | None, mime_type: str | None) -> Any:
    if not text:
        return None
    if mime_type and "json" in mime_type.lower():
        try:
            return sanitize_json(project_id, json.loads(text))
        except json.JSONDecodeError:
            pass
    return sanitize_text(text)
