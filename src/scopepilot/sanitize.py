"""Bounded data minimisation; tool adapters additionally use metadata allowlists."""
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_TEXT = 8_000
REDACTED = "[REDACTED]"
SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
SECRET_KEYS = re.compile(r"(?i)(password|passwd|secret|token|(?:api|access)[_-]?key|session|credential|authorization|cookie|private[_-]?key|signature|csrf|^(?:auth|key|code)$)")
OBJECT_KEYS = re.compile(r"(?i)(^id$|[_-]id$|(?:user|account|order|object|customer|tenant|invoice|document|project)id$)")
BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
KEY_VALUE_SECRET = re.compile(r'''(?ix)(["']?(?:[\w-]*(?:password|passwd|secret|token|(?:api|access)[_-]?key|session|credential|private[_-]?key|signature|csrf)[\w-]*|\b(?:auth|key|code))["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^&\s,;}<>]+)''')
AUTH_LINE = re.compile(r'''(?im)\b(authorization|proxy-authorization|cookie|set-cookie)["']?\s*[:=]\s*[^\r\n]+''')
URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/?#]+@")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|\Z)", re.S)
CREDENTIAL_TOKEN = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
TEXT_URL = re.compile(r'''(?i)https?://[^\s<>"']+''')
OBJECT_SEGMENT = re.compile(r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|[0-9a-fA-F]{16,}|[A-Za-z0-9_=-]{24,})$")
OBJECT_PARENTS = {"users", "accounts", "orders", "objects", "customers", "tenants", "invoices", "documents", "projects"}
STATIC_SEGMENTS = {"me", "self", "current", "search", "list", "new", "create", "count", "export", "import", "profile", "settings", "status", "all"}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object keys are not accepted")
        result[key] = value
    return result


def load_json_limited(content: bytes | str, *, max_bytes: int = 10 * 1024 * 1024) -> Any:
    """Reject excessive size/depth, duplicate keys and non-finite numbers."""
    if not isinstance(content, (bytes, str)):
        raise ValueError("JSON input must be text or bytes")
    if len(content) > max_bytes or (isinstance(content, str) and len(content.encode("utf-8")) > max_bytes):
        raise ValueError(f"JSON exceeds {max_bytes} byte limit")
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON numbers are not accepted")
    try:
        value = json.loads(content, object_pairs_hook=_unique_object, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid or excessively nested JSON") from exc
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON exceeds structure or depth limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def pseudonym(project_id: str, value: str) -> str:
    digest = hashlib.sha256(f"{project_id}:{value}".encode()).hexdigest()[:12]
    return f"obj_{digest}"


def sanitize_headers(headers: list[dict[str, Any]], project_id: str = "") -> dict[str, str]:
    clean: dict[str, str] = {}
    canonical: dict[str, str] = {}
    for header in headers:
        name = str(header.get("name", "")).strip()
        value = str(header.get("value", ""))
        key = canonical.setdefault(name.lower(), name)
        # This CORS boolean contains "credentials" in its name but no secret;
        # preserving it is necessary to evaluate the actual response policy.
        if name.lower() in SECRET_HEADERS or (SECRET_KEYS.search(name) and name.lower() != "access-control-allow-credentials"):
            clean[key] = REDACTED
        else:
            sanitized = sanitize_url(project_id, value, include_query=True) if name.lower() in {"location", "referer", "referrer", "origin"} and value.lower().startswith(("http://", "https://")) else sanitize_text(value)
            clean[key] = f"{clean[key]}, {sanitized}" if key in clean else sanitized
    return clean


def sanitize_text(value: str) -> str:
    value = str(value)
    value = PRIVATE_KEY.sub(REDACTED, value)
    value = URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = TEXT_URL.sub(_redact_text_url, value)
    value = AUTH_LINE.sub(lambda match: f"{match.group(1)}: {REDACTED}", value)
    value = BEARER.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = KEY_VALUE_SECRET.sub(lambda match: f'{match.group(1)}"{REDACTED}"', value)
    value = CREDENTIAL_TOKEN.sub(REDACTED, value)
    value = EMAIL.sub("[EMAIL]", value)
    return value[:MAX_TEXT]


def _redact_text_url(match: re.Match) -> str:
    """Handle percent-encoded query names without recursively parsing text."""
    try:
        parsed = urlsplit(match.group(0))
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=500)
        safe_pairs = []
        for key, value in pairs:
            if SECRET_KEYS.search(key):
                value = REDACTED
            elif OBJECT_KEYS.search(key):
                value = pseudonym("report", value)
            else:
                value = URL_USERINFO.sub(r"\1[REDACTED]@", value)
                value = KEY_VALUE_SECRET.sub(lambda item: f'{item.group(1)}"{REDACTED}"', value)
                value = EMAIL.sub("[EMAIL]", CREDENTIAL_TOKEN.sub(REDACTED, value))
            safe_pairs.append((key, value))
        query = urlencode(safe_pairs)
        return urlunsplit((parsed.scheme, parsed.netloc, sanitize_path("report", parsed.path), query, ""))
    except ValueError:
        return "[INVALID_URL]"


def sanitize_path(project_id: str, path: str) -> str:
    parts = unquote(path or "/").split("/")
    result = []
    for index, part in enumerate(parts):
        previous = parts[index - 1].lower() if index else ""
        if re.fullmatch(r"obj_[0-9a-f]{12}", part):
            result.append(part)
        elif SECRET_KEYS.search(previous) and part:
            result.append("redacted")
        elif part and (OBJECT_SEGMENT.fullmatch(part) or (previous in OBJECT_PARENTS and part.lower() not in STATIC_SEGMENTS)):
            result.append(pseudonym(project_id, part))
        else:
            result.append(quote(sanitize_text(part), safe="-._~:@!$&'()*+,;="))
    return "/".join(result) or "/"


def sanitize_url(project_id: str, url: str, *, include_query: bool = False) -> str:
    """Preserve the origin, including port; discard userinfo and fragments."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return "[INVALID_URL]"
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        host = f"[{host}]" if ":" in host else host
        port = parsed.port or (443 if scheme == "https" else 80)
        query = ""
        if include_query:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=500)
            query = urlencode([(sanitize_text(key), REDACTED if SECRET_KEYS.search(key) else pseudonym(project_id, value) if OBJECT_KEYS.search(key) else sanitize_text(value)) for key, value in pairs])
        return urlunsplit((scheme, f"{host}:{port}", sanitize_path(project_id, parsed.path), query, ""))
    except (ValueError, UnicodeError):
        return "[INVALID_URL]"


def target_identity(url: str) -> str:
    return re.sub(r"(?<=/)obj_[0-9a-f]{12}(?=/|$)", "{object}", url)


def sanitize_json(project_id: str, value: Any, _depth: int = 0) -> Any:
    if _depth > MAX_JSON_DEPTH:
        return "[DEPTH_LIMIT]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:500]:
            clean_key = sanitize_text(str(key))
            if SECRET_KEYS.search(str(key)):
                result[clean_key] = REDACTED
            elif OBJECT_KEYS.search(str(key)) and isinstance(item, (str, int)):
                result[clean_key] = pseudonym(project_id, str(item))
            else:
                result[clean_key] = sanitize_json(project_id, item, _depth + 1)
        return result
    if isinstance(value, list):
        return [sanitize_json(project_id, item, _depth + 1) for item in value[:100]]
    if isinstance(value, str):
        if value.lower().startswith(("http://", "https://")):
            return sanitize_url(project_id, value, include_query=True)
        return sanitize_text(value)
    return value


def sanitize_body(project_id: str, text: str | None, mime_type: str | None) -> Any:
    if not text:
        return None
    if (mime_type and "json" in mime_type.lower()) or text.lstrip().startswith(("{", "[")):
        try:
            return sanitize_json(project_id, load_json_limited(text, max_bytes=1024 * 1024))
        except ValueError:
            return "[INVALID_OR_OVERSIZED_JSON_BODY]"
    if mime_type and "x-www-form-urlencoded" in mime_type.lower():
        try:
            return sanitize_json(project_id, dict(parse_qsl(text, keep_blank_values=True, max_num_fields=500)))
        except ValueError:
            return "[OVERSIZED_FORM_BODY]"
    return sanitize_text(text)
