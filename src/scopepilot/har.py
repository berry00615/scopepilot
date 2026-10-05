import base64
import binascii
import re
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .sanitize import (CREDENTIAL_TOKEN, OBJECT_KEYS, PRIVATE_KEY, SECRET_KEYS,
                       load_json_limited, pseudonym, sanitize_body, sanitize_headers,
                       sanitize_json, sanitize_path, sanitize_text, sanitize_url)
from .schemas import PolicyCreate
from .scope import evaluate_url

MAX_ENTRIES = 2_000
MAX_HAR_BYTES = 10 * 1024 * 1024
MAX_BODY_CHARS = 1024 * 1024
MAX_HEADERS = 300


class HarError(ValueError):
    pass


@dataclass
class ParsedEntry:
    entry_index: int
    allowed: bool
    scope_reason: str
    method: str
    normalized_url: str | None
    path: str
    request_headers: dict[str, str]
    query: dict[str, Any]
    request_body: Any
    response_status: int | None
    response_body: Any
    response_headers: dict[str, str] = field(default_factory=dict)
    response_cookies: list[dict] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise HarError(f"{label} must be an object")
    return value


def _headers(value: Any, label: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_HEADERS:
        raise HarError(f"{label} must be a list with at most {MAX_HEADERS} headers")
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            raise HarError(f"{label} requires string header names and values")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", item["name"]) or len(item["value"]) > 32768 or "\r" in item["value"] or "\n" in item["value"]:
            raise HarError(f"{label} contains an invalid or oversized header")
    return value


def _body(container: dict, label: str) -> tuple[str | None, str | None]:
    text, mime = container.get("text"), container.get("mimeType")
    if text is not None and (not isinstance(text, str) or len(text) > MAX_BODY_CHARS):
        raise HarError(f"{label} text must be a string within the 1 MiB character limit")
    if mime is not None and (not isinstance(mime, str) or len(mime) > 256):
        raise HarError(f"{label} mimeType must be a short string")
    encoding = container.get("encoding")
    if encoding is not None:
        if encoding != "base64":
            raise HarError(f"{label} has unsupported content encoding")
        try:
            text = base64.b64decode(text or "", validate=True).decode("utf-8")
        except (binascii.Error, UnicodeError):
            text = "[BINARY_OR_INVALID_BASE64_CONTENT_OMITTED]"
    return text, mime


def _cookies(project_id: str, response: dict, headers: list[dict]) -> tuple[list[dict], list[str]]:
    result, signals = [], []
    explicit_names = set()
    for header in headers:
        if header["name"].lower() != "set-cookie":
            continue
        jar = SimpleCookie()
        try:
            jar.load(header["value"])
        except CookieError:
            signals.append("cookie_parse_incomplete")
            continue
        if not jar:
            signals.append("cookie_parse_incomplete")
        for name, morsel in jar.items():
            explicit_names.add(name)
            same_site = str(morsel["samesite"]).lower()
            result.append({"name": sanitize_text(name), "secure": bool(morsel["secure"]),
                           "httpOnly": bool(morsel["httponly"]), "sameSite": same_site if same_site in {"lax", "strict", "none"} else "invalid" if same_site else None,
                           "path": sanitize_path(project_id, morsel["path"]) if morsel["path"] else None,
                           "domain": sanitize_text(morsel["domain"]) or None, "source": "set-cookie"})
    cookies = response.get("cookies", [])
    if not isinstance(cookies, list) or len(cookies) > 300:
        raise HarError("response cookies must be a list with at most 300 items")
    for item in cookies:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or len(item["name"]) > 256:
            raise HarError("response cookie requires a short string name")
        for attr in ("secure", "httpOnly"):
            if attr in item and not isinstance(item[attr], bool):
                raise HarError(f"response cookie {attr} must be a boolean")
        for attr in ("sameSite", "path", "domain"):
            if attr in item and (not isinstance(item[attr], str) or len(item[attr]) > 2048):
                raise HarError(f"response cookie {attr} must be a bounded string")
        if item["name"] not in explicit_names:
            same_site = item.get("sameSite", "").lower()
            result.append({"name": sanitize_text(item["name"]), "secure": item.get("secure"),
                           "httpOnly": item.get("httpOnly"), "sameSite": same_site if same_site in {"lax", "strict", "none"} else "invalid" if same_site else None,
                           "path": sanitize_path(project_id, item["path"]) if item.get("path") else None,
                           "domain": sanitize_text(item.get("domain", "")) or None, "source": "har-cookie"})
    return result, signals


def _body_signals(text: str | None, mime: str | None) -> list[str]:
    if not text:
        return []
    signals = []
    if re.search(r"(?i)(traceback \(most recent call last\)|stack trace:|fatal error:|sqlsyntaxerrorexception|you have an error in your sql syntax|at [\w.$]+\([^\n]*:\d+\))", text):
        signals.append("debug_error_detail")
    if CREDENTIAL_TOKEN.search(text) or PRIVATE_KEY.search(text):
        signals.append("suspected_sensitive_content")
    # Token fields in authentication responses are normal; a key name alone is
    # not enough to label an exposure. A manual context review is still required.
    if re.search(r'''(?i)["']?(?:password|passwd|private[_-]?key|api[_-]?key)["']?\s*[:=]\s*["']?[^\s"'\]},;]{4,}''', text):
        signals.append("suspected_sensitive_content")
    if (mime and "html" in mime.lower()) or re.search(r"(?i)<(?:!doctype html|html)[\s>]", text[:1024]):
        signals.append("html_response")
    return list(dict.fromkeys(signals))


def parse_har(project_id: str, content: bytes, policy: PolicyCreate) -> list[ParsedEntry]:
    try:
        document = _object(load_json_limited(content, max_bytes=MAX_HAR_BYTES), "HAR document")
        log = _object(document.get("log"), "HAR log")
        entries = log.get("entries")
    except ValueError as exc:
        raise HarError(f"file is not a valid bounded HAR document: {exc}") from exc
    if not isinstance(entries, list):
        raise HarError("HAR entries must be a list")
    if len(entries) > MAX_ENTRIES:
        raise HarError(f"HAR contains more than {MAX_ENTRIES} entries")

    parsed_entries: list[ParsedEntry] = []
    for index, entry in enumerate(entries):
        entry = _object(entry, f"entry {index}")
        request = _object(entry.get("request"), f"entry {index} request")
        response = _object(entry.get("response", {}), f"entry {index} response")
        url, method = request.get("url"), request.get("method")
        if not isinstance(url, str) or not url or len(url) > 16384 or any(ord(c) < 32 for c in url):
            raise HarError(f"entry {index} requires a bounded URL string")
        if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]{1,24}", method):
            raise HarError(f"entry {index} requires a valid HTTP method")
        method = method.upper()
        decision = evaluate_url(policy, url)
        request_content = _object(request.get("postData", {}), f"entry {index} postData")
        response_content = _object(response.get("content", {}), f"entry {index} response content")
        req_text, req_mime = _body(request_content, "request body")
        res_text, res_mime = _body(response_content, "response body")
        req_headers = _headers(request.get("headers", []), "request headers")
        res_headers = _headers(response.get("headers", []), "response headers")
        status = response.get("status")
        if status is not None and (type(status) is not int or not 0 <= status <= 599):
            raise HarError(f"entry {index} response status must be an integer from 0 to 599")
        try:
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=500)
        except ValueError as exc:
            raise HarError(f"entry {index} has malformed URL or too many query fields") from exc
        query = {}
        for key, value in pairs:
            clean = "[REDACTED]" if SECRET_KEYS.search(key) or key.lower() == "key" else pseudonym(project_id, value) if OBJECT_KEYS.search(key) or key.lower().endswith("id") else sanitize_text(value)
            safe_key = sanitize_text(key)
            if safe_key in query:
                query[safe_key] = [*query[safe_key], clean] if isinstance(query[safe_key], list) else [query[safe_key], clean]
            else:
                query[safe_key] = clean
        cookies, signals = _cookies(project_id, response, res_headers)
        signals.extend(_body_signals(res_text, res_mime))
        if res_mime and "html" in res_mime.lower() and "html_response" not in signals:
            signals.append("html_response")
        # Scope uses the original URL; sanitisation also starts from its encoded
        # form so a percent-encoded '?' or '#' never changes target identity.
        safe_url = sanitize_url(project_id, url) if decision.normalized_url else None
        request_body = sanitize_body(project_id, req_text, req_mime)
        if req_text is None and "params" in request_content:
            params = request_content["params"]
            if not isinstance(params, list) or len(params) > 500:
                raise HarError("postData params must be a list with at most 500 entries")
            fields = {}
            for param in params:
                if not isinstance(param, dict) or not isinstance(param.get("name"), str) or not isinstance(param.get("value", ""), str):
                    raise HarError("postData params require string names and values")
                fields[param["name"]] = param.get("value", "")
            request_body = sanitize_json(project_id, fields)
        parsed_entries.append(
            ParsedEntry(
                entry_index=index,
                allowed=decision.allowed,
                scope_reason=decision.reason,
                method=method,
                normalized_url=safe_url,
                path=urlsplit(safe_url).path if safe_url else "/",
                request_headers=sanitize_headers(req_headers, project_id),
                query=query,
                request_body=request_body,
                response_status=status,
                response_body=sanitize_body(project_id, res_text, res_mime),
                response_headers=sanitize_headers(res_headers, project_id),
                response_cookies=cookies,
                signals=list(dict.fromkeys(signals)),
            )
        )
    return parsed_entries
