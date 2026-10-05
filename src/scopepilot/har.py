import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .sanitize import pseudonym, sanitize_body, sanitize_headers, sanitize_text
from .schemas import PolicyCreate
from .scope import evaluate_url

MAX_ENTRIES = 2_000


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
    query: dict[str, str]
    request_body: Any
    response_status: int | None
    response_body: Any


def parse_har(project_id: str, content: bytes, policy: PolicyCreate) -> list[ParsedEntry]:
    try:
        document = json.loads(content)
        entries = document["log"]["entries"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HarError("file is not a valid HAR document") from exc
    if not isinstance(entries, list):
        raise HarError("HAR entries must be a list")
    if len(entries) > MAX_ENTRIES:
        raise HarError(f"HAR contains more than {MAX_ENTRIES} entries")

    parsed_entries: list[ParsedEntry] = []
    for index, entry in enumerate(entries):
        try:
            request = entry["request"]
            response = entry.get("response", {})
            url = str(request["url"])
            method = str(request["method"]).upper()
        except (KeyError, TypeError) as exc:
            raise HarError(f"entry {index} has no valid request") from exc
        decision = evaluate_url(policy, url)
        request_content = request.get("postData", {}) or {}
        response_content = response.get("content", {}) or {}
        query = {key: sanitize_text(value) for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
        for key in list(query):
            if any(marker in key.lower() for marker in ("token", "password", "secret", "key")):
                query[key] = "[REDACTED]"
            elif key.lower() == "id" or key.lower().endswith("id") or key.lower().endswith("_id"):
                query[key] = pseudonym(project_id, query[key])
        parsed_entries.append(
            ParsedEntry(
                entry_index=index,
                allowed=decision.allowed,
                scope_reason=decision.reason,
                method=method,
                normalized_url=decision.normalized_url,
                path=urlsplit(url).path or "/",
                request_headers=sanitize_headers(request.get("headers", [])),
                query=query,
                request_body=sanitize_body(project_id, request_content.get("text"), request_content.get("mimeType")),
                response_status=response.get("status") if isinstance(response.get("status"), int) else None,
                response_body=sanitize_body(project_id, response_content.get("text"), response_content.get("mimeType")),
            )
        )
    return parsed_entries
