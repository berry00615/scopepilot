from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from .url_paths import decoded_path, encoded_path

from .schemas import PolicyCreate, PolicyStatus, ScopeRule


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    normalized_url: str | None = None


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


def _matches(rule: ScopeRule, scheme: str, host: str, port: int, path: str) -> bool:
    prefix = decoded_path(rule.path_prefix).rstrip("/") or "/"
    path_matches = prefix == "/" or path == prefix or path.startswith(prefix + "/")
    return (
        rule.scheme == scheme
        and rule.host == host
        and rule.port == port
        and path_matches
    )


def evaluate_url(policy: PolicyCreate, url: str, now: datetime | None = None) -> ScopeDecision:
    now = now or datetime.now(timezone.utc)
    if policy.status != PolicyStatus.ACTIVE:
        return ScopeDecision(False, f"policy is {policy.status.value}")
    if not policy.valid_from <= now <= policy.valid_until:
        return ScopeDecision(False, "policy is not currently valid")
    try:
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment or any(ord(c) < 32 for c in url):
            return ScopeDecision(False, "ambiguous URL component is not allowed")
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        port = parsed.port if parsed.port is not None else _default_port(scheme)
        raw_path = parsed.path or "/"
        path = decoded_path(raw_path)
        if scheme not in {"http", "https"} or not host or port is None or port == 0:
            return ScopeDecision(False, "URL must contain an HTTP(S) scheme and exact host")
        display_host = f"[{host}]" if ":" in host else host
        normalized_path = encoded_path(path)
        normalized = f"{scheme}://{display_host}:{port}{normalized_path}"
    except (ValueError, UnicodeError):
        return ScopeDecision(False, "URL could not be parsed unambiguously")

    if any(_matches(rule, scheme, host, port, path) for rule in policy.deny):
        return ScopeDecision(False, "explicit deny rule matched", normalized)
    if any(_matches(rule, scheme, host, port, path) for rule in policy.allow):
        return ScopeDecision(True, "exact allow rule matched", normalized)
    return ScopeDecision(False, "no exact allow rule matched", normalized)
