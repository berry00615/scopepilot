from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from .schemas import PolicyCreate, PolicyStatus, ScopeRule


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    normalized_url: str | None = None


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


def _matches(rule: ScopeRule, scheme: str, host: str, port: int, path: str) -> bool:
    prefix = rule.path_prefix.rstrip("/") or "/"
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
        if parsed.username or parsed.password or parsed.fragment:
            return ScopeDecision(False, "ambiguous URL component is not allowed")
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        port = parsed.port or _default_port(scheme)
        raw_path = parsed.path or "/"
        path = unquote(raw_path)
        if scheme not in {"http", "https"} or not host or port is None:
            return ScopeDecision(False, "URL must contain an HTTP(S) scheme and exact host")
        if "%2f" in raw_path.lower() or "%5c" in raw_path.lower() or "\\" in path:
            return ScopeDecision(False, "ambiguous encoded path separator")
        if any(part in {".", ".."} for part in path.split("/")):
            return ScopeDecision(False, "dot path segments are not allowed")
        display_host = f"[{host}]" if ":" in host else host
        normalized = f"{scheme}://{display_host}:{port}{path}"
    except (ValueError, UnicodeError):
        return ScopeDecision(False, "URL could not be parsed unambiguously")

    if any(_matches(rule, scheme, host, port, path) for rule in policy.deny):
        return ScopeDecision(False, "explicit deny rule matched", normalized)
    if any(_matches(rule, scheme, host, port, path) for rule in policy.allow):
        return ScopeDecision(True, "exact allow rule matched", normalized)
    return ScopeDecision(False, "no exact allow rule matched", normalized)
