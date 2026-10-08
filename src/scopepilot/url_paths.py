"""Shared, conservative URL path canonicalization for rules and material."""
from urllib.parse import quote, unquote


def decoded_path(value: str) -> str:
    if not value.startswith('/'):
        raise ValueError('path must be absolute')
    if '%2f' in value.lower() or '%5c' in value.lower():
        raise ValueError('encoded separators are ambiguous')
    path = unquote(value, errors='strict')
    if '%' in path or '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError('ambiguous or control characters in path')
    if any(part in {'.', '..'} for part in path.split('/')):
        raise ValueError('dot segments are ambiguous')
    return path


def encoded_path(value: str) -> str:
    return quote(value, safe="/:@!$&'()*+,;=-._~")
