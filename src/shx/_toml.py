"""TOML loading that works without Python 3.11's tomllib.

Uses tomllib (3.11+) or tomli when available; otherwise a small reader for the subset this
project uses: comments, [table], [a."b"], [[array-of-tables]], and key = value with strings,
integers, floats, booleans and (possibly multi-line) arrays of those.
"""

from __future__ import annotations

import re

try:  # Python 3.11+
    import tomllib as _impl
except ModuleNotFoundError:  # pragma: no cover - depends on the interpreter
    try:
        import tomli as _impl
    except ModuleNotFoundError:
        _impl = None


class TOMLDecodeError(ValueError):
    pass


def loads(text: str) -> dict:
    if _impl is not None:
        try:
            return _impl.loads(text)
        except _impl.TOMLDecodeError as exc:
            raise TOMLDecodeError(str(exc)) from None
    return _mini_loads(text)


# --- fallback reader ------------------------------------------------------------------

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "b": "\b", "f": "\f"}


def _strip_comment(line: str) -> str:
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


def _split_key(text: str, lineno: int) -> list[str]:
    parts, i, text = [], 0, text.strip()
    while i < len(text):
        if text[i] in "\"'":
            end = text.index(text[i], i + 1)
            parts.append(text[i + 1:end])
            i = end + 1
        else:
            m = _BARE_KEY.match(text, i)
            if not m:
                raise TOMLDecodeError(f"line {lineno}: invalid key {text!r}")
            parts.append(m.group(0))
            i = m.end()
        while i < len(text) and text[i] in " \t":
            i += 1
        if i < len(text):
            if text[i] != ".":
                raise TOMLDecodeError(f"line {lineno}: invalid key {text!r}")
            i += 1
            while i < len(text) and text[i] in " \t":
                i += 1
    return parts


def _parse_value(text: str, i: int, lineno: int):
    """Parse one value starting at text[i]; return (value, next index)."""
    while i < len(text) and text[i] in " \t\n":
        i += 1
    if i >= len(text):
        raise TOMLDecodeError(f"line {lineno}: missing value")
    ch = text[i]
    if ch == '"':
        out, i = [], i + 1
        while text[i] != '"':
            if text[i] == "\\":
                out.append(_ESCAPES.get(text[i + 1], text[i + 1]))
                i += 2
            else:
                out.append(text[i])
                i += 1
        return "".join(out), i + 1
    if ch == "'":
        end = text.index("'", i + 1)
        return text[i + 1:end], end + 1
    if ch == "[":
        items, i = [], i + 1
        while True:
            while i < len(text) and text[i] in " \t\n,":
                i += 1
            if text[i] == "]":
                return items, i + 1
            value, i = _parse_value(text, i, lineno)
            items.append(value)
    m = re.compile(r"[^,\]\s]+").match(text, i)
    token = m.group(0)
    if token in ("true", "false"):
        return token == "true", m.end()
    try:
        return int(token.replace("_", "")), m.end()
    except ValueError:
        try:
            return float(token.replace("_", "")), m.end()
        except ValueError:
            raise TOMLDecodeError(f"line {lineno}: unsupported value {token!r}") from None


def _table(root: dict, path: list[str], lineno: int) -> dict:
    node = root
    for part in path:
        node = node.setdefault(part, {})
        if isinstance(node, list):
            node = node[-1]
        if not isinstance(node, dict):
            raise TOMLDecodeError(f"line {lineno}: {part!r} is not a table")
    return node


def _mini_loads(text: str) -> dict:
    root: dict = {}
    current = root
    lines = text.splitlines()
    n = 0
    while n < len(lines):
        lineno, line = n + 1, _strip_comment(lines[n])
        n += 1
        if not line:
            continue
        if line.startswith("[["):
            path = _split_key(line[2:-2], lineno)
            parent = _table(root, path[:-1], lineno)
            parent.setdefault(path[-1], []).append({})
            current = parent[path[-1]][-1]
            continue
        if line.startswith("["):
            current = _table(root, _split_key(line[1:-1], lineno), lineno)
            continue
        if "=" not in line:
            raise TOMLDecodeError(f"line {lineno}: expected key = value")
        key_text, value_text = line.split("=", 1)
        # Multi-line arrays: keep reading until brackets balance.
        while value_text.count("[") > value_text.count("]") and n < len(lines):
            value_text += "\n" + _strip_comment(lines[n])
            n += 1
        value, end = _parse_value(value_text, 0, lineno)
        if value_text[end:].strip():
            raise TOMLDecodeError(f"line {lineno}: unexpected text after value")
        *parents, key = _split_key(key_text, lineno)
        target = _table(current, parents, lineno)
        if key in target:
            raise TOMLDecodeError(f"line {lineno}: duplicate key {key!r}")
        target[key] = value
    return root
