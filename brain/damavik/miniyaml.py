# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""A tiny, strict YAML *subset* loader.

Why this exists
---------------
Damavik's rules (Sigma-subset) and config are YAML, but the Python standard
library has no YAML parser and the project's first principle is "zero services,
zero dependencies".  Rather than pull in PyYAML for the 5% of YAML we need, we
implement exactly the subset we use - and document it, so a rule that will not
parse fails loudly with a line number instead of silently mis-parsing.

If PyYAML *is* installed we still prefer this loader (behaviour must be
identical on every machine); :func:`loads` accepts ``parser="auto"`` for callers
that want PyYAML when available.

Supported subset
----------------
* block mappings (``key: value``) nested by space indentation,
* block sequences (``- item``), including compact ``- key: value`` items,
* flow sequences ``[a, b]`` and flow mappings ``{a: 1}`` (no nesting of flows),
* plain, single-quoted and double-quoted scalars (``\\n \\t \\" \\\\ \\uXXXX``),
* literal block scalars (``|``) and folded block scalars (``>``),
* comments (``#`` outside quotes), ``---`` document markers,
* ``true/false/yes/no/on/off`` -> bool, ``null/~/""`` -> None, int, float.

Explicitly unsupported (raises :class:`YamlError`, never guesses): anchors and
aliases (``&a`` / ``*a``), explicit tags (``!!str``), multi-document streams
beyond a leading ``---``, complex keys (``? ``), nested flow collections,
tab-indented blocks.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["YamlError", "loads", "load", "safe_load"]


class YamlError(ValueError):
    """Raised for any input outside the supported subset."""


_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_FLOAT_RE = re.compile(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")
_HEX_RE = re.compile(r"^[-+]?0x[0-9a-fA-F]+$")
_OCT_RE = re.compile(r"^[-+]?0o[0-7]+$")
_BOOL_TRUE = frozenset({"true", "yes", "on"})
_BOOL_FALSE = frozenset({"false", "no", "off"})
_NULL = frozenset({"null", "~", ""})

_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    '"': '"',
    "'": "'",
    "\\": "\\",
    "/": "/",
    " ": " ",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "e": "\x1b",
}


class _Line:
    __slots__ = ("indent", "text", "no")

    def __init__(self, indent: int, text: str, no: int) -> None:
        self.indent = indent
        self.text = text
        self.no = no

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Line({self.no}, {self.indent}, {self.text!r})"


def _strip_comment(s: str) -> str:
    """Remove a trailing ``# comment`` that is not inside quotes."""
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(s):
                out.append(s[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in (" ", "\t")):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _lex(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for no, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlError(f"line {no}: tab characters are not allowed in indentation")
        if raw.strip() in ("---", "..."):
            continue
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append(_Line(indent, _strip_comment(raw[indent:]), no))
    return lines


def _unquote_double(s: str, no: int) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(s):
            raise YamlError(f"line {no}: dangling escape in double-quoted scalar")
        nxt = s[i + 1]
        if nxt == "u":
            hexpart = s[i + 2 : i + 6]
            if len(hexpart) != 4 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
                raise YamlError(f"line {no}: bad \\u escape")
            out.append(chr(int(hexpart, 16)))
            i += 6
            continue
        if nxt not in _ESCAPES:
            raise YamlError(f"line {no}: unsupported escape \\{nxt}")
        out.append(_ESCAPES[nxt])
        i += 2
    return "".join(out)


def _scalar(token: str, no: int) -> Any:
    """Interpret a single already-trimmed scalar token."""
    if token.startswith('"'):
        if len(token) < 2 or not token.endswith('"'):
            raise YamlError(f"line {no}: unterminated double-quoted scalar")
        return _unquote_double(token[1:-1], no)
    if token.startswith("'"):
        if len(token) < 2 or not token.endswith("'"):
            raise YamlError(f"line {no}: unterminated single-quoted scalar")
        return token[1:-1].replace("''", "'")
    if token.startswith(("[", "{")):
        return _flow(token, no)
    if token.startswith(("&", "*", "!")):
        raise YamlError(f"line {no}: anchors, aliases and tags are not supported: {token!r}")
    low = token.lower()
    if low in _NULL:
        return None
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    if _INT_RE.match(token):
        return int(token)
    if _HEX_RE.match(token):
        return int(token, 16)
    if _OCT_RE.match(token):
        return int(token, 8)
    if _FLOAT_RE.match(token):
        return float(token)
    return token


def _split_flow(body: str, no: int) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote = ""
    cur: list[str] = []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _flow(token: str, no: int) -> Any:
    """Parse a single-line flow sequence or mapping (no nested collections)."""
    if not (token.endswith("]") or token.endswith("}")):
        raise YamlError(f"line {no}: flow collection must be closed on the same line: {token!r}")
    inner = token[1:-1].strip()
    if token[0] == "[":
        if not inner:
            return []
        return [_scalar(p, no) for p in _split_flow(inner, no)]
    if not inner:
        return {}
    out: dict[str, Any] = {}
    for part in _split_flow(inner, no):
        if ":" not in part:
            raise YamlError(f"line {no}: flow mapping entry without ':': {part!r}")
        key, _, value = part.partition(":")
        out[str(_scalar(key.strip(), no))] = _scalar(value.strip(), no)
    return out


class _Parser:
    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    def peek(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def parse_block(self, indent: int) -> Any:
        line = self.peek()
        if line is None or line.indent < indent:
            return None
        if line.text.startswith("- "):
            return self.parse_seq(line.indent)
        if line.text == "-":
            return self.parse_seq(line.indent)
        return self.parse_map(line.indent)

    def parse_seq(self, indent: int) -> list[Any]:
        out: list[Any] = []
        while True:
            line = self.peek()
            if line is None or line.indent != indent or not (
                line.text == "-" or line.text.startswith("- ")
            ):
                break
            self.pos += 1
            rest = line.text[1:].lstrip()
            if not rest:
                child_indent = self._child_indent(indent)
                out.append(self.parse_block(child_indent) if child_indent is not None else None)
                continue
            # Compact "- key: value" starts a mapping whose first line sits here.
            colon = _find_key_sep(rest)
            if colon > 0:
                synthetic = _Line(indent + 2, rest, line.no)
                self.lines.insert(self.pos, synthetic)
                out.append(self.parse_map(indent + 2))
                continue
            out.append(_scalar(rest, line.no))
        return out

    def _child_indent(self, indent: int) -> int | None:
        nxt = self.peek()
        if nxt is None or nxt.indent <= indent:
            return None
        return nxt.indent

    def parse_map(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            line = self.peek()
            if line is None or line.indent != indent:
                break
            if line.text.startswith("- "):
                break
            sep = _find_key_sep(line.text)
            if sep <= 0:
                raise YamlError(f"line {line.no}: expected 'key: value', got {line.text!r}")
            key = line.text[:sep].strip()
            if key.startswith(("'", '"')):
                key = str(_scalar(key, line.no))
            value = line.text[sep + 1 :].strip()
            self.pos += 1
            if value in ("|", ">", "|-", ">-", "|+", ">+"):
                out[key] = self._block_scalar(indent, value, line.no)
                continue
            if value:
                out[key] = _scalar(value, line.no)
                continue
            child_indent = self._child_indent(indent)
            if child_indent is None:
                out[key] = None
            else:
                out[key] = self.parse_block(child_indent)
        return out

    def _block_scalar(self, indent: int, style: str, no: int) -> str:
        keep = style.endswith("+")
        chomp_none = style.endswith("-")
        base = style[0]
        collected: list[str] = []
        block_indent: int | None = None
        while True:
            nxt = self.peek()
            if nxt is None or nxt.indent <= indent:
                break
            if block_indent is None:
                block_indent = nxt.indent
            collected.append(" " * max(0, nxt.indent - block_indent) + nxt.text)
            self.pos += 1
        if not collected:
            return ""
        if base == "|":
            text = "\n".join(collected)
        else:
            folded: list[str] = []
            for item in collected:
                if folded and folded[-1] and item:
                    folded[-1] = folded[-1] + " " + item.lstrip()
                else:
                    folded.append(item)
            text = "\n".join(folded)
        if not keep and not chomp_none:
            text += "\n"
        elif keep:
            text += "\n"
        return text


def _find_key_sep(text: str) -> int:
    """Index of the ':' that terminates a mapping key, or -1."""
    quote = ""
    depth = 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            if i + 1 == len(text) or text[i + 1] in (" ", "\t"):
                return i
    return -1


def loads(text: str, *, parser: str = "miniyaml") -> Any:
    """Parse a YAML-subset document into Python objects."""
    if parser == "auto":
        try:  # pragma: no cover - depends on optional dependency
            import yaml as _yaml
        except ImportError:
            _yaml = None
        if _yaml is not None:
            return _yaml.safe_load(text)
    lines = _lex(text)
    if not lines:
        return None
    first = lines[0]
    if first.indent != 0:
        raise YamlError(f"line {first.no}: document must start at column 0")
    value = _Parser(lines).parse_block(0)
    return value


def safe_load(text: str) -> Any:  # pragma: no cover - API parity helper
    return loads(text)


def load(fp: Any) -> Any:
    """Parse from a file-like object."""
    return loads(fp.read())
