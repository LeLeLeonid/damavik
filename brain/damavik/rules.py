# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Sigma-subset rule engine.

A Damavik rule is a YAML document with the fields from the master plan::

    title, id, status, level, description, logsource, selection..., condition

Supported field modifiers (Sigma-compatible subset): ``contains``,
``startswith``, ``endswith``, ``re``, ``all``, combinable with ``|``
(``CommandLine|contains|all``).  Multiple keys inside one selection block are
ANDed; list values are ORed; ``condition`` supports ``and`` / ``or`` / ``not``
and parentheses over named selections.

Damavik extension: an optional ``correlate``
block gives the rule a small stateful window, which is how "N of these in T
seconds" detections (beacons, DNS tunnelling, brute force) are expressed
without a second engine::

    correlate:
      group_by: net.dst
      window_s: 60
      min_count: 5

Performance: rules are bucketed by event type at load time, field accessors are
compiled to closures, and regexes are pre-compiled, so a non-matching event
costs a dict lookup plus a few cheap comparisons.
"""

from __future__ import annotations

import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .miniyaml import YamlError, loads

VALID_LEVELS = ("info", "low", "medium", "high", "critical")
VALID_STATUS = ("stable", "test", "experimental", "deprecated")

#: Maps a rule's logsource.category onto the event type(s) it can fire on.
CATEGORY_TO_TYPES: dict[str, frozenset[str]] = {
    "process_creation": frozenset({"proc.exec"}),
    "process": frozenset({"proc.exec"}),
    "network_connect": frozenset({"net.flow"}),
    "network": frozenset({"net.flow"}),
    "dns_query": frozenset({"dns.query"}),
    "dns": frozenset({"dns.query"}),
    "file_event": frozenset({"file.verdict", "proc.exec"}),
    "file": frozenset({"file.verdict", "proc.exec"}),
    "package": frozenset({"pkg.event"}),
    "any": frozenset(),
}

_FIELD_CACHE: dict[str, tuple[str, ...]] = {}


class RuleError(ValueError):
    """A rule file that cannot be used."""


def _path_parts(path: str) -> tuple[str, ...]:
    parts = _FIELD_CACHE.get(path)
    if parts is None:
        parts = tuple(path.split("."))
        _FIELD_CACHE[path] = parts
    return parts


def get_field(event: dict[str, Any], path: str) -> Any:
    """Read ``net.dport`` style paths from an event.  Missing -> None."""
    node: Any = event
    for part in _path_parts(path):
        if isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        else:
            return None
    return node


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


Matcher = Callable[[Any], bool]


def _matcher(path: str, modifiers: list[str], values: list[Any]) -> Matcher:
    """Compile one ``Field|mod: value`` clause into a predicate."""
    mode = "eq"
    require_all = False
    for mod in modifiers:
        if mod == "contains":
            mode = "contains"
        elif mod == "startswith":
            mode = "startswith"
        elif mod == "endswith":
            mode = "endswith"
        elif mod == "re":
            mode = "re"
        elif mod == "all":
            require_all = True
        elif mod in ("gt", "gte", "lt", "lte"):
            mode = mod
        elif mod == "exists":
            mode = "exists"
        elif mod in ("base64", "wide", "utf16", "base64offset"):
            raise RuleError(f"modifier '{mod}' is not implemented in the MVP subset")
        else:
            raise RuleError(f"unknown modifier '{mod}' on field '{path}'")

    if mode == "re":
        needles: list[Any] = [re.compile(_as_text(v), re.IGNORECASE) for v in values]

        def test(text: str, needle: Any) -> bool:
            return bool(needle.search(text))

    elif mode == "contains":
        needles = [_as_text(v).lower() for v in values]

        def test(text: str, needle: Any) -> bool:
            return str(needle) in text.lower()

    elif mode == "startswith":
        needles = [_as_text(v).lower() for v in values]

        def test(text: str, needle: Any) -> bool:
            return text.lower().startswith(str(needle))

    elif mode == "endswith":
        needles = [_as_text(v).lower() for v in values]

        def test(text: str, needle: Any) -> bool:
            return text.lower().endswith(str(needle))

    elif mode in ("gt", "gte", "lt", "lte"):
        needles = [float(v) for v in values]
        op = mode

        def test(text: str, needle: Any) -> bool:  # pragma: no cover - numeric path below
            return False

    elif mode == "exists":
        needles = [bool(v) if isinstance(v, str) else v for v in values]

        def test(text: str, needle: Any) -> bool:  # pragma: no cover - handled below
            return False

    else:  # equality: case-insensitive for text, exact for numbers and bools
        needles = [v.lower() if isinstance(v, str) else v for v in values]

        def test(text: str, needle: Any) -> bool:  # pragma: no cover - unused for eq
            return text.lower() == str(needle)

    def _equals(actual: Any, needle: Any) -> bool:
        if isinstance(actual, bool) or isinstance(needle, bool):
            return actual is needle or actual == needle
        if isinstance(actual, str):
            return actual.lower() == (needle.lower() if isinstance(needle, str) else str(needle))
        if isinstance(actual, (int, float)) and isinstance(needle, (int, float)):
            return actual == needle
        return actual == needle

    def _one(candidate: Any, needle: Any) -> bool:
        if mode == "eq":
            return _equals(candidate, needle)
        if mode in ("gt", "gte", "lt", "lte"):
            try:
                number = float(candidate)
            except (TypeError, ValueError):
                return False
            limit = float(needle)
            return {
                "gt": number > limit,
                "gte": number >= limit,
                "lt": number < limit,
                "lte": number <= limit,
            }[mode]
        return test(_as_text(candidate), needle)

    def predicate(event: dict[str, Any]) -> bool:
        actual = get_field(event, path)
        raw = actual if isinstance(actual, list) else [actual]
        candidates = [item for item in raw if item is not None]
        if mode == "exists":
            wanted = bool(needles[0]) if needles else True
            return (actual not in (None, "", [], {})) is wanted
        if not candidates:
            return False
        if require_all:
            # "|all" means every needle must be found somewhere in the value.
            return all(
                any(_one(candidate, needle) for candidate in candidates) for needle in needles
            )
        return any(
            _one(candidate, needle) for candidate in candidates for needle in needles
        )

    return predicate


@dataclass
class Clause:
    path: str
    modifiers: tuple[str, ...]
    values: list[Any]
    predicate: Matcher


@dataclass(eq=False)
class Rule:
    """A loaded rule.

    ``eq=False`` keeps the default identity hash: rules are singletons per
    load, and callers bucket them into sets (by-type index, overlap checks).
    """

    rule_id: str
    title: str
    level: str
    status: str
    selection_sets: dict[str, list[Clause]]
    condition: str
    types: frozenset[str]
    tags: list[str] = field(default_factory=list)
    description: str = ""
    source: str = ""
    correlate: dict[str, Any] | None = None
    _compiled: Any = None

    @property
    def explain(self) -> str:
        return self.description or self.title

    def matches(self, event: dict[str, Any]) -> bool:
        if self.types and event.get("type") not in self.types:
            return False
        try:
            return bool(self._compiled(event, self.selection_sets))
        except Exception:  # noqa: BLE001 - a bad rule must not kill the pipeline
            return False


def _parse_condition(expr: str) -> Any:
    """Recursive-descent parser for ``a and not (b or c)``."""
    tokens = re.findall(r"\(|\)|\w+", expr)
    pos = 0

    def parse_or() -> Any:
        nonlocal pos
        node = parse_and()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            right = parse_and()
            left = node
            node = lambda ev, sets, l=left, r=right: bool(l(ev, sets)) or bool(r(ev, sets))
        return node

    def parse_and() -> Any:
        nonlocal pos
        node = parse_not()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            right = parse_not()
            left = node
            node = lambda ev, sets, l=left, r=right: bool(l(ev, sets)) and bool(r(ev, sets))
        return node

    def parse_not() -> Any:
        nonlocal pos
        if pos < len(tokens) and tokens[pos] == "not":
            pos += 1
            inner = parse_not()
            return lambda ev, sets, i=inner: not bool(i(ev, sets))
        return parse_atom()

    def parse_atom() -> Any:
        nonlocal pos
        if pos >= len(tokens):
            raise RuleError(f"unexpected end of condition: {expr!r}")
        token = tokens[pos]
        pos += 1
        if token == "(":
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise RuleError(f"missing ')' in condition: {expr!r}")
            pos += 1
            return inner
        if token in ("and", "or", "not", ")"):
            raise RuleError(f"unexpected token {token!r} in condition: {expr!r}")

        def named(ev: dict[str, Any], sets: dict[str, list[Clause]], name: str = token) -> bool:
            clauses = sets.get(name)
            if clauses is None:
                raise RuleError(f"condition refers to unknown selection '{name}'")
            return all(clause.predicate(ev) for clause in clauses)

        return named

    node = parse_or()
    if pos != len(tokens):
        raise RuleError(f"trailing tokens in condition: {expr!r}")
    return node


def _clauses_from_block(block: dict[str, Any]) -> list[Clause]:
    clauses: list[Clause] = []
    for raw_key, value in block.items():
        if not isinstance(raw_key, str):
            raise RuleError(f"selection key must be a string, got {type(raw_key).__name__}")
        parts = raw_key.split("|")
        path = parts[0].strip()
        modifiers = [mod.strip().lower() for mod in parts[1:] if mod.strip()]
        if not path:
            raise RuleError("selection contains an empty field name")
        if value is None:
            raise RuleError(f"field '{path}' has no value")
        values = value if isinstance(value, list) else [value]
        if not values:
            raise RuleError(f"field '{path}' has an empty value list")
        clauses.append(
            Clause(
                path=path,
                modifiers=tuple(modifiers),
                values=values,
                predicate=_matcher(path, modifiers, values),
            )
        )
    if not clauses:
        raise RuleError("selection block is empty")
    return clauses


def rule_from_dict(data: dict[str, Any], *, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError("rule document must be a mapping")
    rule_id = str(data.get("id") or "").strip()
    title = str(data.get("title") or "").strip()
    condition = str(data.get("condition") or "").strip()
    if not rule_id:
        raise RuleError("rule is missing 'id'")
    if not title:
        raise RuleError(f"rule {rule_id} is missing 'title'")
    if not condition:
        raise RuleError(f"rule {rule_id} is missing 'condition'")
    level = str(data.get("level") or "medium").lower()
    if level not in VALID_LEVELS:
        raise RuleError(f"rule {rule_id}: invalid level {level!r}")
    status = str(data.get("status") or "experimental").lower()
    if status not in VALID_STATUS:
        raise RuleError(f"rule {rule_id}: invalid status {status!r}")

    selections: dict[str, list[Clause]] = {}
    for key, value in data.items():
        if key in ("title", "id", "status", "level", "description", "logsource", "condition",
                   "tags", "correlate", "references", "author", "date", "falsepositives"):
            continue
        if not isinstance(value, dict):
            raise RuleError(f"rule {rule_id}: '{key}' must be a mapping of field conditions")
        selections[key] = _clauses_from_block(value)
    if not selections:
        raise RuleError(f"rule {rule_id} has no selection blocks")

    logsource = data.get("logsource") or {}
    category = str(logsource.get("category") or logsource.get("product") or "any").lower()
    types = CATEGORY_TO_TYPES.get(category)
    if types is None:
        raise RuleError(f"rule {rule_id}: unknown logsource.category {category!r}")

    referenced = {
        word for word in re.findall(r"\w+", condition)
        if word not in ("and", "or", "not")
    }
    unknown = sorted(referenced - set(selections))
    if unknown:
        raise RuleError(
            f"rule {rule_id}: condition refers to unknown selection(s) {', '.join(unknown)}"
        )
    compiled = _parse_condition(condition)
    correlate = data.get("correlate")
    if correlate is not None:
        if not isinstance(correlate, dict):
            raise RuleError(f"rule {rule_id}: 'correlate' must be a mapping")
        for required in ("group_by", "window_s", "min_count"):
            if required not in correlate:
                raise RuleError(f"rule {rule_id}: correlate.{required} is required")
        # Fail fast on a bad group_by path at load time, not at event time.
        _path_parts(str(correlate["group_by"]))

    tags = data.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return Rule(
        rule_id=rule_id,
        title=title,
        level=level,
        status=status,
        selection_sets=selections,
        condition=condition,
        types=types,
        tags=[str(tag) for tag in tags],
        description=str(data.get("description") or ""),
        source=source,
        correlate=dict(correlate) if correlate else None,
        _compiled=compiled,
    )


def load_rule_file(path: str) -> Rule:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        data = loads(text)
    except YamlError as exc:
        raise RuleError(f"{path}: {exc}") from exc
    return rule_from_dict(data, source=path)


class RuleSet:
    """Loaded rules plus the correlation state they need."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules: list[Rule] = list(rules)
        self.by_type: dict[str, list[Rule]] = {}
        self.universal: list[Rule] = []
        for rule in self.rules:
            if rule.types:
                for etype in rule.types:
                    self.by_type.setdefault(etype, []).append(rule)
            else:
                self.universal.append(rule)
        self._windows: dict[str, deque[tuple[float, str]]] = {}
        self._fired: set[str] = set()

    def __len__(self) -> int:
        return len(self.rules)

    def ids(self) -> list[str]:
        return [rule.rule_id for rule in self.rules]

    def candidates_for(self, event: dict[str, Any]) -> list[Rule]:
        etype = event.get("type") or ""
        return self.by_type.get(etype, []) + self.universal

    def evaluate(self, event: dict[str, Any], *, now: float | None = None) -> list[Rule]:
        """Return every rule that fires for this event (correlation-aware)."""
        now = time.time() if now is None else now
        fired: list[Rule] = []
        for rule in self.candidates_for(event):
            if not rule.matches(event):
                continue
            if rule.correlate is None:
                fired.append(rule)
                continue
            if self._correlate(rule, event, now):
                fired.append(rule)
        return fired

    def _correlate(self, rule: Rule, event: dict[str, Any], now: float) -> bool:
        spec = rule.correlate or {}
        key = _as_text(get_field(event, str(spec["group_by"])))
        if not key:
            return False
        window = float(spec["window_s"])
        threshold = int(spec["min_count"])
        bucket_key = f"{rule.rule_id}|{key}"
        bucket = self._windows.setdefault(bucket_key, deque())
        bucket.append((now, event.get("id", "")))
        cutoff = now - window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()
        return len(bucket) >= threshold


def load_rules_dir(directory: str, *, include_experimental: bool = True) -> tuple[RuleSet, list[str]]:
    """Load every ``*.yml`` / ``*.yaml`` rule from a directory."""
    errors: list[str] = []
    rules: list[Rule] = []
    expanded = os.path.expanduser(directory)
    if not os.path.isdir(expanded):
        return RuleSet([]), [f"rules directory not found: {directory}"]
    for name in sorted(os.listdir(expanded)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(expanded, name)
        try:
            rule = load_rule_file(path)
        except (RuleError, OSError) as exc:
            errors.append(str(exc))
            continue
        if rule.status == "deprecated":
            continue
        if rule.status == "experimental" and not include_experimental:
            continue
        rules.append(rule)
    return RuleSet(rules), errors
