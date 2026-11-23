"""Detection rules: YAML loading, validation and Sigma-style field matching.

A rule is one of three types:

``match``
    Fires once for every event the detection matches.
``threshold``
    Fires when matching events, grouped by one or more fields, reach a count
    (or a count of distinct values) inside a sliding time window.
``sequence``
    Fires when ordered steps happen for the same key inside a time window,
    for example several failed logons followed by a successful one.

See ``docs/writing-rules.md`` for the full format.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .attack import TECHNIQUES
from .conditions import Condition, ConditionError, compile_condition
from .events import Event, normalize_record

SEVERITIES = ["info", "low", "medium", "high", "critical"]
RULE_TYPES = {"match", "threshold", "sequence"}
MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "gt", "gte", "lt", "lte", "exists", "cased"}
_STRING_MODIFIERS = {"contains", "startswith", "endswith"}
_NUMERIC_MODIFIERS = {"gt": "__gt__", "gte": "__ge__", "lt": "__lt__", "lte": "__le__"}
_WINDOW = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_REQUIRED = ("id", "title", "severity")


class RuleError(ValueError):
    """Raised for a rule that cannot be loaded."""


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


def parse_window(value: Any) -> timedelta:
    match = _WINDOW.match(str(value))
    if not match:
        raise RuleError(f"window '{value}' must look like 30s, 10m, 2h or 1d")
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{units[match.group(2)]: int(match.group(1))})


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(int(text, 16)) if text.lower().startswith("0x") else float(text)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Field matching


class FieldMatcher:
    """Matches one ``Field|modifier: value(s)`` entry against an event."""

    def __init__(self, key: str, values: Any):
        field_name, *modifiers = key.split("|")
        unknown = set(modifiers) - MODIFIERS
        if unknown:
            raise RuleError(f"unknown modifier(s) {sorted(unknown)} on '{key}'")
        self.field = field_name
        self.modifiers = set(modifiers)
        self.values = list(values) if isinstance(values, list) else [values]
        if not self.values:
            raise RuleError(f"'{key}' has an empty value list")
        flags = 0 if "cased" in self.modifiers else re.IGNORECASE
        self._patterns = []
        self._networks = []
        try:
            if "re" in self.modifiers:
                self._patterns = [re.compile(str(v), flags) for v in self.values if v is not None]
            if "cidr" in self.modifiers:
                self._networks = [ipaddress.ip_network(str(v), strict=False) for v in self.values if v is not None]
        except (re.error, ValueError) as exc:
            raise RuleError(f"invalid value for '{key}': {exc}") from exc

    def matches(self, fields: dict[str, Any]) -> bool:
        actual = fields.get(self.field)
        present = actual is not None and actual != ""
        if "exists" in self.modifiers:
            return present == bool(self.values[0])
        if not present:
            return any(v is None for v in self.values)
        if "re" in self.modifiers:
            checks = [lambda a, p=p: bool(p.search(a)) for p in self._patterns]
        elif "cidr" in self.modifiers:
            checks = [lambda a, n=n: _in_network(a, n) for n in self._networks]
        else:
            checks = [lambda a, v=v: self._compare(a, v) for v in self.values if v is not None]
        if not checks:
            return False
        candidates = actual if isinstance(actual, list) else [actual]
        results = (any(check(str(c)) for c in candidates) for check in checks)
        return all(results) if "all" in self.modifiers else any(results)

    def _compare(self, actual: str, expected: Any) -> bool:
        for modifier, method in _NUMERIC_MODIFIERS.items():
            if modifier in self.modifiers:
                a, b = _as_number(actual), _as_number(expected)
                return a is not None and b is not None and getattr(a, method)(b)
        cased = "cased" in self.modifiers
        a = actual if cased else actual.lower()
        b = str(expected) if cased else str(expected).lower()
        if "contains" in self.modifiers:
            return b in a
        if "startswith" in self.modifiers:
            return a.startswith(b)
        if "endswith" in self.modifiers:
            return a.endswith(b)
        if a == b:
            return True
        if "*" in b or "?" in b:
            return fnmatch.fnmatchcase(a, b)
        a_num, b_num = _as_number(actual), _as_number(expected)
        return a_num is not None and a_num == b_num


def _in_network(actual: str, network: ipaddress._BaseNetwork) -> bool:
    try:
        address = ipaddress.ip_address(actual.strip())
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return address.version == network.version and address in network


class Selection:
    """A named selection: a map (AND of fields), a list of maps (OR) or keywords."""

    def __init__(self, name: str, spec: Any):
        self.name = name
        self._groups: list[list[FieldMatcher]] = []
        self._keywords: list[str] = []
        if isinstance(spec, dict):
            self._groups = [self._group(spec)]
        elif isinstance(spec, list) and spec and all(isinstance(item, dict) for item in spec):
            self._groups = [self._group(item) for item in spec]
        elif isinstance(spec, list) and spec and all(isinstance(item, (str, int)) for item in spec):
            self._keywords = [str(item).lower() for item in spec]
        else:
            raise RuleError(f"selection '{name}' must be a map, a list of maps or a list of keywords")

    @staticmethod
    def _group(spec: dict[str, Any]) -> list[FieldMatcher]:
        if not spec:
            raise RuleError("a selection map cannot be empty")
        return [FieldMatcher(str(key), value) for key, value in spec.items()]

    def matches(self, fields: dict[str, Any]) -> bool:
        if self._keywords:
            haystack = [str(v).lower() for v in fields.values() if isinstance(v, (str, int))]
            return any(keyword in value for keyword in self._keywords for value in haystack)
        return any(all(m.matches(fields) for m in group) for group in self._groups)


class Detection:
    """Selections plus the condition that combines them."""

    def __init__(self, spec: Any, where: str = "detection"):
        if not isinstance(spec, dict) or "condition" not in spec:
            raise RuleError(f"{where} needs selections and a 'condition'")
        self.selections = {
            str(name): Selection(str(name), value) for name, value in spec.items() if name != "condition"
        }
        if not self.selections:
            raise RuleError(f"{where} has no selections")
        self.condition_text = str(spec["condition"])
        try:
            self._condition: Condition = compile_condition(self.condition_text, self.selections)
        except ConditionError as exc:
            raise RuleError(f"{where} condition: {exc}") from exc

    def matches(self, event: Event | dict[str, Any]) -> bool:
        fields = event.fields if isinstance(event, Event) else event
        cache: dict[str, bool] = {}

        def lookup(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(fields)
            return cache[name]

        return self._condition(lookup)


# --------------------------------------------------------------------------
# Rules


@dataclass
class Step:
    name: str
    detection: Detection
    min_count: int = 1


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str = "match"
    description: str = ""
    attack: list[str] = field(default_factory=list)
    detection: Detection | None = None
    group_by: list[str] = field(default_factory=list)
    window: timedelta | None = None
    count: int = 1
    distinct: str | None = None
    steps: list[Step] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tests: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    path: Path | None = None

    @property
    def rank(self) -> int:
        return severity_rank(self.severity)

    def warnings(self) -> list[str]:
        unknown = [t for t in self.attack if t not in TECHNIQUES]
        return [f"{self.id}: ATT&CK technique {t} is not in lantern/attack.py" for t in unknown]


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def rule_from_dict(data: dict[str, Any], path: Path | None = None) -> Rule:
    label = path.name if path else "rule"
    if not isinstance(data, dict):
        raise RuleError(f"{label}: a rule must be a YAML mapping")
    missing = [key for key in _REQUIRED if not data.get(key)]
    if missing:
        raise RuleError(f"{label}: missing required field(s): {', '.join(missing)}")
    rule = Rule(
        id=str(data["id"]),
        title=str(data["title"]),
        severity=str(data["severity"]).lower(),
        type=str(data.get("type", "match")).lower(),
        description=str(data.get("description", "")).strip(),
        attack=[str(t) for t in _list(data.get("attack"))],
        fields=[str(f) for f in _list(data.get("fields"))],
        falsepositives=[str(f) for f in _list(data.get("falsepositives"))],
        references=[str(r) for r in _list(data.get("references"))],
        path=path,
    )
    where = f"{label} ({rule.id})"
    if rule.severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    if rule.type not in RULE_TYPES:
        raise RuleError(f"{where}: type must be one of {', '.join(sorted(RULE_TYPES))}")
    try:
        if rule.type in {"match", "threshold"}:
            rule.detection = Detection(data.get("detection"))
        if rule.type == "threshold":
            spec = data.get("threshold") or {}
            rule.group_by = [str(f) for f in _list(spec.get("group_by"))]
            rule.window = parse_window(spec.get("window", "5m"))
            rule.count = int(spec.get("count", 0))
            rule.distinct = str(spec["distinct"]) if spec.get("distinct") else None
            if rule.count < 2:
                raise RuleError("threshold.count must be 2 or more")
        if rule.type == "sequence":
            spec = data.get("sequence") or {}
            rule.group_by = [str(f) for f in _list(spec.get("by"))]
            rule.window = parse_window(spec.get("window", "30m"))
            raw_steps = _list(spec.get("steps"))
            if len(raw_steps) < 2:
                raise RuleError("sequence needs at least two steps")
            for index, step in enumerate(raw_steps, 1):
                if not isinstance(step, dict):
                    raise RuleError(f"sequence step {index} must be a mapping")
                rule.steps.append(
                    Step(
                        name=str(step.get("name", f"step {index}")),
                        detection=Detection(step.get("detection"), where=f"step {index}"),
                        min_count=max(1, int(step.get("min_count", 1))),
                    )
                )
            if not rule.group_by:
                raise RuleError("sequence.by must name at least one field")
        tests = data.get("tests") or {}
        if tests:
            if rule.type != "match":
                raise RuleError("embedded tests are only supported on match rules")
            rule.tests = {
                "match": [t for t in _list(tests.get("match")) if isinstance(t, dict)],
                "nomatch": [t for t in _list(tests.get("nomatch")) if isinstance(t, dict)],
            }
    except RuleError as exc:
        raise RuleError(f"{where}: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{where}: {exc}") from exc
    return rule


def default_rules_dir() -> Path:
    return Path(__file__).parent / "rules"


def load_rules(paths: list[str | Path] | None = None) -> tuple[list[Rule], list[str]]:
    """Load every ``*.yml``/``*.yaml`` rule. Returns (rules, errors)."""
    targets = [Path(p) for p in paths] if paths else [default_rules_dir()]
    files: list[Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(sorted(p for p in target.rglob("*") if p.suffix in {".yml", ".yaml"}))
        elif target.exists():
            files.append(target)
        else:
            raise FileNotFoundError(f"no such rule file or directory: {target}")
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for path in files:
        try:
            with path.open(encoding="utf-8") as handle:
                rule = rule_from_dict(yaml.safe_load(handle), path)
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML: {exc}")
            continue
        except RuleError as exc:
            errors.append(str(exc))
            continue
        if rule.id in seen:
            errors.append(f"{path.name}: duplicate rule id {rule.id} (also in {seen[rule.id].name})")
            continue
        seen[rule.id] = path
        rules.append(rule)
    return rules, errors


def run_rule_tests(rules: list[Rule]) -> tuple[int, list[str]]:
    """Run each rule's embedded ``tests`` block. Returns (cases run, failures)."""
    run = 0
    failures: list[str] = []
    for rule in rules:
        if rule.detection is None:
            continue
        for expected, cases in (("match", True), ("nomatch", False)):
            for index, case in enumerate(rule.tests.get(expected, []), 1):
                run += 1
                if rule.detection.matches(normalize_record(case)) != cases:
                    failures.append(f"{rule.id}: {expected} test #{index} failed")
    return run, failures

