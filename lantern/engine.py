"""Run rules over events and produce findings."""

from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from .attack import tactics_for
from .events import Event
from .rules import Rule, severity_rank

_EMPTY_KEY_VALUES = {"", "-", "none", "null"}
_ENCODED_ARG = re.compile(r"\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)


@dataclass
class Finding:
    rule: Rule
    events: list[Event]
    key: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    details: dict[str, str] = field(default_factory=dict)

    @property
    def start(self) -> datetime:
        return self.events[0].timestamp

    @property
    def end(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def hosts(self) -> list[str]:
        return sorted({e.computer for e in self.events})

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for technique in self.rule.attack:
            for tactic in tactics_for(technique):
                if tactic not in seen:
                    seen.append(tactic)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity,
            "attack": self.rule.attack,
            "tactics": self.tactics,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "hosts": self.hosts,
            "key": self.key,
            "summary": self.summary,
            "details": self.details,
            "event_count": len(self.events),
            "events": [{"source": e.source, **_jsonable(e.fields)} for e in self.events],
        }


def _jsonable(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v if isinstance(v, (str, int, float, bool, type(None), list)) else str(v) for k, v in fields.items()}


# --------------------------------------------------------------------------
# Enrichment


def decode_powershell(command_line: str) -> str | None:
    """Decode a PowerShell ``-EncodedCommand`` argument (base64 UTF-16LE)."""
    match = _ENCODED_ARG.search(" " + command_line)
    if not match:
        return None
    blob = match.group(1)
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
    return decoded.strip() if decoded and printable / len(decoded) > 0.9 else None


def _enrich(finding: Finding) -> None:
    for event in finding.events:
        command_line = event.get("CommandLine")
        if isinstance(command_line, str):
            decoded = decode_powershell(command_line)
            if decoded:
                finding.details["Decoded PowerShell"] = decoded
                return


# --------------------------------------------------------------------------
# Helpers


def _norm(value: Any) -> str:
    return str(value).strip().lower()


def _key_for(event: Event, fields: list[str]) -> tuple[str, ...] | None:
    key = []
    for name in fields:
        value = event.get(name)
        if value is None or _norm(value) in _EMPTY_KEY_VALUES:
            return None
        key.append(_norm(value))
    return tuple(key)


def _describe_fields(rule: Rule, event: Event) -> str:
    parts = []
    for name in rule.fields:
        value = event.get(name)
        if value not in (None, "", "-"):
            text = str(value)
            parts.append(f"{name}={text if len(text) <= 90 else text[:87] + '...'}")
    return ", ".join(parts)


# --------------------------------------------------------------------------
# Rule evaluation


def _run_match(rule: Rule, events: list[Event]) -> list[Finding]:
    assert rule.detection is not None
    return [
        Finding(rule=rule, events=[event], summary=_describe_fields(rule, event))
        for event in events
        if rule.detection.matches(event)
    ]


def _measure(rule: Rule, window: Iterable[Event]) -> int:
    if rule.distinct:
        return len({_norm(e.get(rule.distinct)) for e in window if e.get(rule.distinct) not in (None, "", "-")})
    return sum(1 for _ in window)


def _run_threshold(rule: Rule, events: list[Event]) -> list[Finding]:
    """Sliding-window counting per group.

    Once a group crosses the threshold, later events from the same group keep
    joining that finding as long as each arrives within one window of the
    previous one, so a single long attack burst produces one finding.
    """
    assert rule.detection is not None and rule.window is not None
    groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        if rule.detection.matches(event):
            key = _key_for(event, rule.group_by)
            if key is not None:
                groups[key].append(event)

    findings: list[Finding] = []

    def emit(burst: list[Event]) -> None:
        first = burst[0]
        key = {name: first.get(name) for name in rule.group_by}
        measured = _measure(rule, burst)
        what = f"{measured} distinct {rule.distinct} values" if rule.distinct else f"{measured} matching events"
        span = burst[-1].timestamp - first.timestamp
        key_text = ", ".join(f"{k}={v}" for k, v in key.items())
        summary = f"{what} in {_format_span(span)}" + (f" from {key_text}" if key_text else "")
        findings.append(Finding(rule=rule, events=list(burst), key=key, summary=summary))

    for burst_events in groups.values():
        window: deque[Event] = deque()
        active: list[Event] | None = None
        for event in burst_events:
            if active is not None:
                if event.timestamp - active[-1].timestamp <= rule.window:
                    active.append(event)
                    continue
                emit(active)
                active = None
            window.append(event)
            while event.timestamp - window[0].timestamp > rule.window:
                window.popleft()
            if _measure(rule, window) >= rule.count:
                active = list(window)
                window.clear()
        if active is not None:
            emit(active)
    return findings


def _run_sequence(rule: Rule, events: list[Event]) -> list[Finding]:
    """Ordered steps per key inside a window.

    For every event that matches the last step, Lantern walks backwards
    through that key's history, greedily satisfying each earlier step's
    ``min_count`` with the most recent qualifying events. Events used by one
    finding are not reused by the next one for the same key.
    """
    assert rule.window is not None
    steps = rule.steps
    last = len(steps) - 1
    groups: dict[tuple[str, ...], list[tuple[Event, set[int]]]] = defaultdict(list)
    for event in events:
        matched = {index for index, step in enumerate(steps) if step.detection.matches(event)}
        if matched:
            key = _key_for(event, rule.group_by)
            if key is not None:
                groups[key].append((event, matched))

    findings: list[Finding] = []
    for history in groups.values():
        floor: datetime | None = None
        for position, (trigger, matched) in enumerate(history):
            if last not in matched or (floor is not None and trigger.timestamp <= floor):
                continue
            earliest_allowed = trigger.timestamp - rule.window
            boundary = position + 1
            used: dict[int, list[Event]] = {}
            for step_index in range(last, -1, -1):
                need = steps[step_index].min_count
                got: list[Event] = []
                cursor = boundary - 1
                while cursor >= 0 and len(got) < need:
                    event, event_steps = history[cursor]
                    if event.timestamp < earliest_allowed or (floor is not None and event.timestamp <= floor):
                        break
                    if step_index in event_steps:
                        got.append(event)
                    cursor -= 1
                if len(got) < need:
                    break
                used[step_index] = got
                boundary = cursor + 1
            else:
                start = min(e.timestamp for e in used[0])
                # Pull in earlier first-step events still inside the window as context.
                for event, event_steps in history[:boundary]:
                    if 0 in event_steps and event.timestamp >= earliest_allowed and (floor is None or event.timestamp > floor):
                        start = min(start, event.timestamp)
                window_items = [
                    (event, event_steps)
                    for event, event_steps in history[: position + 1]
                    if start <= event.timestamp and (floor is None or event.timestamp > floor)
                ]
                evidence = [event for event, _ in window_items]
                counts = {
                    steps[i].name: sum(1 for _, event_steps in window_items if i in event_steps)
                    for i in range(len(steps))
                }
                key = {name: trigger.get(name) for name in rule.group_by}
                key_text = ", ".join(f"{k}={v}" for k, v in key.items())
                chain = ", then ".join(f"{count} {name}" for name, count in counts.items())
                summary = f"{chain} in {_format_span(trigger.timestamp - start)} for {key_text}"
                findings.append(Finding(rule=rule, events=evidence, key=key, summary=summary))
                floor = trigger.timestamp
    return findings


def _format_span(span) -> str:
    seconds = int(span.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"


_RUNNERS = {"match": _run_match, "threshold": _run_threshold, "sequence": _run_sequence}


def hunt(events: list[Event], rules: list[Rule], min_severity: str = "info") -> list[Finding]:
    """Evaluate every rule against ``events`` (which must be sorted by time)."""
    floor = severity_rank(min_severity)
    findings: list[Finding] = []
    for rule in rules:
        if rule.rank < floor:
            continue
        for finding in _RUNNERS[rule.type](rule, events):
            _enrich(finding)
            findings.append(finding)
    findings.sort(key=lambda f: (f.start, -f.rule.rank, f.rule.id))
    return findings
