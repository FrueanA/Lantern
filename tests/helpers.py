from datetime import datetime, timedelta, timezone

from lantern.events import events_from_records
from lantern.rules import rule_from_dict

BASE = datetime(2026, 3, 14, 2, 0, tzinfo=timezone.utc)


def at(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat()


def events(*records):
    return events_from_records(list(records))


def rule(**data):
    data.setdefault("id", "TEST-1")
    data.setdefault("title", "Test rule")
    data.setdefault("severity", "medium")
    return rule_from_dict(data)
