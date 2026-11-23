"""Load Windows event records from common export formats and normalize them.

Every record, whatever format it came from, becomes an :class:`Event` with a
flat ``fields`` dictionary. System properties use fixed names (``EventID``,
``TimeCreated``, ``Computer``, ``Channel``, ``Provider``, ``EventRecordID``)
and EventData/UserData values keep their Windows field names
(``TargetUserName``, ``IpAddress``, ``CommandLine`` and so on), so rules read
the same whether the input was JSON Lines, ``evtx_dump`` JSON, Windows event
XML or a raw ``.evtx`` file.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SUPPORTED_SUFFIXES = {".jsonl", ".ndjson", ".json", ".xml", ".evtx"}

# Alternate names used by different exporters, mapped to Lantern's names.
_ALIASES = {
    "Id": "EventID",
    "EventId": "EventID",
    "event_id": "EventID",
    "MachineName": "Computer",
    "Hostname": "Computer",
    "host": "Computer",
    "LogName": "Channel",
    "ProviderName": "Provider",
    "RecordId": "EventRecordID",
    "@timestamp": "TimeCreated",
    "timestamp": "TimeCreated",
}

# System properties that EventData/UserData values must not overwrite. A data
# field with one of these names (System event 104 carries the cleared log's
# name as "Channel", for example) is kept as "EventData.<name>" instead.
SYSTEM_FIELDS = {
    "EventID", "TimeCreated", "Computer", "Channel", "Provider", "EventRecordID",
    "Level", "Task", "Opcode", "Keywords", "Version",
}

_MS_DATE = re.compile(r"/Date\((-?\d+)\)/")
_FRACTION = re.compile(r"\.(\d+)")


@dataclass
class Event:
    """A single normalized event."""

    fields: dict[str, Any]
    timestamp: datetime
    source: str = ""

    def get(self, name: str, default: Any = None) -> Any:
        return self.fields.get(name, default)

    @property
    def event_id(self) -> int | None:
        value = self.fields.get("EventID")
        return value if isinstance(value, int) else None

    @property
    def computer(self) -> str:
        return str(self.fields.get("Computer") or "unknown")


@dataclass
class LoadResult:
    events: list[Event] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Timestamps


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the timestamp formats Windows tooling commonly produces.

    Handles ISO 8601 with or without ``Z``, 7-digit Windows fractions,
    Sysmon's ``2026-03-14 02:10:04.123`` style, PowerShell 5's
    ``/Date(1773454204000)/`` and Unix epochs in seconds or milliseconds.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 10**11 else value
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    else:
        text = str(value).strip()
        ms = _MS_DATE.search(text)
        if ms:
            return datetime.fromtimestamp(int(ms.group(1)) / 1000, tz=timezone.utc)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d.*", text):
            text = text.replace(" ", "T", 1)
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Normalization of dictionary-shaped records


def _scalar(value: Any) -> Any:
    """Unwrap evtx_dump style ``{"#text": ..., "#attributes": {...}}`` values."""
    if isinstance(value, dict):
        if "#text" in value:
            return value["#text"]
        attrs = value.get("#attributes")
        if isinstance(attrs, dict) and len(attrs) == 1:
            return next(iter(attrs.values()))
    return value


def _flatten_system(system: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in system.items():
        attrs = value.get("#attributes", {}) if isinstance(value, dict) else {}
        if key == "Provider":
            out["Provider"] = attrs.get("Name") if attrs else _scalar(value)
        elif key == "TimeCreated":
            out["TimeCreated"] = attrs.get("SystemTime") if attrs else _scalar(value)
        elif key in {"Execution", "Correlation", "Security"}:
            for attr_name, attr_value in attrs.items():
                out[attr_name] = attr_value
        else:
            out[key] = _scalar(value)
    return out


def _flatten_data(data: Any) -> dict[str, Any]:
    """Flatten EventData/UserData in any of the common JSON shapes."""
    out: dict[str, Any] = {}
    if not isinstance(data, dict):
        return out
    items = data.get("Data")
    rest = data
    if isinstance(items, (list, dict)):
        for item in items if isinstance(items, list) else [items]:
            if not isinstance(item, dict):
                continue
            name = item.get("Name") or item.get("@Name") or (item.get("#attributes") or {}).get("Name")
            if name:
                out[name] = item.get("Value", item.get("#text"))
        rest = {k: v for k, v in data.items() if k != "Data"}
    for key, value in rest.items():
        if key == "#attributes":
            continue
        if isinstance(value, dict):
            if "#text" in value:
                out[key] = value["#text"]
            else:
                out.update(_flatten_data(value))
        else:
            out[key] = value
    return out


def _merge_data(out: dict[str, Any], data: dict[str, Any]) -> None:
    for key, value in data.items():
        out[f"EventData.{key}" if key in SYSTEM_FIELDS and key in out else key] = value


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Turn one exported record (flat or nested) into Lantern's flat field set."""
    if isinstance(record.get("Event"), dict):
        record = record["Event"]
    out: dict[str, Any] = {}
    if isinstance(record.get("System"), dict):
        out.update(_flatten_system(record["System"]))
        for key, value in record.items():
            if key in {"EventData", "UserData"}:
                _merge_data(out, _flatten_data(value))
            elif key not in {"System", "#attributes"}:
                out[key] = _scalar(value)
    else:
        for key, value in record.items():
            if key in {"EventData", "UserData"} and isinstance(value, dict):
                _merge_data(out, _flatten_data(value))
            else:
                out[_ALIASES.get(key, key)] = value
    event_id = out.get("EventID")
    if isinstance(event_id, str) and event_id.strip().isdigit():
        out["EventID"] = int(event_id)
    return out


# --------------------------------------------------------------------------
# Windows event XML


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _local(child.tag) == name:
            return child
    return None


def parse_event_xml(elem: ET.Element) -> dict[str, Any]:
    """Convert a Windows ``<Event>`` element into a flat field dictionary."""
    out: dict[str, Any] = {}
    system = _child(elem, "System")
    if system is not None:
        for child in system:
            tag = _local(child.tag)
            if tag == "Provider":
                out["Provider"] = child.get("Name")
            elif tag == "TimeCreated":
                out["TimeCreated"] = child.get("SystemTime")
            elif tag in {"Execution", "Correlation", "Security"}:
                out.update(child.attrib)
            else:
                out[tag] = (child.text or "").strip()
    data: dict[str, Any] = {}
    event_data = _child(elem, "EventData")
    if event_data is not None:
        for item in event_data:
            name = item.get("Name")
            if name:
                data[name] = item.text or ""
    user_data = _child(elem, "UserData")
    if user_data is not None:
        for leaf in user_data.iter():
            if leaf is not user_data and len(leaf) == 0:
                data[_local(leaf.tag)] = (leaf.text or "").strip()
    _merge_data(out, data)
    event_id = out.get("EventID")
    if isinstance(event_id, str) and event_id.isdigit():
        out["EventID"] = int(event_id)
    return out


# --------------------------------------------------------------------------
# File readers


def _read_jsonl(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    with path.open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                yield f"{path.name}:{number}", None
                continue
            yield f"{path.name}:{number}", record if isinstance(record, dict) else None


def _read_json(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    with path.open(encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        for key in ("events", "Events", "records", "Records"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    for index, record in enumerate(data if isinstance(data, list) else [], 1):
        yield f"{path.name}#{index}", record if isinstance(record, dict) else None


def _read_xml(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    root = ET.parse(path).getroot()
    elements = [root] if _local(root.tag) == "Event" else [e for e in root.iter() if _local(e.tag) == "Event"]
    for index, elem in enumerate(elements, 1):
        yield f"{path.name}#{index}", parse_event_xml(elem)


def _read_evtx(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise RuntimeError(
            f"{path.name}: reading .evtx needs the optional dependency; "
            "install it with: pip install 'lantern-hunt[evtx]'"
        ) from exc
    with Evtx(str(path)) as log:  # pragma: no cover - depends on optional extra
        for record in log.records():
            try:
                yield f"{path.name}#{record.record_num()}", parse_event_xml(ET.fromstring(record.xml()))
            except ET.ParseError:
                yield f"{path.name}#{record.record_num()}", None


_READERS = {
    ".jsonl": _read_jsonl,
    ".ndjson": _read_jsonl,
    ".json": _read_json,
    ".xml": _read_xml,
    ".evtx": _read_evtx,
}


def _expand_paths(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() in SUPPORTED_SUFFIXES))
        elif path.exists():
            files.append(path)
        else:
            raise FileNotFoundError(f"no such file or directory: {path}")
    return files


def load_events(paths: Iterable[str | Path]) -> LoadResult:
    """Load and normalize every event in ``paths``, sorted by time."""
    result = LoadResult()
    for path in _expand_paths(paths):
        reader = _READERS.get(path.suffix.lower())
        if reader is None:
            result.warnings.append(f"{path}: unsupported file type, skipped")
            continue
        result.files.append(path)
        for source, record in reader(path):
            if record is None:
                result.skipped += 1
                continue
            fields = normalize_record(record) if reader is not _read_xml and reader is not _read_evtx else record
            timestamp = parse_timestamp(fields.get("TimeCreated"))
            if timestamp is None:
                result.skipped += 1
                continue
            result.events.append(Event(fields=fields, timestamp=timestamp, source=source))
    result.events.sort(key=lambda e: e.timestamp)
    if result.skipped:
        result.warnings.append(f"skipped {result.skipped} record(s) that were not valid events or had no timestamp")
    return result


def events_from_records(records: Iterable[dict[str, Any]]) -> list[Event]:
    """Build events from in-memory dictionaries (used by tests and the sample generator)."""
    events = []
    for index, record in enumerate(records, 1):
        fields = normalize_record(record)
        timestamp = parse_timestamp(fields.get("TimeCreated"))
        if timestamp is not None:
            events.append(Event(fields=fields, timestamp=timestamp, source=f"memory#{index}"))
    events.sort(key=lambda e: e.timestamp)
    return events
