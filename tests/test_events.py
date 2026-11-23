import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from lantern.events import load_events, normalize_record, parse_event_xml, parse_timestamp

WINDOWS_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-03-14T02:10:04.1234567Z"/>
    <EventRecordID>48211</EventRecordID>
    <Execution ProcessID="712" ThreadID="1880"/>
    <Channel>Security</Channel>
    <Computer>WS-FIN-07.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">j.alvarez</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">203.0.113.45</Data>
  </EventData>
</Event>"""


class TimestampTests(unittest.TestCase):
    def test_formats(self):
        expected = datetime(2026, 3, 14, 2, 10, 4, tzinfo=timezone.utc)
        for value in [
            "2026-03-14T02:10:04Z",
            "2026-03-14T02:10:04.0000000Z",
            "2026-03-14 02:10:04.000",
            "2026-03-14T03:10:04+01:00",
            "/Date(1773454204000)/",
            1773454204,
            1773454204000,
        ]:
            with self.subTest(value=value):
                self.assertEqual(parse_timestamp(value).replace(microsecond=0), expected)

    def test_garbage(self):
        self.assertIsNone(parse_timestamp("yesterday"))
        self.assertIsNone(parse_timestamp(None))


class NormalizeTests(unittest.TestCase):
    def test_flat_record_with_aliases(self):
        fields = normalize_record({"Id": "4624", "MachineName": "DC01", "LogName": "Security", "IpAddress": "10.0.0.5"})
        self.assertEqual(fields["EventID"], 4624)
        self.assertEqual(fields["Computer"], "DC01")
        self.assertEqual(fields["Channel"], "Security")

    def test_evtx_dump_shape(self):
        record = {"Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4625,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-03-14T02:10:04.123456Z"}},
                "Channel": "Security",
                "Computer": "WS-FIN-07",
            },
            "EventData": {"TargetUserName": "j.alvarez", "IpAddress": "203.0.113.45"},
        }}
        fields = normalize_record(record)
        self.assertEqual(fields["Provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(fields["TimeCreated"], "2026-03-14T02:10:04.123456Z")
        self.assertEqual(fields["TargetUserName"], "j.alvarez")

    def test_named_data_list(self):
        fields = normalize_record({"EventID": 1, "EventData": {"Data": [{"@Name": "Image", "#text": "C:\\x.exe"}]}})
        self.assertEqual(fields["Image"], "C:\\x.exe")

    def test_data_does_not_overwrite_system_fields(self):
        record = {"System": {"EventID": 104, "Channel": "System"}, "UserData": {"LogFileCleared": {"Channel": "Application"}}}
        fields = normalize_record(record)
        self.assertEqual(fields["Channel"], "System")
        self.assertEqual(fields["EventData.Channel"], "Application")

    def test_windows_xml(self):
        fields = parse_event_xml(ET.fromstring(WINDOWS_XML))
        self.assertEqual(fields["EventID"], 4625)
        self.assertEqual(fields["Computer"], "WS-FIN-07.corp.local")
        self.assertEqual(fields["IpAddress"], "203.0.113.45")
        self.assertEqual(fields["ProcessID"], "712")


class LoadTests(unittest.TestCase):
    def test_load_mixed_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "a.jsonl").write_text(
                json.dumps({"EventID": 4624, "TimeCreated": "2026-03-14T02:00:00Z", "Computer": "A"}) + "\n"
                + "not json\n"
                + json.dumps({"EventID": 4624, "Computer": "no time"}) + "\n",
                encoding="utf-8",
            )
            (folder / "b.xml").write_text(WINDOWS_XML, encoding="utf-8")
            (folder / "c.json").write_text(json.dumps({"events": [
                {"EventID": 1102, "TimeCreated": "2026-03-14T01:00:00Z", "Computer": "C"}
            ]}), encoding="utf-8")
            result = load_events([folder])
        self.assertEqual([e.event_id for e in result.events], [1102, 4624, 4625])
        self.assertEqual(result.skipped, 2)
        self.assertEqual(len(result.files), 3)

    def test_missing_path(self):
        with self.assertRaises(FileNotFoundError):
            load_events(["/definitely/not/here.jsonl"])


if __name__ == "__main__":
    unittest.main()
