import unittest

from lantern.engine import decode_powershell, hunt

from .helpers import at, events, rule

FAILED = {"failed": {"EventID": 4625}, "condition": "failed"}


def failed(seconds, user="j.alvarez", ip="203.0.113.45"):
    return {"EventID": 4625, "TimeCreated": at(seconds), "Computer": "WS1", "TargetUserName": user, "IpAddress": ip}


def success(seconds, ip="203.0.113.45"):
    return {"EventID": 4624, "TimeCreated": at(seconds), "Computer": "WS1", "TargetUserName": "j.alvarez",
            "IpAddress": ip, "LogonType": "10"}


def threshold_rule(**spec):
    return rule(type="threshold", detection=FAILED, threshold=spec)


def sequence_rule(min_failures=3, window="10m"):
    return rule(type="sequence", sequence={
        "by": ["IpAddress"],
        "window": window,
        "steps": [
            {"name": "failed logons", "min_count": min_failures, "detection": FAILED},
            {"name": "successful logon", "detection": {"ok": {"EventID": 4624}, "condition": "ok"}},
        ],
    })


class MatchRuleTests(unittest.TestCase):
    def test_one_finding_per_event(self):
        r = rule(detection={"sel": {"EventID": 1102}, "condition": "sel"}, fields=["SubjectUserName"])
        evs = events(
            {"EventID": 1102, "TimeCreated": at(0), "Computer": "A", "SubjectUserName": "bob"},
            {"EventID": 1102, "TimeCreated": at(5), "Computer": "B"},
            {"EventID": 4624, "TimeCreated": at(9), "Computer": "A"},
        )
        findings = hunt(evs, [r])
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].summary, "SubjectUserName=bob")

    def test_min_severity(self):
        r = rule(severity="low", detection={"sel": {"EventID": 1}, "condition": "sel"})
        evs = events({"EventID": 1, "TimeCreated": at(0)})
        self.assertEqual(len(hunt(evs, [r], min_severity="medium")), 0)


class ThresholdTests(unittest.TestCase):
    def test_count_reached_inside_window(self):
        r = threshold_rule(group_by=["IpAddress"], count=5, window="1m")
        findings = hunt(events(*[failed(i * 10) for i in range(5)]), [r])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].events), 5)

    def test_count_spread_too_thin(self):
        r = threshold_rule(group_by=["IpAddress"], count=5, window="1m")
        self.assertEqual(hunt(events(*[failed(i * 30) for i in range(5)]), [r]), [])

    def test_groups_are_separate(self):
        r = threshold_rule(group_by=["IpAddress"], count=3, window="5m")
        evs = events(failed(0, ip="1.1.1.1"), failed(1, ip="2.2.2.2"), failed(2, ip="1.1.1.1"), failed(3, ip="2.2.2.2"))
        self.assertEqual(hunt(evs, [r]), [])

    def test_distinct(self):
        r = threshold_rule(group_by=["IpAddress"], distinct="TargetUserName", count=3, window="5m")
        same_user = events(*[failed(i) for i in range(6)])
        self.assertEqual(hunt(same_user, [r]), [])
        many_users = events(*[failed(i, user=f"user{i}") for i in range(4)])
        findings = hunt(many_users, [r])
        self.assertEqual(len(findings), 1)
        self.assertIn("4 distinct TargetUserName", findings[0].summary)

    def test_burst_is_one_finding(self):
        r = threshold_rule(group_by=["IpAddress"], count=3, window="1m")
        findings = hunt(events(*[failed(i * 20) for i in range(12)]), [r])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].events), 12)

    def test_separate_bursts(self):
        r = threshold_rule(group_by=["IpAddress"], count=3, window="1m")
        first = [failed(i) for i in range(3)]
        second = [failed(3600 + i) for i in range(3)]
        self.assertEqual(len(hunt(events(*first, *second), [r])), 2)

    def test_empty_key_values_are_ignored(self):
        r = threshold_rule(group_by=["IpAddress"], count=3, window="1m")
        self.assertEqual(hunt(events(*[failed(i, ip="-") for i in range(5)]), [r]), [])


class SequenceTests(unittest.TestCase):
    def test_failures_then_success(self):
        evs = events(failed(0), failed(10), failed(20), success(30))
        findings = hunt(evs, [sequence_rule()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].events), 4)
        self.assertIn("3 failed logons, then 1 successful logon", findings[0].summary)

    def test_not_enough_failures(self):
        self.assertEqual(hunt(events(failed(0), failed(10), success(20)), [sequence_rule()]), [])

    def test_order_matters(self):
        self.assertEqual(hunt(events(success(0), failed(10), failed(20), failed(30)), [sequence_rule()]), [])

    def test_window(self):
        evs = events(failed(0), failed(10), failed(20), success(20 + 11 * 60))
        self.assertEqual(hunt(evs, [sequence_rule(window="10m")]), [])

    def test_different_keys_do_not_combine(self):
        evs = events(failed(0, ip="1.1.1.1"), failed(1, ip="1.1.1.1"), failed(2, ip="1.1.1.1"), success(3, ip="9.9.9.9"))
        self.assertEqual(hunt(evs, [sequence_rule()]), [])

    def test_events_are_not_reused(self):
        evs = events(failed(0), failed(1), failed(2), success(3), success(4))
        self.assertEqual(len(hunt(evs, [sequence_rule()])), 1)

    def test_evidence_includes_earlier_failures_in_window(self):
        evs = events(*[failed(i * 5) for i in range(10)], success(60))
        findings = hunt(evs, [sequence_rule()])
        self.assertEqual(len(findings[0].events), 11)


class DecodeTests(unittest.TestCase):
    def test_decodes_utf16_base64(self):
        command = "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
        self.assertEqual(decode_powershell(command), "IEX (New-Object)")

    def test_ignores_other_flags(self):
        self.assertIsNone(decode_powershell("powershell.exe -ExecutionPolicy Bypass -File run.ps1"))
        self.assertIsNone(decode_powershell("powershell.exe -enc notbase64!!"))


if __name__ == "__main__":
    unittest.main()
