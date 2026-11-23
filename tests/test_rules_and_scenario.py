import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from lantern.attack import TECHNIQUES
from lantern.cli import main
from lantern.engine import hunt
from lantern.events import events_from_records
from lantern.report import HuntContext, render_html, to_json
from lantern.rules import load_rules, run_rule_tests
from lantern.sample import generate

ROOT = Path(__file__).resolve().parent.parent

EXPECTED = Counter({
    "LNT-001": 1, "LNT-002": 1, "LNT-003": 1, "LNT-004": 1, "LNT-005": 1, "LNT-006": 2, "LNT-007": 1,
    "LNT-008": 1, "LNT-009": 1, "LNT-010": 1, "LNT-011": 1, "LNT-012": 1, "LNT-013": 1, "LNT-014": 3,
    "LNT-015": 1, "LNT-016": 1,
})


class BundledRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules, cls.errors = load_rules()

    def test_rules_load_cleanly(self):
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.rules), 16)

    def test_every_rule_is_documented_and_mapped(self):
        for r in self.rules:
            with self.subTest(rule=r.id):
                self.assertTrue(r.description)
                self.assertTrue(r.attack)
                self.assertTrue(all(t in TECHNIQUES for t in r.attack))
                self.assertTrue(r.falsepositives)

    def test_every_match_rule_has_embedded_tests(self):
        for r in self.rules:
            if r.type == "match":
                with self.subTest(rule=r.id):
                    self.assertTrue(r.tests.get("match"))
                    self.assertTrue(r.tests.get("nomatch"))

    def test_embedded_tests_pass(self):
        run, failures = run_rule_tests(self.rules)
        self.assertGreater(run, 30)
        self.assertEqual(failures, [])


class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules, _ = load_rules()

    def test_attack_scenario_is_fully_detected(self):
        findings = hunt(events_from_records(generate()), self.rules)
        self.assertEqual(Counter(f.rule.id for f in findings), EXPECTED)

    def test_benign_baseline_has_no_false_positives(self):
        for seed in (1, 7, 42, 1337):
            with self.subTest(seed=seed):
                findings = hunt(events_from_records(generate(seed=seed, attack=False)), self.rules)
                self.assertEqual([f.rule.id for f in findings], [])

    def test_committed_sample_matches_generator(self):
        committed = (ROOT / "samples" / "attack_scenario.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(line) for line in committed], generate())

    def test_reports_render(self):
        evs = events_from_records(generate())
        ctx = HuntContext(events=evs, rules=self.rules, findings=hunt(evs, self.rules), inputs=["memory"])
        page = render_html(ctx)
        self.assertIn("Lantern hunt report", page)
        self.assertIn("IEX (New-Object Net.WebClient)", page)  # decoded PowerShell
        data = to_json(ctx)
        self.assertEqual(len(data["findings"]), sum(EXPECTED.values()))
        json.dumps(data)


class CliTests(unittest.TestCase):
    def test_hunt_writes_reports_and_fails_on_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            html_path, json_path = Path(tmp) / "r.html", Path(tmp) / "f.json"
            code = main(["hunt", str(ROOT / "samples" / "attack_scenario.jsonl"), "-q",
                         "--html", str(html_path), "--json", str(json_path), "--fail-on", "critical"])
            self.assertEqual(code, 3)
            self.assertTrue(html_path.read_text(encoding="utf-8").startswith("<!doctype html>"))
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["tool"], "lantern")

    def test_benign_sample_exits_cleanly(self):
        self.assertEqual(main(["hunt", str(ROOT / "samples" / "benign_baseline.jsonl"), "-q", "--fail-on", "low"]), 0)


if __name__ == "__main__":
    unittest.main()
