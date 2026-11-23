"""Command-line interface: ``lantern hunt``, ``lantern rules`` and ``lantern sample``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import hunt
from .events import load_events
from .report import HuntContext, print_console, write_html, write_json
from .rules import SEVERITIES, load_rules, run_rule_tests, severity_rank

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 3


def _load_rules_or_exit(paths: list[str] | None):
    try:
        rules, errors = load_rules(paths)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None
    for error in errors:
        print(f"rule error: {error}", file=sys.stderr)
    if errors:
        print(f"error: fix the {len(errors)} rule error(s) above, or point --rules at another folder", file=sys.stderr)
        return None
    return rules


def cmd_hunt(args: argparse.Namespace) -> int:
    rules = _load_rules_or_exit(args.rules)
    if rules is None:
        return EXIT_ERROR
    try:
        loaded = load_events(args.paths)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for warning in loaded.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not loaded.events:
        print("error: no events were loaded; check the file format (see README: Exporting logs)", file=sys.stderr)
        return EXIT_ERROR

    findings = hunt(loaded.events, rules, min_severity=args.min_severity)
    ctx = HuntContext(events=loaded.events, rules=rules, findings=findings,
                      inputs=[str(p) for p in loaded.files])
    if not args.quiet:
        print_console(ctx, color=False if args.no_color else None)
    if args.json:
        print(f"Wrote {write_json(ctx, args.json)}", file=sys.stderr)
    if args.html:
        print(f"Wrote {write_html(ctx, args.html)}", file=sys.stderr)
    if args.fail_on and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rules = _load_rules_or_exit(args.rules)
    if rules is None:
        return EXIT_ERROR
    for rule in sorted(rules, key=lambda r: r.id):
        attack = ", ".join(rule.attack) or "-"
        print(f"{rule.id}  {rule.severity:<8}  {rule.type:<9}  {rule.title}  [{attack}]")
        for warning in rule.warnings():
            print(f"  warning: {warning}", file=sys.stderr)
    if args.test:
        run, failures = run_rule_tests(rules)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"\n{run - len(failures)}/{run} embedded rule tests passed")
        return EXIT_ERROR if failures else EXIT_OK
    return EXIT_OK


def cmd_sample(args: argparse.Namespace) -> int:
    from .sample import generate, write_jsonl

    records = generate(seed=args.seed, attack=not args.benign)
    path = write_jsonl(records, args.output)
    print(f"Wrote {len(records)} events to {path}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lantern",
        description="SIEM-less threat hunting for Windows event logs, with Sigma-style rules mapped to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"lantern {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    hunt_p = sub.add_parser("hunt", help="run detection rules over event files")
    hunt_p.add_argument("paths", nargs="+", help="event files or folders (.jsonl, .json, .xml, .evtx)")
    hunt_p.add_argument("-r", "--rules", action="append", metavar="PATH",
                        help="rule file or folder (repeatable; defaults to the bundled rules)")
    hunt_p.add_argument("--min-severity", choices=SEVERITIES, default="info",
                        help="skip rules below this severity (default: info)")
    hunt_p.add_argument("--html", metavar="FILE", help="write an HTML report")
    hunt_p.add_argument("--json", metavar="FILE", help="write findings as JSON")
    hunt_p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                        help=f"exit with code {EXIT_FINDINGS} if any finding is at or above this severity")
    hunt_p.add_argument("-q", "--quiet", action="store_true", help="do not print findings to the terminal")
    hunt_p.add_argument("--no-color", action="store_true", help="disable colored output")
    hunt_p.set_defaults(func=cmd_hunt)

    rules_p = sub.add_parser("rules", help="list and validate rules")
    rules_p.add_argument("-r", "--rules", action="append", metavar="PATH", help="rule file or folder (repeatable)")
    rules_p.add_argument("--test", action="store_true", help="run the tests embedded in each rule")
    rules_p.set_defaults(func=cmd_rules)

    sample_p = sub.add_parser("sample", help="generate the synthetic attack-scenario dataset")
    sample_p.add_argument("-o", "--output", default="samples/attack_scenario.jsonl", type=Path)
    sample_p.add_argument("--seed", type=int, default=7)
    sample_p.add_argument("--benign", action="store_true", help="generate only normal activity (no attacks)")
    sample_p.set_defaults(func=cmd_sample)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
