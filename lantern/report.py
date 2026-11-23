"""Render findings as console text, JSON or a self-contained HTML report."""

from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .attack import TACTICS, technique_name, technique_url
from .engine import Finding
from .events import Event
from .rules import SEVERITIES, Rule

_ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"
_EVIDENCE_LIMIT = 60
_COMMON_FIELDS = [
    "TargetUserName", "IpAddress", "LogonType", "SubjectUserName", "User", "Image", "NewProcessName",
    "CommandLine", "ScriptBlockText", "ServiceName", "ImagePath", "TaskName", "SourceImage", "GrantedAccess",
]


@dataclass
class HuntContext:
    """Everything the reports need to describe a run."""

    events: list[Event]
    rules: list[Rule]
    findings: list[Finding]
    inputs: list[str] = field(default_factory=list)
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def hosts(self) -> list[str]:
        return sorted({e.computer for e in self.events})

    @property
    def severity_counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)


def _fmt_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def summary_sentence(ctx: HuntContext) -> str:
    if not ctx.findings:
        return f"No findings in {_plural(len(ctx.events), 'event')} across {_plural(len(ctx.hosts), 'host')}."
    hosts = sorted({h for f in ctx.findings for h in f.hosts})
    first = min(f.start for f in ctx.findings)
    last = max(f.end for f in ctx.findings)
    counts = ctx.severity_counts
    breakdown = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    return (
        f"{_plural(len(ctx.findings), 'finding')} on {_plural(len(hosts), 'host')} between "
        f"{first:%H:%M} and {last:%H:%M} UTC ({breakdown})."
    )


# --------------------------------------------------------------------------
# Console


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def print_console(ctx: HuntContext, stream=None, color: bool | None = None) -> None:
    stream = stream or sys.stdout
    color = _use_color(stream) if color is None else color

    def paint(text: str, severity: str) -> str:
        return f"{_ANSI[severity]}{text}{_RESET}" if color else text

    span = ""
    if ctx.events:
        span = f", {_fmt_time(ctx.events[0].timestamp)} to {_fmt_time(ctx.events[-1].timestamp)} UTC"
    print(f"Lantern {__version__}: {_plural(len(ctx.events), 'event')} from {_plural(len(ctx.inputs), 'input')}"
          f"{span}, {_plural(len(ctx.hosts), 'host')}, {_plural(len(ctx.rules), 'rule')}", file=stream)
    print(summary_sentence(ctx), file=stream)
    if not ctx.findings:
        return
    print("", file=stream)
    width = max(len(f.rule.title) for f in ctx.findings)
    for finding in ctx.findings:
        label = paint(f"{finding.severity.upper():<8}", finding.severity)
        host = ",".join(h.split(".")[0] for h in finding.hosts)
        print(f"{_fmt_time(finding.start)}  {label}  {finding.rule.id}  {finding.rule.title:<{width}}  {host}", file=stream)
        if finding.summary:
            print(f"{'':21}{finding.summary}", file=stream)
        for name, value in finding.details.items():
            print(f"{'':21}{name}: {value}", file=stream)


# --------------------------------------------------------------------------
# JSON


def to_json(ctx: HuntContext) -> dict[str, Any]:
    return {
        "tool": "lantern",
        "version": __version__,
        "generated": ctx.generated.isoformat(),
        "inputs": ctx.inputs,
        "event_count": len(ctx.events),
        "hosts": ctx.hosts,
        "rules": [r.id for r in ctx.rules],
        "summary": summary_sentence(ctx),
        "severity_counts": {s: ctx.severity_counts.get(s, 0) for s in SEVERITIES},
        "findings": [f.to_dict() for f in ctx.findings],
    }


def write_json(ctx: HuntContext, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(to_json(ctx), indent=2, default=str), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# HTML

_CSS = """
:root {
  color-scheme: light;
  --bg: #eef1f5; --surface: #ffffff; --ink: #1a2233; --muted: #5b6578; --rule: #d5dbe4;
  --lamp: #e8a33d; --lamp-soft: #fbecd2; --lamp-ink: #5a3a06;
  --critical: #b3261e; --high: #c4521f; --medium: #9a7400; --low: #4f6f8f; --info: #6f7887;
  --serif: "Charter", "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #141a26; --surface: #1c2433; --ink: #e6eaf2; --muted: #9aa4b5; --rule: #2c3546;
    --lamp: #f2b454; --lamp-soft: #3a2f1c; --lamp-ink: #ffe2b0;
    --critical: #ff7a70; --high: #f0915c; --medium: #e2c15a; --low: #8fb0d1; --info: #9aa4b5;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 var(--sans); }
main { max-width: 1120px; margin: 0 auto; padding: 40px 24px 72px; }
h1, h2 { font-family: var(--serif); font-weight: 600; letter-spacing: -0.01em; margin: 0; }
h1 { font-size: 2.1rem; line-height: 1.15; }
h2 { font-size: 1.35rem; margin: 48px 0 14px; }
p { margin: 0; }
a { color: inherit; text-decoration-color: var(--lamp); text-underline-offset: 2px; }
a:hover { text-decoration-thickness: 2px; }
:focus-visible { outline: 3px solid var(--lamp); outline-offset: 2px; border-radius: 3px; }
code, .mono { font-family: var(--mono); font-size: 0.86em; }
.lede { font-family: var(--serif); font-size: 1.25rem; line-height: 1.4; margin-top: 12px; max-width: 46em; }
.meta { color: var(--muted); margin-top: 10px; font-size: 0.9rem; }

/* The tactic path: the one bold element on the page. */
.path { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 4px; margin-top: 32px; }
.tactic { position: relative; min-height: 104px; padding: 12px 10px; border-radius: 6px;
  background: var(--surface); border: 1px solid var(--rule); color: var(--muted); display: flex;
  flex-direction: column; justify-content: space-between; }
.tactic .name { font-size: 0.8rem; line-height: 1.25; }
.tactic .count { font-family: var(--serif); font-size: 1.6rem; line-height: 1; color: var(--rule); }
.tactic.lit { background: var(--lamp-soft);
  background: color-mix(in srgb, var(--lamp) calc(10% + var(--heat, 0.5) * 42%), var(--surface));
  border-color: var(--lamp); color: var(--lamp-ink); box-shadow: 0 0 0 1px var(--lamp), 0 6px 22px -8px var(--lamp); }
.tactic.lit .count { color: var(--lamp-ink); }
.path-note { color: var(--muted); font-size: 0.85rem; margin-top: 8px; }

.controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
.controls button, .controls select { font: inherit; font-size: 0.88rem; padding: 5px 12px; border-radius: 999px;
  border: 1px solid var(--rule); background: var(--surface); color: var(--ink); cursor: pointer; }
.controls button[aria-pressed="false"] { opacity: 0.45; }
.controls select { border-radius: 6px; }
.shown { color: var(--muted); font-size: 0.85rem; margin-left: auto; }

.findings { border-top: 1px solid var(--rule); }
details.finding { border-bottom: 1px solid var(--rule); }
details.finding > summary { list-style: none; cursor: pointer; display: grid;
  grid-template-columns: 11.5em 6.5em minmax(0, 1fr) auto; gap: 14px; align-items: baseline; padding: 12px 6px; }
details.finding > summary::-webkit-details-marker { display: none; }
details.finding > summary:hover { background: var(--surface); }
details.finding[open] > summary { background: var(--surface); }
.when { font-family: var(--mono); font-size: 0.82rem; color: var(--muted); white-space: nowrap; }
.title { font-weight: 600; }
.title small { display: block; font-weight: 400; color: var(--muted); font-size: 0.86rem; margin-top: 2px;
  overflow-wrap: anywhere; }
.where { color: var(--muted); font-size: 0.86rem; text-align: right; white-space: nowrap; }
.sev { font-size: 0.8rem; font-weight: 600; padding: 1px 9px; border-radius: 999px; justify-self: start;
  border: 1px solid currentColor; }
.sev.critical { color: #fff; background: var(--critical); border-color: var(--critical); }
.sev.high { color: var(--high); } .sev.medium { color: var(--medium); }
.sev.low { color: var(--low); } .sev.info { color: var(--info); }
@media (prefers-color-scheme: dark) { .sev.critical { color: #1c2433; } }

.body { padding: 4px 6px 22px calc(11.5em + 14px); background: var(--surface); }
.body > * + * { margin-top: 14px; }
.body .desc { max-width: 62em; }
.facts { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 16px; font-size: 0.9rem; }
.facts dt { color: var(--muted); } .facts dd { margin: 0; overflow-wrap: anywhere; }
pre.decoded { margin: 0; padding: 12px 14px; border-left: 3px solid var(--lamp); background: var(--bg);
  white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--mono); font-size: 0.84rem; }
.evidence-wrap { overflow-x: auto; border: 1px solid var(--rule); border-radius: 6px; }
table { border-collapse: collapse; width: 100%; font-size: 0.84rem; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
th { color: var(--muted); font-weight: 500; background: var(--bg); position: sticky; top: 0; }
td.kv { font-family: var(--mono); font-size: 0.8rem; overflow-wrap: anywhere; min-width: 24em; }
td.nowrap { white-space: nowrap; }
.more { color: var(--muted); font-size: 0.85rem; }

.hosts { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.host { background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; padding: 16px 18px; }
.host h3 { margin: 0 0 10px; font-size: 1rem; font-family: var(--serif); }
.host ol { list-style: none; margin: 0; padding: 0 0 0 14px; border-left: 2px solid var(--rule); }
.host li { position: relative; padding: 0 0 10px 10px; font-size: 0.88rem; }
.host li::before { content: ""; position: absolute; left: -21px; top: 0.5em; width: 10px; height: 10px;
  border-radius: 50%; background: var(--surface); border: 2px solid var(--muted); }
.host li.critical::before { background: var(--critical); border-color: var(--critical); }
.host li.high::before { border-color: var(--high); }
.host li .when { display: block; }

.quiet { color: var(--muted); }
details.rules-off > summary { cursor: pointer; color: var(--muted); }
details.rules-off ul { columns: 2 320px; margin: 10px 0 0; padding-left: 18px; color: var(--muted); font-size: 0.88rem; }
footer { margin-top: 56px; color: var(--muted); font-size: 0.82rem; }

@media (max-width: 860px) {
  .path { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  details.finding > summary { grid-template-columns: 1fr auto; }
  details.finding > summary .title { grid-column: 1 / -1; }
  .where { text-align: left; }
  .body { padding-left: 6px; }
}
@media (max-width: 520px) { .path { grid-template-columns: repeat(3, minmax(0, 1fr)); } h1 { font-size: 1.7rem; } }
@media (prefers-reduced-motion: no-preference) {
  .tactic.lit { animation: glow 1.4s ease-out both; }
  @keyframes glow { from { box-shadow: 0 0 0 1px var(--lamp), 0 0 0 -8px var(--lamp); } }
}
@media print { .controls { display: none; } details.finding .body { display: block; } }
"""

_JS = """
(() => {
  const rows = [...document.querySelectorAll('details.finding')];
  const buttons = [...document.querySelectorAll('[data-sev]')];
  const host = document.getElementById('host-filter');
  const shown = document.getElementById('shown');
  const active = new Set(buttons.map(b => b.dataset.sev));
  function apply() {
    let n = 0;
    for (const row of rows) {
      const ok = active.has(row.dataset.sev) && (!host.value || row.dataset.hosts.split(' ').includes(host.value));
      row.hidden = !ok; if (ok) n++;
    }
    shown.textContent = n === rows.length ? `Showing all ${n}` : `Showing ${n} of ${rows.length}`;
  }
  for (const b of buttons) b.addEventListener('click', () => {
    const on = b.getAttribute('aria-pressed') === 'true';
    b.setAttribute('aria-pressed', String(!on));
    on ? active.delete(b.dataset.sev) : active.add(b.dataset.sev);
    apply();
  });
  host.addEventListener('change', apply);
  document.getElementById('expand').addEventListener('click', e => {
    const open = e.target.dataset.open !== 'true';
    rows.forEach(r => { if (!r.hidden) r.open = open; });
    e.target.dataset.open = String(open);
    e.target.textContent = open ? 'Collapse all' : 'Expand all';
  });
  apply();
})();
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _short(host: str) -> str:
    return host.split(".")[0]


def _evidence_fields(finding: Finding, event: Event) -> str:
    names = list(dict.fromkeys(finding.rule.fields + _COMMON_FIELDS))
    parts = []
    for name in names:
        value = event.get(name)
        if value in (None, "", "-"):
            continue
        text = str(value)
        if len(text) > 240:
            text = text[:237] + "..."
        parts.append(f"<span>{_e(name)}=</span>{_e(text)}")
        if len(parts) == 6:
            break
    return "<br>".join(parts) or '<span class="quiet">no extra fields</span>'


def _finding_html(index: int, finding: Finding) -> str:
    rule = finding.rule
    hosts = " ".join(_short(h) for h in finding.hosts)
    techniques = ", ".join(
        f'<a href="{_e(technique_url(t))}" target="_blank" rel="noopener">{_e(t)} {_e(technique_name(t))}</a>'
        for t in rule.attack
    ) or '<span class="quiet">none</span>'
    when = _fmt_time(finding.start)
    if finding.end != finding.start:
        when_detail = f"{_fmt_time(finding.start)} to {_fmt_time(finding.end)} UTC"
    else:
        when_detail = f"{when} UTC"
    facts = [
        ("Rule", f"{_e(rule.id)} ({_e(rule.type)})"),
        ("When", _e(when_detail)),
        ("Hosts", _e(", ".join(finding.hosts))),
        ("ATT&CK", techniques),
        ("Tactics", _e(", ".join(finding.tactics)) or '<span class="quiet">none</span>'),
    ]
    if rule.falsepositives:
        facts.append(("Could also be", _e("; ".join(rule.falsepositives))))
    facts_html = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
    details = "".join(
        f'<p class="quiet">{_e(name)}</p><pre class="decoded">{_e(value)}</pre>' for name, value in finding.details.items()
    )
    shown_events = finding.events[:_EVIDENCE_LIMIT]
    rows = "".join(
        f'<tr><td class="nowrap mono">{_e(_fmt_time(ev.timestamp))}</td><td>{_e(ev.get("EventID", ""))}</td>'
        f'<td class="nowrap">{_e(_short(ev.computer))}</td><td class="kv">{_evidence_fields(finding, ev)}</td>'
        f'<td class="nowrap mono">{_e(ev.source)}</td></tr>'
        for ev in shown_events
    )
    more = ""
    if len(finding.events) > _EVIDENCE_LIMIT:
        more = f'<p class="more">{len(finding.events) - _EVIDENCE_LIMIT} more events are in the JSON output.</p>'
    count_label = _plural(len(finding.events), "event")
    return f"""
<details class="finding" id="f{index}" data-sev="{_e(finding.severity)}" data-hosts="{_e(hosts)}">
  <summary>
    <span class="when">{_e(when)}</span>
    <span class="sev {_e(finding.severity)}">{_e(finding.severity.capitalize())}</span>
    <span class="title">{_e(rule.title)}<small>{_e(finding.summary)}</small></span>
    <span class="where">{_e(hosts)}</span>
  </summary>
  <div class="body">
    <p class="desc">{_e(rule.description)}</p>
    <dl class="facts">{facts_html}</dl>
    {details}
    <p class="quiet">Evidence ({count_label})</p>
    <div class="evidence-wrap"><table>
      <thead><tr><th>Time (UTC)</th><th>Event</th><th>Host</th><th>Fields</th><th>Source</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    {more}
  </div>
</details>"""


def render_html(ctx: HuntContext) -> str:
    tactic_counts: Counter = Counter()
    for finding in ctx.findings:
        for tactic in finding.tactics:
            tactic_counts[tactic] += 1
    cells = []
    peak = max(tactic_counts.values(), default=1)
    for tactic in TACTICS:
        count = tactic_counts.get(tactic, 0)
        lit = " lit" if count else ""
        heat = f' style="--heat:{count / peak:.2f}"' if count else ""
        label = f"{tactic}: {_plural(count, 'finding')}"
        cells.append(
            f'<div class="tactic{lit}"{heat} role="listitem" aria-label="{_e(label)}">'
            f'<span class="name">{_e(tactic)}</span><span class="count">{count}</span></div>'
        )

    counts = ctx.severity_counts
    buttons = "".join(
        f'<button type="button" data-sev="{s}" aria-pressed="true">{s.capitalize()} ({counts[s]})</button>'
        for s in reversed(SEVERITIES) if counts[s]
    )
    finding_hosts = sorted({h for f in ctx.findings for h in f.hosts})
    host_options = "".join(f'<option value="{_e(_short(h))}">{_e(_short(h))}</option>' for h in finding_hosts)
    findings_html = "".join(_finding_html(i, f) for i, f in enumerate(ctx.findings, 1))
    if ctx.findings:
        findings_block = f"""
<div class="controls" role="group" aria-label="Filter findings">
  {buttons}
  <select id="host-filter" aria-label="Filter by host"><option value="">All hosts</option>{host_options}</select>
  <button type="button" id="expand">Expand all</button>
  <span class="shown" id="shown" aria-live="polite"></span>
</div>
<div class="findings">{findings_html}</div>"""
    else:
        findings_block = '<p class="quiet">No rule matched. Try a lower --min-severity, more data, or more rules.</p>'

    host_cards = []
    for host in finding_hosts:
        items = "".join(
            f'<li class="{_e(f.severity)}"><span class="when">{_e(f.start.strftime("%H:%M:%S"))}</span>'
            f'<a href="#f{i}">{_e(f.rule.title)}</a></li>'
            for i, f in enumerate(ctx.findings, 1) if host in f.hosts
        )
        host_cards.append(f'<section class="host"><h3>{_e(host)}</h3><ol>{items}</ol></section>')

    fired = {f.rule.id for f in ctx.findings}
    silent = [r for r in ctx.rules if r.id not in fired]
    silent_html = ""
    if silent:
        silent_items = "".join(f"<li>{_e(r.id)} {_e(r.title)}</li>" for r in silent)
        silent_html = (f'<h2>Rules with no findings</h2><details class="rules-off"><summary>'
                       f'{_plural(len(silent), "rule")} ran without matching anything</summary><ul>{silent_items}</ul></details>')

    span = ""
    if ctx.events:
        span = f" covering {_fmt_time(ctx.events[0].timestamp)} to {_fmt_time(ctx.events[-1].timestamp)} UTC"
    inputs = ", ".join(Path(i).name for i in ctx.inputs) or "in-memory events"
    meta = (f"{_e(inputs)}: {_plural(len(ctx.events), 'event')} from {_plural(len(ctx.hosts), 'host')}{_e(span)}. "
            f"{_plural(len(ctx.rules), 'rule')} ran. Generated {_e(_fmt_time(ctx.generated))} UTC.")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lantern hunt report</title>
<style>{_CSS}</style>
</head>
<body>
<main>
  <h1>Lantern hunt report</h1>
  <p class="lede">{_e(summary_sentence(ctx))}</p>
  <p class="meta">{meta}</p>

  <div class="path" role="list" aria-label="MITRE ATT&amp;CK tactics with findings">{''.join(cells)}</div>
  <p class="path-note">MITRE ATT&amp;CK tactics in attack order. A finding counts toward every tactic its techniques belong to.</p>

  <h2>Findings</h2>
  {findings_block}

  {'<h2>By host</h2><div class="hosts">' + ''.join(host_cards) + '</div>' if host_cards else ''}
  {silent_html}

  <footer>Generated by Lantern {_e(__version__)}. Findings are leads for investigation, not verdicts.</footer>
</main>
<script>{_JS}</script>
</body>
</html>
"""


def write_html(ctx: HuntContext, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_html(ctx), encoding="utf-8")
    return path
