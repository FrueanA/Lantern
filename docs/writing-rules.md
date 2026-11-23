# Writing rules

Lantern rules are YAML files. The format borrows Sigma's detection syntax (selections, field modifiers and conditions) and adds two stateful rule types, `threshold` and `sequence`, for behavior that a single event cannot show.

Put new rules in `lantern/rules/`, or keep your own folder and pass it with `--rules`. Run `lantern rules --test` after every change.

## Fields every rule has

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique ID, e.g. `LNT-017` |
| `title` | yes | Short name shown in reports |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical` |
| `type` | no | `match` (default), `threshold` or `sequence` |
| `attack` | no | MITRE ATT&CK technique IDs, e.g. `[T1059.001]` |
| `description` | no | What the rule detects and why it matters |
| `fields` | no | Event fields to show in the finding summary |
| `falsepositives` | no | Known benign causes, shown to the analyst |
| `references` | no | Links |
| `tests` | no | Example events that must and must not match (match rules only) |

Add new technique IDs to `lantern/attack.py` so the report can name them and place them under the right tactics.

## Events and field names

Every input format is normalized to one flat dictionary per event. System properties always use these names:

`EventID`, `TimeCreated`, `Computer`, `Channel`, `Provider`, `EventRecordID`

EventData and UserData values keep their Windows names (`TargetUserName`, `IpAddress`, `CommandLine`, `Image`, `ParentImage`, `ScriptBlockText` and so on). If a data field has the same name as a system property, it is stored as `EventData.<name>`. System event 104, for example, reports the cleared log as `EventData.Channel`.

Native Security auditing (4688) and Sysmon (event 1) name process fields differently: `NewProcessName` and `ParentProcessName` against `Image` and `ParentImage`. Rules that should work with either source list both forms (see LNT-005 and LNT-013).

## Selections

A selection is one of:

```yaml
# A map: every field must match (AND).
selection:
  EventID: 4625
  LogonType: 3

# A list of maps: any one map must match (OR).
process:
  - EventID: 4688
    NewProcessName|endswith: '\cmd.exe'
  - EventID: 1
    Image|endswith: '\cmd.exe'

# A list of keywords: any field contains any keyword.
keywords:
  - mimikatz
  - sekurlsa
```

A list of values for one field means any of them (OR). Matching is case-insensitive unless you add `|cased`. A plain value may use `*` and `?` wildcards. A value of `null` matches a missing or empty field.

Quote Windows paths with single quotes so YAML keeps the backslashes: `'\Users\Public\'`. Quote hex values (`'0x17'`) to keep them readable. Lantern also compares numbers numerically, so an unquoted `0x17` (which YAML reads as 23) still matches.

### Modifiers

| Modifier | Example | Matches when |
|---|---|---|
| `contains` | `CommandLine\|contains: vssadmin` | the value appears anywhere |
| `startswith` | `TaskName\|startswith: '\Microsoft\'` | the field starts with the value |
| `endswith` | `Image\|endswith: '\powershell.exe'` | the field ends with the value |
| `all` | `CommandLine\|contains\|all: [delete, shadows]` | every listed value matches, not just one |
| `re` | `CommandLine\|re: '\s-enc\s'` | the regular expression matches (`re.search`) |
| `cidr` | `IpAddress\|cidr: 10.0.0.0/8` | the address is in the network; IPv4-mapped IPv6 such as `::ffff:10.1.2.3` is handled |
| `gt`, `gte`, `lt`, `lte` | `Count\|gte: 5` | numeric comparison (hex strings are understood) |
| `exists` | `ParentImage\|exists: true` | the field is present and not empty |
| `cased` | `ServiceName\|cased: PSEXESVC` | turn off case-insensitive matching |

## Conditions

The `condition` combines selections with `and`, `or`, `not` and parentheses. `and` binds tighter than `or`.

```yaml
condition: selection and not filter
condition: (proc_4688 or proc_sysmon) and suspicious_args
condition: lsass_access and not 1 of filter_*   # none of the filters match
condition: 1 of them                            # any selection matches
condition: all of selection_*                   # every selection_* matches
```

`them` means every selection whose name does not start with `_`. Unknown selection names are rejected when the rule loads, so a typo fails loudly instead of silently never matching.

### Filters and masquerading

Filter trusted software by its full install path, not by file name. A filter on `SourceImage|endswith: '\MsMpEng.exe'` would also trust an attacker's tool renamed to `MsMpEng.exe` and dropped in `C:\Users\Public`. LNT-007 filters Defender by `startswith` on its install folder and includes a test for the renamed case.

## Threshold rules

Count matching events per group inside a sliding window:

```yaml
type: threshold
detection:
  failed_logon:
    EventID: 4625
  condition: failed_logon
threshold:
  group_by: [IpAddress]          # one counter per source address
  distinct: TargetUserName       # optional: count distinct values instead of events
  count: 8                       # fire at this many
  window: 10m                    # s, m, h or d
```

Events whose group field is missing, empty or `-` are ignored. Once a group fires, later events from that group join the same finding as long as each one arrives within one window of the previous one, so a long burst produces one finding rather than dozens.

## Sequence rules

Ordered steps for the same key inside a window:

```yaml
type: sequence
sequence:
  by: [IpAddress]
  window: 30m
  steps:
    - name: failed logons
      min_count: 5
      detection:
        failed: {EventID: 4625}
        condition: failed
    - name: successful logon
      detection:
        ok: {EventID: 4624}
        condition: ok
```

Each time an event matches the last step, Lantern looks back through that key's history and checks that every earlier step reached its `min_count`, in order, inside the window. Events used by one finding are not reused by the next. The finding's evidence includes every step event in the window, so analysts see the whole run of failures, not only the last five.

## Embedded tests

Match rules can carry their own test events. `lantern rules --test` runs them, and CI fails if any break.

```yaml
tests:
  match:
    - {EventID: 4720, Channel: Security, TargetUserName: support_adm}
  nomatch:
    - {EventID: 4722, Channel: Security, TargetUserName: support_adm}
```

Write at least one `nomatch` case for each filter. That is how you prove the filter excludes what you meant it to, and nothing more.

## Checking a new rule against the sample data

```bash
lantern hunt samples/attack_scenario.jsonl --rules my-rules/ --no-color
lantern hunt samples/benign_baseline.jsonl --rules my-rules/ --fail-on info   # should exit 0
```

The benign baseline is generated with the same hosts and users as the attack scenario but no attacker activity. A rule that fires on it needs tighter logic or a filter.
