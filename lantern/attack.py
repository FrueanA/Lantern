"""A small offline subset of MITRE ATT&CK (Enterprise) used by the bundled rules.

Each technique lists every tactic ATT&CK places it under, so a finding is
counted toward all of them in the report's tactic coverage.
"""

from __future__ import annotations

# Enterprise tactics, in ATT&CK's kill-chain order, starting where host logs
# begin to have visibility.
TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["Credential Access"]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ["Lateral Movement"]),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["Execution"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["Defense Evasion"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["Credential Access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["Credential Access"]),
    "T1133": ("External Remote Services", ["Initial Access", "Persistence"]),
    "T1136.001": ("Create Account: Local Account", ["Persistence"]),
    "T1204.002": ("User Execution: Malicious File", ["Execution"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["Credential Access"]),
    "T1566.001": ("Phishing: Spearphishing Attachment", ["Initial Access"]),
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, (technique_id, []))[0]


def tactics_for(technique_id: str) -> list[str]:
    return TECHNIQUES.get(technique_id, ("", []))[1]


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
