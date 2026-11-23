<#
.SYNOPSIS
    Exports Windows event logs to JSON Lines that Lantern can read.

.DESCRIPTION
    Reads the logs Lantern's rules use, flattens each event's EventData and
    UserData into named fields, and writes one JSON object per line. Run it
    from an elevated PowerShell prompt, because reading the Security log
    requires administrator rights.

    Only run this on machines you own or are authorized to investigate.
    Exported logs contain usernames, hostnames and command lines, so treat
    the output file as sensitive.

.PARAMETER Hours
    How far back to export, in hours. Default: 24.

.PARAMETER LogName
    Logs to export. Logs that do not exist on this machine (Sysmon, for
    example) are skipped with a warning.

.PARAMETER OutFile
    Output path. Default: events.jsonl in the current folder.

.EXAMPLE
    .\Export-Events.ps1 -Hours 48 -OutFile C:\Temp\events.jsonl
    lantern hunt C:\Temp\events.jsonl --html report.html
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [string[]]$LogName = @(
        'Security',
        'System',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational'
    ),

    [string]$OutFile = 'events.jsonl'
)

$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$Hours)
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
$writer = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
$total = 0

try {
    foreach ($log in $LogName) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -ErrorAction Stop
        }
        catch {
            Write-Warning "Skipping ${log}: $($_.Exception.Message)"
            continue
        }

        $count = 0
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $record = [ordered]@{
                EventID       = $evt.Id
                TimeCreated   = $evt.TimeCreated.ToUniversalTime().ToString('o')
                Computer      = $evt.MachineName
                Channel       = $evt.LogName
                Provider      = $evt.ProviderName
                EventRecordID = $evt.RecordId
            }

            if ($xml.Event.EventData) {
                foreach ($data in $xml.Event.EventData.SelectNodes('*')) {
                    $name = $data.GetAttribute('Name')
                    if ($name) { $record[$name] = $data.InnerText }
                }
            }

            if ($xml.Event.UserData) {
                foreach ($node in $xml.Event.UserData.SelectNodes('*/*')) {
                    $name = $node.LocalName
                    # Keep system fields intact, as Lantern's own parser does.
                    if ($record.Contains($name)) { $name = "EventData.$name" }
                    $record[$name] = $node.InnerText
                }
            }

            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 3))
            $count++
        }
        Write-Host "${log}: exported $count events"
        $total += $count
    }
}
finally {
    $writer.Close()
}

Write-Host "Wrote $total events to $path"
