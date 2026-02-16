<#
.SYNOPSIS
    Copilot Studio Agent Risk Inventory Scanner
    Runs all hunting queries from YAML files against Microsoft Graph Advanced Hunting API
    and produces an HTML risk report + CSV inventory.

.DESCRIPTION
    Parses YAML hunting query files, executes each KQL query via the Graph API,
    aggregates results into a per-agent risk map, and outputs:
    - AgentRiskInventory.csv  (flat: one row per agent+risk finding)
    - AgentRiskReport.html    (visual dashboard with risk matrix)

.PARAMETER QueryFolder
    Path to folder containing the .yaml hunting query files. Default: .\HuntingQueries

.PARAMETER OutputFolder
    Path to write output files. Default: current directory.

.PARAMETER SkipConnect
    Skip Connect-MgGraph if you are already connected.

.EXAMPLE
    Connect-MgGraph -Scopes "ThreatHunting.Read.All"
    .\Invoke-AgentRiskScan.ps1 -SkipConnect
#>

[CmdletBinding()]
param(
    [string]$QueryFolder = ".\HuntingQueries",
    [string]$OutputFolder = ".",
    [switch]$SkipConnect
)

$ErrorActionPreference = "Continue"
$scanTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scanDateFile = Get-Date -Format "yyyyMMdd_HHmmss"

# ──────────────────────────────────────────────
# 0. Ensure prerequisites
# ──────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Write-Host "[*] Installing powershell-yaml module..." -ForegroundColor Cyan
    Install-Module powershell-yaml -Scope CurrentUser -Force -AllowClobber
}
Import-Module powershell-yaml -ErrorAction Stop

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Security)) {
    Write-Host "[*] Installing Microsoft.Graph.Security module..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Security -Scope CurrentUser -Force -AllowClobber
}

# Import Graph modules explicitly — catches version conflicts early
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Security -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match "Assembly with same name is already loaded") {
        Write-Error ("Microsoft Graph module version conflict detected. " +
            "A different version of Microsoft.Graph.Authentication is already loaded in this session. " +
            "Please close this PowerShell window, open a new one, and re-run the script.")
        exit 1
    }
    throw
}

if (-not $SkipConnect) {
    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "ThreatHunting.Read.All" -ErrorAction Stop
}

# ──────────────────────────────────────────────
# 1. Risk severity mapping
# ──────────────────────────────────────────────
$severityMap = @{
    "AI Agents - No Authentication Required"                          = @{ Severity = "Critical"; RiskNum = 2;  Weight = 4 }
    "AI Agents - Hard-coded credentials in Topics or Actions"         = @{ Severity = "Critical"; RiskNum = 7;  Weight = 4 }
    "AI Agents - Sending email to AI controlled input values"         = @{ Severity = "Critical"; RiskNum = 4;  Weight = 4 }
    "AI Agents - Organization or Multi-tenant Shared"                 = @{ Severity = "High";     RiskNum = 1;  Weight = 3 }
    "AI Agents - Published Agents with Author Authentication"         = @{ Severity = "High";     RiskNum = 6;  Weight = 3 }
    "AI Agents - MCP Tool with Maker Credentials"                     = @{ Severity = "High";     RiskNum = 6;  Weight = 3 }
    "AI Agents - Orphaned Agents with Disabled Owners"                = @{ Severity = "High";     RiskNum = 10; Weight = 3 }
    "AI Agents - HTTP Requests to Non-HTTPS Endpoints"                = @{ Severity = "Medium";   RiskNum = 3;  Weight = 2 }
    "AI Agents - HTTP Requests to Non-standard Ports"                 = @{ Severity = "Medium";   RiskNum = 3;  Weight = 2 }
    "AI Agents - HTTP Requests to Connector Endpoints"                = @{ Severity = "Medium";   RiskNum = 3;  Weight = 2 }
    "AI Agents - Published Generative Orchestration without Instructions" = @{ Severity = "Medium"; RiskNum = 9; Weight = 2 }
    "AI Agents - MCP Tool Configured"                                 = @{ Severity = "Medium";   RiskNum = 8;  Weight = 2 }
    "AI Agents - Sending email to external mailboxes"                 = @{ Severity = "Medium";   RiskNum = 4;  Weight = 2 }
    "AI Agents - Dormant Author Authentication Connection"            = @{ Severity = "Low";      RiskNum = 5;  Weight = 1 }
    "AI Agents - Unused Actions"                                      = @{ Severity = "Low";      RiskNum = 5;  Weight = 1 }
    "AI Agents - Published Dormant (30d)"                             = @{ Severity = "Low";      RiskNum = 5;  Weight = 1 }
    "AI Agents - Unpublished Unmodified (30d)"                        = @{ Severity = "Low";      RiskNum = 5;  Weight = 1 }
}

# ──────────────────────────────────────────────
# 2. Parse YAML files
# ──────────────────────────────────────────────
Write-Host "`n[*] Loading hunting queries from: $QueryFolder" -ForegroundColor Cyan
$yamlFiles = Get-ChildItem -Path $QueryFolder -Filter "*.yaml" -ErrorAction Stop
Write-Host "    Found $($yamlFiles.Count) YAML files" -ForegroundColor Green

$huntingQueries = @()
foreach ($file in $yamlFiles) {
    try {
        $raw = Get-Content $file.FullName -Raw
        $parsed = $raw | ConvertFrom-Yaml
        $queryName = $parsed.name
        $kqlQuery  = $parsed.query
        $tactics   = if ($parsed.tactics) { ($parsed.tactics -join ", ") } else { "" }
        $techniques = if ($parsed.relevantTechniques) { ($parsed.relevantTechniques -join ", ") } else { "" }
        $desc      = ($parsed.description -replace "`n", " ").Trim()
        # Truncate description for CSV friendliness
        $shortDesc = if ($desc.Length -gt 300) { $desc.Substring(0, 300) + "..." } else { $desc }

        $sev = $severityMap[$queryName]
        if (-not $sev) { $sev = @{ Severity = "Info"; RiskNum = 0; Weight = 0 } }

        $huntingQueries += [PSCustomObject]@{
            FileName    = $file.Name
            QueryName   = $queryName
            Query       = $kqlQuery.Trim()
            Tactics     = $tactics
            Techniques  = $techniques
            Description = $shortDesc
            FullDescription = $desc
            Severity    = $sev.Severity
            RiskNumber  = $sev.RiskNum
            Weight      = $sev.Weight
        }
    } catch {
        Write-Warning "Failed to parse $($file.Name): $_"
    }
}

# ──────────────────────────────────────────────
# 3. Execute queries against Graph API
# ──────────────────────────────────────────────
Write-Host "`n[*] Executing $($huntingQueries.Count) hunting queries against Graph API..." -ForegroundColor Cyan

$allFindings = @()
$queryResults = @{}
$queryIndex = 0

foreach ($hq in $huntingQueries) {
    $queryIndex++
    $pct = [math]::Round(($queryIndex / $huntingQueries.Count) * 100)
    Write-Host "    [$queryIndex/$($huntingQueries.Count)] ($pct%) $($hq.QueryName)..." -ForegroundColor Gray -NoNewline

    try {
        $body = @{ Query = $hq.Query }
        $response = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
            -Body $body -ErrorAction Stop

        $results = $response.results
        $schema  = $response.schema
        $count   = if ($results) { $results.Count } else { 0 }

        if ($count -gt 0) {
            Write-Host " $count finding(s)" -ForegroundColor Yellow
        } else {
            Write-Host " clean" -ForegroundColor Green
        }

        $queryResults[$hq.QueryName] = @{
            Count   = $count
            Results = $results
            Schema  = $schema
        }

        # Extract agent-level findings
        if ($results) {
            foreach ($row in $results) {
                $agentId   = $row.AIAgentId
                $agentName = $row.AIAgentName
                $creator   = $row.CreatorAccountUpn
                $envId     = $row.EnvironmentId
                $owner     = $row.OwnerAccountUpns

                # Some queries don't return all fields — handle gracefully
                if (-not $agentId -and -not $agentName) { 
                    # Try to find any agent identifier in the row
                    $agentId   = $row.PSObject.Properties | Where-Object { $_.Name -match "AgentId" } | Select-Object -First 1 -ExpandProperty Value
                    $agentName = $row.PSObject.Properties | Where-Object { $_.Name -match "AgentName" } | Select-Object -First 1 -ExpandProperty Value
                }

                $allFindings += [PSCustomObject]@{
                    AIAgentId        = $agentId
                    AIAgentName      = $agentName
                    CreatorAccountUpn = $creator
                    OwnerAccountUpns = $owner
                    EnvironmentId    = $envId
                    RiskName         = $hq.QueryName
                    Severity         = $hq.Severity
                    Weight           = $hq.Weight
                    RiskNumber       = $hq.RiskNumber
                    Tactics          = $hq.Tactics
                    Techniques       = $hq.Techniques
                    Description      = $hq.Description
                    FileName         = $hq.FileName
                    ScanTimestamp    = $scanTimestamp
                }
            }
        }
    } catch {
        Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $queryResults[$hq.QueryName] = @{ Count = -1; Results = @(); Schema = @(); Error = $_.Exception.Message }
    }

    # Small delay to avoid throttling
    Start-Sleep -Milliseconds 500
}

# ──────────────────────────────────────────────
# 4. Aggregate per-agent risk summary
# ──────────────────────────────────────────────
Write-Host "`n[*] Aggregating results..." -ForegroundColor Cyan

$agentSummary = @{}
foreach ($f in $allFindings) {
    $key = "$($f.AIAgentId)|$($f.AIAgentName)"
    if (-not $agentSummary.ContainsKey($key)) {
        $agentSummary[$key] = @{
            AIAgentId         = $f.AIAgentId
            AIAgentName       = $f.AIAgentName
            CreatorAccountUpn = $f.CreatorAccountUpn
            OwnerAccountUpns  = $f.OwnerAccountUpns
            EnvironmentId     = $f.EnvironmentId
            Risks             = @()
            TotalWeight       = 0
            HighestSeverity   = "None"
            CriticalCount     = 0
            HighCount         = 0
            MediumCount       = 0
            LowCount          = 0
        }
    }
    $agent = $agentSummary[$key]
    $agent.Risks += $f.RiskName
    $agent.TotalWeight += $f.Weight

    # Update owner/env if we got a better value
    if ($f.CreatorAccountUpn -and -not $agent.CreatorAccountUpn) { $agent.CreatorAccountUpn = $f.CreatorAccountUpn }
    if ($f.OwnerAccountUpns -and -not $agent.OwnerAccountUpns) { $agent.OwnerAccountUpns = $f.OwnerAccountUpns }
    if ($f.EnvironmentId -and -not $agent.EnvironmentId) { $agent.EnvironmentId = $f.EnvironmentId }

    switch ($f.Severity) {
        "Critical" { $agent.CriticalCount++; if ($agent.HighestSeverity -ne "Critical") { $agent.HighestSeverity = "Critical" } }
        "High"     { $agent.HighCount++;     if ($agent.HighestSeverity -notin @("Critical")) { $agent.HighestSeverity = "High" } }
        "Medium"   { $agent.MediumCount++;   if ($agent.HighestSeverity -notin @("Critical","High")) { $agent.HighestSeverity = "Medium" } }
        "Low"      { $agent.LowCount++;      if ($agent.HighestSeverity -notin @("Critical","High","Medium")) { $agent.HighestSeverity = "Low" } }
    }
}

# ──────────────────────────────────────────────
# 5. Output CSV
# ──────────────────────────────────────────────
$csvPath = Join-Path $OutputFolder "AgentRiskInventory_$scanDateFile.csv"
Write-Host "`n[*] Writing CSV to: $csvPath" -ForegroundColor Cyan

if ($allFindings.Count -gt 0) {
    $allFindings | Select-Object AIAgentId, AIAgentName, CreatorAccountUpn, OwnerAccountUpns, EnvironmentId, `
        RiskName, Severity, RiskNumber, Weight, Tactics, Techniques, Description, FileName, ScanTimestamp |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "    $($allFindings.Count) rows written" -ForegroundColor Green
} else {
    "No findings - all queries returned clean results." | Out-File -FilePath $csvPath -Encoding UTF8
    Write-Host "    No findings to write" -ForegroundColor Green
}

# ──────────────────────────────────────────────
# 6. Generate HTML report
# ──────────────────────────────────────────────
$htmlPath = Join-Path $OutputFolder "AgentRiskReport_$scanDateFile.html"
Write-Host "[*] Writing HTML report to: $htmlPath" -ForegroundColor Cyan

# Summary stats
$totalAgents    = $agentSummary.Count
$totalFindings  = $allFindings.Count
$criticalTotal  = ($allFindings | Where-Object Severity -eq "Critical").Count
$highTotal      = ($allFindings | Where-Object Severity -eq "High").Count
$mediumTotal    = ($allFindings | Where-Object Severity -eq "Medium").Count
$lowTotal       = ($allFindings | Where-Object Severity -eq "Low").Count
$queriesRun     = $huntingQueries.Count
$queriesClean   = ($queryResults.Values | Where-Object { $_.Count -eq 0 }).Count
$queriesError   = ($queryResults.Values | Where-Object { $_.Count -eq -1 }).Count
$queriesWithHits = ($queryResults.Values | Where-Object { $_.Count -gt 0 }).Count

# Helper: Encode KQL query to gzip+base64url for Defender Advanced Hunting URL
function ConvertTo-DefenderQueryUrl {
    param([string]$KqlQuery)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($KqlQuery)
    $ms = [System.IO.MemoryStream]::new()
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    $compressed = $ms.ToArray()
    $ms.Close()
    $b64 = [Convert]::ToBase64String($compressed)
    # Convert to base64url: + -> -, / -> _, remove trailing =
    $b64url = $b64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
    return "https://security.microsoft.com/v2/advanced-hunting?query=$b64url&timeRangeId=month"
}

# Build query summary rows
$querySummaryRows = ""
foreach ($hq in ($huntingQueries | Sort-Object { switch ($_.Severity) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } "Low" { 3 } default { 4 } } })) {
    $qr = $queryResults[$hq.QueryName]
    $count = if ($qr) { $qr.Count } else { "?" }
    $statusClass = if ($count -eq -1) { "status-error" } elseif ($count -gt 0) { "status-hit" } else { "status-clean" }
    $statusText  = if ($count -eq -1) { "Error" } elseif ($count -gt 0) { "$count finding(s)" } else { "Clean" }
    $sevClass    = $hq.Severity.ToLower()
    $errorMsg    = if ($qr -and $qr.Error) { "<br><small class='error-detail'>$($qr.Error)</small>" } else { "" }
    $escapedDesc = $hq.FullDescription -replace '"', '&quot;' -replace "'", '&#39;' -replace '<', '&lt;' -replace '>', '&gt;'
    $defenderUrl = ConvertTo-DefenderQueryUrl -KqlQuery $hq.Query
    $querySummaryRows += @"
        <tr>
            <td><span class="severity-badge $sevClass">$($hq.Severity)</span></td>
            <td>#$($hq.RiskNumber)</td>
            <td><span class="query-name" title="$escapedDesc">$($hq.QueryName)</span></td>
            <td>$($hq.Tactics)</td>
            <td>$($hq.Techniques)</td>
            <td class="$statusClass">$statusText$errorMsg</td>
            <td class="actions-cell">
                <a class="btn btn-run" href="$defenderUrl" target="_blank" title="Run in Defender Advanced Hunting">&#x25B6; Run</a>
            </td>
        </tr>
"@
}

# Build agent risk matrix rows
$agentRows = ""
$sortedAgents = $agentSummary.Values | Sort-Object { $_.TotalWeight } -Descending
foreach ($agent in $sortedAgents) {
    $sevClass = $agent.HighestSeverity.ToLower()

    # Build risk cells for each query
    $riskCells = ""
    foreach ($hq in $huntingQueries) {
        $hit = $agent.Risks -contains $hq.QueryName
        if ($hit) {
            $cellSev = $hq.Severity.ToLower()
            $riskCells += "<td class='risk-cell hit-$cellSev' title='$($hq.QueryName)'>&#x26A0;</td>"
        } else {
            $riskCells += "<td class='risk-cell clean' title='$($hq.QueryName)'>&#x2713;</td>"
        }
    }

    $agentRows += @"
        <tr>
            <td class="agent-name">$($agent.AIAgentName)</td>
            <td class="agent-creator">$($agent.CreatorAccountUpn)</td>
            <td><span class="severity-badge $sevClass">$($agent.HighestSeverity)</span></td>
            <td class="score">$($agent.TotalWeight)</td>
            <td class="count critical-count">$($agent.CriticalCount)</td>
            <td class="count high-count">$($agent.HighCount)</td>
            <td class="count medium-count">$($agent.MediumCount)</td>
            <td class="count low-count">$($agent.LowCount)</td>
            $riskCells
        </tr>
"@
}

# Build column headers for the risk matrix
$riskHeaders = ""
foreach ($hq in $huntingQueries) {
    # Short label from filename
    $shortLabel = $hq.FileName -replace "\.yaml$","" -replace "AIAgents",""
    if ($shortLabel.Length -gt 20) { $shortLabel = $shortLabel.Substring(0, 20) + ".." }
    $riskHeaders += "<th class='risk-header' title='$($hq.QueryName)'>$shortLabel</th>"
}

# Assemble HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Copilot Studio Agent Risk Report - $scanTimestamp</title>
<style>
    :root {
        --bg: #0d1117; --surface: #161b22; --border: #30363d;
        --text: #e6edf3; --text-muted: #8b949e;
        --critical: #f85149; --critical-bg: rgba(248,81,73,.15);
        --high: #f0883e; --high-bg: rgba(240,136,62,.15);
        --medium: #d29922; --medium-bg: rgba(210,153,34,.15);
        --low: #58a6ff; --low-bg: rgba(88,166,255,.15);
        --clean: #3fb950; --clean-bg: rgba(63,185,80,.1);
        --error: #f85149;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    h1 { font-size: 1.8rem; margin-bottom: 4px; }
    h2 { font-size: 1.3rem; margin: 32px 0 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .subtitle { color: var(--text-muted); font-size: .9rem; margin-bottom: 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
    .card .value { font-size: 2rem; font-weight: 700; }
    .card .label { color: var(--text-muted); font-size: .85rem; margin-top: 4px; }
    .card.critical .value { color: var(--critical); }
    .card.high .value { color: var(--high); }
    .card.medium .value { color: var(--medium); }
    .card.low .value { color: var(--low); }
    .card.clean .value { color: var(--clean); }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 24px; font-size: .85rem; }
    th { background: #1c2128; text-align: left; padding: 10px 12px; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); white-space: nowrap; }
    td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
    tr:last-child td { border-bottom: none; }
    tr:hover { background: rgba(255,255,255,.03); }
    .severity-badge { padding: 2px 10px; border-radius: 12px; font-size: .75rem; font-weight: 600; text-transform: uppercase; }
    .severity-badge.critical { background: var(--critical-bg); color: var(--critical); }
    .severity-badge.high { background: var(--high-bg); color: var(--high); }
    .severity-badge.medium { background: var(--medium-bg); color: var(--medium); }
    .severity-badge.low { background: var(--low-bg); color: var(--low); }
    .severity-badge.info, .severity-badge.none { background: rgba(139,148,158,.15); color: var(--text-muted); }
    .status-hit { color: var(--critical); font-weight: 600; }
    .status-clean { color: var(--clean); }
    .status-error { color: var(--error); }
    .error-detail { color: var(--text-muted); font-size: .75rem; }
    .query-name { cursor: help; border-bottom: 1px dotted var(--text-muted); }
    .query-name:hover { color: var(--low); }
    .actions-cell { white-space: nowrap; }
    .btn { display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: .72rem; font-weight: 600; cursor: pointer; text-decoration: none; border: 1px solid var(--border); transition: all .15s; }
    .btn-run { background: rgba(88,166,255,.1); color: var(--low); border-color: rgba(88,166,255,.3); margin-left: 4px; }
    .btn-run:hover { background: rgba(88,166,255,.2); }
    .risk-cell { text-align: center; font-size: .9rem; width: 36px; min-width: 36px; }
    .risk-cell.clean { color: var(--clean); opacity: .4; }
    .hit-critical { background: var(--critical-bg); color: var(--critical); }
    .hit-high { background: var(--high-bg); color: var(--high); }
    .hit-medium { background: var(--medium-bg); color: var(--medium); }
    .hit-low { background: var(--low-bg); color: var(--low); }
    .risk-header { writing-mode: vertical-lr; text-orientation: mixed; transform: rotate(180deg); font-size: .7rem; padding: 8px 4px; max-width: 36px; }
    .score { font-weight: 700; font-size: 1.1rem; }
    .count { text-align: center; font-weight: 600; }
    .critical-count { color: var(--critical); }
    .high-count { color: var(--high); }
    .medium-count { color: var(--medium); }
    .low-count { color: var(--low); }
    .agent-name { font-weight: 600; white-space: nowrap; }
    .agent-creator { color: var(--text-muted); font-size: .8rem; }
    .no-findings { text-align: center; padding: 48px; color: var(--clean); font-size: 1.2rem; }
    .footer { color: var(--text-muted); font-size: .8rem; margin-top: 32px; text-align: center; border-top: 1px solid var(--border); padding-top: 16px; }
    .table-wrapper { overflow-x: auto; }
    @media (max-width: 768px) { .cards { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>

<h1>&#x1F6E1; Copilot Studio Agent Risk Report</h1>
<p class="subtitle">Scan completed: $scanTimestamp &nbsp;|&nbsp; Based on <a href="https://www.microsoft.com/en-us/security/blog/2026/02/12/copilot-studio-agent-security-top-10-risks-detect-prevent/" style="color:var(--low)">Microsoft's Top 10 Agent Security Risks</a></p>

<!-- Summary Cards -->
<div class="cards">
    <div class="card"><div class="value">$totalAgents</div><div class="label">Agents Flagged</div></div>
    <div class="card"><div class="value">$totalFindings</div><div class="label">Total Findings</div></div>
    <div class="card critical"><div class="value">$criticalTotal</div><div class="label">Critical</div></div>
    <div class="card high"><div class="value">$highTotal</div><div class="label">High</div></div>
    <div class="card medium"><div class="value">$mediumTotal</div><div class="label">Medium</div></div>
    <div class="card low"><div class="value">$lowTotal</div><div class="label">Low</div></div>
    <div class="card clean"><div class="value">$queriesClean</div><div class="label">Queries Clean</div></div>
    <div class="card"><div class="value">$queriesRun</div><div class="label">Queries Executed</div></div>
</div>

<!-- Agent Risk Matrix -->
<h2>&#x1F4CB; Agent Risk Matrix</h2>
$(if ($agentRows) {
@"
<div class="table-wrapper">
<table>
<thead>
    <tr>
        <th>Agent</th>
        <th>Creator</th>
        <th>Top Severity</th>
        <th>Score</th>
        <th title="Critical">C</th>
        <th title="High">H</th>
        <th title="Medium">M</th>
        <th title="Low">L</th>
        $riskHeaders
    </tr>
</thead>
<tbody>
$agentRows
</tbody>
</table>
</div>
"@
} else {
    '<div class="no-findings">&#x2705; All queries returned clean &mdash; no agent risks detected.</div>'
})

<!-- Query Execution Summary -->
<h2>&#x1F50D; Query Execution Summary</h2>
<table>
<thead>
    <tr>
        <th>Severity</th>
        <th>Risk #</th>
        <th>Query Name</th>
        <th>Tactics</th>
        <th>Techniques</th>
        <th>Result</th>
        <th>Actions</th>
    </tr>
</thead>
<tbody>
$querySummaryRows
</tbody>
</table>

<div class="footer">
    Generated by Invoke-AgentRiskScan.ps1 &nbsp;|&nbsp; Queries sourced from
    <a href="https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/AI%20Agents" style="color:var(--low)">Azure Sentinel Community Hunting Queries</a>
    &nbsp;|&nbsp; $queriesRun queries executed, $queriesWithHits with findings, $queriesError errors
</div>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

# ──────────────────────────────────────────────
# 7. Summary
# ──────────────────────────────────────────────
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  SCAN COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  Agents flagged : $totalAgents"
Write-Host "  Total findings : $totalFindings"
Write-Host "  Critical       : $criticalTotal" -ForegroundColor $(if ($criticalTotal -gt 0) { "Red" } else { "Green" })
Write-Host "  High           : $highTotal" -ForegroundColor $(if ($highTotal -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Medium         : $mediumTotal" -ForegroundColor $(if ($mediumTotal -gt 0) { "DarkYellow" } else { "Green" })
Write-Host "  Low            : $lowTotal" -ForegroundColor $(if ($lowTotal -gt 0) { "Cyan" } else { "Green" })
Write-Host "  Queries clean  : $queriesClean / $queriesRun"
if ($queriesError -gt 0) {
    Write-Host "  Query errors   : $queriesError (check report for details)" -ForegroundColor Red
}
Write-Host "───────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  CSV  : $csvPath" -ForegroundColor White
Write-Host "  HTML : $htmlPath" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
