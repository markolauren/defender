# Copilot Studio Agent Risk Scanner

Automated security posture scanner for Microsoft Copilot Studio agents. Runs [community hunting queries](https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/AI%20Agents) against the Microsoft Graph Advanced Hunting API and produces an agent inventory with risk mapping.

Based on Microsoft's blog post: [Copilot Studio agent security: Top 10 risks you can detect and prevent](https://www.microsoft.com/en-us/security/blog/2026/02/12/copilot-studio-agent-security-top-10-risks-detect-prevent/)

<img width="1916" height="871" alt="image" src="https://github.com/user-attachments/assets/c1e9370c-3637-4512-b16a-f74981303c8c" />
<img width="1915" height="850" alt="image" src="https://github.com/user-attachments/assets/0b3bbed7-e82c-4e0f-abe3-3413b508d30d" />

## Background — AIAgentsInfo table

This scanner queries the [`AIAgentsInfo`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table) table in Microsoft Defender XDR Advanced Hunting. The table is currently in **Preview** and is populated by Microsoft Defender for Cloud Apps once the [AI agent inventory](https://learn.microsoft.com/en-us/defender-cloud-apps/ai-agent-inventory) is enabled.

### Enabling the AI agent inventory

Enabling the Copilot Studio AI agent inventory requires collaboration between a **Defender admin** and a **Power Platform admin**:

1. In the [Microsoft Defender portal](https://security.microsoft.com/) → **System > Settings > Cloud Apps > Copilot Studio AI Agents** — turn on the toggle.
2. In the [Power Platform admin center](https://admin.preview.powerplatform.microsoft.com/security/threatdetection) → **Security > Threat Protection** — select **Microsoft Defender - Copilot Studio AI Agents** and enable it.

It can take up to 30 minutes for the initial connection, and longer for the full inventory to populate depending on environment size.

## What it does

1. **Parses** 17 YAML hunting query files from `HuntingQueries/`
2. **Executes** each KQL query against the Graph API (`POST /v1.0/security/runHuntingQuery`)
3. **Aggregates** results into a per-agent risk inventory
4. **Outputs**:
   - **HTML report** — visual dashboard with risk matrix, severity cards, and direct links to run queries in Defender
   - **CSV file** — flat format (one row per agent + risk finding), Excel-friendly

## Quick start

```powershell
# 1. Clone/download this folder

# 2. Run the scanner (it will auto-install dependencies and prompt for login)
.\Invoke-AgentRiskScan.ps1

# Or, if you're already connected to Microsoft Graph:
Connect-MgGraph -Scopes "ThreatHunting.Read.All"
.\Invoke-AgentRiskScan.ps1 -SkipConnect
```

## Prerequisites

- **PowerShell 7+** (or Windows PowerShell 5.1)
- **Microsoft Graph permissions**: `ThreatHunting.Read.All` (delegated)
- **Microsoft Defender license** with Advanced Hunting enabled

The following PowerShell modules are **auto-installed** if missing:
- `Microsoft.Graph.Security` — for `Invoke-MgGraphRequest` and `Connect-MgGraph`
- `powershell-yaml` — for parsing YAML hunting query files

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-QueryFolder` | `.\HuntingQueries` | Path to folder containing `.yaml` hunting query files |
| `-OutputFolder` | `.` (current dir) | Path to write output files |
| `-SkipConnect` | `$false` | Skip `Connect-MgGraph` if you are already connected |

## Output files

Each run generates timestamped output files:

| File | Format | Description |
|---|---|---|
| `AgentRiskReport_<timestamp>.html` | HTML | Visual dashboard with summary cards, per-agent risk matrix, query results, and "Run in Defender" links |
| `AgentRiskInventory_<timestamp>.csv` | CSV | Flat table — one row per agent + risk finding. Columns: `AIAgentId`, `AIAgentName`, `CreatorAccountUpn`, `OwnerAccountUpns`, `EnvironmentId`, `RiskName`, `Severity`, `RiskNumber`, `Weight`, `Tactics`, `Techniques`, `Description`, `FileName`, `ScanTimestamp` |

## Risk coverage

The 17 hunting queries map to Microsoft's Top 10 Copilot Studio agent security risks:

| # | Risk | Severity | Queries |
|---|---|---|---|
| 1 | Agent shared with entire organization | High | Organization or Multi-tenant Shared |
| 2 | No authentication required | Critical | No Authentication Required |
| 3 | HTTP requests with risky configurations | Medium | HTTP Connector Endpoints, HTTP Non-HTTPS, HTTP Non-standard Ports |
| 4 | Email-based data exfiltration | Critical / Medium | Email AI-controlled Inputs, Email External Mailbox |
| 5 | Dormant connections, actions, or agents | Low | Published Dormant (30d), Unpublished Unmodified (30d), Unused Actions, Dormant Author Auth |
| 6 | Author (maker) authentication | High | Published Author Authentication, MCP Tool Maker Credentials |
| 7 | Hard-coded credentials | Critical | Hard-coded Credentials in Topics or Actions |
| 8 | MCP tools configured | Medium | MCP Tool Configured |
| 9 | Generative orchestration without instructions | Medium | Published Generative Orchestration without Instructions |
| 10 | Orphaned agents | High | Orphaned Agents with Disabled Owners |

## Risk score calculation

Each hunting query has a static **severity** and corresponding **weight**:

| Severity | Weight | Findings |
|----------|--------|----------|
| Critical | 4 | No Authentication Required, Hard-coded Credentials, Email to AI-controlled Inputs |
| High | 3 | Org-wide Shared, Author Authentication, MCP Maker Credentials, Orphaned Agents |
| Medium | 2 | Non-HTTPS Endpoints, Non-standard Ports, Connector Endpoints, Gen Orchestration w/o Instructions, MCP Configured, External Email |
| Low | 1 | Dormant Auth Connection, Unused Actions, Published Dormant (30d), Unpublished Unmodified (30d) |

Queries not present in the severity map default to `Info` with a weight of `0`.

### Per-agent aggregation

For each agent that appears in at least one query result, the scanner:

1. **Sums the weights** of every matched finding → this becomes the agent's **TotalWeight** (the "Score" column in the risk matrix)
2. Tracks **per-severity counts**: Critical, High, Medium, and Low
3. Records the **highest severity** among all matched findings

Agents in the matrix are **sorted by TotalWeight descending** — highest-risk agents appear first.

**Example:** An agent flagged by 2 Critical findings (4 + 4 = 8) and 1 Medium finding (2) would have a **score of 10**, highest severity "Critical", and counts Critical = 2, Medium = 1.

## HTML report features

- **Summary cards** — total agents flagged, findings by severity
- **Agent risk matrix** — color-coded heatmap showing which risks apply to which agents
- **Risk score** — additive weight-based score per agent (see [Risk score calculation](#risk-score-calculation) above)
- **Query descriptions on hover** — hover over any query name to see the full description and mitigation guidance
- **Run in Defender** — each query has a button that opens it directly in Microsoft Defender Advanced Hunting
- **MITRE ATT&CK mapping** — tactics and techniques displayed per query

## Folder structure

```
CopilotStudioAgentRiskScanner/
├── Invoke-AgentRiskScan.ps1          # Main scanner script
├── README.md                         # This file
├── HuntingQueries/                   # YAML hunting query files
│   ├── AIAgentsEmailAIControlledInputs.yaml
│   ├── AIAgentsEmailExternalMailbox.yaml
│   ├── AIAgentsGenerativeOrchestrationNoInstructions.yaml
│   ├── AIAgentsHTTPConnectorEndpoints.yaml
│   ├── AIAgentsHTTPNonHTTPS.yaml
│   ├── AIAgentsHTTPNonStandardPorts.yaml
│   ├── AIAgentsHardCodedCredentials.yaml
│   ├── AIAgentsMCPToolConfigured.yaml
│   ├── AIAgentsMCPToolMakerCredentials.yaml
│   ├── AIAgentsOrganizationWideShared.yaml
│   ├── AIAgentsUnusedActions.yaml
│   ├── DormantAuthorAuthenticationAIAgents.yaml
│   ├── NoAuthenticationRequiredAIAgents.yaml
│   ├── OrphanedAIAgents.yaml
│   ├── PublishedAIAgentsAuthorAuthentication.yaml
│   ├── PublishedDormantAIAgents.yaml
│   └── UnpublishedUnmodifiedAIAgents.yaml
├── AgentRiskReport_<timestamp>.html  # Generated HTML report
└── AgentRiskInventory_<timestamp>.csv # Generated CSV inventory
```

## Adding custom queries

Drop any `.yaml` file into `HuntingQueries/` following this format:

```yaml
id: <unique-guid>
name: My Custom Query Name
description: |
  What this query detects and recommended actions.
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  AIAgentsInfo
  | summarize arg_max(Timestamp, *) by AIAgentId
  | where AgentStatus != "Deleted"
  | where <your conditions>
  | project-reorder AgentCreationTime, AIAgentId, AIAgentName, AgentStatus, CreatorAccountUpn
```

If the query name matches a known entry in the severity map, it will use the predefined severity. Otherwise, it defaults to `Info`.

## Notes

- All queries use `arg_max(Timestamp, *) by AIAgentId` to get the **latest state** of each agent — this is a point-in-time posture snapshot, not a historical search
- Some queries (`Orphaned Agents`, `Email External Mailbox`) cross-reference the `IdentityInfo` table — these require the corresponding data connector in your Defender instance
- Some queries (`Published Dormant`, `Dormant Author Auth`) reference `CloudAppEvents` with a 30-day lookback for agent usage data
- The "Run in Defender" links encode the KQL query as gzip + base64url in the URL, matching the Defender portal's native format
