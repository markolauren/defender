# Microsoft Defender for Cloud Coverage & Assets Report Script
# This script runs a hardcoded Azure Resource Graph (ARG) query, logs in to the specified Azure tenant, and displays/export results.
# Edit $Query as needed.

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId
)

# --- Configuration ---
$First = 1000                           # max rows to fetch

# Hardcoded ARG query:
# Replace the Kusto query below with the exact ARG query you want to run.
$Query = @'

resourcecontainers
| where type == "microsoft.resources/subscriptions"
| project subscriptionId, subscriptionName = name
| join kind=inner (
    securityresources
    | where type =~ "microsoft.security/pricings"
    | extend pricingTier = iff(properties.pricingTier == "Free", "OFF", "on"), subPlan = properties.subPlan
    | extend planSet = pack(name, level = case(isnotempty(subPlan), subPlan, pricingTier))
    | summarize defenderPlans = make_bag(planSet) by subscriptionId
    | join kind=leftouter (
        resources
        | summarize 
            cloudPostureBillableCount = countif(type == "microsoft.compute/virtualmachines")
                                      + countif(type == "microsoft.compute/virtualmachinescalesets/virtualmachines")
                                      + countif(type == "microsoft.classiccompute/virtualmachines")
                                      + countif(type == "microsoft.storage/storageaccounts")
                                      + countif(type == "microsoft.sql/servers")
                                      + countif(type == "microsoft.sql/managedinstances")
                                      + countif(type == "microsoft.dbforpostgresql/flexibleservers")
                                      + countif(type == "microsoft.dbforpostgresql/servers")
                                      + countif(type == "microsoft.dbformysql/flexibleservers")
                                      + countif(type == "microsoft.dbformysql/servers")
                                      + countif(type == "microsoft.dbformariadb/servers")
                                      + countif(type == "microsoft.synapse/workspaces"),
            vmCount = countif(type == "microsoft.compute/virtualmachines") 
                    + countif(type == "microsoft.hybridcompute/machines")                             
                    + countif(type == "microsoft.compute/virtualmachinescalesets/virtualmachines")
                    + countif(type == "microsoft.classiccompute/virtualmachines"),
            appServiceCount = countif(type == "microsoft.web/sites" and kind has "app"),
            sqlServerCount = countif(type == "microsoft.sql/servers")
                           + countif(type == "microsoft.sql/managedinstances"),
            sqlVMCount = countif(type == "microsoft.sqlvirtualmachine/sqlvirtualmachines") 
                       + countif(type == "microsoft.azurearcdata/sqlserverinstances"),
            openSourceDBCount = countif(type == "microsoft.dbforpostgresql/servers")
                              + countif(type == "microsoft.dbforpostgresql/flexibleservers")
                              + countif(type == "microsoft.dbformysql/servers")
                              + countif(type == "microsoft.dbformysql/flexibleservers")
                              + countif(type == "microsoft.dbformariadb/servers"),
            cosmosCount = countif(type == "microsoft.documentdb/databaseaccounts"),
            storageCount = countif(type == "microsoft.storage/storageaccounts"),
            aksCount = countif(type == "microsoft.containerservice/managedclusters"),
            acrCount = countif(type == "microsoft.containerregistry/registries"),
            keyVaultCount = countif(type == "microsoft.keyvault/vaults"),
            armCount = 1,
            aiCount = countif(type == "microsoft.cognitiveservices/accounts"),
            //        + countif(type == "microsoft.aifoundry/projects"),
            //        + countif(type == "microsoft.machinelearningservices/workspaces"),
            //        + countif(type == "microsoft.search/searchservices"),
            apiManagementCount = countif(type == "microsoft.apimanagement/service")
        by subscriptionId
    ) on subscriptionId
) on subscriptionId
| extend
    assetsDefended = 
	    iif(defenderPlans.CloudPosture != "OFF", cloudPostureBillableCount, 0) +
	    iif(defenderPlans.VirtualMachines != "OFF", vmCount, 0) +
	    iif(defenderPlans.AppServices != "OFF", appServiceCount, 0) +
	    iif(defenderPlans.SqlServers != "OFF", sqlServerCount, 0) +
	    iif(defenderPlans.SqlServerVirtualMachines != "OFF", sqlVMCount, 0) +
	    iif(defenderPlans.OpenSourceRelationalDatabases != "OFF", openSourceDBCount, 0) +
	    iif(defenderPlans.CosmosDbs != "OFF", cosmosCount, 0) +
	    iif(defenderPlans.StorageAccounts != "OFF", storageCount, 0) +
	    iif(defenderPlans.Containers != "OFF", aksCount + acrCount, 0) +
	    iif(defenderPlans.KeyVaults != "OFF", keyVaultCount, 0) +
	    iif(defenderPlans.Arm != "OFF", armCount, 0) +
	    iif(defenderPlans.AI != "OFF", aiCount, 0) +
	    iif(defenderPlans.Api != "OFF", apiManagementCount, 0),
	assetsUNdefended = 
	    iif(defenderPlans.CloudPosture == "OFF", cloudPostureBillableCount, 0) +
	    iif(defenderPlans.VirtualMachines == "OFF", vmCount, 0) +
	    iif(defenderPlans.AppServices == "OFF", appServiceCount, 0) +
	    iif(defenderPlans.SqlServers == "OFF", sqlServerCount, 0) +
	    iif(defenderPlans.SqlServerVirtualMachines == "OFF", sqlVMCount, 0) +
	    iif(defenderPlans.OpenSourceRelationalDatabases == "OFF", openSourceDBCount, 0) +
	    iif(defenderPlans.CosmosDbs == "OFF", cosmosCount, 0) +
	    iif(defenderPlans.StorageAccounts == "OFF", storageCount, 0) +
	    iif(defenderPlans.Containers == "OFF", aksCount + acrCount, 0) +
	    iif(defenderPlans.KeyVaults == "OFF", keyVaultCount, 0) +
	    iif(defenderPlans.Arm == "OFF", armCount, 0) +
	    iif(defenderPlans.AI == "OFF", aiCount, 0) +
	    iif(defenderPlans.Api == "OFF", apiManagementCount, 0)
    | project subscriptionName, subscriptionId, 
    assetsDefended,
    assetsUNdefended,
    CloudPosture = defenderPlans.CloudPosture,
    CSPMCount = cloudPostureBillableCount,
    VirtualMachines = defenderPlans.VirtualMachines,
    ServersCount = vmCount,
    AppServices = defenderPlans.AppServices,
    AppServiceCount = appServiceCount,
    SqlServers = defenderPlans.SqlServers,
    AzureSQLCount = sqlServerCount,
    SqlServerVirtualMachines = defenderPlans.SqlServerVirtualMachines,
    SQLVMCount = sqlVMCount,
    OpenSourceRelationalDatabases = defenderPlans.OpenSourceRelationalDatabases,
    OSSdbCount = openSourceDBCount,
    CosmosDB = defenderPlans.CosmosDbs,
    CosmosDatabaseCount = cosmosCount,
    StorageAccounts = defenderPlans.StorageAccounts,
    StorageCount = storageCount,
    Containers = defenderPlans.Containers,
    AKSCount = aksCount,
    ACRCount = acrCount,
    KeyVaults = defenderPlans.KeyVaults,
    KeyVaultCount = keyVaultCount,
    AI = defenderPlans.AI,
    AICount = aiCount,
    API = defenderPlans.Api,
    APIMCount = apiManagementCount,
    Arm = defenderPlans.Arm,
    DNS = defenderPlans.Dns,
    KubernetesService = defenderPlans.KubernetesService,
    ContainerRegistry = defenderPlans.ContainerRegistry
'@

# --- Ensure required modules are available ---
$requiredModules = @('Az.Accounts','Az.ResourceGraph')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "$mod module not found. Installing $mod (this may require admin/NuGet setup)..."
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod -ErrorAction Stop
}

# --- Login to Azure (interactive) ---
Write-Host "Signing in to Azure tenant: $TenantId"
Connect-AzAccount -Tenant $TenantId -SkipContextPopulation -ErrorAction Stop

# Optionally set the context to a subscription if you want to scope to a specific subscription
# Set-AzContext -SubscriptionId "<SUBSCRIPTION_ID>"

# --- Execute query ---
Write-Host "Executing query..."
try {
    $results = Search-AzGraph -Query $Query -First $First -ErrorAction Stop
} catch {
    Write-Host "Failed to run ARG query: $_"
    exit 1
}

# --- Show results to user ---
if ($null -eq $results -or $results.Count -eq 0) {
    Write-Host "No results returned."
} else {
    # Pretty table output
    $results | Format-Table -AutoSize

    # Export to CSV file
    $csvPath = "DefenderUsageReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Results exported to: $csvPath"

    # Generate fancy HTML report
    $htmlPath = "DefenderUsageReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Defender for Cloud Usage Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 24px; }
        .header p { margin: 5px 0 0 0; opacity: 0.9; }
        .container { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow-x: auto; }
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 1200px; }
        th { background-color: #0078d4; color: white; padding: 12px 8px; text-align: center; font-weight: 600; white-space: nowrap; }
        th:first-child { text-align: left; }
        td { padding: 10px 8px; border-bottom: 1px solid #e0e0e0; white-space: nowrap; text-align: center; }
        td:first-child { text-align: left; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .status-on { color: #28a745; font-weight: bold; }
        .status-off { background-color: #dc3545 !important; color: white !important; font-weight: bold; padding: 8px 12px; border-radius: 4px; }
        .number { font-family: 'Courier New', monospace; }
        .undefended-alert { 
            background-color: #dc3545 !important; 
            color: white !important; 
            font-weight: bold !important; 
            animation: pulse 2s infinite;
            border: 2px solid #a71e2a !important;
        }
        @keyframes pulse {
            0% { background-color: #dc3545; }
            50% { background-color: #ff4757; }
            100% { background-color: #dc3545; }
        }
        .summary { margin: 20px 0; padding: 15px; background: #e3f2fd; border-radius: 8px; border-left: 4px solid #0078d4; }
        .footer { margin-top: 20px; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft Defender for Cloud Usage Report</h1>
        <p>Generated on: $timestamp</p>
    </div>
    
    <div class="summary">
        <strong>Report Summary:</strong> This report shows Microsoft Defender for Cloud plan status and asset counts across all subscriptions.
    </div>
    
    <div class="container">
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Subscription</th>
                        <th>Assets Defended</th>
                        <th>Assets Undefended</th>
                        <th>Cloud Posture</th>
                        <th>CSPM Count</th>
                        <th>Virtual Machines</th>
                        <th>Servers Count</th>
                        <th>App Services</th>
                        <th>App Service Count</th>
                        <th>SQL Servers</th>
                        <th>Azure SQL Count</th>
                        <th>SQL Server VMs</th>
                        <th>SQL VM Count</th>
                        <th>OSS Databases</th>
                        <th>OSS DB Count</th>
                        <th>Cosmos DB</th>
                        <th>Cosmos Count</th>
                        <th>Storage Accounts</th>
                        <th>Storage Count</th>
                        <th>Containers</th>
                        <th>AKS Count</th>
                        <th>ACR Count</th>
                        <th>Key Vaults</th>
                        <th>Key Vault Count</th>
                        <th>AI</th>
                        <th>AI Count</th>
                        <th>API</th>
                        <th>APIM Count</th>
                        <th>ARM</th>
                        <th>DNS</th>
                        <th>Kubernetes Service</th>
                        <th>Container Registry</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($row in $results) {
        $htmlContent += "                <tr>`n"
        $htmlContent += "                    <td>$($row.subscriptionName)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.assetsDefended)</td>`n"
        
        # Special styling for undefended assets > 0
        if ($row.assetsUNdefended -gt 0) {
            $htmlContent += "                    <td class='undefended-alert'>$($row.assetsUNdefended)</td>`n"
        } else {
            $htmlContent += "                    <td class='number'>$($row.assetsUNdefended)</td>`n"
        }
        
        $htmlContent += "                    <td class='$(if($row.CloudPosture -eq "OFF"){"status-off"}else{"status-on"})'>$($row.CloudPosture)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.CSPMCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.VirtualMachines -eq "OFF"){"status-off"}else{"status-on"})'>$($row.VirtualMachines)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.ServersCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.AppServices -eq "OFF"){"status-off"}else{"status-on"})'>$($row.AppServices)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.AppServiceCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.SqlServers -eq "OFF"){"status-off"}else{"status-on"})'>$($row.SqlServers)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.AzureSQLCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.SqlServerVirtualMachines -eq "OFF"){"status-off"}else{"status-on"})'>$($row.SqlServerVirtualMachines)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.SQLVMCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.OpenSourceRelationalDatabases -eq "OFF"){"status-off"}else{"status-on"})'>$($row.OpenSourceRelationalDatabases)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.OSSdbCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.CosmosDB -eq "OFF"){"status-off"}else{"status-on"})'>$($row.CosmosDB)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.CosmosDatabaseCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.StorageAccounts -eq "OFF"){"status-off"}else{"status-on"})'>$($row.StorageAccounts)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.StorageCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.Containers -eq "OFF"){"status-off"}else{"status-on"})'>$($row.Containers)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.AKSCount)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.ACRCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.KeyVaults -eq "OFF"){"status-off"}else{"status-on"})'>$($row.KeyVaults)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.KeyVaultCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.AI -eq "OFF"){"status-off"}else{"status-on"})'>$($row.AI)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.AICount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.API -eq "OFF"){"status-off"}else{"status-on"})'>$($row.API)</td>`n"
        $htmlContent += "                    <td class='number'>$($row.APIMCount)</td>`n"
        $htmlContent += "                    <td class='$(if($row.Arm -eq "OFF"){"status-off"}else{"status-on"})'>$($row.Arm)</td>`n"
        $htmlContent += "                    <td class='$(if($row.DNS -eq "OFF"){"status-off"}else{"status-on"})'>$($row.DNS)</td>`n"
        $htmlContent += "                    <td class='$(if($row.KubernetesService -eq "OFF"){"status-off"}else{"status-on"})'>$($row.KubernetesService)</td>`n"
        $htmlContent += "                    <td class='$(if($row.ContainerRegistry -eq "OFF"){"status-off"}else{"status-on"})'>$($row.ContainerRegistry)</td>`n"
        $htmlContent += "                </tr>`n"
    }

    $htmlContent += @"
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by Azure Resource Graph Query | Microsoft Defender for Cloud Usage Report</p>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "HTML report exported to: $htmlPath"

    # Also write JSON to stdout if user prefers
    # $results | ConvertTo-Json -Depth 5 | Write-Output

}
