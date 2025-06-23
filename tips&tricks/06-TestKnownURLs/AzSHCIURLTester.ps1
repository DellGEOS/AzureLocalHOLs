# Initialize the results array
$results = @()

# User-defined keyvault URL replacement (modify if needed)
$KeyVaultReplacement = "demo1.vault.azure.net"  # Replace with your own keyvault URL if needed

# Function to extract domains from URLs
function Get-DomainFromURL {
    param (
        [string]$url
    )
    $url = $url -replace "^https?://", ""
    if ($url -match ":(\d+)$") {
        $port = [int]($url -replace ".*:(\d+)$", '$1')
        $url = $url -replace ":(\d+)$", ""
    } else {
        $port = $null
    }
    $domain = $url -split '/' | Select-Object -First 1
    return @{ Domain = $domain; Port = $port }
}

# Function to test connectivity
function Test-Connectivity {
    param (
        [string]$url,
        [int]$port
    )
    $testResult = Test-NetConnection -ComputerName $url -Port $port -WarningAction SilentlyContinue
    $status = if ($testResult.TcpTestSucceeded) { "Success" } else { "Failed" }
    $ipAddress = $testResult.RemoteAddress
    return $status, $ipAddress
}

# Function to perform NTP test for time.windows.com
function Test-NTPConnectivity {
    param (
        [string]$ntpServer
    )
    $ntpResult = w32tm /stripchart /computer:$ntpServer /dataonly /samples:1
    if ($ntpResult -match "error:") {
        $status = "Failed"
        $ipAddress = ""
    } else {
        $status = "Success"
        if ($ntpResult -match "\[(.*?)\]") {
            $ipAddress = $matches[1]
        } else {
            $ipAddress = ""
        }
    }
    return $status, $ipAddress
}

# Enhanced function to expand wildcard URLs dynamically
function Expand-WildcardUrlsDynamically {
    param (
        [array]$results
    )

    # Split into wildcard and non-wildcard results
    $wildcardResults = $results | Where-Object { $_.IsWildcard -eq $true }
    $nonWildcardResults = $results | Where-Object { $_.IsWildcard -eq $false }

    $expandedResults = @()

    foreach ($wildcard in $wildcardResults) {
        # Create a regex pattern from the wildcard URL
        $wildcardPattern = $wildcard.URL -replace "\*", ".*"

        # Find matching non-wildcard URLs
        $matchingUrls = $nonWildcardResults | Where-Object { $_.URL -match "^$wildcardPattern$" }

        if ($matchingUrls.Count -eq 0) {
            # No matches found, retain the original wildcard entry
            $expandedResults += $wildcard
        } else {
            foreach ($match in $matchingUrls) {
                # Handle both HTTP and HTTPS formats
                $newEntryHttp = $wildcard.PSObject.Copy()
                $newEntryHttp.URL = $match.URL
                $newEntryHttp.Port = 80
                $newEntryHttp.Note = "Expanded Wildcard URL"
                $newEntryHttp.IsWildcard = $false
                $newEntryHttp.Status, $newEntryHttp.IPAddress = Test-Connectivity -url $match.URL -port 80
                $expandedResults += $newEntryHttp

                $newEntryHttps = $wildcard.PSObject.Copy()
                $newEntryHttps.URL = $match.URL
                $newEntryHttps.Port = 443
                $newEntryHttps.Note = "Expanded Wildcard URL"
                $newEntryHttps.IsWildcard = $false
                $newEntryHttps.Status, $newEntryHttps.IPAddress = Test-Connectivity -url $match.URL -port 443
                $expandedResults += $newEntryHttps
            }
        }
    }

    $expandedResults += $nonWildcardResults
    return $expandedResults
}

# Function to manually test known subdomains for wildcard URLs
function Test-ManuallyDefinedSubdomains {
    param (
        [array]$wildcardUrls
    )

    # Define manually known subdomains to test for each wildcard
    $manualSubdomains = @(
        @{ Wildcard = "*.blob.storage.azure.net"; Subdomains = @("mystorageaccount.blob.core.windows.net") },
        @{ Wildcard = "*.download.windowsupdate.com"; Subdomains = @("download.windowsupdate.com", "fe2.update.microsoft.com") },
        @{ Wildcard = "*.endpoint.security.microsoft.com"; Subdomains = @("global.endpoint.security.microsoft.com") },
        @{ Wildcard = "*.prod.hot.ingest.monitor.core.windows.net"; Subdomains = @("eastus.prod.hot.ingest.monitor.core.windows.net") },
        @{ Wildcard = "*.windowsupdate.microsoft.com"; Subdomains = @("update.microsoft.com") }
    )

    $manualResults = @()

    # Test each subdomain for connectivity
    foreach ($entry in $manualSubdomains) {
        $wildcard = $entry.Wildcard
        $subdomains = $entry.Subdomains

        foreach ($subdomain in $subdomains) {
            foreach ($port in @(80, 443)) {
                $status, $ipAddress = Test-Connectivity -url $subdomain -port $port

                $manualResults += [PSCustomObject]@{
                    RowID = 0
                    URL = $subdomain
                    Port = $port
                    IsWildcard = $false
                    Note = "Manually defined URL"
                    Status = $status
                    IPAddress = $ipAddress
                }
            }
        }
    }

    return $manualResults
}

# Function to process results
function Process-Results {
    param (
        [array]$results
    )

    # Remove duplicate URLs with the same port
    $results = $results | Sort-Object URL, Port -Unique

    # Assign Row IDs and reorder columns
    $rowIdCounter = 1
    foreach ($result in $results) {
        $result.RowID = $rowIdCounter
        $rowIdCounter++
    }

    $results = $results | Select-Object RowID, URL, Port, IsWildcard, Note, Status, IPAddress

    # Export results to CSV
    $csvFile = "ConnectivityTestResults.csv"
    $results | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host "Test results have been saved to $csvFile"

    # Display failed and skipped URLs
    $failedResults = $results | Where-Object { $_.Status -eq "Failed" }
    $skippedResults = $results | Where-Object { $_.Status -like "Skipped*" }

    if ($failedResults.Count -gt 0) {
        Write-Host "The following URLs failed:"
        $failedResults | Format-Table -Property RowID, URL, Port, Status -AutoSize
    } else {
        Write-Host "No URLs failed."
    }

    if ($skippedResults.Count -gt 0) {
        Write-Host "The following URLs were skipped:"
        $skippedResults | Format-Table -Property RowID, URL, Status -AutoSize
    } else {
        Write-Host "No URLs were skipped."
    }
}

# Load URLs from environment checker (Targets.json)
$Location = (Get-Module -Name AzStackHci.EnvironmentChecker -ListAvailable).ModuleBase
$Files = Get-ChildItem -Recurse -Path $Location | Where-Object Name -like "*Targets.json"

foreach ($File in $Files) {
    $content = Get-Content -Path $File.FullName
    $object = $content | ConvertFrom-Json
    foreach ($item in $Object) {
        foreach ($endpoint in $Item.Endpoint) {
            $domainPort = Get-DomainFromURL -url $endpoint
            $url = $domainPort.Domain
            $port = if ($domainPort.Port) { $domainPort.Port } else { if ($item.Protocol -eq 'https') { 443 } else { 80 } }
            
            $results += [PSCustomObject]@{
                RowID = 0
                URL = $url
                Port = $port
                IsWildcard = $false
                Note = "Environment Checker URL"
                Status = ""
                IPAddress = ""
            }
        }
    }
}

# Load URLs from GitHub pages
$regionUrls = @{
    "East US" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/EastUSendpoints/eastus-hci-endpoints.md"
    "West Europe" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/WestEuropeendpoints/westeurope-hci-endpoints.md"
    "Australia East" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/AustraliaEastendpoints/AustraliaEast-hci-endpoints.md"
    "Canada Central" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/CanadaCentralEndpoints/canadacentral-hci-endpoints.md"
    "Central India" = "https://raw.githubusercontent.com/Azure/AzureStack-Tools/refs/heads/master/HCI/IndiaCentralEndpoints/IndiaCentral-hci-endpoints.md"
}

# Download and parse URLs from GitHub pages
$region = Read-Host "Select a region (East US, West Europe, Australia East, Canada Central, Central India)"
if ($regionUrls.ContainsKey($region)) {
    $endpointUrl = $regionUrls[$region]
    $endpointsContent = Invoke-WebRequest -Uri $endpointUrl -UseBasicParsing
    $lines = $endpointsContent.Content -split "`n"

    foreach ($line in $lines) {
        if ($line -match "^\|\s*(\d+)\s*\|") {
            $rowId = [int]($line -replace "^\|\s*(\d+)\s*\|.*", '$1')
            $columns = $line -split "\|"
            $url = $columns[3].Trim()
            $ports = $columns[4].Trim() -split ','

            $url = (Get-DomainFromURL -url $url).Domain
            foreach ($port in $ports) {
                $isWildcard = $url.Contains("*")
                $results += [PSCustomObject]@{
                    RowID = 0
                    URL = $url
                    Port = [int]$port
                    IsWildcard = $isWildcard
                    Note = if ($isWildcard) { "Wildcard URL" } else { "GitHub URL" }
                    Status = ""
                    IPAddress = ""
                }
            }
        }
    }
}

# Add Dell URLs
$additionalUrls = @(
    [PSCustomObject]@{ RowID = 0; URL = "downloads.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "downloads.dell.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "dl.dell.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "esrs3-core.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "esrs3-core.emc.com"; Port = 8443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "esrs3-coredr.emc.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "esrs3-coredr.emc.com"; Port = 8443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" },
    [PSCustomObject]@{ RowID = 0; URL = "colu.dell.com"; Port = 443; IsWildcard = $false; Note = "Dell URL"; Status = ""; IPAddress = "" }
)

$results += $additionalUrls

# Process URLs
$skipUrls = @("*.waconazure.com", "wustat.windows.com", "<yourarcgatewayendpointid>.gw.arc.azure.net")

foreach ($urlObj in $results) {
    if ($urlObj.URL -eq "time.windows.com") {
        $urlObj.Status, $urlObj.IPAddress = Test-NTPConnectivity -ntpServer $urlObj.URL
    } elseif ($urlObj.URL -eq "yourhcikeyvaultname.vault.azure.net") {
        $urlObj.URL = $KeyVaultReplacement
        $urlObj.Status, $urlObj.IPAddress = Test-Connectivity -url $urlObj.URL -port $urlObj.Port
    } elseif ($skipUrls -contains $urlObj.URL) {
        $urlObj.Status = "Skipped: Known Incorrect URL"
    } elseif ($urlObj.Note -eq "Wildcard URL") {
        continue
    } else {
        $urlObj.Status, $urlObj.IPAddress = Test-Connectivity -url $urlObj.URL -port $urlObj.Port
    }
}

# Dynamically expand wildcard URLs
$allUrlsToTest = Expand-WildcardUrlsDynamically -results $results

# Test manually defined subdomains
$manualSubdomainTests = Test-ManuallyDefinedSubdomains -wildcardUrls $results
$allUrlsToTest += $manualSubdomainTests

# Process the final results
Process-Results -results $allUrlsToTest
