<#
.SYNOPSIS
    Tests outbound connectivity to every known URL/port that an Azure Local deployment needs,
    including the Dell-specific endpoints for Dell AX Systems and Dell Private Cloud (Dell Automation Platform).

.DESCRIPTION
    Consolidates the following sources into a single, actionable connectivity report:

      1. Microsoft Environment Checker connectivity manifest
         - Downloaded live from https://aka.ms/hciconnectivitytargets (the same manifest the
           AzStackHci.EnvironmentChecker module downloads at run time).
         - Falls back to the Targets.json files bundled with a locally installed
           AzStackHci.EnvironmentChecker module if the download fails.

      2. Microsoft consolidated per-region endpoint lists (Azure/AzureStack-Tools on GitHub)
         - East US, West Europe, Australia East, Canada Central, India Central, Southeast Asia,
           Japan East, South Central US and US Gov Virginia.

      3. Dell OEM endpoints published by Microsoft (Azure/AzureStack-Tools/HCI/OEMEndpoints/Dell)
         - Solution Builder Extension (SBE) discovery/download and CRL endpoints.

      4. Dell Private Cloud / Dell Automation Platform and Secure Connect Gateway endpoints
         - From the Dell Private Cloud pre-deployment guides ("Firewall services") and the
           Secure Connect Gateway network requirements.

    Wildcard entries (e.g. *.servicebus.windows.net) cannot be tested directly, so the script:
      - expands them against every concrete hostname it has already collected,
      - queries the Azure guest notification allow-list API for the real Service Bus hostnames
        used by the Arc agent in the chosen region, and
      - tests a small table of well-known concrete hostnames for the remaining wildcards.

    Connectivity is tested at the TCP level (DNS resolution + TCP connect with a timeout), which is
    fast and does not depend on ICMP. time.windows.com is tested with an NTP query via w32tm.
    If your Azure Local machines egress through a proxy, pass -Proxy to test through it instead.

.PARAMETER Region
    Azure region the Azure Local instance will be registered in. Prompted for if not supplied.

.PARAMETER KeyVaultName
    Name of the key vault that will be used for deployment secrets. Replaces the
    "yourhcikeyvaultname.vault.azure.net" placeholder. If omitted, a demo name is tested purely
    to confirm *.vault.azure.net is reachable.

.PARAMETER ArcGatewayEndpointId
    Your Arc gateway endpoint ID. Replaces the "yourarcgatewayendpointid.gw.arc.azure.com"
    placeholder. If omitted the placeholder is skipped (only relevant when using Arc gateway).

.PARAMETER DellPlatform
    Which Dell endpoints to include:
      PrivateCloud (default) - Dell AX/SBE endpoints + Dell Automation Platform + Secure Connect Gateway
      AXSystem               - Dell AX/SBE endpoints + Secure Connect Gateway (no Dell Automation Platform)
      None                   - Microsoft endpoints only

.PARAMETER Proxy
    Optional HTTP proxy (e.g. http://proxy.contoso.com:3128). When set, HTTP/HTTPS endpoints are
    tested with an HTTP request through the proxy instead of a direct TCP connect.

.PARAMETER TimeoutMs
    TCP connect timeout per attempt in milliseconds. Default 5000.

.PARAMETER OutputPath
    Path of the CSV report. Default .\ConnectivityTestResults.csv

.PARAMETER SkipEnvironmentChecker
    Do not download/parse the Environment Checker manifest.

.EXAMPLE
    .\AzSHCIURLTester.ps1 -Region 'West Europe' -KeyVaultName 'contoso-azl-kv'

.EXAMPLE
    .\AzSHCIURLTester.ps1 -Region 'East US' -DellPlatform AXSystem -Proxy http://proxy.contoso.com:3128

.NOTES
    Sources last reviewed: September 2026.
    Environment Checker manifest: https://aka.ms/hciconnectivitytargets
    Microsoft firewall requirements: https://learn.microsoft.com/azure/azure-local/concepts/firewall-requirements
    Dell OEM endpoints: https://github.com/Azure/AzureStack-Tools/blob/master/HCI/OEMEndpoints/Dell/DellAzureLocalEndpoints.md
#>
[CmdletBinding()]
param (
    [ValidateSet('East US', 'West Europe', 'Australia East', 'Canada Central', 'India Central',
                 'Southeast Asia', 'Japan East', 'South Central US', 'US Gov Virginia')]
    [string]$Region,

    [string]$KeyVaultName,

    [string]$ArcGatewayEndpointId,

    [ValidateSet('PrivateCloud', 'AXSystem', 'None')]
    [string]$DellPlatform = 'PrivateCloud',

    [string]$Proxy,

    [int]$TimeoutMs = 5000,

    [string]$OutputPath = '.\ConnectivityTestResults.csv',

    [switch]$SkipEnvironmentChecker
)

#region ---------------------------------------------------------------- Configuration

# Force TLS 1.2 for downloads (Windows PowerShell 5.1 defaults can be older).
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Environment Checker live manifest (redirects to the versioned XML on azurestackreleases.download.prss.microsoft.com)
$EnvironmentCheckerManifestUrl = 'https://aka.ms/hciconnectivitytargets'

# Microsoft consolidated per-region endpoint lists.
# Location  = Azure location code, used for the Service Bus allow-list lookup.
# Cloud     = Public or Government, drives which guest notification service to query.
$RegionDefinitions = @{
    'East US'          = @{ Location = 'eastus';         Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/EastUSendpoints/eastus-hci-endpoints.md' }
    'West Europe'      = @{ Location = 'westeurope';     Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/WestEuropeendpoints/westeurope-hci-endpoints.md' }
    'Australia East'   = @{ Location = 'australiaeast';  Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/AustraliaEastendpoints/AustraliaEast-hci-endpoints.md' }
    'Canada Central'   = @{ Location = 'canadacentral';  Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/CanadaCentralEndpoints/canadacentral-hci-endpoints.md' }
    'India Central'    = @{ Location = 'centralindia';   Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/IndiaCentralEndpoints/IndiaCentral-hci-endpoints.md' }
    'Southeast Asia'   = @{ Location = 'southeastasia';  Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/SouthEastAsiaEndpoints/southeastasia-hci-endpoints.md' }
    'Japan East'       = @{ Location = 'japaneast';      Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/JapanEastEndpoints/japaneast-hci-endpoints.md' }
    'South Central US' = @{ Location = 'southcentralus'; Cloud = 'Public';     Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/SouthCentralUSEndpoints/southcentralus-hci-endpoints.md' }
    'US Gov Virginia'  = @{ Location = 'usgovvirginia';  Cloud = 'Government'; Url = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/usgovvirginia-hci-endpoints/usgovvirginia-hci-endpoints.md' }
}

# Dell OEM endpoints published by Microsoft (SBE discovery, redirection link, CRLs)
$DellOemEndpointsUrl = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/HCI/OEMEndpoints/Dell/DellAzureLocalEndpoints.md'

# Dell endpoints that are not published in the Microsoft OEM list.
# Source: Dell Private Cloud pre-deployment guides > "Firewall services", and
#         Secure Connect Gateway 5.x network requirements.
# Applies: AX = Dell AX System / Integrated System for Azure Local; DPC = Dell Private Cloud (Dell Automation Platform)
$DellStaticEndpoints = @(
    @{ URL = 'dl.dell.com';           Port = 443;  Applies = 'AX,DPC'; Component = 'Dell Lifecycle Manager / SBE'; Note = 'Firmware, driver and SBE package downloads' }
    @{ URL = 'downloads.dell.com';    Port = 443;  Applies = 'AX,DPC'; Component = 'Dell Lifecycle Manager / SBE'; Note = 'Dell catalog and SBE manifest downloads' }
    @{ URL = 'esrs3-core.emc.com';    Port = 443;  Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG enterprise server (IPv4): registration, alerts, remote support' }
    @{ URL = 'esrs3-core.emc.com';    Port = 8443; Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG enterprise server (IPv4): MQTT over TLS, inventory sync' }
    @{ URL = 'esrs3-coredr.emc.com';  Port = 443;  Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG disaster recovery server (IPv4)' }
    @{ URL = 'esrs3-coredr.emc.com';  Port = 8443; Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG disaster recovery server (IPv4): MQTT over TLS' }
    @{ URL = 'srs-1-v6.dell.com';     Port = 443;  Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG enterprise server (IPv6 only) - only required for IPv6 egress'; IPv6Only = $true }
    @{ URL = 'srs-1-v6.dell.com';     Port = 9443; Applies = 'AX,DPC'; Component = 'Dell Secure Connect Gateway';  Note = 'SCG enterprise server (IPv6 only) - only required for IPv6 egress'; IPv6Only = $true }
    @{ URL = 'colu.dell.com';         Port = 443;  Applies = 'AX,DPC'; Component = 'Dell iDRAC / OpenManage';      Note = 'Dell connectivity online update (iDRAC/OpenManage SupportAssist)' }
    @{ URL = 'automation.dell.com';   Port = 443;  Applies = 'DPC';    Component = 'Dell Automation Platform';     Note = 'Dell Automation Platform SaaS portal and orchestrator' }
    @{ URL = 'automation.dell.com';   Port = 80;   Applies = 'DPC';    Component = 'Dell Automation Platform';     Note = 'Dell Automation Platform SaaS portal (HTTP redirect)' }
    @{ URL = 'rv.dell.com';           Port = 443;  Applies = 'DPC';    Component = 'Dell Automation Platform';     Note = 'Global FDO rendezvous server for iDRAC/asset onboarding' }
)

# Placeholders in the Microsoft lists that must be replaced or skipped
$KeyVaultPlaceholder   = 'yourhcikeyvaultname.vault.azure.net'
$ArcGatewayPlaceholder = 'yourarcgatewayendpointid.gw.arc.azure.com'

# URLs that are known not to be testable before deployment (or known incorrect)
$SkipUrls = @{
    'wustat.windows.com'                          = 'Known incorrect URL - does not resolve'
    '<yourarcgatewayendpointid>.gw.arc.azure.net' = 'Legacy Arc gateway placeholder'
    'microsoft.com'                               = 'Environment Checker DNS-only check, not a port test'
}

# Concrete hostnames to test for wildcard entries that cannot be expanded from other sources.
# {location} is replaced with the Azure location code of the selected region.
$ManualWildcardHosts = @{
    '*.blob.core.windows.net'                    = @('arcplatformcliextprod.blob.core.windows.net', 'hciarcvmsstorage.blob.core.windows.net')
    '*.prod.do.dsp.mp.microsoft.com'             = @('kv801.prod.do.dsp.mp.microsoft.com', 'geo.prod.do.dsp.mp.microsoft.com')
    '*.do.dsp.mp.microsoft.com'                  = @('kv801.prod.do.dsp.mp.microsoft.com', 'geo.prod.do.dsp.mp.microsoft.com')
    '*.prod.hot.ingest.monitor.core.windows.net' = @('{location}.prod.hot.ingest.monitor.core.windows.net')
    '*.endpoint.security.microsoft.com'          = @('global.endpoint.security.microsoft.com')
    '*.data.mcr.microsoft.com'                   = @('westus.data.mcr.microsoft.com', 'westeurope.data.mcr.microsoft.com')
    '*.download.windowsupdate.com'               = @('download.windowsupdate.com')
    '*.windowsupdate.microsoft.com'              = @('update.microsoft.com')
    '*.delivery.mp.microsoft.com'                = @('msk8s.sb.tlu.dl.delivery.mp.microsoft.com')
}

# Wildcards that are genuinely untestable before deployment
$UntestableWildcards = @{
    '*.waconazure.com'         = 'Windows Admin Center relay - hostname only exists after deployment'
    '*.blob.storage.azure.net' = 'No public concrete hostname known - covered by *.blob.core.windows.net tests'
}

#endregion

#region ---------------------------------------------------------------- Helper functions

function Get-DomainFromURL {
    # Strips protocol, path and explicit port from an endpoint string.
    param ([string]$Url)
    $Url = $Url.Trim() -replace '^https?://', ''
    $Url = ($Url -split '[/?]')[0]
    $port = $null
    if ($Url -match '^(.*):(\d+)$') {
        $Url  = $Matches[1]
        $port = [int]$Matches[2]
    }
    return @{ Domain = $Url.ToLowerInvariant(); Port = $port }
}

function Invoke-WebRequestWithRetry {
    # Thin wrapper around Invoke-WebRequest that retries transient DNS/HTTP failures.
    param ([string]$Uri, [string]$OutFile, [int]$Attempts = 3)
    $lastError = $null
    foreach ($attempt in 1..$Attempts) {
        try {
            if ($OutFile) {
                return Invoke-WebRequest -Uri $Uri -UseBasicParsing -OutFile $OutFile -ErrorAction Stop
            }
            return Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop
        } catch {
            $lastError = $_
            if ($attempt -lt $Attempts) { Start-Sleep -Seconds (2 * $attempt) }
        }
    }
    throw $lastError
}

function New-EndpointRecord {
    param (
        [string]$URL,
        [int]$Port,
        [string]$Source,
        [string]$Component = '',
        [string]$Note = '',
        [string]$RequiredFor = ''
    )
    [PSCustomObject]@{
        RowID       = 0
        URL         = $URL
        Port        = $Port
        IsWildcard  = $URL.Contains('*')
        Source      = $Source
        Component   = $Component
        RequiredFor = $RequiredFor
        Note        = $Note
        Status      = ''
        IPAddress   = ''
    }
}

function Test-TcpEndpoint {
    # DNS resolution followed by a TCP connect with timeout. IPv4 addresses are tried first.
    param ([string]$HostName, [int]$Port, [int]$TimeoutMs)

    # Resolve with a retry - the Windows resolver occasionally fails transiently under a burst of lookups.
    $addresses = $null
    foreach ($attempt in 1..3) {
        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
            if ($addresses -and $addresses.Count -gt 0) { break }
        } catch {
            $addresses = $null
        }
        Start-Sleep -Milliseconds (300 * $attempt)
    }
    if (-not $addresses -or $addresses.Count -eq 0) {
        return @{ Status = 'Failed: DNS resolution'; IPAddress = '' }
    }

    $ordered = @($addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }) +
               @($addresses | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' })

    $lastError = 'TCP connect timed out'
    foreach ($attempt in 1..2) {
        foreach ($address in $ordered) {
            $client = New-Object System.Net.Sockets.TcpClient($address.AddressFamily)
            try {
                $async = $client.BeginConnect($address, $Port, $null, $null)
                if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                    $client.EndConnect($async)
                    if ($client.Connected) {
                        return @{ Status = 'Success'; IPAddress = $address.IPAddressToString }
                    }
                } else {
                    $lastError = 'TCP connect timed out'
                }
            } catch {
                $lastError = 'TCP connect refused/failed'
            } finally {
                $client.Close()
            }
        }
    }
    return @{ Status = "Failed: $lastError"; IPAddress = $ordered[0].IPAddressToString }
}

function Test-HttpEndpointViaProxy {
    # Any HTTP response (including 4xx/5xx) proves the proxy can reach the endpoint.
    param ([string]$HostName, [int]$Port, [string]$ProxyUrl, [int]$TimeoutMs)
    $scheme = if ($Port -eq 80) { 'http' } else { 'https' }
    $uri = "${scheme}://${HostName}:${Port}/"
    try {
        $null = Invoke-WebRequest -Uri $uri -Proxy $ProxyUrl -Method Head -UseBasicParsing -TimeoutSec ([math]::Ceiling($TimeoutMs / 1000)) -ErrorAction Stop
        return @{ Status = 'Success'; IPAddress = 'via proxy' }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            return @{ Status = 'Success'; IPAddress = 'via proxy' }
        }
        return @{ Status = "Failed: $($_.Exception.Status)"; IPAddress = 'via proxy' }
    } catch {
        return @{ Status = "Failed: $($_.Exception.Message)"; IPAddress = 'via proxy' }
    }
}

function Test-Connectivity {
    param ([string]$HostName, [int]$Port)
    if ($Proxy -and ($Port -eq 80 -or $Port -eq 443)) {
        return Test-HttpEndpointViaProxy -HostName $HostName -Port $Port -ProxyUrl $Proxy -TimeoutMs $TimeoutMs
    }
    return Test-TcpEndpoint -HostName $HostName -Port $Port -TimeoutMs $TimeoutMs
}

function Test-NTPConnectivity {
    param ([string]$NtpServer)
    $ntpResult = & w32tm /stripchart /computer:$NtpServer /dataonly /samples:1 2>&1 | Out-String
    if ($ntpResult -match 'error:' -or $ntpResult -match '0x8007') {
        return @{ Status = 'Failed: NTP query'; IPAddress = '' }
    }
    $ip = ''
    if ($ntpResult -match '\[(.*?)\]') { $ip = $Matches[1] }
    return @{ Status = 'Success'; IPAddress = $ip }
}

function Get-EnvironmentCheckerEndpoints {
    # Returns endpoint records from the live manifest, falling back to the installed module.
    $records = @()

    try {
        Write-Host "Downloading Environment Checker manifest from $EnvironmentCheckerManifestUrl ..."
        # Download to a file and let XmlDocument.Load handle the UTF-8 byte-order mark.
        $manifestFile = Join-Path ([System.IO.Path]::GetTempPath()) 'AzStackHciConnectivityTargets.xml'
        $null = Invoke-WebRequestWithRetry -Uri $EnvironmentCheckerManifestUrl -OutFile $manifestFile
        $xml = New-Object System.Xml.XmlDocument
        $xml.Load($manifestFile)

        $manifestVersion = ($xml.Objects.Object.Property | Where-Object { $_.Name -eq 'Version' }).'#text'
        Write-Host "  Manifest version $manifestVersion"

        $targets = ($xml.Objects.Object.Property | Where-Object { $_.Name -eq 'Targets' }).Property
        foreach ($target in $targets) {
            $props = @{}
            foreach ($p in $target.Property) { $props[$p.Name] = $p }

            $endpoints = @($props['EndPoint'].Property | ForEach-Object { $_.'#text' } | Where-Object { $_ })
            $protocols = @($props['Protocol'].Property | ForEach-Object { $_.'#text' } | Where-Object { $_ })
            $services  = (@($props['Service'].Property | ForEach-Object { $_.'#text' }) -join '; ')
            $title     = $props['Title'].'#text'
            $mandatory = $props['Mandatory'].'#text'
            $optype    = (@($props['OperationType'].Property | ForEach-Object { $_.'#text' }) -join '/')

            if ($endpoints.Count -eq 0 -or $protocols.Count -eq 0) { continue }   # DNS-only / proxy checks

            foreach ($endpoint in $endpoints) {
                $parsed = Get-DomainFromURL -Url $endpoint
                if (-not $parsed.Domain) { continue }
                $port = if ($parsed.Port) { $parsed.Port } elseif ($protocols[0] -eq 'http') { 80 } else { 443 }
                $note = "$title (Mandatory: $mandatory)"
                $records += New-EndpointRecord -URL $parsed.Domain -Port $port -Source "Environment Checker $manifestVersion" -Component $services -Note $note -RequiredFor $optype
            }
        }
        return $records
    } catch {
        Write-Warning "Could not download/parse the Environment Checker manifest: $($_.Exception.Message)"
    }

    # Fallback: locally installed module
    $module = Get-Module -Name AzStackHci.EnvironmentChecker -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        Write-Warning 'AzStackHci.EnvironmentChecker is not installed locally either - skipping Environment Checker endpoints. Install-Module AzStackHci.EnvironmentChecker to enable the fallback.'
        return $records
    }
    Write-Host "  Falling back to installed AzStackHci.EnvironmentChecker $($module.Version) Targets.json files"
    $files = Get-ChildItem -Recurse -Path $module.ModuleBase -Filter '*Targets.json'
    foreach ($file in $files) {
        $items = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        foreach ($item in $items) {
            foreach ($endpoint in @($item.Endpoint)) {
                $parsed = Get-DomainFromURL -Url $endpoint
                if (-not $parsed.Domain) { continue }
                $protocol = @($item.Protocol)[0]
                $port = if ($parsed.Port) { $parsed.Port } elseif ($protocol -eq 'http') { 80 } else { 443 }
                $records += New-EndpointRecord -URL $parsed.Domain -Port $port -Source "Environment Checker $($module.Version) (local)" -Component (@($item.Service) -join '; ') -Note "$($item.Title) (Mandatory: $($item.Mandatory))" -RequiredFor (@($item.OperationType) -join '/')
            }
        }
    }
    return $records
}

function Get-MarkdownTableEndpoints {
    # Parses the Microsoft GitHub markdown tables:
    # | Id | Component | Endpoint URL | Port | Notes | Arc gateway support | Required for |
    param ([string]$Uri, [string]$Source)
    $records = @()
    try {
        Write-Host "Downloading $Source from $Uri ..."
        $content = (Invoke-WebRequestWithRetry -Uri $Uri).Content
    } catch {
        Write-Warning "Could not download $Source list: $($_.Exception.Message)"
        return $records
    }

    if ($content -match '\*\*This list was last updated on ([^*]+)\*\*' -or $content -match '\*\*Last updated on ([^*]+)\*\*') {
        Write-Host "  List last updated: $($Matches[1].Trim())"
    }

    foreach ($line in ($content -split "`n")) {
        if ($line -notmatch '^\|\s*\d+\s*\|') { continue }
        $columns = $line -split '\|'
        if ($columns.Count -lt 5) { continue }
        $component   = $columns[2].Trim()
        $rawUrl      = $columns[3].Trim()
        $rawPorts    = $columns[4].Trim()
        $note        = if ($columns.Count -gt 5) { $columns[5].Trim() } else { '' }
        $requiredFor = if ($columns.Count -gt 7) { $columns[7].Trim() } else { '' }

        $parsed = Get-DomainFromURL -Url $rawUrl
        if (-not $parsed.Domain) { continue }
        # Trailing wildcard paths such as crl3.digicert.com/* have already been stripped to the host.
        $ports = @()
        if ($parsed.Port) { $ports += $parsed.Port }
        foreach ($p in ($rawPorts -split '[,/ ]')) { if ($p -match '^\d+$') { $ports += [int]$p } }
        if ($ports.Count -eq 0) { $ports = @(443) }

        foreach ($port in ($ports | Select-Object -Unique)) {
            $records += New-EndpointRecord -URL $parsed.Domain -Port $port -Source $Source -Component $component -Note $note -RequiredFor $requiredFor
        }
    }
    Write-Host "  Parsed $($records.Count) endpoint/port rows"
    return $records
}

function Get-ServiceBusEndpoints {
    # The Arc agent's *.servicebus.windows.net hostnames are region specific and published by the
    # guest notification service allow-list API. Returns a representative subset.
    param ([string]$Location, [string]$Cloud)
    $serviceHost = if ($Cloud -eq 'Government') { 'guestnotificationservice.azure.us' } else { 'guestnotificationservice.azure.com' }
    $uri = "https://$serviceHost/urls/allowlist?api-version=2020-01-01&location=$Location"
    try {
        Write-Host "Querying Arc guest notification allow-list for Service Bus namespaces in $Location ..."
        $hosts = (Invoke-WebRequestWithRetry -Uri $uri).Content | ConvertFrom-Json
    } catch {
        Write-Warning "Could not query the Arc guest notification allow-list for $Location : $($_.Exception.Message)"
        return @()
    }
    # The azgn-* namespaces are the ones the Microsoft lists call out (azgn*.servicebus.windows.net).
    # The API also returns g<n>-prod-* gateway namespaces; add them here if you want every namespace tested.
    $selected = @($hosts | Where-Object { $_ -like 'azgn-*' } | Select-Object -Unique)
    Write-Host "  $($selected.Count) azgn-* namespaces returned"
    return $selected
}

function Expand-WildcardEndpoints {
    # Turns wildcard rows into concrete, testable rows using (in order):
    #   1. concrete hosts already in the list that match the wildcard,
    #   2. the Service Bus allow-list API,
    #   3. the manual host table.
    param ([array]$Records, [string]$Location, [string]$Cloud)

    $wildcards = @($Records | Where-Object { $_.IsWildcard })
    $concrete  = @($Records | Where-Object { -not $_.IsWildcard })
    $expanded  = @()

    # Pool of concrete hostnames that wildcards can be matched against.
    $knownHosts = @($concrete | ForEach-Object { $_.URL })
    if ($wildcards | Where-Object { $_.URL -like '*servicebus*' }) {
        $knownHosts += Get-ServiceBusEndpoints -Location $Location -Cloud $Cloud
    }

    foreach ($wildcard in $wildcards) {
        $pattern = '^' + [regex]::Escape($wildcard.URL).Replace('\*', '.*') + '$'
        $hostsToTest = @()

        if ($UntestableWildcards.ContainsKey($wildcard.URL)) {
            $wildcard.Status = "Skipped: $($UntestableWildcards[$wildcard.URL])"
            $expanded += $wildcard
            continue
        }

        $hostsToTest += @($knownHosts | Where-Object { $_ -match $pattern })

        if ($ManualWildcardHosts.ContainsKey($wildcard.URL)) {
            $hostsToTest += @($ManualWildcardHosts[$wildcard.URL] | ForEach-Object { $_ -replace '\{location\}', $Location })
        }

        $hostsToTest = @($hostsToTest | Where-Object { $_ -match $pattern } | Select-Object -Unique)

        if ($hostsToTest.Count -eq 0) {
            $wildcard.Status = 'Skipped: Wildcard with no known concrete hostname'
            $expanded += $wildcard
            continue
        }

        foreach ($h in $hostsToTest) {
            $expanded += New-EndpointRecord -URL $h -Port $wildcard.Port -Source $wildcard.Source -Component $wildcard.Component -Note "Expanded from $($wildcard.URL): $($wildcard.Note)" -RequiredFor $wildcard.RequiredFor
        }
    }

    return @($concrete) + @($expanded)
}

#endregion

#region ---------------------------------------------------------------- Collect endpoints

if (-not $Region) {
    $Region = Read-Host "Select a region ($(($RegionDefinitions.Keys | Sort-Object) -join ', '))"
    if (-not $RegionDefinitions.ContainsKey($Region)) {
        throw "Unknown region '$Region'. Valid values: $(($RegionDefinitions.Keys | Sort-Object) -join ', ')"
    }
}
$regionInfo = $RegionDefinitions[$Region]

Write-Host ''
Write-Host "Azure Local outbound URL tester - region '$Region' ($($regionInfo.Location)), Dell platform '$DellPlatform'" -ForegroundColor Cyan
if ($Proxy) { Write-Host "HTTP/HTTPS endpoints will be tested through proxy $Proxy" -ForegroundColor Cyan }
Write-Host ''

$results = @()

# 1. Environment Checker manifest
if (-not $SkipEnvironmentChecker) {
    $results += Get-EnvironmentCheckerEndpoints
}

# 2. Microsoft consolidated region list
$results += Get-MarkdownTableEndpoints -Uri $regionInfo.Url -Source "Microsoft $Region list"

# 3. Dell endpoints
if ($DellPlatform -ne 'None') {
    $results += Get-MarkdownTableEndpoints -Uri $DellOemEndpointsUrl -Source 'Dell OEM list (Microsoft GitHub)'

    $applies = if ($DellPlatform -eq 'PrivateCloud') { 'DPC' } else { 'AX' }
    $hasGlobalIPv6 = [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                            Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fd*' -and $_.IPAddress -notlike 'fc*' })
    foreach ($entry in $DellStaticEndpoints) {
        if (($entry.Applies -split ',') -contains $applies) {
            $record = New-EndpointRecord -URL $entry.URL -Port $entry.Port -Source 'Dell Private Cloud / SCG docs' -Component $entry.Component -Note $entry.Note -RequiredFor 'Deployment & Post deployment'
            if ($entry.IPv6Only -and -not $hasGlobalIPv6) {
                $record.Status = 'Skipped: IPv6-only endpoint and this machine has no global IPv6 address'
            }
            $results += $record
        }
    }
}

if ($results.Count -eq 0) {
    throw 'No endpoints were collected from any source. Check internet access from this machine.'
}

# Replace placeholders
foreach ($record in $results) {
    if ($record.URL -eq $KeyVaultPlaceholder) {
        if ($KeyVaultName) {
            $record.URL  = "$KeyVaultName.vault.azure.net".ToLowerInvariant()
            $record.Note = "Key vault (from -KeyVaultName): $($record.Note)"
        } else {
            $record.Status = 'Skipped: Key vault placeholder - pass -KeyVaultName to test your vault'
        }
    } elseif ($record.URL -eq $ArcGatewayPlaceholder) {
        if ($ArcGatewayEndpointId) {
            $record.URL  = "$ArcGatewayEndpointId.gw.arc.azure.com".ToLowerInvariant()
            $record.Note = "Arc gateway (from -ArcGatewayEndpointId): $($record.Note)"
        } else {
            $record.Status = 'Skipped: Arc gateway placeholder - pass -ArcGatewayEndpointId if you use Arc gateway'
        }
    } elseif ($SkipUrls.ContainsKey($record.URL)) {
        $record.Status = "Skipped: $($SkipUrls[$record.URL])"
    }
}

# Expand wildcards into testable hostnames
$results = Expand-WildcardEndpoints -Records $results -Location $regionInfo.Location -Cloud $regionInfo.Cloud

# De-duplicate on URL + Port, keeping the first occurrence (Environment Checker first, then region list, then Dell)
$results = @($results | Sort-Object URL, Port, Source | Group-Object URL, Port | ForEach-Object { $_.Group[0] })

#endregion

#region ---------------------------------------------------------------- Test

$total = $results.Count
$index = 0
Write-Host ''
Write-Host "Testing $total unique endpoint/port combinations ..." -ForegroundColor Cyan

foreach ($record in $results) {
    $index++
    Write-Progress -Activity 'Testing connectivity' -Status "$($record.URL):$($record.Port)" -PercentComplete (($index / $total) * 100)

    if ($record.Status) { continue }   # already skipped

    if ($record.Port -eq 123 -or $record.URL -eq 'time.windows.com') {
        $r = Test-NTPConnectivity -NtpServer $record.URL
    } else {
        $r = Test-Connectivity -HostName $record.URL -Port $record.Port
    }
    $record.Status    = $r.Status
    $record.IPAddress = $r.IPAddress
}
Write-Progress -Activity 'Testing connectivity' -Completed

#endregion

#region ---------------------------------------------------------------- Report

$rowId = 1
foreach ($record in $results) { $record.RowID = $rowId; $rowId++ }
$results = $results | Select-Object RowID, URL, Port, Status, IPAddress, Source, Component, RequiredFor, Note, IsWildcard

$results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host ''
Write-Host "Test results have been saved to $OutputPath" -ForegroundColor Green

$failed  = @($results | Where-Object { $_.Status -like 'Failed*' })
$skipped = @($results | Where-Object { $_.Status -like 'Skipped*' })
$passed  = @($results | Where-Object { $_.Status -eq 'Success' })

Write-Host ''
Write-Host "Summary: $($passed.Count) succeeded, $($failed.Count) failed, $($skipped.Count) skipped (of $total)" -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host 'The following URLs FAILED:' -ForegroundColor Red
    $failed | Format-Table -Property RowID, URL, Port, Status, Source -AutoSize | Out-String -Width 220 | Write-Host
} else {
    Write-Host 'No URLs failed.' -ForegroundColor Green
}

if ($skipped.Count -gt 0) {
    Write-Host 'The following URLs were skipped:' -ForegroundColor Yellow
    $skipped | Format-Table -Property RowID, URL, Port, Status -AutoSize | Out-String -Width 220 | Write-Host
}

#endregion
