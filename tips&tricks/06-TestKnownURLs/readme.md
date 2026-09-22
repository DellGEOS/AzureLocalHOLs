# Test known Azure Local URLs (Microsoft + Dell)

Multiple repositories and methods exist for checking whether your Azure Local machines can reach all of the URLs and ports that Azure Local needs, both for deployment and for ongoing management.

This PowerShell script consolidates those disparate sources into one simple-to-run script that produces actionable output. It pulls definitive, testable URLs out of the live Environment Checker manifest and replaces the wildcard entries in the public Microsoft lists with concrete hostnames wherever possible.

The script is available [here](AzSHCIURLTester.ps1). It runs on Windows PowerShell 5.1 (i.e. directly on an Azure Local machine before deployment) as well as PowerShell 7.

## Sources consolidated

| # | Source | What it provides |
|---|--------|------------------|
| 1 | [Environment Checker connectivity manifest](https://aka.ms/hciconnectivitytargets) | The exact endpoint list the `AzStackHci.EnvironmentChecker` connectivity validator downloads at run time. Falls back to the `Targets.json` files in a locally installed copy of the module if the download fails. |
| 2 | [Microsoft consolidated per-region lists](https://learn.microsoft.com/azure/azure-local/concepts/firewall-requirements) (Azure/AzureStack-Tools on GitHub) | Region-specific endpoints for Azure Local, Arc-enabled servers, Arc Resource Bridge and AKS. All nine published regions are supported: East US, West Europe, Australia East, Canada Central, India Central, Southeast Asia, Japan East, South Central US and US Gov Virginia. |
| 3 | [Dell OEM endpoints](https://github.com/Azure/AzureStack-Tools/blob/master/HCI/OEMEndpoints/Dell/DellAzureLocalEndpoints.md) (published by Microsoft) | Solution Builder Extension (SBE) discovery manifest, the `aka.ms` redirection link and the DigiCert CRL endpoints used to verify the Dell SBE catalog signature. |
| 4 | Dell Private Cloud pre-deployment guides ("Firewall services") and Secure Connect Gateway network requirements | Dell Automation Platform SaaS portal and FDO rendezvous server, Dell download/lifecycle hosts, Secure Connect Gateway enterprise servers (IPv4 and IPv6), and the iDRAC/OpenManage connectivity host. |

## Usage

```powershell
# Interactive region prompt, Dell Private Cloud endpoints included (default)
.\AzSHCIURLTester.ps1

# Non-interactive, with your own key vault and Arc gateway names substituted for the placeholders
.\AzSHCIURLTester.ps1 -Region 'West Europe' -KeyVaultName 'contoso-azl-kv' -ArcGatewayEndpointId 'abc123'

# Dell AX System (no Dell Automation Platform endpoints), egress via a proxy
.\AzSHCIURLTester.ps1 -Region 'East US' -DellPlatform AXSystem -Proxy http://proxy.contoso.com:3128

# Microsoft endpoints only
.\AzSHCIURLTester.ps1 -Region 'Japan East' -DellPlatform None
```

| Parameter | Purpose |
|-----------|---------|
| `-Region` | Azure region the instance will register in. Prompted for if omitted. |
| `-KeyVaultName` | Replaces the `yourhcikeyvaultname.vault.azure.net` placeholder. Skipped if omitted. |
| `-ArcGatewayEndpointId` | Replaces the `yourarcgatewayendpointid.gw.arc.azure.com` placeholder. Skipped if omitted. |
| `-DellPlatform` | `PrivateCloud` (default: AX/SBE + Secure Connect Gateway + Dell Automation Platform), `AXSystem` (AX/SBE + Secure Connect Gateway) or `None`. |
| `-Proxy` | Test HTTP/HTTPS endpoints through this proxy instead of a direct TCP connect. |
| `-TimeoutMs` | TCP connect timeout per attempt. Default 5000. |
| `-OutputPath` | CSV report path. Default `.\ConnectivityTestResults.csv`. |
| `-SkipEnvironmentChecker` | Do not download the Environment Checker manifest. |

Results are written to CSV with the source, component and "required for" information from the originating list, and failed/skipped endpoints are summarised on screen.

## How wildcards are handled

Wildcard entries such as `*.servicebus.windows.net` cannot be tested directly. The script:

* expands each wildcard against every concrete hostname already collected from the other sources,
* queries the Azure guest notification allow-list API for the real `azgn-*.servicebus.windows.net` namespaces used by the Arc agent in your region, and
* tests a small table of well-known concrete hostnames for the remaining wildcards (Delivery Optimization, Microsoft Defender for Endpoint, Azure Monitor ingestion, and so on).

## Notes

* Connectivity is tested at the TCP level (DNS resolution followed by a TCP connect with a timeout). It does not depend on ICMP and is much faster than `Test-NetConnection`. It also does not prove that TLS inspection is disabled on the path; Azure Local does not support HTTPS inspection, so check that separately.
* `*.waconazure.com` is not testable prior to deployment and is skipped.
* `*.blob.storage.azure.net` has no publicly known concrete hostname and is skipped; `*.blob.core.windows.net` is tested with real storage accounts used by Azure Local.
* `wustat.windows.com` still appears in some lists but does not resolve, so it is skipped.
* `<region>.obo.arc.azure.com:8084` is a post-deployment AKS endpoint on a non-standard port and is commonly blocked by firewalls that only allow 80/443. Expect it to fail if you have not explicitly allowed 8084.
* `automation.dell.com:80` is listed by Dell alongside 443, but the host currently refuses plain HTTP; port 443 is the one that matters.
* `srs-1-v6.dell.com` is the IPv6-only Secure Connect Gateway endpoint and is skipped automatically when the machine has no global IPv6 address.
* The script honours `-Proxy` for HTTP/HTTPS endpoints only; non-web ports (8443, 9443, 8084, NTP) are always tested directly.

This is intended to provide a starting point into which the community can contribute. Please open pull requests to make changes to the script or add URL tests as appropriate. This is not a static space, and sharing knowledge and building together is how we will build the most robust community tooling for this ecosystem.
