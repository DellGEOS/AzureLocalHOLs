# Azure Local 23H2 Deployment

<!-- TOC -->

- [Azure Local 23H2 Deployment](#azure-local-23h2-deployment)
    - [About the lab](#about-the-lab)
        - [Prerequisites](#prerequisites)
        - [LabConfig](#labconfig)
        - [NTP Prerequisite Virtual Lab](#ntp-prerequisite-virtual-lab)
        - [Example Initial Config AX Nodes - Example, needs to be modified](#example-initial-config-ax-nodes---example-needs-to-be-modified)
    - [The Lab](#the-lab)
        - [Task01 - Validate connectivity to servers](#task01---validate-connectivity-to-servers)
            - [Step 1 Test name resolution works with simple ping](#step-1-test-name-resolution-works-with-simple-ping)
            - [Step 2 Check WinRM connectivity](#step-2-check-winrm-connectivity)
            - [Step 3 Connect to servers using WinRM](#step-3-connect-to-servers-using-winrm)
        - [Task02 - Install features & drivers](#task02---install-features--drivers)
            - [Step 1 Install server features - skip if you use latest media](#step-1-install-server-features---skip-if-you-use-latest-media)
            - [Step 2 Install Network Drivers - AXnodes - fresh install only](#step-2-install-network-drivers---axnodes---fresh-install-only)
            - [Step 3 Install Dell Drivers - Optional - AX Nodes](#step-3-install-dell-drivers---optional---ax-nodes)
            - [Step 4 Restart servers to apply changes](#step-4-restart-servers-to-apply-changes)
            - [Step 5 Rename Network adapters - Optional](#step-5-rename-network-adapters---optional)
        - [Task03 - Validate environment using Environment Checker tool](#task03---validate-environment-using-environment-checker-tool)
        - [Task04 - Create Azure Resources](#task04---create-azure-resources)
        - [Task05 - Create AD Prerequisites](#task05---create-ad-prerequisites)
        - [Task 06a - Connect nodes to Azure - WebUI](#task-06a---connect-nodes-to-azure---webui)
        - [Task 06b - Connect nodes to Azure - PowerShell](#task-06b---connect-nodes-to-azure---powershell)
        - [Task07 - Validation Prerequisites](#task07---validation-prerequisites)
            - [Step 1 Password complexity in MSLab is password not complex enough](#step-1-password-complexity-in-mslab-is-password-not-complex-enough)
            - [Step 2 IP Configuration](#step-2-ip-configuration)
            - [Step 3 NTP Server if NTP protocol is blocked by firewall and servers time is not synced](#step-3-ntp-server-if-ntp-protocol-is-blocked-by-firewall-and-servers-time-is-not-synced)
        - [Task08 - Validation Prerequisites - AXNodes](#task08---validation-prerequisites---axnodes)
            - [Step 1 - Populate latest SBE package AXNodes only](#step-1---populate-latest-sbe-package-axnodes-only)
            - [Step 2 - Exclude iDRAC adapters from cluster networks](#step-2---exclude-idrac-adapters-from-cluster-networks)
            - [Step 3 - Clear data disks](#step-3---clear-data-disks)
            - [Step 4 - Reboot iDRAC if needed](#step-4---reboot-idrac-if-needed)
        - [Task 09 - Deploy Azure Local from Azure Portal](#task-09---deploy-azure-local-from-azure-portal)

<!-- /TOC -->

## About the lab

In this lab you will deploy 2 node Azure Local cluster using [cloud deployment](https://learn.microsoft.com/en-us/azure-stack/hci/whats-new#cloud-based-deployment).

You can also deploy physical machines with [MDT](../../admin-guides/03-DeployPhysicalServersWithMSLab/readme.md). In this guide you will also see notes for physical environment.

You can deploy physical machines with simple click-next-next from ISO. Make sure correct OS disk is selected and if DHCP is not available, configure an IP address and rename computers.

[Latest ISO](https://aka.ms/HCIReleaseImage) contains web interface to register servers to Azure. It also contains all Az PowerShell modules, so it's not necessary to upload it into nodes.
[Older ISO](https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/25398.469.231004-1141.zn_release_svc_refresh_SERVERAZURESTACKHCICOR_OEMRET_x64FRE_en-us.iso) does not contain webUI and PowerShell modules.

You can register servers using PowerShell or using WebUI. WebUI process simplifies the deployment a bit, but several steps are still needed. The OS will automatically use SN of the server and will use it as a hostname. If you are on the same network, you can simply navigate to https://`<device-serial-number>`.local (it uses local discovery).

### Prerequisites

* Hydrated MSLab with LabConfig from [01-HydrateMSLab](../../admin-guides/01-HydrateMSLab/readme.md)

* Understand [how MSLab works](../../admin-guides/02-WorkingWithMSLab/readme.md)

* Make sure you hydrate latest [Azure Local 23H2 Image](https://aka.ms/HCIReleaseImage) using CreateParentDisk.ps1 located in ParentDisks folder as it contains [WebUI onboarding](https://learn.microsoft.com/en-us/azure-stack/hci/deploy/deployment-arc-register-local-ui)

* Note: this lab uses ~60GB RAM. To reduce amount of RAM, you would need to reduce number of nodes.

### LabConfig

```PowerShell
$LabConfig=@{AllowedVLANs="1-10,711-719" ; DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; DCEdition='4'; Internet=$true; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#Azure Local 23H2
#labconfig will not domain join VMs
1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "ALNode$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI23H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 1TB ; MemoryStartupBytes= 24GB; VMProcessorCount="MAX" ; vTPM=$true ; Unattend="NoDjoin" ; NestedVirt=$true }}

#Windows Admin Center in GW mode
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2025Core_G2.vhdx'; MGMTNICs=1}

#Management machine (windows server 2025)
$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2025_G2.vhdx'; MGMTNICs=1 ; AddToolsVHD=$True }
 
```

result: 

![](./media/powershell01.png)

![](./media/hvmanager01.png)


### NTP Prerequisite (Virtual Lab)

To successfully configure NTP server it's necessary to disable time synchronization from Hyper-V host.

Run following code **from hyper-v host** to disable time sync

```PowerShell
Get-VM *ALNode* | Disable-VMIntegrationService -Name "Time Synchronization"

```

### Example Initial Config (AX Nodes) - Example, needs to be modified

If you receive servers from factory and you don't have DHCP, by default there's no Password set. Just log in, and configure password. Next thing is to configure Server Name, and IP config (+VLAN if needed)

Here is code example that you can use if you provision multiple servers, so you can just populate pscustomobject and have one universal script.

```PowerShell
$Servers=@()
$Servers+=[PSCustomObject]@{SerialNumber="asdfgh" ; ComputerName="Node1" ; NICName="Integrated NIC 1 Port 1-1" ;  IPAddress= "10.0.0.101" <# ; VLANID=101 #> }
$Servers+=[PSCustomObject]@{SerialNumber="qwerty" ; ComputerName="Node2" ; NICName="Integrated NIC 1 Port 1-1" ;  IPAddress= "10.0.0.102" <# ; VLANID=101 #> }
$DefaultGateway="10.0.0.1"
$DNSServerAddresses=("10.0.0.1","10.0.0.2")

$Serialnumber=(Get-CimInstance -ClassName win32_bios).SerialNumber
#lookup server in PSCustomObject
$Server=($Servers | Where-Object Serialnumber -EQ $Serialnumber)

Rename-Computer -NewName $Server.ComputerName
New-NetIPAddress -InterfaceAlias $Server.NICName -IPAddress $Server.IPAddress -PrefixLength 24 -DefaultGateway $DefaultGateway -Confirm:$false
Set-DnsClientServerAddress -InterfaceAlias $Server.NICName  -ServerAddresses $DNSServerAddresses
if ($Server.VLANID){
    Set-NetAdapter -VlanID $Server.VLANID -InterfaceAlias $Server.NicName
    #note: you should also configure VLAN for second NIC in Management intent (as it's checked in prerequisites - technically not needed, but still checked as for now (02/2025))
}
Restart-Computer
 
```

## The Lab

**Run all commands from Management machine**

![](./media/hvconnect01.png)

### Task01 - Validate connectivity to servers

#### Step 1 Test name resolution works with simple ping

> If name resolution does not work, simply add IPs to hosts file  you can even use [Host File Editor](https://learn.microsoft.com/en-us/windows/powertoys/hosts-file-editor)

![](./media/powershell02.png)

Notice, that host is replying. Latest image Azure Local already allows ICMP packets. Important is, that name resolution works

#### Step 2 Check WinRM connectivity

```PowerShell
Test-NetConnection -ComputerName "ALNode1","ALNode2" -CommonTCPPort WINRM

```

![](./media/powershell03.png)

> If WINRM fails and if your management is in different subnet, Windows Firewall is by default configured to accept connections on local subnet only

![](./media/powershell04.png)

> you can modify it by running following code on every node (any, or just some IP address/range)

```Powershell
Get-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress Any
 
```

#### Step 3 Connect to servers using WinRM

```PowerShell
$Servers="ALNode1","ALNode2"
$UserName="Administrator"
$Password="LS1setup!"
$SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
$Credentials= New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

#configure trusted hosts to be able to communicate with servers
$TrustedHosts=@()
$TrustedHosts+=$Servers
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($TrustedHosts -join ',') -Force

#Send some command to servers
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-NetAdapter
} -Credential $Credentials

```

![](./media/powershell05.png)

### Task02 - Install features & drivers 

If you receive servers from factory, drivers are already installed, you can completely skip this task

#### Step 1 Install server features - skip if you use latest media

Features are optional as features are already present in latest ISO.

```PowerShell
#install hyper-v and Failover-Clustering feature (this is useful if you use older ISO)
#failover clustering will enable firewall rules such as icmp, computer management, event log management... 

Invoke-Command -ComputerName $servers -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
    Install-WindowsFeature -Name Failover-Clustering
} -Credential $Credentials

```

#### Step 2 Install Network Drivers - AXnodes - fresh install only

```PowerShell
#you can lookup latest driver in https://dell.github.io/azurestack-docs/docs/hci/supportmatrix/

    #region check version first
        $NICs=Invoke-Command -ComputerName $Servers -Credential $Credentials -ScriptBlock {get-NetAdapter}
        $NICs | Where-Object {$_.InterfaceDescription -like "Intel*" -or $_.InterfaceDescription -Like "Mellanox*"} | Select-Object Driver*
    #endregion

    #region check if NICs are Intel or Mellanox
        $NICs=Invoke-Command -ComputerName $servers -ScriptBlock {
            Get-NetAdapter
        } -Credential $Credentials
        If ($NICs | Where InterfaceDescription -like "Mellanox*" ){
            #nvidia/mellanox
            $URL="https://dl.dell.com/FOLDER11591518M/2/Network_Driver_G6M58_WN64_24.04.03_01.EXE"
        }else{
            #intel
            $URL="https://dl.dell.com/FOLDER11890492M/1/Network_Driver_6JHVK_WN64_23.0.0_A00.EXE"
        }
    #endregion

    #region download
        #Set up web client to download files with authenticated web request in case there's a proxy
        $WebClient = New-Object System.Net.WebClient
        #$proxy = new-object System.Net.WebProxy
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #$proxy.Address = $proxyAdr
        #$proxy.useDefaultCredentials = $true
        $WebClient.proxy = $proxy
        #add headers wihth user-agent as some versions of SBE requires it for download
        $webclient.Headers.Add("User-Agent", "WhateverUser-AgentString/1.0")
        $FileName=$($URL.Split("/")| Select-Object -Last 1)
        $WebClient.DownloadFile($URL,"$env:userprofile\Downloads\$FileName")
    #endregion

    #region copy driver to nodes and install
        $sessions = New-PSSession -ComputerName $Servers -Credential $Credentials
        foreach ($Session in $Sessions){
            Copy-Item -Path $env:userprofile\Downloads\$FileName -Destination c:\users\$UserName\Downloads\$FileName -ToSession $session
        }
        
        #install
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Start-Process -FilePath c:\users\$Using:UserName\Downloads\$using:FileName -ArgumentList "/i /s" -Wait
        } -Credential $Credentials
    #endregion

    #region check version again
        $NICs=Invoke-Command -ComputerName $Servers -Credential $Credentials -ScriptBlock {get-NetAdapter}
        $NICs | Where-Object {$_.InterfaceDescription -like "Intel*" -or $_.InterfaceDescription -Like "Mellanox*"} | Select-Object Driver*
    #endregion

```

Before

![](./media/powershell16.png)

After

![](./media/powershell17.png)


#### Step 3 Install Dell Drivers - Optional - AX Nodes

Following example installs all drivers and in case you have newer drivers, it will downgrade. You can simply modify the code to just scan for compliance and display status. This will also make your life easier if for some reason you updated to newer drivers than SBE. SBE would fail as firmware extension can't downgrade.

```PowerShell
#region Dell AX Nodes
    #region update servers with latest hardware updates
        $DSUDownloadFolder="$env:USERPROFILE\Downloads\DSU"

        #Set up web client to download files with authenticated web request
        $WebClient = New-Object System.Net.WebClient
        #$proxy = new-object System.Net.WebProxy
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #$proxy.Address = $proxyAdr
        #$proxy.useDefaultCredentials = $true
        $WebClient.proxy = $proxy

        #Download DSU
        #https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1
        #download latest DSU to Downloads
            $LatestDSU="https://dl.dell.com/FOLDER10889507M/1/Systems-Management_Application_RPW7K_WN64_2.0.2.3_A00.EXE"
            if (-not (Test-Path $DSUDownloadFolder -ErrorAction Ignore)){New-Item -Path $DSUDownloadFolder -ItemType Directory}
            #Start-BitsTransfer -Source $LatestDSU -Destination $DSUDownloadFolder\DSU.exe
            $WebClient.DownloadFile($LatestDSU,"$DSUDownloadFolder\DSU.exe")

        #Download catalog and unpack
            #Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$DSUDownloadFolder\ASHCI-Catalog.xml.gz"
            $WebClient.DownloadFile("https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz","$DSUDownloadFolder\ASHCI-Catalog.xml.gz")     

            #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
            Function Expand-GZipArchive{
                Param(
                    $infile,
                    $outfile = ($infile -replace '\.gz$','')
                    )
                $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
                $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
                $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
                $buffer = New-Object byte[](1024)
                while($true){
                    $read = $gzipstream.Read($buffer, 0, 1024)
                    if ($read -le 0){break}
                    $output.Write($buffer, 0, $read)
                    }
                $gzipStream.Close()
                $output.Close()
                $input.Close()
            }
            Expand-GZipArchive "$DSUDownloadFolder\ASHCI-Catalog.xml.gz" "$DSUDownloadFolder\ASHCI-Catalog.xml"

        #upload DSU and catalog to servers
        $Sessions=New-PSSession -ComputerName $Servers -Credential $Credentials
        Invoke-Command -Session $Sessions -ScriptBlock {
            if (-not (Test-Path $using:DSUDownloadFolder -ErrorAction Ignore)){New-Item -Path $using:DSUDownloadFolder -ItemType Directory}
        }
        foreach ($Session in $Sessions){
            Copy-Item -Path "$DSUDownloadFolder\DSU.exe" -Destination "$DSUDownloadFolder" -ToSession $Session -Force -Recurse
            Copy-Item -Path "$DSUDownloadFolder\ASHCI-Catalog.xml" -Destination "$DSUDownloadFolder" -ToSession $Session -Force -Recurse
        }

        #install DSU
        Invoke-Command -Session $Sessions -ScriptBlock {
            Start-Process -FilePath "$using:DSUDownloadFolder\DSU.exe" -ArgumentList "/silent" -Wait 
        }

        #Check compliance
        Invoke-Command -Session $Sessions -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --output-format="json" --output="$using:DSUDownloadFolder\Compliance.json" --catalog-location="$using:DSUDownloadFolder\ASHCI-Catalog.xml"
        }

        #collect results
        $Compliance=@()
        foreach ($Session in $Sessions){
            $json=Invoke-Command -Session $Session -ScriptBlock {Get-Content "$using:DSUDownloadFolder\Compliance.json"}
            $object = $json | ConvertFrom-Json 
            $components=$object.SystemUpdateCompliance.UpdateableComponent
            $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
            $components | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $Session.ComputerName
            $Compliance+=$Components
        }

        #display results
        $Compliance | Out-GridView

        #Or just choose what updates to install
        #$Compliance=$Compliance | Out-GridView -OutputMode Multiple

        #or Select only NIC drivers/firmware (as the rest will be processed by SBE)
        #$Compliance=$Compliance | Where-Object categoryType -eq "NI"

        #Install Dell updates https://www.dell.com/support/home/en-us/product-support/product/system-update/docs
        Invoke-Command -Session $Sessions -ScriptBlock {
            $Packages=(($using:Compliance | Where-Object {$_.ServerName -eq $env:computername -and $_.compliancestatus -eq $false}))
            if ($Packages){
                $UpdateNames=($packages.PackageFilePath | Split-Path -Leaf) -join ","
                & "C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location="$using:DSUDownloadFolder\ASHCI-Catalog.xml" --update-list="$UpdateNames" --apply-upgrades --apply-downgrades
            }
        }
        $Sessions | Remove-PSSession
#endregion
 
```

![](./media/powershell10.png)

![](./media/powershell11.png)

#### Step 4 Restart servers to apply changes

Needed only if you installed features and all dell drivers (as firmware update requires reboot)

```PowerShell
#region restart servers to apply changes
    Restart-Computer -ComputerName $Servers -Credential $Credentials -WsmanAuthentication Negotiate -Wait -For PowerShell
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
    #make sure computers are restarted
    Foreach ($Server in $Servers){
        do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
    }
#endregion

```


#### Step 5 Rename Network adapters - Optional

Since new ISO is renaming adapters to simply Port 0, Port1, ... it might be useful to revert back to original names that describe physical position

```PowerShell
Invoke-Command -ComputerName $Servers -ScriptBlock {
    $AdaptersHWInfo=Get-NetAdapterHardwareInfo
    foreach ($Adapter in $AdaptersHWInfo){
        #PCIe NICs do not have PCIDeviceLabelString
        if ($adapter.Slot){
            $NewName="Slot $($Adapter.Slot) Port $($Adapter.Function +1)"
        #then the remaining NICs should have PCIDeviceLabelString
        }elseif ($adapter.PCIDeviceLabelString){
            $NewName=$adapter.PCIDeviceLabelString
        }else{
        #just in case there is not any nic with conditions above.
            $NewName="NIC$($Adapter.Function +1)"
        }
        $adapter | Rename-NetAdapter -NewName $NewName
    }
} -Credential $Credentials
 
```

Before

![](./media/powershell18.png)

After

![](./media/powershell19.png)

### Task03 - Validate environment using Environment Checker tool

* about: https://learn.microsoft.com/en-in/azure/azure-local/manage/use-environment-checker?tabs=connectivity

Since we already have credentials and TrustedHosts configured in Powershell from Task01, we can run the following code

> for some reason I was not able to run it using sessions as it complained about not being able to create PSDrive

```PowerShell
#install modules
Invoke-Command -ComputerName $Servers -Scriptblock {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module PowerShellGet -AllowClobber -Force
    Install-Module -Name AzStackHci.EnvironmentChecker -Force
} -Credential $Credentials
#validate environment
$result=Invoke-Command -ComputerName $Servers -Scriptblock {
    Invoke-AzStackHciConnectivityValidation -PassThru
} -Credential $Credentials
$result | Out-GridView

```

![](./media/powershell06.png)

You can select just failed URLs with this PowerShell

```PowerShell
($result | Where-Object Status -eq Failure).TargetResourceName | Select-Object -Unique
 
```

### Task04 - Create Azure Resources

Following script will simply create Resource Group and ARC Gateway (optional).

```PowerShell
$GatewayName="ALClus01-ArcGW"
$ResourceGroupName="ALClus01-RG"
$Location="eastus"

#login to azure
    #download Azure module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force 
    }
    #login using device authentication
    Connect-AzAccount -UseDeviceAuthentication

    #assuming new az.accounts module was used and it asked you what subscription to use - then correct subscription is selected for context
    $Subscription=(Get-AzContext).Subscription

    #install az resources module
        if (!(Get-InstalledModule -Name az.resources -ErrorAction Ignore)){
            Install-Module -Name az.resources -Force
        }

    #create resource group
        if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $location
        }
#region (Optional) configure ARC Gateway
<#
    #install az.arcgateway module
        if (!(Get-InstalledModule -Name az.arcgateway -ErrorAction Ignore)){
            Install-Module -Name az.arcgateway -Force
        }
    #make sure "Microsoft.HybridCompute" is registered (and possibly other RPs)
        Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridCompute"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridConnectivity"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.AzureStackHCI"

    #create GW
    if (Get-AzArcGateway -Name $gatewayname -ResourceGroupName $ResourceGroupName -ErrorAction Ignore){
        $ArcGWInfo=Get-AzArcGateway -Name $gatewayname -ResourceGroupName $ResourceGroupName
    }else{
        $ArcGWInfo=New-AzArcGateway -Name $GatewayName -ResourceGroupName $ResourceGroupName -Location $Location -SubscriptionID $Subscription.ID
    }
#>
#endregion

#generate variables for use in this window
$SubscriptionID=$Subscription.ID
$Region=$Location
$TenantID=$Subscription.TenantID
$ArcGatewayID=$ArcGWInfo.ID

#output variables (so you can just copy it and have powershell code to create variables in another session or you can copy it to WebUI deployment)
Write-Host -ForegroundColor Cyan @"
    #Variables to copy
    `$SubscriptionID=`"$($Subscription.ID)`"
    `$ResourceGroupName=`"$ResourceGroupName`"
    `$Region=`"$Location`"
    `$TenantID=`"$($subscription.tenantID)`"
    `$ArcGatewayID=`"$(($ArcGWInfo).ID)`"
"@ 
```

![](./media/powershell07.png)

![](./media/edge01.png)


### Task05 - Create AD Prerequisites

Simply run the following PowerShell script to create objects

> LCM = LifeCycle Management account. Account that will be used to domain join machines and create CAU account.

```PowerShell
$AsHCIOUName="OU=ALClus01,DC=Corp,DC=contoso,DC=com"
$LCMUserName="ALClus01-LCMUser"
$LCMPassword="LS1setup!LS1setup!"
#Create LCM credentials
$SecuredPassword = ConvertTo-SecureString $LCMPassword -AsPlainText -Force
$LCMCredentials= New-Object System.Management.Automation.PSCredential ($LCMUserName,$SecuredPassword)

#create objects in Active Directory
    #install posh module for prestaging Active Directory
    Install-PackageProvider -Name NuGet -Force
    Install-Module AsHciADArtifactsPreCreationTool -Repository PSGallery -Force

    #make sure active directory module and GPMC is installed
    Install-WindowsFeature -Name RSAT-AD-PowerShell,GPMC

    #populate objects
    New-HciAdObjectsPreCreation -AzureStackLCMUserCredential $LCMCredentials -AsHciOUName $AsHCIOUName

    #to check OU (and future cluster) in GUI install management tools
    Install-WindowsFeature -Name "RSAT-ADDS","RSAT-Clustering"

```

![](./media/powershell08.png)

### Task 06a - Connect nodes to Azure - WebUI

As you now have all variables needed from Task03, you can proceed with navigating to WebUI on each node.

In MSLab you can simply navigate to https://LTPNode1 and https://LTPNode2. In production environment you can either navigate to https://<serialnumber> or simply configure an IP address and navigate there. The webUI takes ~15 minutes to start after booting the servers.

Log in with **Administrator/LS1setup!** and proceed with all three steps to register nodes to Azure.

![](./media/edge02.png)

![](./media/edge03.png)

![](./media/edge04.png)

![](./media/edge05.png)

![](./media/edge06.png)

![](./media/edge08.png)

![](./media/edge09.png)

### Task 06b - Connect nodes to Azure - PowerShell

Assuming you have still variables from Task03, you can continue with following PowerShell

More info: https://learn.microsoft.com/en-us/azure/azure-local/deploy/deployment-arc-register-server-permissions?tabs=powershell

```PowerShell
#region install modules (latest ISO already contains modules, but does not hurt installing it)
    #make sure nuget is installed on nodes
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    } -Credential $Credentials

    #make sure azshci.arcinstaller is installed on nodes
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-Module -Name azshci.arcinstaller -Force
    } -Credential $Credentials

    #make sure Az.Resources module is installed on nodes
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-Module -Name Az.Resources -Force
    } -Credential $Credentials

    #make sure az.accounts module is installed on nodes
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-Module -Name az.accounts -Force
    } -Credential $Credentials

    #make sure az.accounts module is installed on nodes
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-Module -Name Az.ConnectedMachine -Force
    } -Credential $Credentials
#endregion

#region or copy downloaded modules to nodes if above does not work
<#
    #download powershell modules
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $Modules="azshci.arcinstaller","Az.Resources","az.accounts","Az.ConnectedMachine"

    #create folder for modules
    New-Item -Path $env:USERPROFILE\Downloads\ -Name "modules" -ItemType Directory -ErrorAction Ignore
    foreach ($Module in $Modules){
        Save-Module -Name $Module -Path $env:USERPROFILE\Downloads\Modules
    }

    #copy modules to servers
        #create sessions
        $Sessions=New-PSSession -ComputerName $Servers -Credential $Credentials
        #copy
        foreach ($Session in $Sessions){
            Copy-Item -Path $env:USERPROFILE\Downloads\Modules\* -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -ToSession $Session -ErrorAction Ignore
        }

    #remove sessions
    $Sessions | Remove-PSSession
#>
#endregion

#Make sure resource providers are registered
Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridCompute"
Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridConnectivity"
Register-AzResourceProvider -ProviderNamespace "Microsoft.AzureStackHCI"

#deploy ARC Agent (with Arc Gateway, without proxy. For more examples visit https://learn.microsoft.com/en-us/azure/azure-local/deploy/deployment-arc-register-server-permissions?tabs=powershell)
    $ARMtoken = (Get-AzAccessToken).Token
    $id = (Get-AzContext).Account.Id
    $Cloud="AzureCloud"

    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Invoke-AzStackHciArcInitialization -SubscriptionID $using:SubscriptionID -ResourceGroup $using:ResourceGroupName -TenantID $using:TenantID -Cloud $using:Cloud -Region $Using:Location -ArmAccessToken $using:ARMtoken -AccountID $using:id #-ArcGatewayID $using:ArcGatewayID
    } -Credential $Credentials
 
```

![](./media/powershell09.png)

![](./media/edge09.png)


### Task07 - Validation Prerequisites

#### Step 1 Password complexity (in MSLab is password not complex enough)

In MSLab password is not complex enough. You can change password using following script.

```PowerShell
#region and make sure password is complex and long enough (12chars at least)
    $NewPassword="LS1setup!LS1setup!"
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Set-LocalUser -Name Administrator -AccountNeverExpires -Password (ConvertTo-SecureString $Using:NewPassword -AsPlainText -Force)
    } -Credential $Credentials
    #create new credentials
    $UserName="Administrator"
    $SecuredPassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    $Credentials= New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)
#endregion

```

#### Step 2 IP Configuration

In MSLab is DHCP enabled. This script will make sure there's just one GW and DHCP address is converted to Static.

```PowerShell
#region to successfully validate you need make sure there's just one GW
    #make sure there is only one management NIC with IP address (setup is complaining about multiple gateways)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Get-NetIPConfiguration | Where-Object IPV4defaultGateway | Get-NetAdapter | Sort-Object Name | Select-Object -Skip 1 | Set-NetIPInterface -Dhcp Disabled
    } -Credential $Credentials
#endregion

#region Convert DHCP address to Static (since 2411 there's a check for static IP)
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        $InterfaceAlias=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -NotLike "169*" -and $_.PrefixOrigin -eq "DHCP"}).InterfaceAlias
        $IPConf=Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias
        $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $InterfaceAlias
        $IP=$IPAddress.IPAddress
        $Index=$IPAddress.InterfaceIndex
        $GW=$IPConf.IPv4DefaultGateway.NextHop
        $Prefix=$IPAddress.PrefixLength
        $DNSServers=@()
        $ipconf.dnsserver | ForEach-Object {if ($_.addressfamily -eq 2){$DNSServers+=$_.ServerAddresses}}
        Set-NetIPInterface -InterfaceIndex $Index -Dhcp Disabled
        New-NetIPAddress -InterfaceIndex $Index -AddressFamily IPv4 -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $GW -ErrorAction SilentlyContinue
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $DNSServers
    } -Credential $Credentials
#endregion
 
```

#### Step 3 NTP Server (if NTP protocol is blocked by firewall and servers time is not synced)

This script simply tests if offset between management machine and any of the servers is greater than 2s. If so, it will configure NTP server. Just provide your NTP server (you can use domain controller)

```PowerShell
$SyncNeeded=$false
$NTPServer="DC.corp.contoso.com"  

#test if there is an time offset on servers
Foreach ($Server in $Servers){
    $localtime=get-date
    $delay=Measure-Command -Expression {
        $remotetime=Invoke-Command -ComputerName $Server -ScriptBlock {get-date} -Credential $Credentials
    }

    $Offset=$localtime-$remotetime+$Delay
    if ($Offset.Second -gt 2){
        $SyncNeeded=$True
    }
}

#if offset is greater than 2 seconds (I pulled this number out of thin air. I guess it should be less than 5 minutes or so), simply configure NTP servers

If ($SyncNeeded){
    Write-Output "Time offset found, NTP Server needs to be configured."
    #Configure NTP
    Invoke-Command -ComputerName $servers -ScriptBlock {
            w32tm /config /manualpeerlist:$using:NTPServer /syncfromflags:manual /update
            Restart-Service w32time
    } -Credential $Credentials
}

```

### Task08 - Validation Prerequisites - AXNodes

One prerequisite is to install NIC Drivers, but we already covered this in Task02 where servers were updated

#### Step 1 - Populate latest SBE package (AXNodes only)

```PowerShell
    #15G 
    $LatestSBE="https://dl.dell.com/FOLDER12528657M/1/Bundle_SBE_Dell_AX-15G_4.1.2412.1201.zip"
    #or 16G
    #$LatestSBE="https://dl.dell.com/FOLDER12528644M/1/Bundle_SBE_Dell_AX-16G_4.1.2412.1202.zip"

    #region populate SBE package
        #Set up web client to download files with authenticated web request in case there's a proxy
        $WebClient = New-Object System.Net.WebClient
        #$proxy = new-object System.Net.WebProxy
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #$proxy.Address = $proxyAdr
        #$proxy.useDefaultCredentials = $true
        $WebClient.proxy = $proxy
        #add headers wihth user-agent as some versions of SBE requires it for download
        $webclient.Headers.Add("User-Agent", "WhateverUser-AgentString/1.0")

        #Download SBE
            $FileName=$($LatestSBE.Split("/")| Select-Object -Last 1)
            $WebClient.DownloadFile($LatestSBE,"$env:userprofile\Downloads\$FileName")

            #Transfer to servers
            $Sessions=New-PSSession -ComputerName $Servers -Credential $Credentials
            foreach ($Session in $Sessions){
                Copy-Item -Path $env:userprofile\Downloads\$FileName -Destination c:\users\$UserName\Downloads\ -ToSession $Session
            }

        Invoke-Command -ComputerName $Servers -scriptblock {
            #unzip to c:\SBE
            New-Item -Path c:\ -Name SBE -ItemType Directory -ErrorAction Ignore
            Expand-Archive -LiteralPath $env:userprofile\Downloads\$using:FileName -DestinationPath C:\SBE -Force
        } -Credential $Credentials

        #populate latest metadata file
            #download
            Invoke-WebRequest -Uri https://aka.ms/AzureStackSBEUpdate/DellEMC -OutFile $env:userprofile\Downloads\SBE_Discovery_Dell.xml
            #copy to servers
            foreach ($Session in $Session){
                Copy-Item -Path $env:userprofile\Downloads\SBE_Discovery_Dell.xml -Destination C:\SBE -ToSession $Session
            }

        $Sessions | Remove-PSSession
    #endregion
```

#### Step 2 - Exclude iDRAC adapters from cluster networks

```PowerShell
#region exclude iDRAC adapters from cluster networks (as validation was failing in latest versions)
    Invoke-Command -computername $Servers -scriptblock {
        New-Item -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -ErrorAction Ignore
        New-ItemProperty -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Name ExcludeAdaptersByDescription -Value "Remote NDIS Compatible Device" -ErrorAction Ignore
        #Get-ItemProperty -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Name ExcludeAdaptersByDescription | Format-List ExcludeAdaptersByDescription
    } -Credential $Credentials
#endregion
```

#### Step 3 - Clear data disks

In case disks were used before, it might be useful to wipe it.

```PowerShell
#region clean disks (if the servers are repurposed)
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        $disks=Get-Disk | Where-Object IsBoot -eq $false
        $disks | Set-Disk -IsReadOnly $false
        $disks | Set-Disk -IsOffline $false
        $disks | Clear-Disk -RemoveData -RemoveOEM -Confirm:0
        $disks | get-disk | Set-Disk -IsOffline $true
    } -Credential $Credentials
#endregion

```

#### Step 4 - Reboot iDRAC if needed

Check if there is leftover in USB. This is be caused by DSU updating iDRAC, and might leave "leftover" attached to virtual USB.

```PowerShell
#check if there are any SECUPD devices attached
Invoke-Command -ComputerName $Servers -ScriptBlock {get-disk | Where-Object FriendlyName -eq "Linux SECUPD"} -Credential $Credentials | Select-Object FriendlyName,Path,PSComputerName

```

![](./media/powershell14.png)

if so, reboot iDRAC from webUI as it would interrupt deployment process as it would find attached USB media.

![](./media/edge10.png)

### Task 09 - Deploy Azure Local from Azure Portal

Use values below for virtual cluster

```
Basics:
    Resource Group: ALClus01-RG
    ClusterName:    ALClus01
    Keyvaultname:   <Just generate new>

Configuration:
    New Configuration

Networking
    Network Switch for storage
    Group All traffic

    Network adapter 1:          Ethernet
    Network adapter 1 VLAN ID:  711 (default)
    Network adapter 2:          Ethernet 2
    Network adapter 2 VLAN ID:  712 (default)

    RDMA Protocol:              Disabled (in case you are running lab in VMs)
    Jumbo Frames:               1514 (in case you are running lab in VMs as hyper-v does not by default support Jumbo Frames)

    Starting IP:                10.0.0.111
    ENding IP:                  10.0.0.116
    Subnet mask:                255.255.255.0
    Default Gateway:            10.0.0.1
    DNS Server:                 10.0.0.1

Management
    Custom location name:       ALClus01CustomLocation (default)\
    Azure storage account name: <just generate new>

    Domain:                     corp.contoso.com
    Computer name prefix:       ALClus01
    OU:                         OU=ALClus01,DC=Corp,DC=contoso,DC=com

    Deployment account:
        Username:               ALClus01-LCMUser
        Password:               LS1setup!LS1setup!

    Local Administrator
        Username:               Administrator
    Password:                   LS1setup!LS1setup!

Security:
    Customized security settings
        Unselect Bitlocker for data volumes (would consume too much space)

Advanced:
    Create workload volumes (Default)

Tags:
    <keep default>
```

