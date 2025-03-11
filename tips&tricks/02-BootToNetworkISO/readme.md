# Boot to network ISO

<!-- TOC -->

- [Boot to network ISO](#boot-to-network-iso)
    - [Modify MDT ISO File](#modify-mdt-iso-file)
    - [Let iDRAC boot from the modified ISO](#let-idrac-boot-from-the-modified-iso)

<!-- /TOC -->

iDrac has interesting function, where you can boot from ISO from a file share with a single command [BootToNetworkISO](https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v3.3-series/idrac9_3.36_redfishapiguide/supported-action-%E2%80%94-boottonetworkiso?guid=guid-03f535e6-476e-473d-b7bb-ebc924538cf0&lang=en-us). This allows scenario like deploying OS using MDT without PXE.




## Modify MDT ISO File

You need to install Microsoft ADK first, to have OSCDIMG tool available

```
    #install ADK
    Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
 
```

Following script assumes you want to modify LiteTouchPE_x64.iso located on MDT server and will create new one LiteTouchPE_x64_Fixed.iso

```PowerShell
    $MDTServer="MDT"

    $oscdimg = Get-ChildItem -Path "c:\" -Filter "OSCDIMG.EXE" -Recurse -ErrorAction SilentlyContinue -Force | % { $_.FullName } | Select-String -Pattern "amd64" 
    $oscdimgfolder = Split-Path $oscdimg -Parent 
    $etfsboot = "$oscdimgfolder\etfsboot.com" 
    $efisys = "$oscdimgfolder\efisys_noprompt.bin"
    $workfolder="c:\temp\iso\"

    # Mount ISO 
    $ISO = "\\$MDTServer\DeploymentShare$\Boot\LiteTouchPE_x64.iso"
    $image=Mount-DiskImage -ImagePath $ISO -StorageType ISO -Passthru -Verbose
    $DriveLetter=($image | Get-Volume).DriveLetter

    #copy files to c:\temp\iso
    New-Item -Path $workfolder -ItemType Directory -ErrorAction Ignore
    Copy-Item -Path "$($DriveLetter):\*" -Destination $workfolder -Recurse

    # Unmount ISO 
    Dismount-DiskImage -ImagePath $ISO -Verbose 

    # Remove read-only attributes 
    Get-ChildItem $workfolder -Recurse | %{ if (! $_.psiscontainer) { $_.isreadonly = $false}} 

    #repack ISO and upload back to MDT under new name
    $bootdata = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f $etfsboot, $efisys
    Start-Process $oscdimg -args @("-bootdata:$bootdata",'-m', '-o', '-u2','-udfver102', $workfolder, "\\$MDTServer\DeploymentShare$\Boot\LiteTouchPE_x64_Fixed.iso") -wait -nonewwindow

```

## Let iDRAC boot from the modified ISO

Note: following command will immediately reboot the server into the ISO image.

```PowerShell
#region boot from ISO (service partition)
    $iDracUsername="LabAdmin"
    $iDracPassword="LS1setup!"
    $SecureStringPassword = ConvertTo-SecureString $iDracPassword -AsPlainText -Force
    $iDRACCredentials = New-Object System.Management.Automation.PSCredential ($iDracUsername, $SecureStringPassword)
        
    #share properties
    $UserName="MDTUser@corp.contoso.com"
    $Password="LS1setup!"
    $ImageName="LiteTouchPE_x64_Fixed.iso"
    #assuming ip Address is reachable from iDRAC!
    $IPAddress=(Resolve-DnsName -Name $MDTServer).IPAddress #as iDRAC usually does not have DNS Server configured
    $ShareName="DeploymentShare$/Boot"
    $Sharetype="CIFS"
    $ExposeDuration = "0000-00-00T01:30:00+00:00" #1.5hours

    #hyper-v hosts
    $HVHosts = @()
    $HVHosts+=@{ComputerName="AXNode3" ; idracIP="192.168.x.y"}
    $HVHosts+=@{ComputerName="AXNode4" ; idracIP="192.168.x.z"}

   #ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck to Invoke-WebRequest
    function Ignore-SSLCertificates {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $False
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $False
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
    Ignore-SSLCertificates

    #boot from virtual media
    #more info: https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v3.3-series/idrac9_3.36_redfishapiguide/supported-action-%E2%80%94-boottonetworkiso?guid=guid-03f535e6-476e-473d-b7bb-ebc924538cf0&lang=en-us

    $Headers=@{"Accept"="application/json"}
    $ContentType='application/json'
    foreach ($HVHost in $HVHosts){
        $JSONBody=@{"UserName"=$UserName;"Password"=$Password;"IPAddress"=$IPAddress;"ImageName"=$ImageName;"ShareName"=$ShareName;"ShareType"=$ShareType;"ExposeDuration"=$ExposeDuration} | ConvertTo-Json -Compress
        $uri = "https://$($HVHost.idracIP)/redfish/v1/Dell/Systems/System.Embedded.1/DellOSDeploymentService/Actions/DellOSDeploymentService.BootToNetworkISO"
        $result=Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
        $result
    }

    #remove ISO if needed
    <#
    #detach ISO
    foreach ($HVHost in $HVHosts){
        $JsonBody = @{} | ConvertTo-Json -Compress
        $uri = "https://$($HVHost.idracIP)/redfish/v1/Dell/Systems/System.Embedded.1/DellOSDeploymentService/Actions/DellOSDeploymentService.DetachISOImage"
        Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
    }
    #>
```