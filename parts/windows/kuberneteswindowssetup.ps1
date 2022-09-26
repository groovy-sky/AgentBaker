<#
    .SYNOPSIS
        Provisions VM as a Kubernetes agent.

    .DESCRIPTION
        Provisions VM as a Kubernetes agent.

        The parameters passed in are required, and will vary per-deployment.

        Notes on modifying this file:
        - This file extension is PS1, but it is actually used as a template from pkg/engine/template_generator.go
        - All of the lines that have braces in them will be modified. Please do not change them here, change them in the Go sources
        - Single quotes are forbidden, they are reserved to delineate the different members for the ARM template concat() call
        - windowscsehelper.ps1 contains basic util functions. It will be compressed to a zip file and then be converted to base64 encoding
          string and stored in $zippedFiles. Reason: This script is a template and has some limitations.
        - All other scripts will be packaged and published in a single package. It will be downloaded in provisioning VM.
          Reason: CustomData has length limitation 87380.
        - ProvisioningScriptsPackage contains scripts to start kubelet, kubeproxy, etc. The source is https://github.com/Azure/aks-engine/tree/master/staging/provisioning/windows
#>
[CmdletBinding(DefaultParameterSetName="Standard")]
param(
    [string]
    [ValidateNotNullOrEmpty()]
    $MasterIP,

    [parameter()]
    [ValidateNotNullOrEmpty()]
    $KubeDnsServiceIp,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $MasterFQDNPrefix,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $Location,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $AgentKey,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $AADClientId,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $AADClientSecret, # base64

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $NetworkAPIVersion,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $TargetEnvironment,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $LogFile,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $CSEResultFilePath,

    [string]
    $UserAssignedClientID
)
# Do not parse the start time from $LogFile to simplify the logic
$StartTime=Get-Date
$global:ExitCode=0
$global:ErrorMessage=""

# These globals will not change between nodes in the same cluster, so they are not
# passed as powershell parameters

## SSH public keys to add to authorized_keys
$global:SSHKeys = @( {{ GetSshPublicKeysPowerShell }} )

## Certificates generated by aks-engine
$global:CACertificate = "{{GetParameter "caCertificate"}}"
$global:AgentCertificate = "{{GetParameter "clientCertificate"}}"

## Download sources provided by aks-engine
$global:KubeBinariesPackageSASURL = "{{GetParameter "kubeBinariesSASURL"}}"
$global:WindowsKubeBinariesURL = "{{GetParameter "windowsKubeBinariesURL"}}"
$global:KubeBinariesVersion = "{{GetParameter "kubeBinariesVersion"}}"
$global:ContainerdUrl = "{{GetParameter "windowsContainerdURL"}}"
$global:ContainerdSdnPluginUrl = "{{GetParameter "windowsSdnPluginURL"}}"

## Docker Version
$global:DockerVersion = "{{GetParameter "windowsDockerVersion"}}"

## ContainerD Usage
$global:ContainerRuntime = "{{GetParameter "containerRuntime"}}"
$global:DefaultContainerdWindowsSandboxIsolation = "{{GetParameter "defaultContainerdWindowsSandboxIsolation"}}"
$global:ContainerdWindowsRuntimeHandlers = "{{GetParameter "containerdWindowsRuntimeHandlers"}}"

## VM configuration passed by Azure
$global:WindowsTelemetryGUID = "{{GetParameter "windowsTelemetryGUID"}}"
{{if eq GetIdentitySystem "adfs"}}
$global:TenantId = "adfs"
{{else}}
$global:TenantId = "{{GetVariable "tenantID"}}"
{{end}}
$global:SubscriptionId = "{{GetVariable "subscriptionId"}}"
$global:ResourceGroup = "{{GetVariable "resourceGroup"}}"
$global:VmType = "{{GetVariable "vmType"}}"
$global:SubnetName = "{{GetVariable "subnetName"}}"
# NOTE: MasterSubnet is still referenced by `kubeletstart.ps1` and `windowsnodereset.ps1`
# for case of Kubenet
$global:MasterSubnet = ""
$global:SecurityGroupName = "{{GetVariable "nsgName"}}"
$global:VNetName = "{{GetVariable "virtualNetworkName"}}"
$global:RouteTableName = "{{GetVariable "routeTableName"}}"
$global:PrimaryAvailabilitySetName = "{{GetVariable "primaryAvailabilitySetName"}}"
$global:PrimaryScaleSetName = "{{GetVariable "primaryScaleSetName"}}"

$global:KubeClusterCIDR = "{{GetParameter "kubeClusterCidr"}}"
$global:KubeServiceCIDR = "{{GetParameter "kubeServiceCidr"}}"
$global:VNetCIDR = "{{GetParameter "vnetCidr"}}"
{{if IsKubernetesVersionGe "1.16.0"}}
$global:KubeletNodeLabels = "{{GetAgentKubernetesLabels . }}"
{{else}}
$global:KubeletNodeLabels = "{{GetAgentKubernetesLabelsDeprecated . }}"
{{end}}
$global:KubeletConfigArgs = @( {{GetKubeletConfigKeyValsPsh}} )
$global:KubeproxyConfigArgs = @( {{GetKubeproxyConfigKeyValsPsh}} )

$global:KubeproxyFeatureGates = @( {{GetKubeProxyFeatureGatesPsh}} )

$global:UseManagedIdentityExtension = "{{GetVariable "useManagedIdentityExtension"}}"
$global:UseInstanceMetadata = "{{GetVariable "useInstanceMetadata"}}"

$global:LoadBalancerSku = "{{GetVariable "loadBalancerSku"}}"
$global:ExcludeMasterFromStandardLB = "{{GetVariable "excludeMasterFromStandardLB"}}"


# Windows defaults, not changed by aks-engine
$global:CacheDir = "c:\akse-cache"
$global:KubeDir = "c:\k"
$global:HNSModule = [Io.path]::Combine("$global:KubeDir", "hns.psm1")

$global:KubeDnsSearchPath = "svc.cluster.local"

$global:CNIPath = [Io.path]::Combine("$global:KubeDir", "cni")
$global:NetworkMode = "L2Bridge"
$global:CNIConfig = [Io.path]::Combine($global:CNIPath, "config", "`$global:NetworkMode.conf")
$global:CNIConfigPath = [Io.path]::Combine("$global:CNIPath", "config")


$global:AzureCNIDir = [Io.path]::Combine("$global:KubeDir", "azurecni")
$global:AzureCNIBinDir = [Io.path]::Combine("$global:AzureCNIDir", "bin")
$global:AzureCNIConfDir = [Io.path]::Combine("$global:AzureCNIDir", "netconf")

# Azure cni configuration
# $global:NetworkPolicy = "{{GetParameter "networkPolicy"}}" # BUG: unused
$global:NetworkPlugin = "{{GetParameter "networkPlugin"}}"
$global:VNetCNIPluginsURL = "{{GetParameter "vnetCniWindowsPluginsURL"}}"
$global:IsDualStackEnabled = {{if IsIPv6DualStackFeatureEnabled}}$true{{else}}$false{{end}}

# CSI Proxy settings
$global:EnableCsiProxy = [System.Convert]::ToBoolean("{{GetVariable "windowsEnableCSIProxy" }}");
$global:CsiProxyUrl = "{{GetVariable "windowsCSIProxyURL" }}";

# Hosts Config Agent settings
$global:EnableHostsConfigAgent = [System.Convert]::ToBoolean("{{ EnableHostsConfigAgent }}");

# These scripts are used by cse
$global:CSEScriptsPackageUrl = "{{GetVariable "windowsCSEScriptsPackageURL" }}";

# PauseImage
$global:WindowsPauseImageURL = "{{GetVariable "windowsPauseImageURL" }}";
$global:AlwaysPullWindowsPauseImage = [System.Convert]::ToBoolean("{{GetVariable "alwaysPullWindowsPauseImage" }}");

# Calico
$global:WindowsCalicoPackageURL = "{{GetVariable "windowsCalicoPackageURL" }}";

# GMSA
$global:WindowsGmsaPackageUrl = "{{GetVariable "windowsGmsaPackageUrl" }}";

# TLS Bootstrap Token
$global:TLSBootstrapToken = "{{GetTLSBootstrapTokenForKubeConfig}}"

$global:IsNotRebootWindowsNode = [System.Convert]::ToBoolean("{{GetVariable "isNotRebootWindowsNode" }}");

# Disable OutBoundNAT in Azure CNI configuration
$global:IsDisableWindowsOutboundNat = [System.Convert]::ToBoolean("{{GetVariable "isDisableWindowsOutboundNat" }}");

# Base64 representation of ZIP archive
$zippedFiles = "{{ GetKubernetesWindowsAgentFunctions }}"

$useContainerD = ($global:ContainerRuntime -eq "containerd")
$global:KubeClusterConfigPath = "c:\k\kubeclusterconfig.json"
$fipsEnabled = [System.Convert]::ToBoolean("{{ FIPSEnabled }}")

# HNS remediator
$global:HNSRemediatorIntervalInMinutes = [System.Convert]::ToUInt32("{{GetHnsRemediatorIntervalInMinutes}}");

# Extract cse helper script from ZIP
[io.file]::WriteAllBytes("scripts.zip", [System.Convert]::FromBase64String($zippedFiles))
Expand-Archive scripts.zip -DestinationPath "C:\\AzureData\\"

# Dot-source windowscsehelper.ps1 with functions that are called in this script
. c:\AzureData\windows\windowscsehelper.ps1
# util functions only can be used after this line, for example, Write-Log

try
{
    Write-Log ".\CustomDataSetupScript.ps1 -MasterIP $MasterIP -KubeDnsServiceIp $KubeDnsServiceIp -MasterFQDNPrefix $MasterFQDNPrefix -Location $Location -AADClientId $AADClientId -NetworkAPIVersion $NetworkAPIVersion -TargetEnvironment $TargetEnvironment"

    $WindowsCSEScriptsPackage = "aks-windows-cse-scripts-v0.0.16.zip"
    Write-Log "CSEScriptsPackageUrl is $global:CSEScriptsPackageUrl"
    Write-Log "WindowsCSEScriptsPackage is $WindowsCSEScriptsPackage"
    # Old AKS RP sets the full URL (https://acs-mirror.azureedge.net/aks/windows/cse/aks-windows-cse-scripts-v0.0.11.zip) in CSEScriptsPackageUrl
    # but it is better to set the CSE package version in Windows CSE in AgentBaker
    # since most changes in CSE package also need the change in Windows CSE in AgentBaker
    # In future, AKS RP only sets the endpoint with the pacakge name, for example, https://acs-mirror.azureedge.net/aks/windows/cse/
    if ($global:CSEScriptsPackageUrl.EndsWith("/")) {
        $global:CSEScriptsPackageUrl = $global:CSEScriptsPackageUrl + $WindowsCSEScriptsPackage
        Write-Log "CSEScriptsPackageUrl is set to $global:CSEScriptsPackageUrl"
    }
    # Download CSE function scripts
    Write-Log "Getting CSE scripts"
    $tempfile = 'c:\csescripts.zip'
    DownloadFileOverHttp -Url $global:CSEScriptsPackageUrl -DestinationPath $tempfile -ExitCode $global:WINDOWS_CSE_ERROR_DOWNLOAD_CSE_PACKAGE
    Expand-Archive $tempfile -DestinationPath "C:\\AzureData\\windows"
    Remove-Item -Path $tempfile -Force

    # Dot-source cse scripts with functions that are called in this script
    . c:\AzureData\windows\azurecnifunc.ps1
    . c:\AzureData\windows\calicofunc.ps1
    . c:\AzureData\windows\configfunc.ps1
    . c:\AzureData\windows\containerdfunc.ps1
    . c:\AzureData\windows\kubeletfunc.ps1
    . c:\AzureData\windows\kubernetesfunc.ps1

    # Exit early if the script has been executed
    if (Test-Path -Path $CSEResultFilePath -PathType Leaf) {
        Write-Log "The script has been executed before, will exit without doing anything."
        return
    }
    # Install OpenSSH if SSH enabled
    $sshEnabled = [System.Convert]::ToBoolean("{{ WindowsSSHEnabled }}")

    if ( $sshEnabled ) {
        Write-Log "Install OpenSSH"
        Install-OpenSSH -SSHKeys $SSHKeys
    }

    Write-Log "Apply telemetry data setting"
    Set-TelemetrySetting -WindowsTelemetryGUID $global:WindowsTelemetryGUID

    Write-Log "Resize os drive if possible"
    Resize-OSDrive

    Write-Log "Initialize data disks"
    Initialize-DataDisks

    Write-Log "Create required data directories as needed"
    Initialize-DataDirectories

    Create-Directory -FullPath "c:\k"
    Write-Log "Remove `"NT AUTHORITY\Authenticated Users`" write permissions on files in c:\k"
    icacls.exe "c:\k" /inheritance:r
    icacls.exe "c:\k" /grant:r SYSTEM:`(OI`)`(CI`)`(F`)
    icacls.exe "c:\k" /grant:r BUILTIN\Administrators:`(OI`)`(CI`)`(F`)
    icacls.exe "c:\k" /grant:r BUILTIN\Users:`(OI`)`(CI`)`(RX`)
    Write-Log "c:\k permissions: "
    icacls.exe "c:\k"
    Get-ProvisioningScripts

    Write-KubeClusterConfig -MasterIP $MasterIP -KubeDnsServiceIp $KubeDnsServiceIp

    Write-Log "Download kubelet binaries and unzip"
    Get-KubePackage -KubeBinariesSASURL $global:KubeBinariesPackageSASURL

    # This overwrites the binaries that are downloaded from the custom packge with binaries.
    # The custom package has a few files that are necessary for future steps (nssm.exe)
    # this is a temporary work around to get the binaries until we depreciate
    # custom package and nssm.exe as defined in aks-engine#3851.
    if ($global:WindowsKubeBinariesURL){
        Write-Log "Overwriting kube node binaries from $global:WindowsKubeBinariesURL"
        Get-KubeBinaries -KubeBinariesURL $global:WindowsKubeBinariesURL
    }

    if ($useContainerD) {
        Write-Log "Installing ContainerD"
        $cniBinPath = $global:AzureCNIBinDir
        $cniConfigPath = $global:AzureCNIConfDir
        if ($global:NetworkPlugin -eq "kubenet") {
            $cniBinPath = $global:CNIPath
            $cniConfigPath = $global:CNIConfigPath
        }
        Install-Containerd-Based-On-Kubernetes-Version -ContainerdUrl $global:ContainerdUrl -CNIBinDir $cniBinPath -CNIConfDir $cniConfigPath -KubeDir $global:KubeDir -KubernetesVersion $global:KubeBinariesVersion
    } else {
        Write-Log "Install docker"
        Install-Docker -DockerVersion $global:DockerVersion
        Set-DockerLogFileOptions
    }

    # For AKSClustomCloud, TargetEnvironment must be set to AzureStackCloud
    Write-Log "Write Azure cloud provider config"
    Write-AzureConfig `
        -KubeDir $global:KubeDir `
        -AADClientId $AADClientId `
        -AADClientSecret $([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($AADClientSecret))) `
        -TenantId $global:TenantId `
        -SubscriptionId $global:SubscriptionId `
        -ResourceGroup $global:ResourceGroup `
        -Location $Location `
        -VmType $global:VmType `
        -SubnetName $global:SubnetName `
        -SecurityGroupName $global:SecurityGroupName `
        -VNetName $global:VNetName `
        -RouteTableName $global:RouteTableName `
        -PrimaryAvailabilitySetName $global:PrimaryAvailabilitySetName `
        -PrimaryScaleSetName $global:PrimaryScaleSetName `
        -UseManagedIdentityExtension $global:UseManagedIdentityExtension `
        -UserAssignedClientID $UserAssignedClientID `
        -UseInstanceMetadata $global:UseInstanceMetadata `
        -LoadBalancerSku $global:LoadBalancerSku `
        -ExcludeMasterFromStandardLB $global:ExcludeMasterFromStandardLB `
        -TargetEnvironment {{if IsAKSCustomCloud}}"AzureStackCloud"{{else}}$TargetEnvironment{{end}} 

    # we borrow the logic of AzureStackCloud to achieve AKSCustomCloud. 
    # In case of AKSCustomCloud, customer cloud env will be loaded from azurestackcloud.json 
    {{if IsAKSCustomCloud}}
    $azureStackConfigFile = [io.path]::Combine($global:KubeDir, "azurestackcloud.json")
    $envJSON = "{{ GetBase64EncodedEnvironmentJSON }}"
    [io.file]::WriteAllBytes($azureStackConfigFile, [System.Convert]::FromBase64String($envJSON))

    Get-CACertificates
    {{end}}

    Write-Log "Write ca root"
    Write-CACert -CACertificate $global:CACertificate `
        -KubeDir $global:KubeDir

    if ($global:EnableCsiProxy) {
        New-CsiProxyService -CsiProxyPackageUrl $global:CsiProxyUrl -KubeDir $global:KubeDir
    }

    if ($global:TLSBootstrapToken) {
        Write-Log "Write TLS bootstrap kubeconfig"
        Write-BootstrapKubeConfig -CACertificate $global:CACertificate `
            -KubeDir $global:KubeDir `
            -MasterFQDNPrefix $MasterFQDNPrefix `
            -MasterIP $MasterIP `
            -TLSBootstrapToken $global:TLSBootstrapToken

        # NOTE: we need kubeconfig to setup calico even if TLS bootstrapping is enabled
        #       This kubeconfig will deleted after calico installation.
        # TODO(hbc): once TLS bootstrap is fully enabled, remove this if block
        Write-Log "Write temporary kube config"
    } else {
        Write-Log "Write kube config"
    }

    Write-KubeConfig -CACertificate $global:CACertificate `
        -KubeDir $global:KubeDir `
        -MasterFQDNPrefix $MasterFQDNPrefix `
        -MasterIP $MasterIP `
        -AgentKey $AgentKey `
        -AgentCertificate $global:AgentCertificate

    if ($global:EnableHostsConfigAgent) {
            Write-Log "Starting hosts config agent"
            New-HostsConfigService
        }

    Write-Log "Create the Pause Container kubletwin/pause"
    New-InfraContainer -KubeDir $global:KubeDir -ContainerRuntime $global:ContainerRuntime

    if (-not (Test-ContainerImageExists -Image "kubletwin/pause" -ContainerRuntime $global:ContainerRuntime)) {
        Write-Log "Could not find container with name kubletwin/pause"
        if ($useContainerD) {
            $o = ctr -n k8s.io image list
            Write-Log $o
        } else {
            $o = docker image list
            Write-Log $o
        }
        Set-ExitCode -ExitCode $global:WINDOWS_CSE_ERROR_PAUSE_IMAGE_NOT_EXIST -ErrorMessage "kubletwin/pause container does not exist!"
    }

    Write-Log "Configuring networking with NetworkPlugin:$global:NetworkPlugin"

    # Configure network policy.
    Get-HnsPsm1 -HNSModule $global:HNSModule
    Import-Module $global:HNSModule

    Write-Log "Installing Azure VNet plugins"
    Install-VnetPlugins -AzureCNIConfDir $global:AzureCNIConfDir `
        -AzureCNIBinDir $global:AzureCNIBinDir `
        -VNetCNIPluginsURL $global:VNetCNIPluginsURL

    Set-AzureCNIConfig -AzureCNIConfDir $global:AzureCNIConfDir `
        -KubeDnsSearchPath $global:KubeDnsSearchPath `
        -KubeClusterCIDR $global:KubeClusterCIDR `
        -KubeServiceCIDR $global:KubeServiceCIDR `
        -VNetCIDR $global:VNetCIDR `
        -IsDualStackEnabled $global:IsDualStackEnabled

    if ($TargetEnvironment -ieq "AzureStackCloud") {
        GenerateAzureStackCNIConfig `
            -TenantId $global:TenantId `
            -SubscriptionId $global:SubscriptionId `
            -ResourceGroup $global:ResourceGroup `
            -AADClientId $AADClientId `
            -KubeDir $global:KubeDir `
            -AADClientSecret $([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($AADClientSecret))) `
            -NetworkAPIVersion $NetworkAPIVersion `
            -AzureEnvironmentFilePath $([io.path]::Combine($global:KubeDir, "azurestackcloud.json")) `
            -IdentitySystem "{{ GetIdentitySystem }}"
    }

    New-ExternalHnsNetwork -IsDualStackEnabled $global:IsDualStackEnabled

    Install-KubernetesServices `
        -KubeDir $global:KubeDir `
        -ContainerRuntime $global:ContainerRuntime

    Get-LogCollectionScripts

    Write-Log "Disable Internet Explorer compat mode and set homepage"
    Set-Explorer

    Write-Log "Adjust pagefile size"
    Adjust-PageFileSize

    Write-Log "Start preProvisioning script"
    PREPROVISION_EXTENSION

    Write-Log "Update service failure actions"
    Update-ServiceFailureActions -ContainerRuntime $global:ContainerRuntime
    Adjust-DynamicPortRange
    Register-LogsCleanupScriptTask
    Register-NodeResetScriptTask
    Update-DefenderPreferences


    $windowsVersion = Get-WindowsVersion
    if ($windowsVersion -ne "1809") {
        Write-Log "Skip secure TLS protocols for Windows version: $windowsVersion"
    } else {
        Write-Log "Enable secure TLS protocols"
        try {
            . C:\k\windowssecuretls.ps1
            Enable-SecureTls
        }
        catch {
            Set-ExitCode -ExitCode $global:WINDOWS_CSE_ERROR_ENABLE_SECURE_TLS -ErrorMessage $_
        }
    }

    Enable-FIPSMode -FipsEnabled $fipsEnabled
    if ($global:WindowsGmsaPackageUrl) {
        Write-Log "Start to install Windows gmsa package"
        Install-GmsaPlugin -GmsaPackageUrl $global:WindowsGmsaPackageUrl
    }

    Check-APIServerConnectivity -MasterIP $MasterIP

    if ($global:WindowsCalicoPackageURL) {
        Write-Log "Start calico installation"
        Start-InstallCalico -RootDir "c:\" -KubeServiceCIDR $global:KubeServiceCIDR -KubeDnsServiceIp $KubeDnsServiceIp
    }

    if (Test-Path $CacheDir)
    {
        Write-Log "Removing aks-engine bits cache directory"
        Remove-Item $CacheDir -Recurse -Force
    }

    if ($global:TLSBootstrapToken) {
        Write-Log "Removing temporary kube config"
        $kubeConfigFile = [io.path]::Combine($KubeDir, "config")
        Remove-Item $kubeConfigFile
    }

    if ($global:IsNotRebootWindowsNode) {
        Write-Log "Setup Complete, starting NodeResetScriptTask to register Winodws node without reboot"
        Start-ScheduledTask -TaskName "k8s-restart-job"

        $timeout = 180 ##  seconds
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-ScheduledTask -TaskName 'k8s-restart-job').State -ne 'Ready') {
            # The task `k8s-restart-job` needs ~8 seconds.
            if ($timer.Elapsed.TotalSeconds -gt $timeout) {
                Set-ExitCode -ExitCode $global:WINDOWS_CSE_ERROR_START_NODE_RESET_SCRIPT_TASK -ErrorMessage "NodeResetScriptTask is not finished after [$($timer.Elapsed.TotalSeconds)] seconds"
            }

            Write-Log -Message "Waiting on NodeResetScriptTask..."
            Start-Sleep -Seconds 3
        }
        $timer.Stop()
        Write-Log -Message "We waited [$($timer.Elapsed.TotalSeconds)] seconds on NodeResetScriptTask"
    } else {
        # Postpone restart-computer so we can generate CSE response before restarting computer
        Write-Log "Setup Complete, reboot computer"
        Postpone-RestartComputer
    }
}
catch
{
    # Set-ExitCode will exit with the specified ExitCode immediately and not be caught by this catch block
    # Ideally all exceptions will be handled and no exception will be thrown.
    Set-ExitCode -ExitCode $global:WINDOWS_CSE_ERROR_UNKNOWN -ErrorMessage $_
}
finally
{
    # Generate CSE result so it can be returned as the CSE response in csecmd.ps1
    $ExecutionDuration=$(New-Timespan -Start $StartTime -End $(Get-Date))
    Write-Log "CSE ExecutionDuration: $ExecutionDuration"

    # Windows CSE does not return any error message so we cannot generate below content as the response
    # $JsonString = "ExitCode: `"{0}`", Output: `"{1}`", Error: `"{2}`", ExecDuration: `"{3}`"" -f $global:ExitCode, "", $global:ErrorMessage, $ExecutionDuration.TotalSeconds
    Write-Log "Generate CSE result to $CSEResultFilePath : $global:ExitCode"
    echo $global:ExitCode | Out-File -FilePath $CSEResultFilePath -Encoding utf8
}

