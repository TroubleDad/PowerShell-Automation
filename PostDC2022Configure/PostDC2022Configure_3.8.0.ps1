# =================================================================================================
# Script:        PostDC2022Configure.ps1
# Author:        Mari Eustace, Alan W Phillips
# Date:          05/11/2026
# Version:       3.8.0
#
# Purpose:       Apply standardized post-configuration to a newly promoted
#                Windows Server 2022 Domain Controller.
#
# Description:   Executes a controlled, validated, and optionally simulated set of
#                post-deployment tasks including network configuration, DNS/InfoBlox
#                preparation, and Splunk Universal Forwarder deployment.
#
# Features:      - Internal DryRun execution mode (magenta output)
#                - Unified color-coded output framework
#                - Step execution model with validation + error handling
#                - Self-healing Splunk installation source validation
#                - Transcript-based logging (single source of truth)
#                - FSMO-style state/action output
#
# Change Log:
# 3.8.0 - DryRun semantics + service validation + readability improvements
# =================================================================================================


# ===============================================================
# SECTION: Parameters
# ===============================================================

param (
    [string]$SplunkPath   = 'C:\Temp\Splunk',
    [string]$InfoBloxPath = 'C:\Temp\InfoBlox',
    [string]$LogPath      = 'C:\Temp\PostDC2022Configure.log'
)


# ===============================================================
# SECTION: Global Variables
# ===============================================================

$ErrorActionPreference = 'Stop'
$SplunkInstallerSource = '\\cdshare.uhhs.com\technet\SplunkInstall'


# ===============================================================
# SECTION: Execution Control
# ===============================================================

$DryRun = $false


# ===============================================================
# SECTION: Execution State Tracking
# ===============================================================

$SplunkServiceRunning = $false


# ===============================================================
# SECTION: Logging / Transcript
# ===============================================================

Start-Transcript -Path $LogPath -Append | Out-Null


# ===============================================================
# SECTION: Unified Output Framework
# ===============================================================

function Write-Info     { param ([string]$Message) Write-Host "[INFO ] $Message" -ForegroundColor Cyan }
function Write-Warn     { param ([string]$Message) Write-Host "[WARN ] $Message" -ForegroundColor Yellow }
function Write-ErrorMsg { param ([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-Success  { param ([string]$Message) Write-Host "[ OK  ] $Message" -ForegroundColor Green }

function Write-Log
{
    param ([string]$Message)
}

function Invoke-Step
{
    param (
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Info "Starting: $Name"

    try
    {
        if ($DryRun)
        {
            Write-Host "[SKIP ] $Name (DryRun)" -ForegroundColor Magenta
            Write-Success "Simulated: $Name"
        }
        else
        {
            & $Action
            Write-Success "Completed: $Name"
        }
    }
    catch
    {
        Write-ErrorMsg "$Name failed: $($_.Exception.Message)"
        Stop-Transcript | Out-Null
        throw
    }

    Write-Host ""
}


# ===============================================================
# SECTION: Execution Mode
# ===============================================================

if ($DryRun)
{
    Write-Host "DryRun enabled - no changes will be applied" -ForegroundColor Magenta
}


# ===============================================================
# SECTION: Validation
# ===============================================================

function Test-Admin
{
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin))
{
    Write-ErrorMsg "Script must be run as Administrator"
    Stop-Transcript | Out-Null
    exit 1
}


# ===============================================================
# SECTION: Execution Policy
# ===============================================================

Invoke-Step -Name 'Set Execution Policy' -Action {
    Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
}


# ===============================================================
# SECTION: Network Configuration
# ===============================================================

Invoke-Step -Name 'Disable IPv6' -Action {
    Get-NetAdapterBinding -ComponentID 'ms_tcpip6' |
        Disable-NetAdapterBinding -ComponentID 'ms_tcpip6' |
        Out-Null
}


# ===============================================================
# SECTION: DNS / InfoBlox Configuration
# ===============================================================

Invoke-Step -Name 'Prepare InfoBlox Directory' -Action {
    if (-not (Test-Path $InfoBloxPath))
    {
        New-Item -Path $InfoBloxPath -ItemType Directory | Out-Null
    }
}

Invoke-Step -Name 'Backup and Reconfigure DNS' -Action {
    Stop-Service DNS -Force

    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" "$InfoBloxPath\Zones.reg" | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" "$InfoBloxPath\DnsSettings.reg" | Out-Null

    reg copy "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\ZonesBackup" /s /f | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /f | Out-Null

    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v BootMethod /d 2 /t REG_DWORD /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v Forwarders /d 10.51.98.206\010.51.98.207 /t REG_MULTI_SZ /f | Out-Null

    Start-Service DNS
    Restart-Service Netlogon
}

Invoke-Step -Name 'Configure DNS Global Query Block List' -Action {
    Set-DnsServerGlobalQueryBlockList -List 'Isatap' | Out-Null
}


# ===============================================================
# SECTION: Splunk Source Validation and Remediation
# ===============================================================

Invoke-Step -Name 'Validate Splunk Installation Source' -Action {

    $msi = Join-Path $SplunkPath 'splunkuniversalforwarder.msi'
    $deployment = Join-Path $SplunkPath '1uh_all_deploymentclient'

    $needsCopy =
        -not (Test-Path $SplunkPath)   -or
        -not (Test-Path $msi)          -or
        -not (Test-Path $deployment)

    if ($needsCopy)
    {
        Write-Warn "Splunk source missing or incomplete - restoring"

        $tempRoot = Split-Path $SplunkPath -Parent

        Copy-Item -Path $SplunkInstallerSource -Destination $tempRoot -Recurse -Force

        if (Test-Path $SplunkPath)
        {
            Remove-Item -Path $SplunkPath -Recurse -Force
        }

        Rename-Item -Path (Join-Path $tempRoot 'SplunkInstall') -NewName 'Splunk'
    }
    else
    {
        Write-Info "Splunk source validated"
    }
}


# ===============================================================
# SECTION: Splunk Installation and Configuration
# ===============================================================

Invoke-Step -Name 'Install Splunk Forwarder' -Action {
    $msi = Join-Path $SplunkPath 'splunkuniversalforwarder.msi'
    $log = Join-Path $SplunkPath 'SplunkInstallLog.log'
    $args = @("/i", $msi, "/quiet", "AGREETOLICENSE=Yes", "LAUNCHSPLUNK=0", "/L*v", $log)

    if (-not (Get-Service SplunkForwarder -ErrorAction SilentlyContinue))
    {
        Start-Process 'msiexec.exe' -ArgumentList $args -Wait
    }
}

Invoke-Step -Name 'Deploy Splunk Configuration' -Action {
    $src = Join-Path $SplunkPath '1uh_all_deploymentclient'
    $dst = 'C:\Program Files\SplunkUniversalForwarder\etc\apps'
    Copy-Item -Path $src -Destination $dst -Recurse -Force
}

Invoke-Step -Name 'Configure Splunk Services' -Action {
    sc.exe config SplunkForwarder start= delayed-auto | Out-Null
    sc.exe config EventLog depend= RpcSs | Out-Null
    sc.exe config SplunkForwarder depend= EventLog | Out-Null
}

Invoke-Step -Name 'Start Splunk Service' -Action {
    Start-Service SplunkForwarder
}


# ===============================================================
# SECTION: Post-Splunk Validation
# ===============================================================

Invoke-Step -Name 'Validate Splunk Service' -Action {
    $svc = Get-Service SplunkForwarder

    if ($svc.Status -eq 'Running')
    {
        Write-Success "SplunkForwarder service is running"
        $script:SplunkServiceRunning = $true
    }
    else
    {
        Write-Warn "SplunkForwarder service is NOT running"
    }
}


# ===============================================================
# SECTION: Finalization
# ===============================================================

Write-Success "Script execution complete"

if ($SplunkServiceRunning)
{
    Write-Host ""

    Write-Host "[STATE ] SplunkForwarder : STOPPED → RUNNING" -ForegroundColor Cyan
    Write-Host "[ACTION] Reboot Required" -ForegroundColor Yellow
    Write-Host "         Press any key to reboot" -ForegroundColor Yellow

    if (-not $DryRun)
    {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        Write-Info "Rebooting system..."
        Restart-Computer -Force
    }
}

Stop-Transcript | Out-Null
