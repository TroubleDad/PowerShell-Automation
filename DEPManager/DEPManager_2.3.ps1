<#
.SYNOPSIS
    DEP Manager v2.3 for SolarWinds / Orion servers.
 
.DESCRIPTION
    Manages Data Execution Prevention (DEP) boot configuration across SolarWinds servers.
 
    Default behavior:
        - Runs a dry run first
        - If changes are needed, prompts user to execute or exit
 
    Features:
        - Dry run mode by default
        - Interactive execute-or-exit menu after dry run finds changes
        - Execution mode with -Execute
        - Rollback mode with -Rollback
        - Optional rollback NX value with -RollbackNx
        - Optional reboot with -Reboot
        - Parallel execution with -Parallel and -ThrottleLimit
        - Pre/post health checks
        - Drift detection
        - CSV audit report
        - Transcript logging
        - PowerShell 5.1 compatible
        - No hashtable or array remoting argument binding
 
.NOTES
    Author:
        Jeff Altomari + Copilot
 
    Version:
        2.3
 
    CAB Notes:
        - DEP boot configuration changes require a reboot to fully take effect.
        - bcdedit changes the boot configuration immediately.
        - Runtime DEP state may not reflect new boot settings until after reboot.
 
.EXAMPLES
    Dry run, then prompt:
        .\DEPManager_v2.3.ps1
 
    Dry run in parallel, then prompt:
        .\DEPManager_v2.3.ps1 -Parallel -ThrottleLimit 4
 
    Execute directly:
        .\DEPManager_v2.3.ps1 -Execute
 
    Execute directly in parallel:
        .\DEPManager_v2.3.ps1 -Execute -Parallel -ThrottleLimit 4
 
    Execute and reboot:
        .\DEPManager_v2.3.ps1 -Execute -Parallel -ThrottleLimit 4 -Reboot
 
    Rollback to OptOut:
        .\DEPManager_v2.3.ps1 -Execute -Rollback -RollbackNx OptOut -Parallel -ThrottleLimit 4
 
    WhatIf:
        .\DEPManager_v2.3.ps1 -Execute -WhatIf
#>
 
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string[]]$ComputerName = @(
        "UHSLRWNDNPM01",
        "UHSLRWNDPOL01",
        "UHSLRWNDPOL02",
        "UHSLRWNDPOL03",
        "UHSLRWNDPOL04",
        "UHSLRWNDPOL05",
        "UHSLRWNDPOL06",
        "UHSLRWNDPOL07",
        "UHSLRWNDPOL08",
        "UHSLRWNDPOL09"
    ),
 
    [switch]$Execute,
 
    [switch]$Rollback,
 
    [ValidateSet("AlwaysOff", "AlwaysOn", "OptIn", "OptOut")]
    [string]$RollbackNx = "OptOut",
 
    [switch]$Reboot,
 
    [switch]$Parallel,
 
    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 5,
 
    [string]$OutputDirectory = "C:\Temp",
 
    [int[]]$HealthPorts = @(80, 443, 17777, 17778),
 
    [string[]]$ServiceNamePatterns = @(
        "*SolarWinds*",
        "SW*",
        "Orion*",
        "W3SVC",
        "WAS"
    )
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
 
# ============================================================
# REGION: INITIALIZATION
# ============================================================
 
$ScriptStart = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
 
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
 
$ReportPath = Join-Path -Path $OutputDirectory -ChildPath "DEP_Report_$Timestamp.csv"
$TranscriptPath = Join-Path -Path $OutputDirectory -ChildPath "DEP_Transcript_$Timestamp.txt"
 
try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
}
catch {
    Write-Warning "Unable to start transcript: $($_.Exception.Message)"
}
 
$ModeText = "DRY RUN"
if ($Execute) {
    $ModeText = "EXECUTION"
}
 
$RequestedActionText = "Disable DEP"
$TargetNxDefault = "AlwaysOff"
 
if ($Rollback) {
    $RequestedActionText = "Rollback DEP"
    $TargetNxDefault = $RollbackNx
}
 
$HealthPortsCsv = ($HealthPorts | ForEach-Object { [string]$_ }) -join ","
$ServicePatternsCsv = $ServiceNamePatterns -join ";"

# $Reboot is a [switch] parameter. A [switch] is a SwitchParameter object, not a true
# System.Boolean. Casting it inline as [bool]$Reboot at an Invoke-Command -ArgumentList
# call site does not reliably flatten it to a primitive boolean before PowerShell
# remoting serializes the argument list. On the remote end, the scriptblock's strongly
# typed [bool]$RebootRemote parameter, combined with Set-StrictMode -Version Latest and
# $ErrorActionPreference = "Stop", rejects the mismatched deserialized type instead of
# silently coercing it, which produces "Argument types do not match" / System.ArgumentException.
#
# .IsPresent returns a genuine System.Boolean and must be used instead of a [bool] cast
# anywhere a switch value crosses the Invoke-Command -ComputerName remoting boundary.
$RebootBool = $Reboot.IsPresent
 
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " DEP Manager v2.3" -ForegroundColor Cyan
Write-Host " Mode              : $ModeText" -ForegroundColor Cyan
Write-Host " Requested Action  : $RequestedActionText" -ForegroundColor Cyan
Write-Host " Target NX         : $TargetNxDefault" -ForegroundColor Cyan
Write-Host " Parallel          : $Parallel" -ForegroundColor Cyan
Write-Host " ThrottleLimit     : $ThrottleLimit" -ForegroundColor Cyan
Write-Host " Reboot Requested  : $Reboot" -ForegroundColor Cyan
Write-Host " Report Path       : $ReportPath" -ForegroundColor Cyan
Write-Host " Transcript Path   : $TranscriptPath" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray
 
# ============================================================
# REGION: LOCAL HELPER FUNCTIONS
# ============================================================
 
function Write-Log {
    param (
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level,
 
        [string]$Message
    )
 
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
 
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
    }
}
 
function New-LocalResultObject {
    param (
        [string]$Server,
        [string]$InvocationMode,
        [string]$Action,
        [string]$Message,
        [string]$DriftStatus,
        [string]$TargetNx
    )
 
    [PSCustomObject]@{
        InvocationMode                  = $InvocationMode
        RequestedAction                 = $RequestedActionText
        Server                          = $Server
        Reachable                       = $false
        Pre_DEP_Code                    = "N/A"
        Pre_DEP_Status                  = "N/A"
        Pre_NX_Config                   = "N/A"
        Target_NX_Config                = $TargetNx
        Needs_Change                    = "UNKNOWN"
        Change_Attempted                = $false
        Action                          = $Action
        Bcdedit_Result                  = $Message
        Bcdedit_ExitCode                = "N/A"
        Post_DEP_Code                   = "N/A"
        Post_DEP_Status                 = "N/A"
        Post_NX_Config                  = "N/A"
        DriftStatus                     = $DriftStatus
        RebootRequested                 = [bool]$Reboot
        RebootAction                    = "N/A"
        PendingReboot_Pre               = "N/A"
        PendingReboot_Post              = "N/A"
        UptimeDays_Pre                  = "N/A"
        UptimeDays_Post                 = "N/A"
        SolarWindsServiceTotal_Pre      = "N/A"
        SolarWindsServicesRunning_Pre   = "N/A"
        SolarWindsServicesStopped_Pre   = "N/A"
        SolarWindsServicesOther_Pre     = "N/A"
        SolarWindsServiceDetails_Pre    = "N/A"
        IISServiceDetails_Pre           = "N/A"
        HealthPorts_Pre                 = "N/A"
        HealthSummary_Pre               = "N/A"
        SolarWindsServiceTotal_Post     = "N/A"
        SolarWindsServicesRunning_Post  = "N/A"
        SolarWindsServicesStopped_Post  = "N/A"
        SolarWindsServicesOther_Post    = "N/A"
        SolarWindsServiceDetails_Post   = "N/A"
        IISServiceDetails_Post          = "N/A"
        HealthPorts_Post                = "N/A"
        HealthSummary_Post              = "N/A"
        ErrorMessage                    = $Message
        Timestamp                       = Get-Date
    }
}
 
function Show-DryRunExecutionMenu {
    param (
        [object[]]$DryRunResults
    )
 
    $serversNeedingChange = @(
        $DryRunResults |
            Where-Object {
                $_.Reachable -eq $true -and
                $_.Needs_Change -eq $true
            } |
            Select-Object -ExpandProperty Server -Unique
    )
 
    if ($serversNeedingChange.Count -eq 0) {
        Write-Host ""
        Write-Host "Dry run completed. No DEP changes are required." -ForegroundColor Green
        return "Exit"
    }
 
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " DRY RUN RESULT: Changes Required" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host "The dry run found $($serversNeedingChange.Count) server(s) that need the requested DEP change:" -ForegroundColor Yellow
 
    foreach ($server in $serversNeedingChange) {
        Write-Host " - $server" -ForegroundColor Yellow
    }
 
    Write-Host ""
    Write-Host "Choose an option:" -ForegroundColor Cyan
    Write-Host " [1] Execute changes now" -ForegroundColor Green
    Write-Host " [2] Exit script" -ForegroundColor Red
    Write-Host ""
 
    do {
        $choice = Read-Host "Enter 1 or 2"
    }
    until ($choice -in @("1", "2"))
 
    if ($choice -eq "1") {
        return "Execute"
    }
 
    return "Exit"
}
 
function Write-RunSummary {
    param (
        [object[]]$ResultsToSummarize,
        [string]$SummaryTitle
    )
 
    $total = @($ResultsToSummarize).Count
    $changed = @($ResultsToSummarize | Where-Object { $_.Action -eq "CHANGED" }).Count
    $dryRunWouldChange = @($ResultsToSummarize | Where-Object { $_.DriftStatus -eq "DRYRUN_WOULD_CHANGE" }).Count
    $errors = @($ResultsToSummarize | Where-Object { $_.Action -eq "ERROR" -or $_.Reachable -eq $false }).Count
    $drift = @($ResultsToSummarize | Where-Object { $_.DriftStatus -eq "DRIFT_BOOTCFG_NOT_TARGET" }).Count
    $pendingReboot = @($ResultsToSummarize | Where-Object { $_.PendingReboot_Post -eq $true }).Count
    $healthWarnings = @($ResultsToSummarize | Where-Object { $_.HealthSummary_Post -ne "OK" -and $_.HealthSummary_Post -ne "N/A" }).Count
 
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " $SummaryTitle" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " Total Results        : $total"
    Write-Host " Changed              : $changed"
    Write-Host " DryRun Would Change  : $dryRunWouldChange"
    Write-Host " Drift                : $drift"
    Write-Host " Errors               : $errors"
    Write-Host " Pending Reboot       : $pendingReboot"
    Write-Host " Health Warnings      : $healthWarnings"
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host ""
 
    $ResultsToSummarize |
        Sort-Object -Property Server |
        Select-Object `
            Server,
            InvocationMode,
            RequestedAction,
            Pre_NX_Config,
            Target_NX_Config,
            Post_NX_Config,
            Needs_Change,
            Action,
            DriftStatus,
            HealthSummary_Pre,
            HealthSummary_Post,
            RebootAction |
        Format-Table -AutoSize
}
 
function Invoke-PostExecutionReboots {
    param (
        [object[]]$ExecutionResults
    )
 
    if (-not $Reboot) {
        return
    }
 
    $serversToReboot = @(
        $ExecutionResults |
            Where-Object {
                $_.Reachable -eq $true -and
                $_.Action -eq "CHANGED"
            } |
            Select-Object -ExpandProperty Server -Unique
    )
 
    if ($serversToReboot.Count -eq 0) {
        Write-Log -Level "INFO" -Message "Reboot requested, but no changed servers require reboot."
        return
    }
 
    foreach ($server in $serversToReboot) {
        Write-Log -Level "WARN" -Message "Triggering reboot on $server"
 
        try {
            Restart-Computer -ComputerName $server -Force -ErrorAction Stop
 
            foreach ($row in ($ExecutionResults | Where-Object { $_.Server -eq $server })) {
                $row.RebootAction = "Triggered"
            }
        }
        catch {
            foreach ($row in ($ExecutionResults | Where-Object { $_.Server -eq $server })) {
                $row.RebootAction = "Failed: $($_.Exception.Message)"
                $row.ErrorMessage = $_.Exception.Message
            }
 
            Write-Log -Level "ERROR" -Message "Failed to reboot $server : $($_.Exception.Message)"
        }
    }
}
 
# ============================================================
# REGION: REMOTE SCRIPTBLOCK
# ============================================================
 
$RemoteDEPManagerScript = {
    param (
        [bool]$ExecuteRemote,
        [string]$TargetNxRemote,
        [bool]$RebootRemote,
        [string]$HealthPortsCsvRemote,
        [string]$ServicePatternsCsvRemote,
        [string]$RequestedActionTextRemote
    )
 
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
 
    $HealthPortsRemote = @()
 
    if (-not [string]::IsNullOrWhiteSpace($HealthPortsCsvRemote)) {
        $HealthPortsRemote = @(
            $HealthPortsCsvRemote.Split(",") |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [int]$_ }
        )
    }
 
    $ServiceNamePatternsRemote = @()
 
    if (-not [string]::IsNullOrWhiteSpace($ServicePatternsCsvRemote)) {
        $ServiceNamePatternsRemote = @(
            $ServicePatternsCsvRemote.Split(";") |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [string]$_ }
        )
    }
 
    function Get-DEPPolicyText {
        param (
            [int]$Code
        )
 
        switch ($Code) {
            0 { return "AlwaysOff (Disabled)" }
            1 { return "AlwaysOn" }
            2 { return "OptIn (Default Windows Services)" }
            3 { return "OptOut (Exceptions Allowed)" }
            default { return "Unknown" }
        }
    }
 
    function Get-CurrentBcdNx {
        $nxValue = "UNKNOWN"
 
        try {
            $bcdOutput = & bcdedit.exe /enum "{current}" 2>&1
 
            foreach ($line in $bcdOutput) {
                $lineText = [string]$line
 
                if ($lineText -match '^\s*nx\s+(\S+)\s*$') {
                    $nxValue = $Matches[1]
                    break
                }
            }
        }
        catch {
            $nxValue = "ERROR: $($_.Exception.Message)"
        }
 
        return $nxValue
    }
 
    function Get-CurrentDEPState {
        $code = -1
 
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $code = [int]$os.DataExecutionPrevention_SupportPolicy
        }
        catch {
            try {
                $wmi = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                $code = [int]$wmi.DataExecutionPrevention_SupportPolicy
            }
            catch {
                $code = -1
            }
        }
 
        $status = Get-DEPPolicyText -Code $code
        $nx = Get-CurrentBcdNx
 
        [PSCustomObject]@{
            DEP_Code   = $code
            DEP_Status = $status
            NX_Config  = $nx
        }
    }
 
    function Test-PendingReboot {
        $pending = $false
        $reasonList = New-Object System.Collections.Generic.List[string]
 
        $rebootPendingPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        $wuRebootPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        $sessionManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
 
        try {
            if (Test-Path -Path $rebootPendingPath) {
                $pending = $true
                $reasonList.Add($rebootPendingPath) | Out-Null
            }
        }
        catch {
        }
 
        try {
            if (Test-Path -Path $wuRebootPath) {
                $pending = $true
                $reasonList.Add($wuRebootPath) | Out-Null
            }
        }
        catch {
        }
 
        try {
            if (Test-Path -Path $sessionManagerPath) {
                $sessionManager = Get-ItemProperty -Path $sessionManagerPath -ErrorAction SilentlyContinue
 
                if ($null -ne $sessionManager.PendingFileRenameOperations) {
                    $pending = $true
                    $reasonList.Add("PendingFileRenameOperations") | Out-Null
                }
            }
        }
        catch {
        }
 
        [PSCustomObject]@{
            Pending = $pending
            Reasons = ($reasonList -join "; ")
        }
    }
 
    function Test-LocalTcpPort {
        param (
            [int]$Port
        )
 
        $result = "Closed"
 
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(1000, $false)
 
            if ($wait -and $client.Connected) {
                $client.EndConnect($async)
                $result = "Open"
            }
 
            $client.Close()
        }
        catch {
            $result = "Error"
        }
 
        return $result
    }
 
    function Get-NodeHealth {
        param (
            [int[]]$HealthPorts,
            [string[]]$ServiceNamePatterns
        )
 
        $pendingRebootInfo = Test-PendingReboot
 
        $uptimeDays = "UNKNOWN"
 
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $lastBoot = $os.LastBootUpTime
            $uptime = New-TimeSpan -Start $lastBoot -End (Get-Date)
            $uptimeDays = [math]::Round($uptime.TotalDays, 2)
        }
        catch {
            try {
                $osWmi = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                $lastBootWmi = $osWmi.ConvertToDateTime($osWmi.LastBootUpTime)
                $uptimeWmi = New-TimeSpan -Start $lastBootWmi -End (Get-Date)
                $uptimeDays = [math]::Round($uptimeWmi.TotalDays, 2)
            }
            catch {
                $uptimeDays = "UNKNOWN"
            }
        }
 
        $matchedServices = @()
 
        try {
            $allServices = Get-Service -ErrorAction Stop
 
            $matchedServices = $allServices | Where-Object {
                $svc = $_
                $matched = $false
 
                foreach ($pattern in $ServiceNamePatterns) {
                    if ($svc.Name -like $pattern -or $svc.DisplayName -like $pattern) {
                        $matched = $true
                        break
                    }
                }
 
                $matched
            }
        }
        catch {
            $matchedServices = @()
        }
 
        $solarWindsServices = $matchedServices | Where-Object {
            $_.Name -like "*SolarWinds*" -or
            $_.DisplayName -like "*SolarWinds*" -or
            $_.Name -like "SW*" -or
            $_.DisplayName -like "SW*" -or
            $_.Name -like "Orion*" -or
            $_.DisplayName -like "Orion*"
        }
 
        $iisServices = $matchedServices | Where-Object {
            $_.Name -eq "W3SVC" -or
            $_.Name -eq "WAS"
        }
 
        $swTotal = @($solarWindsServices).Count
        $swRunning = @($solarWindsServices | Where-Object { $_.Status -eq "Running" }).Count
        $swStopped = @($solarWindsServices | Where-Object { $_.Status -eq "Stopped" }).Count
        $swOther = $swTotal - $swRunning - $swStopped
 
        $swDetails = "No SolarWinds-like services matched"
 
        if ($swTotal -gt 0) {
            $swDetails = ($solarWindsServices |
                Sort-Object -Property DisplayName |
                ForEach-Object { "$($_.Name)=$($_.Status)" }) -join "; "
        }
 
        $iisDetails = "No IIS services matched"
 
        if (@($iisServices).Count -gt 0) {
            $iisDetails = ($iisServices |
                Sort-Object -Property Name |
                ForEach-Object { "$($_.Name)=$($_.Status)" }) -join "; "
        }
 
        $portResults = New-Object System.Collections.Generic.List[string]
 
        foreach ($port in $HealthPorts) {
            $portStatus = Test-LocalTcpPort -Port $port
            $portResults.Add("$port=$portStatus") | Out-Null
        }
 
        $healthSummary = "OK"
 
        if ($pendingRebootInfo.Pending) {
            $healthSummary = "WARN_PENDING_REBOOT"
        }
 
        if ($swTotal -gt 0 -and $swStopped -gt 0) {
            if ($healthSummary -eq "OK") {
                $healthSummary = "WARN_STOPPED_SOLARWINDS_SERVICES"
            }
            else {
                $healthSummary = "$healthSummary; WARN_STOPPED_SOLARWINDS_SERVICES"
            }
        }
 
        [PSCustomObject]@{
            PendingReboot              = $pendingRebootInfo.Pending
            PendingRebootReasons       = $pendingRebootInfo.Reasons
            UptimeDays                 = $uptimeDays
            SolarWindsServiceTotal     = $swTotal
            SolarWindsServicesRunning  = $swRunning
            SolarWindsServicesStopped  = $swStopped
            SolarWindsServicesOther    = $swOther
            SolarWindsServiceDetails   = $swDetails
            IISServiceDetails          = $iisDetails
            HealthPorts                = ($portResults -join "; ")
            HealthSummary              = $healthSummary
        }
    }
 
    function Set-BcdNx {
        param (
            [ValidateSet("AlwaysOff", "AlwaysOn", "OptIn", "OptOut")]
            [string]$NxValue
        )
 
        $output = & bcdedit.exe /set "{current}" nx $NxValue 2>&1
        $exitCode = $LASTEXITCODE
 
        [PSCustomObject]@{
            Output   = (($output | ForEach-Object { [string]$_ }) -join " ")
            ExitCode = $exitCode
        }
    }
 
    $computer = $env:COMPUTERNAME
 
    $remoteInvocationMode = "DRY RUN"
 
    if ($ExecuteRemote) {
        $remoteInvocationMode = "EXECUTION"
    }
 
    $preState = Get-CurrentDEPState
    $preHealth = Get-NodeHealth -HealthPorts $HealthPortsRemote -ServiceNamePatterns $ServiceNamePatternsRemote
 
    $needsChange = $true
 
    if ($preState.NX_Config -eq $TargetNxRemote) {
        $needsChange = $false
    }
 
    $changeAttempted = $false
    $action = "DRY RUN - No Change"
    $bcdeditResult = "No change attempted"
    $bcdeditExitCode = "N/A"
    $rebootAction = "Not Requested"
 
    if ($RebootRemote -and -not $ExecuteRemote) {
        $rebootAction = "Dry Run - Reboot Not Triggered"
    }
 
    if ($ExecuteRemote -and $needsChange) {
        $changeAttempted = $true
        $setResult = Set-BcdNx -NxValue $TargetNxRemote
        $bcdeditResult = $setResult.Output
        $bcdeditExitCode = $setResult.ExitCode
 
        if ($setResult.ExitCode -eq 0) {
            $action = "CHANGED"
 
            if ($RebootRemote) {
                $rebootAction = "Pending Local Reboot Trigger"
            }
        }
        else {
            $action = "ERROR"
            throw "bcdedit failed with exit code $($setResult.ExitCode): $($setResult.Output)"
        }
    }
    elseif ($ExecuteRemote -and -not $needsChange) {
        $action = "NO CHANGE - Already Target"
 
        if ($RebootRemote) {
            $rebootAction = "Not Triggered - No Change Needed"
        }
    }
 
    Start-Sleep -Seconds 2
 
    $postState = Get-CurrentDEPState
    $postHealth = Get-NodeHealth -HealthPorts $HealthPortsRemote -ServiceNamePatterns $ServiceNamePatternsRemote
 
    $driftStatus = "N/A"
 
    if ($postState.NX_Config -eq $TargetNxRemote) {
        if ($ExecuteRemote -and $changeAttempted) {
            $driftStatus = "BOOTCFG_COMPLIANT_REBOOT_REQUIRED"
        }
        elseif ($ExecuteRemote -and -not $changeAttempted) {
            $driftStatus = "BOOTCFG_ALREADY_COMPLIANT"
        }
        else {
            $driftStatus = "DRYRUN_TARGET_MATCH"
        }
    }
    else {
        if ($ExecuteRemote) {
            $driftStatus = "DRIFT_BOOTCFG_NOT_TARGET"
        }
        else {
            $driftStatus = "DRYRUN_WOULD_CHANGE"
        }
    }
 
    [PSCustomObject]@{
        InvocationMode                  = $remoteInvocationMode
        RequestedAction                 = $RequestedActionTextRemote
        Server                          = $computer
        Reachable                       = $true
        Pre_DEP_Code                    = $preState.DEP_Code
        Pre_DEP_Status                  = $preState.DEP_Status
        Pre_NX_Config                   = $preState.NX_Config
        Target_NX_Config                = $TargetNxRemote
        Needs_Change                    = $needsChange
        Change_Attempted                = $changeAttempted
        Action                          = $action
        Bcdedit_Result                  = $bcdeditResult
        Bcdedit_ExitCode                = $bcdeditExitCode
        Post_DEP_Code                   = $postState.DEP_Code
        Post_DEP_Status                 = $postState.DEP_Status
        Post_NX_Config                  = $postState.NX_Config
        DriftStatus                     = $driftStatus
        RebootRequested                 = $RebootRemote
        RebootAction                    = $rebootAction
        PendingReboot_Pre               = $preHealth.PendingReboot
        PendingReboot_Post              = $postHealth.PendingReboot
        UptimeDays_Pre                  = $preHealth.UptimeDays
        UptimeDays_Post                 = $postHealth.UptimeDays
        SolarWindsServiceTotal_Pre      = $preHealth.SolarWindsServiceTotal
        SolarWindsServicesRunning_Pre   = $preHealth.SolarWindsServicesRunning
        SolarWindsServicesStopped_Pre   = $preHealth.SolarWindsServicesStopped
        SolarWindsServicesOther_Pre     = $preHealth.SolarWindsServicesOther
        SolarWindsServiceDetails_Pre    = $preHealth.SolarWindsServiceDetails
        IISServiceDetails_Pre           = $preHealth.IISServiceDetails
        HealthPorts_Pre                 = $preHealth.HealthPorts
        HealthSummary_Pre               = $preHealth.HealthSummary
        SolarWindsServiceTotal_Post     = $postHealth.SolarWindsServiceTotal
        SolarWindsServicesRunning_Post  = $postHealth.SolarWindsServicesRunning
        SolarWindsServicesStopped_Post  = $postHealth.SolarWindsServicesStopped
        SolarWindsServicesOther_Post    = $postHealth.SolarWindsServicesOther
        SolarWindsServiceDetails_Post   = $postHealth.SolarWindsServiceDetails
        IISServiceDetails_Post          = $postHealth.IISServiceDetails
        HealthPorts_Post                = $postHealth.HealthPorts
        HealthSummary_Post              = $postHealth.HealthSummary
        ErrorMessage                    = ""
        Timestamp                       = Get-Date
    }
}
 
# ============================================================
# REGION: EXECUTION WRAPPER
# ============================================================
 
function Invoke-DEPBatch {
    param (
        [string[]]$TargetServers,
        [bool]$ExecuteBatch,
        [string]$InvocationModeLabel
    )
 
    $batchResults = New-Object System.Collections.Generic.List[object]
    $approvedServers = New-Object System.Collections.Generic.List[string]
 
    foreach ($server in $TargetServers) {
        if ($ExecuteBatch) {
            $shouldProcessMessage = "Set DEP boot NX value to $TargetNxDefault"
 
            if ($PSCmdlet.ShouldProcess($server, $shouldProcessMessage)) {
                $approvedServers.Add($server) | Out-Null
            }
            else {
                $batchResults.Add((New-LocalResultObject `
                    -Server $server `
                    -InvocationMode $InvocationModeLabel `
                    -Action "WHATIF - Not Executed" `
                    -Message "ShouldProcess returned false; no remote change attempted." `
                    -DriftStatus "WHATIF" `
                    -TargetNx $TargetNxDefault)) | Out-Null
            }
        }
        else {
            $approvedServers.Add($server) | Out-Null
        }
    }
 
    if ($approvedServers.Count -eq 0) {
        Write-Log -Level "WARN" -Message "No servers approved for processing."
        return @($batchResults)
    }
 
    if ($Parallel) {
        Write-Log -Level "INFO" -Message "Starting parallel processing with ThrottleLimit $ThrottleLimit."
 
        $pendingServers = New-Object System.Collections.Generic.Queue[string]
 
        foreach ($server in $approvedServers) {
            $pendingServers.Enqueue($server)
        }
 
        $jobs = New-Object System.Collections.Generic.List[object]
 
        while ($pendingServers.Count -gt 0 -or @($jobs | Where-Object { $_.State -eq "Running" }).Count -gt 0) {
            while ($pendingServers.Count -gt 0 -and @($jobs | Where-Object { $_.State -eq "Running" }).Count -lt $ThrottleLimit) {
                $serverToStart = $pendingServers.Dequeue()
 
                Write-Log -Level "INFO" -Message "Starting remote job for $serverToStart"
 
                try {
                    $job = Invoke-Command `
                        -ComputerName $serverToStart `
                        -ScriptBlock $RemoteDEPManagerScript `
                        -ArgumentList `
                            ([bool]$ExecuteBatch),
                            ([string]$TargetNxDefault),
                            ($RebootBool),
                            ([string]$HealthPortsCsv),
                            ([string]$ServicePatternsCsv),
                            ([string]$RequestedActionText) `
                        -AsJob `
                        -ErrorAction Stop

                    $jobs.Add($job) | Out-Null
                }
                catch {
                    $batchResults.Add((New-LocalResultObject `
                        -Server $serverToStart `
                        -InvocationMode $InvocationModeLabel `
                        -Action "ERROR" `
                        -Message $_.Exception.Message `
                        -DriftStatus "ERROR" `
                        -TargetNx $TargetNxDefault)) | Out-Null
                }
            }
 
            Start-Sleep -Milliseconds 500
 
            $completedJobs = @($jobs | Where-Object { $_.State -ne "Running" })
 
            foreach ($completedJob in $completedJobs) {
                $location = $completedJob.Location
 
                try {
                    $received = Receive-Job -Job $completedJob -ErrorAction Stop
 
                    foreach ($item in $received) {
                        $batchResults.Add($item) | Out-Null
                    }
                }
                catch {
                    $batchResults.Add((New-LocalResultObject `
                        -Server $location `
                        -InvocationMode $InvocationModeLabel `
                        -Action "ERROR" `
                        -Message $_.Exception.Message `
                        -DriftStatus "ERROR" `
                        -TargetNx $TargetNxDefault)) | Out-Null
                }
 
                Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
 
                $remainingJobs = New-Object System.Collections.Generic.List[object]
 
                foreach ($existingJob in $jobs) {
                    if ($existingJob.Id -ne $completedJob.Id) {
                        $remainingJobs.Add($existingJob) | Out-Null
                    }
                }
 
                $jobs = $remainingJobs
            }
        }
    }
    else {
        Write-Log -Level "INFO" -Message "Starting sequential processing."
 
        foreach ($server in $approvedServers) {
            Write-Log -Level "INFO" -Message "Processing $server"
 
            try {
                $remoteResult = Invoke-Command `
                    -ComputerName $server `
                    -ScriptBlock $RemoteDEPManagerScript `
                    -ArgumentList `
                        ([bool]$ExecuteBatch),
                        ([string]$TargetNxDefault),
                        ($RebootBool),
                        ([string]$HealthPortsCsv),
                        ([string]$ServicePatternsCsv),
                        ([string]$RequestedActionText) `
                    -ErrorAction Stop
 
                foreach ($item in $remoteResult) {
                    $batchResults.Add($item) | Out-Null
                }
            }
            catch {
                Write-Log -Level "ERROR" -Message "$server failed: $($_.Exception.Message)"
 
                $batchResults.Add((New-LocalResultObject `
                    -Server $server `
                    -InvocationMode $InvocationModeLabel `
                    -Action "ERROR" `
                    -Message $_.Exception.Message `
                    -DriftStatus "ERROR" `
                    -TargetNx $TargetNxDefault)) | Out-Null
            }
        }
    }
 
    if ($ExecuteBatch) {
        Invoke-PostExecutionReboots -ExecutionResults $batchResults
    }
 
    return @($batchResults)
}
 
# ============================================================
# REGION: MAIN FLOW
# ============================================================
 
$AllResults = New-Object System.Collections.Generic.List[object]
 
if ($Execute) {
    Write-Log -Level "INFO" -Message "Execution mode specified. Running execution directly."
 
    $executionResults = Invoke-DEPBatch `
        -TargetServers $ComputerName `
        -ExecuteBatch $true `
        -InvocationModeLabel "EXECUTION"
 
    foreach ($result in $executionResults) {
        $AllResults.Add($result) | Out-Null
    }
 
    Write-RunSummary -ResultsToSummarize $executionResults -SummaryTitle "DEP Manager v2.3 Execution Summary"
}
else {
    Write-Log -Level "INFO" -Message "No -Execute specified. Running dry run first."
 
    $dryRunResults = Invoke-DEPBatch `
        -TargetServers $ComputerName `
        -ExecuteBatch $false `
        -InvocationModeLabel "DRY RUN"
 
    foreach ($result in $dryRunResults) {
        $AllResults.Add($result) | Out-Null
    }
 
    Write-RunSummary -ResultsToSummarize $dryRunResults -SummaryTitle "DEP Manager v2.3 Dry Run Summary"
 
    $menuDecision = Show-DryRunExecutionMenu -DryRunResults $dryRunResults
 
    if ($menuDecision -eq "Execute") {
        $serversToExecute = @(
            $dryRunResults |
                Where-Object {
                    $_.Reachable -eq $true -and
                    $_.Needs_Change -eq $true
                } |
                Select-Object -ExpandProperty Server -Unique
        )
 
        Write-Host ""
        Write-Host "Executing DEP changes against $($serversToExecute.Count) server(s) identified by dry run." -ForegroundColor Yellow
        Write-Host ""
 
        $executionResultsFromMenu = Invoke-DEPBatch `
            -TargetServers $serversToExecute `
            -ExecuteBatch $true `
            -InvocationModeLabel "EXECUTION_FROM_DRYRUN_MENU"
 
        foreach ($result in $executionResultsFromMenu) {
            $AllResults.Add($result) | Out-Null
        }
 
        Write-RunSummary -ResultsToSummarize $executionResultsFromMenu -SummaryTitle "DEP Manager v2.3 Menu Execution Summary"
    }
    else {
        Write-Log -Level "INFO" -Message "User selected exit or no changes were required. No execution performed."
    }
}
 
# ============================================================
# REGION: EXPORT AND FINAL SUMMARY
# ============================================================
 
$ResultsSorted = $AllResults | Sort-Object -Property Server, InvocationMode, Timestamp
 
$ResultsSorted | Export-Csv -Path $ReportPath -NoTypeInformation
 
$ScriptEnd = Get-Date
$Duration = New-TimeSpan -Start $ScriptStart -End $ScriptEnd
 
Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " DEP Manager v2.3 Final Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " Total Rows     : $(@($ResultsSorted).Count)"
Write-Host " Duration       : $($Duration.ToString())"
Write-Host " Report         : $ReportPath"
Write-Host " Transcript     : $TranscriptPath"
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""
 
$ResultsSorted |
    Select-Object `
        Server,
        InvocationMode,
        RequestedAction,
        Pre_NX_Config,
        Target_NX_Config,
        Post_NX_Config,
        Needs_Change,
        Action,
        DriftStatus,
        HealthSummary_Post,
        RebootAction |
    Format-Table -AutoSize
 
try {
    Stop-Transcript | Out-Null
}
catch {
}
