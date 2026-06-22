# =====================================================================
# Script      : DEPManager.ps1
# Author      : Jeff Altomari
# Date        : 06-18-2026
# Version     : 2.4
#
# Description : Manages Data Execution Prevention (DEP) boot configuration
#               (the bcdedit nx value) across SolarWinds / Orion servers.
#               Runs a dry run by default, prompts to execute when changes
#               are found, supports direct execution, rollback, optional
#               reboot, parallel processing with a throttle limit, pre/post
#               health checks, drift detection, a CSV audit report, transcript
#               logging, and an HTML status email to the listed recipients.
# Requirements: PowerShell 5.1; WinRM remoting enabled to all targets; local
#
#               administrator rights on the targets; an open SMTP relay
#               reachable at smtp.uhhs.com on port 25.
#
# Change Log:
#   2.4 - Reworked to the canonical script standard: regioned layout, single
#         VARIABLES block, six aligned logging helpers, Allman braces, no
#         backticks, splatting for all multi-parameter calls.
#       - Fixed the "Argument types do not match" (System.ArgumentException)
#         terminating error observed at end of run:
#           * Booleans now cross the WinRM remoting boundary as [int] (0/1)
#             instead of [switch]/[bool], removing the type-binding fault.
#           * Remote (deserialized) results are re-projected into local
#             PSCustomObjects with the Timestamp normalized to [datetime], so
#             the result set is type-homogeneous before any Sort/Export/Email.
#           * The final sort no longer orders on the Timestamp property.
#       - Added an HTML report email sent to Jeffrey Altomari and Alan Phillips.
#   2.3 - Switch-to-bool remoting hardening attempt; interactive
#         execute-or-exit menu after dry run.
#   2.2 - Parallel processing, drift detection, pre/post health checks,
#         CSV audit report, transcript logging.
# =====================================================================

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
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

# ============================================================
# REGION: VARIABLES
# ============================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptName    = "DEPManager"
$ScriptVersion = "2.4"
$ScriptStart   = Get-Date
$FriendlyDate  = Get-Date -Format "MM-dd-yyyy"
$Timestamp     = Get-Date -Format "yyyyMMdd_HHmmss"

$SmtpServer = "smtp.uhhs.com"
$SmtpPort   = 25
$MailFrom   = "DEPManager@uhhs.com"
$MailTo     = @(
    "Jeffrey.Altomari@UHhospitals.org",
    "Alan.Phillips@UHhospitals.org"
)

$ReportPath     = Join-Path -Path $OutputDirectory -ChildPath "DEP_Report_${Timestamp}.csv"
$TranscriptPath = Join-Path -Path $OutputDirectory -ChildPath "DEP_Transcript_${Timestamp}.txt"
$LogPath        = Join-Path -Path $OutputDirectory -ChildPath "DEP_Log_${Timestamp}.log"

# Derived from the -Reboot switch so a SwitchParameter never crosses the
# remoting boundary. All booleans are marshaled to the remote session as
# [int] (0/1) to avoid the type-binding fault that produced the
# "Argument types do not match" terminating error.
$RebootRequested = $Reboot.IsPresent

$ModeText = "DRY RUN"
if ($Execute)
{
    $ModeText = "EXECUTION"
}

$RequestedActionText = "Disable DEP"
$TargetNxDefault     = "AlwaysOff"
if ($Rollback)
{
    $RequestedActionText = "Rollback DEP"
    $TargetNxDefault     = $RollbackNx
}

$HealthPortsCsv     = ($HealthPorts | ForEach-Object { [string]$_ }) -join ","
$ServicePatternsCsv = $ServiceNamePatterns -join ";"

$ResultColumns = @(
    "Server",
    "InvocationMode",
    "RequestedAction",
    "Pre_NX_Config",
    "Target_NX_Config",
    "Post_NX_Config",
    "Needs_Change",
    "Action",
    "DriftStatus",
    "HealthSummary_Pre",
    "HealthSummary_Post",
    "RebootAction"
)

$UseConsoleIcons = $false
$Icons = @{
    Info    = [char]::ConvertFromUtf32(0x2139)
    Success = [char]::ConvertFromUtf32(0x2705)
    Warn    = [char]::ConvertFromUtf32(0x26A0)
    Error   = [char]::ConvertFromUtf32(0x274C)
    DryRun  = [char]::ConvertFromUtf32(0x1F50D)
}

# ============================================================
# REGION: LOGGING FUNCTIONS
# ============================================================

function Write-Log
{
    param
    (
        [string]$Message
    )

    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[${stamp}] ${Message}"

    try
    {
        Add-Content -Path $LogPath -Value $entry -Encoding UTF8
    }
    catch
    {
    }
}

function Write-InfoMsg
{
    param
    (
        [string]$Message
    )

    $prefix = "[INFO ]"
    if ($UseConsoleIcons)
    {
        $prefix = "$($Icons.Info) ${prefix}"
    }

    $line = "${prefix} ${Message}"
    Write-Host $line -ForegroundColor Cyan
    Write-Log -Message $line
}

function Write-SuccessMsg
{
    param
    (
        [string]$Message
    )

    $prefix = "[OK   ]"
    if ($UseConsoleIcons)
    {
        $prefix = "$($Icons.Success) ${prefix}"
    }

    $line = "${prefix} ${Message}"
    Write-Host $line -ForegroundColor Green
    Write-Log -Message $line
}

function Write-WarnMsg
{
    param
    (
        [string]$Message
    )

    $prefix = "[WARN ]"
    if ($UseConsoleIcons)
    {
        $prefix = "$($Icons.Warn) ${prefix}"
    }

    $line = "${prefix} ${Message}"
    Write-Host $line -ForegroundColor Yellow
    Write-Log -Message $line
}

function Write-ErrorMsg
{
    param
    (
        [string]$Message
    )

    $prefix = "[ERROR]"
    if ($UseConsoleIcons)
    {
        $prefix = "$($Icons.Error) ${prefix}"
    }

    $line = "${prefix} ${Message}"
    Write-Host $line -ForegroundColor Red
    Write-Log -Message $line
}

function Write-DryRunMsg
{
    param
    (
        [string]$Message
    )

    $prefix = "[DRYRUN]"
    if ($UseConsoleIcons)
    {
        $prefix = "$($Icons.DryRun) ${prefix}"
    }

    $line = "${prefix} ${Message}"
    Write-Host $line -ForegroundColor Magenta
    Write-Log -Message $line
}

# ============================================================
# REGION: INITIALIZATION
# ============================================================

if (-not (Test-Path -Path $OutputDirectory))
{
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

try
{
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
}
catch
{
    Write-WarnMsg -Message "Unable to start transcript: $($_.Exception.Message)"
}

Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " DEP Manager v${ScriptVersion}"                              -ForegroundColor Cyan
Write-Host " Mode              : ${ModeText}"                            -ForegroundColor Cyan
Write-Host " Requested Action  : ${RequestedActionText}"                -ForegroundColor Cyan
Write-Host " Target NX         : ${TargetNxDefault}"                    -ForegroundColor Cyan
Write-Host " Parallel          : $($Parallel.IsPresent)"               -ForegroundColor Cyan
Write-Host " ThrottleLimit     : ${ThrottleLimit}"                     -ForegroundColor Cyan
Write-Host " Reboot Requested  : ${RebootRequested}"                   -ForegroundColor Cyan
Write-Host " Report Path       : ${ReportPath}"                        -ForegroundColor Cyan
Write-Host " Transcript Path   : ${TranscriptPath}"                    -ForegroundColor Cyan
Write-Host " Log Path          : ${LogPath}"                           -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray

# ============================================================
# REGION: HELPER FUNCTIONS
# ============================================================

function New-LocalResultObject
{
    param
    (
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
        RebootRequested                 = $RebootRequested
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
        Timestamp                       = (Get-Date)
    }
}

function ConvertTo-DEPResult
{
    param
    (
        [object]$InputObject
    )

    # Re-project the (possibly deserialized) remote object into a fresh local
    # PSCustomObject. This guarantees a single CLR type across the whole result
    # set and normalizes Timestamp to a real [datetime], which is what keeps
    # Sort-Object, Export-Csv and ConvertTo-Html from raising
    # "Argument types do not match".
    $normalized = [ordered]@{}

    foreach ($property in $InputObject.PSObject.Properties)
    {
        $normalized[$property.Name] = $property.Value
    }

    if ($normalized.Contains("Timestamp"))
    {
        try
        {
            $normalized["Timestamp"] = [datetime]$normalized["Timestamp"]
        }
        catch
        {
            $normalized["Timestamp"] = Get-Date
        }
    }

    [PSCustomObject]$normalized
}

function ConvertTo-HtmlSafe
{
    param
    (
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text))
    {
        return ""
    }

    $safe = $Text
    $safe = $safe.Replace("&", "&amp;")
    $safe = $safe.Replace("<", "&lt;")
    $safe = $safe.Replace(">", "&gt;")
    return $safe
}

function Show-DryRunExecutionMenu
{
    param
    (
        [object[]]$DryRunResults
    )

    $serversNeedingChange = @(
        $DryRunResults |
            Where-Object { $_.Reachable -eq $true -and $_.Needs_Change -eq $true } |
            Select-Object -ExpandProperty Server -Unique
    )

    if ($serversNeedingChange.Count -eq 0)
    {
        Write-Host ""
        Write-Host "Dry run completed. No DEP changes are required." -ForegroundColor Green
        return "Exit"
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " DRY RUN RESULT: Changes Required"                            -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host "The dry run found $($serversNeedingChange.Count) server(s) that need the requested DEP change:" -ForegroundColor Yellow

    foreach ($server in $serversNeedingChange)
    {
        Write-Host " - ${server}" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Choose an option:"        -ForegroundColor Cyan
    Write-Host " [1] Execute changes now" -ForegroundColor Green
    Write-Host " [2] Exit script"         -ForegroundColor Red
    Write-Host ""

    do
    {
        $choice = Read-Host "Enter 1 or 2"
    }
    until ($choice -in @("1", "2"))

    if ($choice -eq "1")
    {
        return "Execute"
    }

    return "Exit"
}

function Write-RunSummary
{
    param
    (
        [object[]]$ResultsToSummarize,
        [string]$SummaryTitle
    )

    $total             = @($ResultsToSummarize).Count
    $changed           = @($ResultsToSummarize | Where-Object { $_.Action -eq "CHANGED" }).Count
    $dryRunWouldChange = @($ResultsToSummarize | Where-Object { $_.DriftStatus -eq "DRYRUN_WOULD_CHANGE" }).Count
    $errors            = @($ResultsToSummarize | Where-Object { $_.Action -eq "ERROR" -or $_.Reachable -eq $false }).Count
    $drift             = @($ResultsToSummarize | Where-Object { $_.DriftStatus -eq "DRIFT_BOOTCFG_NOT_TARGET" }).Count
    $pendingReboot     = @($ResultsToSummarize | Where-Object { $_.PendingReboot_Post -eq $true }).Count
    $healthWarnings    = @($ResultsToSummarize | Where-Object { $_.HealthSummary_Post -ne "OK" -and $_.HealthSummary_Post -ne "N/A" }).Count

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " ${SummaryTitle}"                                             -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " Total Results        : ${total}"
    Write-Host " Changed              : ${changed}"
    Write-Host " DryRun Would Change  : ${dryRunWouldChange}"
    Write-Host " Drift                : ${drift}"
    Write-Host " Errors               : ${errors}"
    Write-Host " Pending Reboot       : ${pendingReboot}"
    Write-Host " Health Warnings      : ${healthWarnings}"
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host ""

    $ResultsToSummarize |
        Sort-Object -Property Server, InvocationMode |
        Select-Object $ResultColumns |
        Format-Table -AutoSize
}

function Invoke-PostExecutionReboots
{
    param
    (
        [object[]]$ExecutionResults
    )

    if (-not $RebootRequested)
    {
        return
    }

    $serversToReboot = @(
        $ExecutionResults |
            Where-Object { $_.Reachable -eq $true -and $_.Action -eq "CHANGED" } |
            Select-Object -ExpandProperty Server -Unique
    )

    if ($serversToReboot.Count -eq 0)
    {
        Write-InfoMsg -Message "Reboot requested, but no changed servers require reboot."
        return
    }

    foreach ($server in $serversToReboot)
    {
        Write-WarnMsg -Message "Triggering reboot on ${server}"

        try
        {
            $rebootParams = @{
                ComputerName = $server
                Force        = $true
                ErrorAction  = "Stop"
            }

            Restart-Computer @rebootParams

            foreach ($row in ($ExecutionResults | Where-Object { $_.Server -eq $server }))
            {
                $row.RebootAction = "Triggered"
            }
        }
        catch
        {
            foreach ($row in ($ExecutionResults | Where-Object { $_.Server -eq $server }))
            {
                $row.RebootAction = "Failed: $($_.Exception.Message)"
                $row.ErrorMessage = $_.Exception.Message
            }

            Write-ErrorMsg -Message "Failed to reboot ${server}: $($_.Exception.Message)"
        }
    }
}

# ============================================================
# REGION: EMAIL FUNCTIONS
# ============================================================

function Get-EmailSubject
{
    return "${ScriptName} - $(Get-Date -Format 'MM-dd-yyyy')"
}

function New-HtmlReport
{
    param
    (
        [object[]]$Results,
        [string]$RunContext
    )

    $total             = @($Results).Count
    $changed           = @($Results | Where-Object { $_.Action -eq "CHANGED" }).Count
    $dryRunWouldChange = @($Results | Where-Object { $_.DriftStatus -eq "DRYRUN_WOULD_CHANGE" }).Count
    $errors            = @($Results | Where-Object { $_.Action -eq "ERROR" -or $_.Reachable -eq $false }).Count
    $drift             = @($Results | Where-Object { $_.DriftStatus -eq "DRIFT_BOOTCFG_NOT_TARGET" }).Count
    $pendingReboot     = @($Results | Where-Object { $_.PendingReboot_Post -eq $true }).Count
    $healthWarnings    = @($Results | Where-Object { $_.HealthSummary_Post -ne "OK" -and $_.HealthSummary_Post -ne "N/A" }).Count

    $rowsHtml = ""

    foreach ($row in ($Results | Sort-Object -Property Server, InvocationMode))
    {
        $rowColor = "#ffffff"

        switch -Wildcard ($row.Action)
        {
            "CHANGED" { $rowColor = "#e8f5e9" }
            "ERROR*"  { $rowColor = "#ffebee" }
            default   { $rowColor = "#ffffff" }
        }

        if ($row.Reachable -eq $false)
        {
            $rowColor = "#ffebee"
        }

        $server     = ConvertTo-HtmlSafe -Text ([string]$row.Server)
        $mode       = ConvertTo-HtmlSafe -Text ([string]$row.InvocationMode)
        $preNx      = ConvertTo-HtmlSafe -Text ([string]$row.Pre_NX_Config)
        $targetNx   = ConvertTo-HtmlSafe -Text ([string]$row.Target_NX_Config)
        $postNx     = ConvertTo-HtmlSafe -Text ([string]$row.Post_NX_Config)
        $needs      = ConvertTo-HtmlSafe -Text ([string]$row.Needs_Change)
        $action     = ConvertTo-HtmlSafe -Text ([string]$row.Action)
        $driftText  = ConvertTo-HtmlSafe -Text ([string]$row.DriftStatus)
        $healthPost = ConvertTo-HtmlSafe -Text ([string]$row.HealthSummary_Post)
        $rebootAct  = ConvertTo-HtmlSafe -Text ([string]$row.RebootAction)
        $errMsg     = ConvertTo-HtmlSafe -Text ([string]$row.ErrorMessage)

        $rowsHtml += '<tr style="background-color:' + $rowColor + ';">'
        $rowsHtml += "<td>${server}</td>"
        $rowsHtml += "<td>${mode}</td>"
        $rowsHtml += "<td>${preNx}</td>"
        $rowsHtml += "<td>${targetNx}</td>"
        $rowsHtml += "<td>${postNx}</td>"
        $rowsHtml += "<td>${needs}</td>"
        $rowsHtml += "<td>${action}</td>"
        $rowsHtml += "<td>${driftText}</td>"
        $rowsHtml += "<td>${healthPost}</td>"
        $rowsHtml += "<td>${rebootAct}</td>"
        $rowsHtml += "<td>${errMsg}</td>"
        $rowsHtml += "</tr>"
    }

    $contextSafe = ConvertTo-HtmlSafe -Text $RunContext
    $targetSafe  = ConvertTo-HtmlSafe -Text $TargetNxDefault
    $actionSafe  = ConvertTo-HtmlSafe -Text $RequestedActionText

    $html = @"
<html>
<head>
<style>
    body  { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; color: #1a1a1a; }
    h2    { color: #003a5d; margin-bottom: 4px; }
    .meta { margin: 0 0 12px 0; font-size: 12px; color: #444444; }
    .meta span { font-weight: bold; color: #003a5d; }
    table { border-collapse: collapse; width: 100%; margin-top: 8px; }
    th    { background-color: #003a5d; color: #ffffff; text-align: left; padding: 6px 8px; font-size: 12px; }
    td    { border: 1px solid #d0d0d0; padding: 5px 8px; font-size: 11px; vertical-align: top; }
    .summary { border-collapse: collapse; margin-top: 8px; }
    .summary td { border: none; padding: 2px 14px 2px 0; }
    .summary .label { font-weight: bold; color: #003a5d; }
</style>
</head>
<body>
<h2>DEP Manager v${ScriptVersion} Report</h2>
<p class="meta">
    <span>Run Context:</span> ${contextSafe} &nbsp;|&nbsp;
    <span>Requested Action:</span> ${actionSafe} &nbsp;|&nbsp;
    <span>Target NX:</span> ${targetSafe} &nbsp;|&nbsp;
    <span>Generated:</span> ${FriendlyDate}
</p>
<table class="summary">
    <tr><td class="label">Total Results</td><td>${total}</td><td class="label">Changed</td><td>${changed}</td></tr>
    <tr><td class="label">DryRun Would Change</td><td>${dryRunWouldChange}</td><td class="label">Drift</td><td>${drift}</td></tr>
    <tr><td class="label">Errors / Unreachable</td><td>${errors}</td><td class="label">Pending Reboot</td><td>${pendingReboot}</td></tr>
    <tr><td class="label">Health Warnings</td><td>${healthWarnings}</td><td></td><td></td></tr>
</table>
<table>
    <tr>
        <th>Server</th>
        <th>Mode</th>
        <th>Pre NX</th>
        <th>Target NX</th>
        <th>Post NX</th>
        <th>Needs Change</th>
        <th>Action</th>
        <th>Drift</th>
        <th>Health (Post)</th>
        <th>Reboot</th>
        <th>Error</th>
    </tr>
    ${rowsHtml}
</table>
</body>
</html>
"@

    return $html
}

function Send-DEPReportEmail
{
    param
    (
        [object[]]$Results,
        [string]$RunContext
    )

    $subject  = Get-EmailSubject
    $bodyHtml = New-HtmlReport -Results $Results -RunContext $RunContext

    $mailParams = @{
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        From       = $MailFrom
        To         = $MailTo
        Subject    = $subject
        Body       = $bodyHtml
        BodyAsHtml = $true
    }

    try
    {
        Send-MailMessage @mailParams
        Write-SuccessMsg -Message "Report email sent to: $($MailTo -join ', ')"
    }
    catch
    {
        Write-ErrorMsg -Message "Failed to send report email: $($_.Exception.Message)"
    }
}

# ============================================================
# REGION: REMOTE SCRIPTBLOCK
# ============================================================

$RemoteDEPManagerScript =
{
    param
    (
        [int]$ExecuteRemote,
        [string]$TargetNxRemote,
        [int]$RebootRemote,
        [string]$HealthPortsCsvRemote,
        [string]$ServicePatternsCsvRemote,
        [string]$RequestedActionTextRemote
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    $executeRemoteBool = ($ExecuteRemote -eq 1)
    $rebootRemoteBool  = ($RebootRemote -eq 1)

    $HealthPortsRemote = @()

    if (-not [string]::IsNullOrWhiteSpace($HealthPortsCsvRemote))
    {
        $HealthPortsRemote = @(
            $HealthPortsCsvRemote.Split(",") |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [int]$_ }
        )
    }

    $ServiceNamePatternsRemote = @()

    if (-not [string]::IsNullOrWhiteSpace($ServicePatternsCsvRemote))
    {
        $ServiceNamePatternsRemote = @(
            $ServicePatternsCsvRemote.Split(";") |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [string]$_ }
        )
    }

    function Get-DEPPolicyText
    {
        param
        (
            [int]$Code
        )

        switch ($Code)
        {
            0       { return "AlwaysOff (Disabled)" }
            1       { return "AlwaysOn" }
            2       { return "OptIn (Default Windows Services)" }
            3       { return "OptOut (Exceptions Allowed)" }
            default { return "Unknown" }
        }
    }

    function Get-CurrentBcdNx
    {
        $nxValue = "UNKNOWN"

        try
        {
            $bcdOutput = & bcdedit.exe /enum "{current}" 2>&1

            foreach ($line in $bcdOutput)
            {
                $lineText = [string]$line

                if ($lineText -match '^\s*nx\s+(\S+)\s*$')
                {
                    $nxValue = $Matches[1]
                    break
                }
            }
        }
        catch
        {
            $nxValue = "ERROR: $($_.Exception.Message)"
        }

        return $nxValue
    }

    function Get-CurrentDEPState
    {
        $code = -1

        try
        {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $code = [int]$os.DataExecutionPrevention_SupportPolicy
        }
        catch
        {
            try
            {
                $wmi = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                $code = [int]$wmi.DataExecutionPrevention_SupportPolicy
            }
            catch
            {
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

    function Test-PendingReboot
    {
        $pending = $false
        $reasonList = New-Object System.Collections.Generic.List[string]

        $rebootPendingPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        $wuRebootPath       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        $sessionManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

        try
        {
            if (Test-Path -Path $rebootPendingPath)
            {
                $pending = $true
                $reasonList.Add($rebootPendingPath) | Out-Null
            }
        }
        catch
        {
        }

        try
        {
            if (Test-Path -Path $wuRebootPath)
            {
                $pending = $true
                $reasonList.Add($wuRebootPath) | Out-Null
            }
        }
        catch
        {
        }

        try
        {
            if (Test-Path -Path $sessionManagerPath)
            {
                $sessionManager = Get-ItemProperty -Path $sessionManagerPath -ErrorAction SilentlyContinue

                if ($null -ne $sessionManager.PendingFileRenameOperations)
                {
                    $pending = $true
                    $reasonList.Add("PendingFileRenameOperations") | Out-Null
                }
            }
        }
        catch
        {
        }

        [PSCustomObject]@{
            Pending = $pending
            Reasons = ($reasonList -join "; ")
        }
    }

    function Test-LocalTcpPort
    {
        param
        (
            [int]$Port
        )

        $result = "Closed"

        try
        {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(1000, $false)

            if ($wait -and $client.Connected)
            {
                $client.EndConnect($async)
                $result = "Open"
            }

            $client.Close()
        }
        catch
        {
            $result = "Error"
        }

        return $result
    }

    function Get-NodeHealth
    {
        param
        (
            [int[]]$HealthPorts,
            [string[]]$ServiceNamePatterns
        )

        $pendingRebootInfo = Test-PendingReboot

        $uptimeDays = "UNKNOWN"

        try
        {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $lastBoot = $os.LastBootUpTime
            $uptime = New-TimeSpan -Start $lastBoot -End (Get-Date)
            $uptimeDays = [math]::Round($uptime.TotalDays, 2)
        }
        catch
        {
            try
            {
                $osWmi = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                $lastBootWmi = $osWmi.ConvertToDateTime($osWmi.LastBootUpTime)
                $uptimeWmi = New-TimeSpan -Start $lastBootWmi -End (Get-Date)
                $uptimeDays = [math]::Round($uptimeWmi.TotalDays, 2)
            }
            catch
            {
                $uptimeDays = "UNKNOWN"
            }
        }

        $matchedServices = @()

        try
        {
            $allServices = Get-Service -ErrorAction Stop

            $matchedServices = $allServices | Where-Object {
                $svc = $_
                $matched = $false

                foreach ($pattern in $ServiceNamePatterns)
                {
                    if ($svc.Name -like $pattern -or $svc.DisplayName -like $pattern)
                    {
                        $matched = $true
                        break
                    }
                }

                $matched
            }
        }
        catch
        {
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

        $swTotal   = @($solarWindsServices).Count
        $swRunning = @($solarWindsServices | Where-Object { $_.Status -eq "Running" }).Count
        $swStopped = @($solarWindsServices | Where-Object { $_.Status -eq "Stopped" }).Count
        $swOther   = $swTotal - $swRunning - $swStopped

        $swDetails = "No SolarWinds-like services matched"

        if ($swTotal -gt 0)
        {
            $swDetails = ($solarWindsServices |
                Sort-Object -Property DisplayName |
                ForEach-Object { "$($_.Name)=$($_.Status)" }) -join "; "
        }

        $iisDetails = "No IIS services matched"

        if (@($iisServices).Count -gt 0)
        {
            $iisDetails = ($iisServices |
                Sort-Object -Property Name |
                ForEach-Object { "$($_.Name)=$($_.Status)" }) -join "; "
        }

        $portResults = New-Object System.Collections.Generic.List[string]

        foreach ($port in $HealthPorts)
        {
            $portStatus = Test-LocalTcpPort -Port $port
            $portResults.Add("${port}=${portStatus}") | Out-Null
        }

        $healthSummary = "OK"

        if ($pendingRebootInfo.Pending)
        {
            $healthSummary = "WARN_PENDING_REBOOT"
        }

        if ($swTotal -gt 0 -and $swStopped -gt 0)
        {
            if ($healthSummary -eq "OK")
            {
                $healthSummary = "WARN_STOPPED_SOLARWINDS_SERVICES"
            }
            else
            {
                $healthSummary = "${healthSummary}; WARN_STOPPED_SOLARWINDS_SERVICES"
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

    function Set-BcdNx
    {
        param
        (
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

    if ($executeRemoteBool)
    {
        $remoteInvocationMode = "EXECUTION"
    }

    $preState  = Get-CurrentDEPState
    $preHealth = Get-NodeHealth -HealthPorts $HealthPortsRemote -ServiceNamePatterns $ServiceNamePatternsRemote

    $needsChange = $true

    if ($preState.NX_Config -eq $TargetNxRemote)
    {
        $needsChange = $false
    }

    $changeAttempted = $false
    $action          = "DRY RUN - No Change"
    $bcdeditResult   = "No change attempted"
    $bcdeditExitCode = "N/A"
    $rebootAction    = "Not Requested"

    if ($rebootRemoteBool -and -not $executeRemoteBool)
    {
        $rebootAction = "Dry Run - Reboot Not Triggered"
    }

    if ($executeRemoteBool -and $needsChange)
    {
        $changeAttempted = $true
        $setResult = Set-BcdNx -NxValue $TargetNxRemote
        $bcdeditResult = $setResult.Output
        $bcdeditExitCode = $setResult.ExitCode

        if ($setResult.ExitCode -eq 0)
        {
            $action = "CHANGED"

            if ($rebootRemoteBool)
            {
                $rebootAction = "Pending Local Reboot Trigger"
            }
        }
        else
        {
            $action = "ERROR"
            throw "bcdedit failed with exit code $($setResult.ExitCode): $($setResult.Output)"
        }
    }
    elseif ($executeRemoteBool -and -not $needsChange)
    {
        $action = "NO CHANGE - Already Target"

        if ($rebootRemoteBool)
        {
            $rebootAction = "Not Triggered - No Change Needed"
        }
    }

    Start-Sleep -Seconds 2

    $postState  = Get-CurrentDEPState
    $postHealth = Get-NodeHealth -HealthPorts $HealthPortsRemote -ServiceNamePatterns $ServiceNamePatternsRemote

    $driftStatus = "N/A"

    if ($postState.NX_Config -eq $TargetNxRemote)
    {
        if ($executeRemoteBool -and $changeAttempted)
        {
            $driftStatus = "BOOTCFG_COMPLIANT_REBOOT_REQUIRED"
        }
        elseif ($executeRemoteBool -and -not $changeAttempted)
        {
            $driftStatus = "BOOTCFG_ALREADY_COMPLIANT"
        }
        else
        {
            $driftStatus = "DRYRUN_TARGET_MATCH"
        }
    }
    else
    {
        if ($executeRemoteBool)
        {
            $driftStatus = "DRIFT_BOOTCFG_NOT_TARGET"
        }
        else
        {
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
        RebootRequested                 = $rebootRemoteBool
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
        Timestamp                       = (Get-Date)
    }
}

# ============================================================
# REGION: EXECUTION WRAPPER
# ============================================================

function Invoke-DEPBatch
{
    param
    (
        [string[]]$TargetServers,
        [bool]$ExecuteBatch,
        [string]$InvocationModeLabel
    )

    $batchResults    = New-Object System.Collections.Generic.List[object]
    $approvedServers = New-Object System.Collections.Generic.List[string]

    foreach ($server in $TargetServers)
    {
        if ($ExecuteBatch)
        {
            $shouldProcessMessage = "Set DEP boot NX value to ${TargetNxDefault}"

            if ($PSCmdlet.ShouldProcess($server, $shouldProcessMessage))
            {
                $approvedServers.Add($server) | Out-Null
            }
            else
            {
                $whatIfParams = @{
                    Server         = $server
                    InvocationMode = $InvocationModeLabel
                    Action         = "WHATIF - Not Executed"
                    Message        = "ShouldProcess returned false; no remote change attempted."
                    DriftStatus    = "WHATIF"
                    TargetNx       = $TargetNxDefault
                }

                $batchResults.Add((New-LocalResultObject @whatIfParams)) | Out-Null
            }
        }
        else
        {
            $approvedServers.Add($server) | Out-Null
        }
    }

    if ($approvedServers.Count -eq 0)
    {
        Write-WarnMsg -Message "No servers approved for processing."
        return @($batchResults)
    }

    $executeInt = 0
    if ($ExecuteBatch)
    {
        $executeInt = 1
    }

    $rebootInt = 0
    if ($RebootRequested)
    {
        $rebootInt = 1
    }

    if ($Parallel)
    {
        Write-InfoMsg -Message "Starting parallel processing with ThrottleLimit ${ThrottleLimit}."

        $pendingServers = New-Object System.Collections.Generic.Queue[string]

        foreach ($server in $approvedServers)
        {
            $pendingServers.Enqueue($server)
        }

        $jobs = New-Object System.Collections.Generic.List[object]

        while ($pendingServers.Count -gt 0 -or @($jobs | Where-Object { $_.State -eq "Running" }).Count -gt 0)
        {
            while ($pendingServers.Count -gt 0 -and @($jobs | Where-Object { $_.State -eq "Running" }).Count -lt $ThrottleLimit)
            {
                $serverToStart = $pendingServers.Dequeue()

                Write-InfoMsg -Message "Starting remote job for ${serverToStart}"

                try
                {
                    $invokeParams = @{
                        ComputerName = $serverToStart
                        ScriptBlock  = $RemoteDEPManagerScript
                        ArgumentList = @(
                            [int]$executeInt,
                            [string]$TargetNxDefault,
                            [int]$rebootInt,
                            [string]$HealthPortsCsv,
                            [string]$ServicePatternsCsv,
                            [string]$RequestedActionText
                        )
                        AsJob        = $true
                        ErrorAction  = "Stop"
                    }

                    $job = Invoke-Command @invokeParams
                    $jobs.Add($job) | Out-Null
                }
                catch
                {
                    $errorParams = @{
                        Server         = $serverToStart
                        InvocationMode = $InvocationModeLabel
                        Action         = "ERROR"
                        Message        = $_.Exception.Message
                        DriftStatus    = "ERROR"
                        TargetNx       = $TargetNxDefault
                    }

                    $batchResults.Add((New-LocalResultObject @errorParams)) | Out-Null
                }
            }

            Start-Sleep -Milliseconds 500

            $completedJobs = @($jobs | Where-Object { $_.State -ne "Running" })

            foreach ($completedJob in $completedJobs)
            {
                $location = $completedJob.Location

                try
                {
                    $received = Receive-Job -Job $completedJob -ErrorAction Stop

                    foreach ($item in $received)
                    {
                        $batchResults.Add((ConvertTo-DEPResult -InputObject $item)) | Out-Null
                    }
                }
                catch
                {
                    $errorParams = @{
                        Server         = $location
                        InvocationMode = $InvocationModeLabel
                        Action         = "ERROR"
                        Message        = $_.Exception.Message
                        DriftStatus    = "ERROR"
                        TargetNx       = $TargetNxDefault
                    }

                    $batchResults.Add((New-LocalResultObject @errorParams)) | Out-Null
                }

                Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue

                $remainingJobs = New-Object System.Collections.Generic.List[object]

                foreach ($existingJob in $jobs)
                {
                    if ($existingJob.Id -ne $completedJob.Id)
                    {
                        $remainingJobs.Add($existingJob) | Out-Null
                    }
                }

                $jobs = $remainingJobs
            }
        }
    }
    else
    {
        Write-InfoMsg -Message "Starting sequential processing."

        foreach ($server in $approvedServers)
        {
            Write-InfoMsg -Message "Processing ${server}"

            try
            {
                $invokeParams = @{
                    ComputerName = $server
                    ScriptBlock  = $RemoteDEPManagerScript
                    ArgumentList = @(
                        [int]$executeInt,
                        [string]$TargetNxDefault,
                        [int]$rebootInt,
                        [string]$HealthPortsCsv,
                        [string]$ServicePatternsCsv,
                        [string]$RequestedActionText
                    )
                    ErrorAction  = "Stop"
                }

                $remoteResult = Invoke-Command @invokeParams

                foreach ($item in $remoteResult)
                {
                    $batchResults.Add((ConvertTo-DEPResult -InputObject $item)) | Out-Null
                }
            }
            catch
            {
                Write-ErrorMsg -Message "${server} failed: $($_.Exception.Message)"

                $errorParams = @{
                    Server         = $server
                    InvocationMode = $InvocationModeLabel
                    Action         = "ERROR"
                    Message        = $_.Exception.Message
                    DriftStatus    = "ERROR"
                    TargetNx       = $TargetNxDefault
                }

                $batchResults.Add((New-LocalResultObject @errorParams)) | Out-Null
            }
        }
    }

    if ($ExecuteBatch)
    {
        Invoke-PostExecutionReboots -ExecutionResults $batchResults
    }

    return @($batchResults)
}

# ============================================================
# REGION: MAIN FLOW
# ============================================================

$AllResults = New-Object System.Collections.Generic.List[object]

if ($Execute)
{
    Write-InfoMsg -Message "Execution mode specified. Running execution directly."

    $executionParams = @{
        TargetServers      = $ComputerName
        ExecuteBatch       = $true
        InvocationModeLabel = "EXECUTION"
    }

    $executionResults = Invoke-DEPBatch @executionParams

    foreach ($result in $executionResults)
    {
        $AllResults.Add($result) | Out-Null
    }

    Write-RunSummary -ResultsToSummarize $executionResults -SummaryTitle "DEP Manager v${ScriptVersion} Execution Summary"
}
else
{
    Write-InfoMsg -Message "No -Execute specified. Running dry run first."

    $dryRunParams = @{
        TargetServers      = $ComputerName
        ExecuteBatch       = $false
        InvocationModeLabel = "DRY RUN"
    }

    $dryRunResults = Invoke-DEPBatch @dryRunParams

    foreach ($result in $dryRunResults)
    {
        $AllResults.Add($result) | Out-Null
    }

    Write-RunSummary -ResultsToSummarize $dryRunResults -SummaryTitle "DEP Manager v${ScriptVersion} Dry Run Summary"

    $menuDecision = Show-DryRunExecutionMenu -DryRunResults $dryRunResults

    if ($menuDecision -eq "Execute")
    {
        $serversToExecute = @(
            $dryRunResults |
                Where-Object { $_.Reachable -eq $true -and $_.Needs_Change -eq $true } |
                Select-Object -ExpandProperty Server -Unique
        )

        Write-Host ""
        Write-Host "Executing DEP changes against $($serversToExecute.Count) server(s) identified by dry run." -ForegroundColor Yellow
        Write-Host ""

        $menuExecutionParams = @{
            TargetServers      = $serversToExecute
            ExecuteBatch       = $true
            InvocationModeLabel = "EXECUTION_FROM_DRYRUN_MENU"
        }

        $executionResultsFromMenu = Invoke-DEPBatch @menuExecutionParams

        foreach ($result in $executionResultsFromMenu)
        {
            $AllResults.Add($result) | Out-Null
        }

        Write-RunSummary -ResultsToSummarize $executionResultsFromMenu -SummaryTitle "DEP Manager v${ScriptVersion} Menu Execution Summary"
    }
    else
    {
        Write-InfoMsg -Message "User selected exit or no changes were required. No execution performed."
    }
}

# ============================================================
# REGION: EXPORT AND FINAL SUMMARY
# ============================================================

$ResultsSorted = $AllResults | Sort-Object -Property Server, InvocationMode

$ResultsSorted | Export-Csv -Path $ReportPath -NoTypeInformation

$RunContext = (@($ResultsSorted | Select-Object -ExpandProperty InvocationMode -Unique) -join ", ")
if ([string]::IsNullOrWhiteSpace($RunContext))
{
    $RunContext = $ModeText
}

Send-DEPReportEmail -Results @($ResultsSorted) -RunContext $RunContext

$ScriptEnd = Get-Date
$Duration = New-TimeSpan -Start $ScriptStart -End $ScriptEnd

Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " DEP Manager v${ScriptVersion} Final Summary"                 -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " Total Rows     : $(@($ResultsSorted).Count)"
Write-Host " Duration       : $($Duration.ToString())"
Write-Host " Report         : ${ReportPath}"
Write-Host " Transcript     : ${TranscriptPath}"
Write-Host " Log            : ${LogPath}"
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""

$ResultsSorted |
    Select-Object $ResultColumns |
    Format-Table -AutoSize

try
{
    Stop-Transcript | Out-Null
}
catch
{
}
