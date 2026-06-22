# =====================================================================
# Script      : Set-SQLServiceEncryptionTypes.ps1
# Author      : Alan W. Phillips
# Date        : 06-10-2026
# Version     : 1.0.0
# Description : Sets the msDS-SupportedEncryptionTypes attribute to 0x18
#               (AES128 + AES256 = decimal 24) on user objects in a target
#               OU. Any object whose current value is a designated skip
#               value (0 or 24) is left unchanged. Every object is logged
#               with its prior value, the action taken, and the resulting
#               status. Results are written to a CSV log and emailed as a
#               color-coded HTML report.
# Requirements: PowerShell 5.1, ActiveDirectory module, and rights to
#               modify msDS-SupportedEncryptionTypes on the target objects.
# =====================================================================
# Change Log:
#   1.0.0 - 06-10-2026 - Initial canonical release. Rebuilt from SQL0x18.ps1:
#                        fixed hyphenated attribute access (was parsed as a
#                        subtraction), removed backtick line continuations,
#                        broadened filter to all users in the OU, added a
#                        DryRun guard, file + console logging, log retention,
#                        HTML email reporting, and a full helper-function
#                        structure.
# =====================================================================

# ============================================================
# REGION: VARIABLES
# ============================================================

$ScriptName    = 'Set-SQLServiceEncryptionTypes'
$FriendlyDate  = Get-Date -Format 'MM-dd-yyyy'
$RunTimestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'

# --- Behavior toggles -------------------------------------------------
$DryRun          = $false     # $true = report only; set $false to apply changes.
$UseConsoleIcons = $true      # Icons always render in HTML; console only when $true.

# --- Target scope -----------------------------------------------------
$SearchBase     = 'OU=SQLService,OU=Services,OU=Accounts,DC=uhhs,DC=com'
#$SearchBase     = 'OU=Services,OU=Accounts,DC=uhhs,DC=com'
$SearchScope    = 'Subtree'    # OU and everything beneath it.
$UserFilter = '*'             # All user objects in the OU.
                               # Original (svc accounts only):
                               # $UserFilter = "Enabled -eq `$true -and SamAccountName -like 'svc*'"
                               # $UserFilter = "Enabled -eq `$true -and SamAccountName -like 'svc_sqlentraconnect'"

# --- Encryption type rules --------------------------------------------
$TargetValue    = 24           # 0x18 = AES128 (8) + AES256 (16).
$SkipValues     = @(0, 24)     # Current values that are left unchanged.

# --- Logging / output paths -------------------------------------------
$LogDirectory   = 'C:\Temp\EncryptionTypeReports'
$LogFilePath    = Join-Path -Path $LogDirectory -ChildPath ('{0}-{1}.log'  -f $ScriptName, $RunTimestamp)
$CsvPath        = Join-Path -Path $LogDirectory -ChildPath ('{0}-{1}.csv'  -f $ScriptName, $RunTimestamp)
$HtmlPath       = Join-Path -Path $LogDirectory -ChildPath ('{0}-{1}.html' -f $ScriptName, $RunTimestamp)
$RetentionKeep  = 2            # Most recent files of each type to retain.

# --- SMTP configuration (open relay, no authentication) ---------------
$SmtpServer     = 'smtp.uhhs.com'
$SmtpPort       = 25
$MailFrom       = 'AD-Automation@uhhs.com'
$MailTo         = @(
                    'Alan.Phillips@UHhospitals.org'
                   #,'David.Butcher@UHhospitals.org'
                   #,'Mari.Eustace@UHhospitals.org'
                   #,'Jeffrey.Altomari@UHhospitals.org'
                   #,'Randall.Richards@UHhospitals.org'
                  )

# --- Unicode status icons --------------------------------------------
$Icons = @{
    Info   = [char]::ConvertFromUtf32(0x2139)   # info
    OK     = [char]::ConvertFromUtf32(0x2714)   # check mark
    Warn   = [char]::ConvertFromUtf32(0x26A0)   # warning
    Error  = [char]::ConvertFromUtf32(0x2716)   # cross mark
    DryRun = [char]::ConvertFromUtf32(0x25B6)   # play arrow
    Skip   = [char]::ConvertFromUtf32(0x2796)   # heavy minus
}

# --- Runtime result store --------------------------------------------
$Results = @()

# ============================================================
# REGION: LOGGING FUNCTIONS
# ============================================================

function Write-Log
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Line  = '{0}  {1}' -f $Stamp, $Message

    Add-Content -Path $LogFilePath -Value $Line -Encoding UTF8
}

function Write-ConsoleLine
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [System.ConsoleColor]$Color,

        [Parameter(Mandatory = $false)]
        [string]$Icon = ''
    )

    # File log and aligned prefixes never carry icons.
    $FileText = '[{0}] {1}' -f $Prefix, $Message
    Write-Log -Message $FileText

    $ConsoleText = $FileText

    if ($UseConsoleIcons -and $Icon -ne '')
    {
        $ConsoleText = '[{0}] {1} {2}' -f $Prefix, $Icon, $Message
    }

    Write-Host $ConsoleText -ForegroundColor $Color
}

function Write-InfoMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-ConsoleLine -Prefix 'INFO ' -Message $Message -Color Cyan -Icon $Icons.Info
}

function Write-SuccessMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-ConsoleLine -Prefix 'OK   ' -Message $Message -Color Green -Icon $Icons.OK
}

function Write-WarnMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-ConsoleLine -Prefix 'WARN ' -Message $Message -Color Yellow -Icon $Icons.Warn
}

function Write-ErrorMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-ConsoleLine -Prefix 'ERROR' -Message $Message -Color Red -Icon $Icons.Error
}

function Write-DryRunMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-ConsoleLine -Prefix 'DRYRUN' -Message $Message -Color Magenta -Icon $Icons.DryRun
}

# ============================================================
# REGION: SUPPORT FUNCTIONS
# ============================================================

function Get-EmailSubject
{
    return ('{0} - {1}' -f $ScriptName, $FriendlyDate)
}

function Format-EncValue
{
    param
    (
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value)
    {
        return 'Not Set'
    }

    return ('{0} (0x{1:X})' -f [int]$Value, [int]$Value)
}

function Initialize-LogDirectory
{
    if (-not (Test-Path -Path $LogDirectory))
    {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }
}

function Invoke-LogRetention
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Directory,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [int]$Keep
    )

    if (-not (Test-Path -Path $Directory))
    {
        return
    }

    $GetParams = @{
        Path        = $Directory
        Filter      = $Pattern
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }

    $Files = Get-ChildItem @GetParams | Sort-Object -Property LastWriteTime -Descending

    if ($Files.Count -le $Keep)
    {
        return
    }

    $Stale = $Files | Select-Object -Skip $Keep

    foreach ($File in $Stale)
    {
        try
        {
            Remove-Item -Path $File.FullName -Force -ErrorAction Stop
            Write-InfoMsg -Message ('Retention - removed old file {0}' -f $File.Name)
        }
        catch
        {
            Write-WarnMsg -Message ('Retention - could not remove {0} - {1}' -f $File.Name, $_.Exception.Message)
        }
    }
}

function Import-ADModule
{
    if (Get-Module -Name ActiveDirectory)
    {
        return $true
    }

    try
    {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
        return $true
    }
    catch
    {
        Write-ErrorMsg -Message ('Unable to load the ActiveDirectory module - {0}' -f $_.Exception.Message)
        return $false
    }
}

function Get-TargetUsers
{
    $GetParams = @{
        SearchBase  = $SearchBase
        SearchScope = $SearchScope
        Filter      = $UserFilter
        Properties  = @('msDS-SupportedEncryptionTypes', 'DistinguishedName', 'Enabled')
        ErrorAction = 'Stop'
    }

    return Get-ADUser @GetParams
}

function Set-UserEncryptionType
{
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )

    $Sam           = $User.SamAccountName
    $CurrentValue  = $User.'msDS-SupportedEncryptionTypes'
    $PrevDisplay   = Format-EncValue -Value $CurrentValue
    $TargetDisplay = Format-EncValue -Value $TargetValue

    if ($null -ne $CurrentValue -and ($SkipValues -contains [int]$CurrentValue))
    {
        Write-InfoMsg -Message ('{0} - current {1} - skipped (designated skip value)' -f $Sam, $PrevDisplay)

        return [PSCustomObject]@{
            SamAccountName    = $Sam
            DistinguishedName = $User.DistinguishedName
            PreviousValue     = $PrevDisplay
            NewValue          = $PrevDisplay
            Action            = 'Skipped'
            Status            = 'NoChange'
        }
    }

    if ($DryRun)
    {
        Write-DryRunMsg -Message ('{0} - current {1} - would set to {2}' -f $Sam, $PrevDisplay, $TargetDisplay)

        return [PSCustomObject]@{
            SamAccountName    = $Sam
            DistinguishedName = $User.DistinguishedName
            PreviousValue     = $PrevDisplay
            NewValue          = $TargetDisplay
            Action            = 'Would Set to 0x18'
            Status            = 'DryRun'
        }
    }

    try
    {
        $SetParams = @{
            Identity    = $User.DistinguishedName
            Replace     = @{ 'msDS-SupportedEncryptionTypes' = $TargetValue }
            ErrorAction = 'Stop'
        }

        Set-ADUser @SetParams

        Write-SuccessMsg -Message ('{0} - changed from {1} to {2}' -f $Sam, $PrevDisplay, $TargetDisplay)

        return [PSCustomObject]@{
            SamAccountName    = $Sam
            DistinguishedName = $User.DistinguishedName
            PreviousValue     = $PrevDisplay
            NewValue          = $TargetDisplay
            Action            = 'Set to 0x18'
            Status            = 'Updated'
        }
    }
    catch
    {
        Write-ErrorMsg -Message ('{0} - failed to set value - {1}' -f $Sam, $_.Exception.Message)

        return [PSCustomObject]@{
            SamAccountName    = $Sam
            DistinguishedName = $User.DistinguishedName
            PreviousValue     = $PrevDisplay
            NewValue          = $TargetDisplay
            Action            = 'Attempted Set'
            Status            = 'Failed'
        }
    }
}

function Get-StatusColor
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status)
    {
        'Updated'  { return '#1B7F3B' }
        'NoChange' { return '#6C757D' }
        'DryRun'   { return '#0B5FA5' }
        'Failed'   { return '#B00020' }
        default    { return '#000000' }
    }
}

function Get-StatusIcon
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status)
    {
        'Updated'  { return $Icons.OK }
        'NoChange' { return $Icons.Skip }
        'DryRun'   { return $Icons.DryRun }
        'Failed'   { return $Icons.Error }
        default    { return '' }
    }
}

function Build-HtmlReport
{
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$ResultSet
    )

    $Updated  = @($ResultSet | Where-Object { $_.Status -eq 'Updated'  }).Count
    $NoChange = @($ResultSet | Where-Object { $_.Status -eq 'NoChange' }).Count
    $DryRunN  = @($ResultSet | Where-Object { $_.Status -eq 'DryRun'   }).Count
    $Failed   = @($ResultSet | Where-Object { $_.Status -eq 'Failed'   }).Count
    $Total    = $ResultSet.Count
    $ModeText = if ($DryRun) { 'DRY RUN (no changes written)' } else { 'LIVE (changes applied)' }

    $Rows = ''

    foreach ($Row in $ResultSet)
    {
        $Color = Get-StatusColor -Status $Row.Status
        $Icon  = Get-StatusIcon  -Status $Row.Status

        $Rows += @"
        <tr>
            <td>$($Row.SamAccountName)</td>
            <td>$($Row.PreviousValue)</td>
            <td>$($Row.NewValue)</td>
            <td>$($Row.Action)</td>
            <td style="color:$Color;font-weight:bold;">$Icon $($Row.Status)</td>
        </tr>
"@
    }

    $Html = @"
<html>
<head>
<style>
    body  { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; color: #222; }
    h2    { color: #0B5FA5; margin-bottom: 4px; }
    .meta { color: #555; margin-bottom: 14px; }
    .summary td { padding: 4px 14px 4px 0; }
    table.detail { border-collapse: collapse; width: 100%; margin-top: 10px; }
    table.detail th { background: #0B5FA5; color: #fff; text-align: left; padding: 6px 10px; }
    table.detail td { border-bottom: 1px solid #ddd; padding: 6px 10px; }
    table.detail tr:nth-child(even) { background: #f5f7fa; }
</style>
</head>
<body>
    <h2>msDS-SupportedEncryptionTypes Report</h2>
    <div class="meta">
        Run mode: <b>$ModeText</b><br/>
        Target OU: $SearchBase<br/>
        Target value: $(Format-EncValue -Value $TargetValue) &nbsp;|&nbsp; Skip values: $($SkipValues -join ', ')<br/>
        Generated: $FriendlyDate
    </div>
    <table class="summary">
        <tr>
            <td><b>Total processed:</b> $Total</td>
            <td style="color:#1B7F3B;"><b>Updated:</b> $Updated</td>
            <td style="color:#0B5FA5;"><b>DryRun:</b> $DryRunN</td>
            <td style="color:#6C757D;"><b>Unchanged:</b> $NoChange</td>
            <td style="color:#B00020;"><b>Failed:</b> $Failed</td>
        </tr>
    </table>
    <table class="detail">
        <tr>
            <th>SamAccountName</th>
            <th>Previous Value</th>
            <th>New Value</th>
            <th>Action</th>
            <th>Status</th>
        </tr>
$Rows
    </table>
</body>
</html>
"@

    return $Html
}

function Send-ReportEmail
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$HtmlBody
    )

    $MailParams = @{
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        From       = $MailFrom
        To         = $MailTo
        Subject    = (Get-EmailSubject)
        Body       = $HtmlBody
        BodyAsHtml = $true
        Encoding   = 'UTF8'
    }

    if (Test-Path -Path $CsvPath)
    {
        $MailParams.Attachments = $CsvPath
    }

    try
    {
        Send-MailMessage @MailParams
        Write-SuccessMsg -Message ('Report email sent to {0}' -f ($MailTo -join ', '))
    }
    catch
    {
        Write-ErrorMsg -Message ('Failed to send report email - {0}' -f $_.Exception.Message)
    }
}

# ============================================================
# REGION: MAIN
# ============================================================

Initialize-LogDirectory

$ModeLabel = if ($DryRun) { 'DRY RUN (no changes will be written)' } else { 'LIVE (changes will be applied)' }
Write-InfoMsg -Message ('Starting {0} in {1}' -f $ScriptName, $ModeLabel)
Write-InfoMsg -Message ('Target OU {0} (scope {1}); target value {2}; skip values {3}' -f $SearchBase, $SearchScope, (Format-EncValue -Value $TargetValue), ($SkipValues -join ', '))

if (Import-ADModule)
{
    try
    {
        $Users = Get-TargetUsers
        Write-InfoMsg -Message ('Retrieved {0} user object(s) from the target OU' -f @($Users).Count)

        foreach ($User in $Users)
        {
            $Results += Set-UserEncryptionType -User $User
        }

        if ($Results.Count -gt 0)
        {
            $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-InfoMsg -Message ('CSV log written to {0}' -f $CsvPath)
        }
        else
        {
            Write-WarnMsg -Message 'No user objects were found to process.'
        }

        $HtmlBody = Build-HtmlReport -ResultSet $Results
        Set-Content -Path $HtmlPath -Value $HtmlBody -Encoding UTF8
        Write-InfoMsg -Message ('HTML report written to {0}' -f $HtmlPath)

        Invoke-LogRetention -Directory $LogDirectory -Pattern ('{0}-*.log'  -f $ScriptName) -Keep $RetentionKeep
        Invoke-LogRetention -Directory $LogDirectory -Pattern ('{0}-*.csv'  -f $ScriptName) -Keep $RetentionKeep
        Invoke-LogRetention -Directory $LogDirectory -Pattern ('{0}-*.html' -f $ScriptName) -Keep $RetentionKeep

        Send-ReportEmail -HtmlBody $HtmlBody

        $Updated  = @($Results | Where-Object { $_.Status -eq 'Updated'  }).Count
        $NoChange = @($Results | Where-Object { $_.Status -eq 'NoChange' }).Count
        $DryRunN  = @($Results | Where-Object { $_.Status -eq 'DryRun'   }).Count
        $Failed   = @($Results | Where-Object { $_.Status -eq 'Failed'   }).Count

        Write-InfoMsg -Message ('Summary - Total {0} | Updated {1} | DryRun {2} | Unchanged {3} | Failed {4}' -f $Results.Count, $Updated, $DryRunN, $NoChange, $Failed)
    }
    catch
    {
        Write-ErrorMsg -Message ('Processing halted - {0}' -f $_.Exception.Message)
    }
}