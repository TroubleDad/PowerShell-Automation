# ===========================================================================
#
# Name           : CertificateExpiryReport.ps1
# Author         : Alan Phillips
# Version        : 4.7.0
# Date           : 06/17/2026
#
# Requires       : PowerShell Remoting enabled for remote systems
#                  Python 3 + openpyxl  (for Excel export)
#                    Install: pip install openpyxl
#
# Purpose        : Enterprise certificate discovery, parallel scanning,
#                  rich reporting, EKU classification, full logging,
#                  filtered HTML alerting, and color-formatted Excel export
#
# Change Log
#
#   4.7.0  - Hardened the script for execution under Set-StrictMode -Version 2.0
#            (now declared explicitly after the param block so behavior no longer
#            depends on the launching session).
#          - Fixed a long-standing output leak in Invoke-CertScan: the six
#            $ps.AddArgument(...) calls returned the PowerShell instance into the
#            output stream, polluting $results with [powershell] objects. Each is
#            now cast to [void].
#          - MAIN result filter changed from Where-Object { $_.Status } to
#            Where-Object { $_.Result -eq 'Success' }; the old form referenced a
#            property absent on Unreachable/Failed records, which throws under
#            strict mode.
#          - All collection counts wrapped as @( ... ).Count so a zero- or
#            one-element pipeline result no longer collapses to a scalar/null and
#            throws PropertyNotFoundStrict under strict mode.
#   4.6.0  - Template column now shows the certificate template's friendly
#            (display) name instead of the raw template OID. Added
#            Get-CertificateTemplateMap, which builds an OID / common-name ->
#            display-name lookup from the AD Certificate Templates container
#            (CN=Certificate Templates,CN=Public Key Services,CN=Services in
#            the Configuration partition). The remote scan now returns the raw
#            template OID (V2 extension) and common name (V1 extension); the
#            friendly name is resolved on the calling side, where AD is
#            reachable. Falls back to common name, then the raw extension
#            value, then 'N/A'.
#   4.5.4  - Cert report HTML sort refined: non-expired certs first by days
#            ascending, then expired certs below ordered closest-to-zero first
#            (e.g. -1919 before -2905).
#   4.5.3  - Email body now sorts by Days remaining, descending.
#   4.5.2  - All logs/output now write to a CertReportFiles subdirectory beneath
#            the script location (silently created); removed the C:\Temp default.
#          - Dropped *.csv from the log cleanup extension list.
#          - Email body cells set to one row high (no wrap), including Issuer.
#          - Cert report HTML now sorts by Days remaining, ascending.
#   4.5.1  - Removed CSV creation and attachment ($CsvPath retired); the Excel
#            workbook is now the first attachment.
#          - Moved the Template Name column to the end of the email body table.
#          - Tightened the cert report HTML cells (smaller padding/font, single
#            line spacing) for a denser, single-spaced layout.
#   4.5.0  - Added a color-coded HTML version of the certificate report
#            (Write-CertReportHtml); it is attached alongside the Excel workbook.
#          - Scan now reads the certificate Template Name (V2 template-info, then
#            V1 template-name extension) on the remote side; EKU usage is also
#            classified remotely.
#          - Added a Template Name column to the cert report HTML attachment and
#            to the email body table.
#          - Converted the remaining Section banners to canonical # REGION:
#            format (Option C).
#   4.4.3  - Converted all region banners to the canonical format
#            (# REGION: <NAME>) with bars matching the header bar length (75 =);
#            normalized one blank line before and after each region.
#   4.4.2  - Added $ExcludedOUPaths (full-DN exclusion list) and excluded the
#            uhhs.com/zMaintenance OU subtree from discovery.
#          - Reformatted the $EmailTo array to one recipient per line.
#   4.4.1  - Unreachable matrix OU column now shows the friendly canonical path
#            (e.g. uhhs.com/Machines/WebServers) instead of the DN form.
#            Get-ServerList requests CanonicalName; Get-ParentOU derives the
#            parent OU from it.
#   4.4.0  - AD discovery now skips computer objects under the CTX, CTX-Test,
#            ThinClients, VDI, and Workstations sub-OUs of OU=Machines (and any
#            OUs nested beneath them); excluded sub-OUs are set via $ExcludedSubOUs.
#          - Get-ServerList now returns Name + parent OU per object (added the
#            Get-ParentOU helper); the OU is threaded through the runspace onto
#            the unreachable record.
#          - Added an OU column (before Detail) to the unreachable HTML matrix.
#   4.3.0  - Reworked the unreachable scan diagnostics to capture independent
#            category flags (NotInDns / NoPing / WinRMDown) instead of a single
#            reason string.
#          - Replaced the unreachable CSV attachment with a self-contained,
#            color-coded HTML matrix: one row per unique server, a column per
#            failure category, and a checkmark in each category that applies.
#          - Email body breakdown now counts servers per failure category.
#          - Added *.html to the log cleanup extensions.
#   4.2.0  - Unreachable servers now capture a categorized Reason (Host not
#            found / Not pingable / WinRM not available) plus a Detail string.
#          - Added a separate CSV attachment listing each unreachable server
#            with its Reason and Detail; attached to the email alongside the
#            existing CSV/XLSX.
#          - Added an "Unreachable Servers" breakdown table to the HTML body.
#          - Removed backtick line continuations (Sort-Object in Send-EmailReport
#            and the Export-ExcelReport call in MAIN) in favor of splatting.
#   4.1.0  - Added more name pattern matching for Epic certs.
#   4.0.0  - FINAL Revision.  Console & Email functions work as designed.
#   3.26.1 - Added Python install check function
#   3.26.0 - Added Excel (.xlsx) export as parallel output alongside CSV
#          - Two-sheet workbook: "Certificate Report" + "Execution Summary"
#          - Full color mapping from console output (status, issuer, days)
#          - Freeze panes + auto-filter on Certificate Report sheet
#          - Excel file attached to email alongside existing CSV attachment
#          - Excel generation via embedded Python/openpyxl (no extra PS modules)
#          - Falls back gracefully if Python/openpyxl unavailable (CSV still runs)
#   3.25.0 - Added Logfile Cleanup Function
#   3.24.9 - Finalized Script Reporting and Email Logic
#   3.24.8 - Fixed HTML Email formatting and sort issues
#   3.24.7 - Tweaked onscreen table layout and coloring issues
#   3.24.6 - ZERO REGRESSION CORRECTION BUILD
#   3.24.5 - FINAL DISPLAY REFINEMENT BUILD
#   3.24.4 - DISPLAY + OUTPUT CORRECTION BUILD
#   3.24.3 - REPORT COLOR CORRECTION (SERVER + ISSUER LOGIC UPDATE)
#   3.24.2 - TARGETED CORRECTION BUILD
#   3.24.1 - FULL VALIDATION RELEASE
#   3.23.8 - FULL VISUAL + STRUCTURAL RESTORATION
#   3.23.7 - FULL DRIFT CORRECTION REBUILD
#   3.23.6 - FULL RESTORATION (NO OMISSIONS)
#   3.23.5 - FUNCTION RESTORATION + API CORRECTION
#   3.23.4 - Header text + color update
#   3.23.3 - HTML email enhancement + summary integration
#   3.23.2 - REAL API CORRECTION
#   3.23.1 - Progress fix + full verification
#   3.23.0 - Email sort + global log alignment + API fix
#   3.22.5 - Summary formatting finalization
#   3.22.4 - FULL SCRIPT RESTORED
#   3.22.3 - Magenta highlight for non-UH expiring certs
#   3.22.2 - Final validated production build
#   3.22.1 - Removed menu, enforced AD discovery
#   3.22.0 - FINAL VERIFIED BUILD
#   3.21.3 - Runspace + collection stability fix
#   3.21.2 - Full integrity rebuild
#   3.21.1 - Summary alignment restoration
#   3.21.0 - Sorting fix + final validation pass
#   3.20.9 - Removed timeout constraint from remote execution
#   3.20.8 - REAL RUNSPACE API FINALIZATION
#   3.20.7 - Data model hardening + runtime stability fix
#   3.20.6 - Enterprise Full Rebuild
#   3.20.5 - Final completeness + visibility fix
#   3.20.4 - Engine + Reporting Merge
#   3.20.3 - TRUE FINAL BUILD
#   3.20.2 - Final stability + validation pass
#   3.20.1 - Restored Email Subsystem
#   3.20.0 - Enterprise optimization release
#   3.19.x - Various runspace + email fixes
#   3.18.x - HTML email + output path centralization
#   3.17.0 - Added CommonName column
#   3.16.x - Issuer coloring + AD discovery
#   3.12.x - Runspace conversion + AD integration
#
# ===========================================================================

param(
    [int]$DaysThreshold = 45
)

Set-StrictMode -Version 2.0

# ===========================================================================
# REGION: VARIABLES
# ===========================================================================

$ScriptStartTime  = Get-Date
$Now              = Get-Date
$ThrottleLimit    = 20
$StorePath        = 'Cert:\LocalMachine\My'
$ProgressActivity = 'Scanning Certificates'

# All logs and generated files are written to a CertReportFiles subdirectory
# beneath the script's own location. Fall back to the current directory if the
# script root cannot be resolved (e.g. run via console paste).
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$OutputPath = Join-Path -Path $ScriptRoot -ChildPath 'CertReportFiles'
if (!(Test-Path $OutputPath))
{
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$TimeStamp = $Now.ToString('yyyyMMdd_HHmmss')

$LogPath      = "$OutputPath\CertReport_$TimeStamp.log"
$ErrorLogPath = "$OutputPath\CertReport_${TimeStamp}_errors.log"
$XlsxPath     = "$OutputPath\CertReport_$TimeStamp.xlsx"

$UnreachablePath = "$OutputPath\CertReport_${TimeStamp}_unreachable.html"
$CertReportHtmlPath = "$OutputPath\CertReport_${TimeStamp}.html"

$ExpectedIssuer = 'University Hospitals Sub CA 3'

# Active Directory discovery scope. Computer objects under any of the listed
# sub-OUs of $MachinesOUBase (and their nested OUs) are skipped during scan.
$MachinesOUBase = 'OU=Machines,DC=uhhs,DC=com'
$ExcludedSubOUs = @('CTX','CTX-Test','ThinClients','VDI','Workstations')

# Additional OU subtrees to exclude, expressed as full distinguished names
# (for OUs that are not children of $MachinesOUBase). Nested OUs are also skipped.
$ExcludedOUPaths = @('OU=zMaintenance,DC=uhhs,DC=com')

$SMTPServer = 'smtp.uhhs.com'
$EmailTo    = @(
    'Alan.Phillips@UHhospitals.org',
    'Jeffrey.Altomari@UHhospitals.org'
)
$EmailFrom  = 'CERTALERT@UHhospitals.org'

# ===========================================================================
# REGION: IMPORTS
# ===========================================================================

$DependencyScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Ensure-PythonOpenPyXL.ps1"

if (-not (Test-Path -Path $DependencyScriptPath))
{
    throw "Dependency script not found at path: $DependencyScriptPath"
}

. $DependencyScriptPath


# ===========================================================================
# REGION: DEPENDENCY VALIDATION
# ===========================================================================

try
{
    Write-Host "[INFO] Ensuring Python and required modules are present..." -ForegroundColor Cyan

    Ensure-PythonOpenPyXL
}
catch
{
    Write-Host "[ERROR] Dependency validation failed: $_" -ForegroundColor Red
    throw
}


# ===========================================================================
# REGION: VARIABLES
# ===========================================================================

$ReportPath = Join-Path -Path $PSScriptRoot -ChildPath "CertificateReport.xlsx"


# ===========================================================================
# REGION: FUNCTIONS
# ===========================================================================

function Get-CertificateData
{
    # Existing logic here
}


function Export-CertificateReport
{
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Existing logic that depends on Python/openpyxl
}


# ===========================================================================
# REGION: EXECUTION
# ===========================================================================

Write-Host "[INFO] Starting Certificate Expiry Report..." -ForegroundColor Green

$data = Get-CertificateData

Export-CertificateReport -Path $ReportPath

Write-Host "[INFO] Report generation complete." -ForegroundColor Green

# ===========================================================================
# REGION: LOGGING
# ===========================================================================

function Write-Log
{
    param(
        [string]$Message,
        [string]$Level = 'INFO',

        [switch]$Header,
        [string]$HeaderColor,

        [string]$Color,
        [switch]$VerboseOnly
    )

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    if ($Header)
    {
        $headerColorToUse = if ($HeaderColor) { $HeaderColor } else { 'Green' }

        $width = 60
        $pad   = [math]::Floor(($width - $Message.Length) / 2)
        $text  = (" " * $pad) + $Message.ToUpper()

        $line = "`n" +
        ("=" * $width) + "`n" +
        $text + "`n" +
        ("=" * $width)

        if (-not $VerboseOnly)
        {
            Write-Host $line -ForegroundColor $headerColorToUse
        }

        Add-Content $LogPath $line
        return
    }

    $lvl   = "[{0,-5}]" -f $Level
    $entry = "[{0}] {1} {2}" -f $ts, $lvl, $Message

    if (-not $VerboseOnly)
    {
        if ($Color)
        {
            Write-Host ("{0} {1}" -f $lvl, $Message) -ForegroundColor $Color
        }
        else
        {
            Write-Host ("{0} {1}" -f $lvl, $Message)
        }
    }

    Add-Content $LogPath $entry
}

# ===========================================================================
# REGION: LOG CLEANUP
# ===========================================================================

function Invoke-LogCleanup
{
    param(
        [string]$Path,
        [int]$Keep = 2
    )

    if (!(Test-Path $Path))
    {
        return
    }

    $extensions = @('*.log','*.txt','*.xlsx','*.html')

    foreach ($ext in $extensions)
    {
        $files = Get-ChildItem -Path $Path -Filter "CertReport_$ext" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending

        if (-not $files -or @($files).Count -le $Keep)
        {
            continue
        }

        $filesToRemove = $files | Select-Object -Skip $Keep

        foreach ($file in $filesToRemove)
        {
            try
            {
                Remove-Item $file.FullName -Force -ErrorAction Stop
                Write-Log ("Removed old file: {0}" -f $file.Name) -VerboseOnly
            }
            catch
            {
                Write-Log ("Failed to remove file: {0}" -f $file.Name) -VerboseOnly
            }
        }
    }
}

# ===========================================================================
# REGION: DRIFT VALIDATION
# ===========================================================================

function Test-ScriptDrift
{
    param([string]$ScriptPath)

    Write-Log "Drift Validation" -Header -VerboseOnly

    $content = Get-Content $ScriptPath -Raw
    $ok = $true

    if ($content -notmatch '\[powershell\]::Create\(\)'){ $ok=$false }
    if ($content -notmatch '\[runspacefactory\]::CreateRunspacePool'){ $ok=$false }

    if ($ok)
    {
        Write-Log "Drift validation passed" -VerboseOnly
    }
    else
    {
        Write-Log "Drift validation FAILED" -VerboseOnly
    }

    return $ok
}

# ===========================================================================
# REGION: AD DISCOVERY
# ===========================================================================

function Get-ParentOU
{
    param(
        [Parameter(Mandatory)]
        [string]$CanonicalName
    )

    # CanonicalName is "domain/OU/.../Object" (e.g. uhhs.com/Machines/WebServers/SRV01).
    # Drop the trailing object segment to yield the friendly parent OU path
    # (e.g. uhhs.com/Machines/WebServers).
    $idx = $CanonicalName.LastIndexOf('/')

    if ($idx -lt 0)
    {
        return $CanonicalName
    }

    return $CanonicalName.Substring(0, $idx)
}

function Get-ServerList
{
    Write-Log "Active Directory Discovery" -Header -HeaderColor Cyan

    Import-Module ActiveDirectory -ErrorAction Stop

    # Each excluded subtree is identified by the trailing DN fragment that marks
    # it: ",OU=<name>,$MachinesOUBase" for the Machines sub-OUs, and ",<fullDN>"
    # for any additional OU paths. A computer is skipped if its DN ends with one.
    $excludedPaths = New-Object System.Collections.Generic.List[string]

    foreach ($ou in $ExcludedSubOUs)
    {
        $excludedPaths.Add(",OU=$ou,$MachinesOUBase")
    }

    foreach ($ouPath in $ExcludedOUPaths)
    {
        $excludedPaths.Add(",$ouPath")
    }

    $computers = Get-ADComputer -Properties CanonicalName -Filter {
        Name -like "*WEB*" -or
        Name -like "*INT*" -or
        Name -like "*APP*" -or
        Name -like "*RPT*" -or
        Name -like "*BCA*" -or
        Name -like "*BCW*" -or
        Name -like "*BIR*" -or
        Name -like "*CEV*" -or
        Name -like "*CLC*" -or
        Name -like "*HSW*" -or
        Name -like "*ICX*" -or
        Name -like "*KRP*" -or
        Name -like "*LNK*" -or
        Name -like "*MYC*" -or
        Name -like "*PRT*" -or
        Name -like "*SCA*" -or
        Name -like "*SCL*" -or
        Name -like "*SDW*" -or
        Name -like "*SIG*" -or
        Name -like "*WBS*" -or
        Name -like "*HSW*" -or
        Name -like "*PLS*" -or
        Name -like "*PXY*" -or
        Name -like "*WDM*" -or
        Name -like "*AIO*"
    }

    $servers = foreach ($c in $computers)
    {
        $dn = $c.DistinguishedName

        $excluded = $false
        foreach ($path in $excludedPaths)
        {
            if ($dn.EndsWith($path, [System.StringComparison]::OrdinalIgnoreCase))
            {
                $excluded = $true
                break
            }
        }

        if (-not $excluded)
        {
            [pscustomobject]@{
                Name = $c.Name
                OU   = Get-ParentOU -CanonicalName $c.CanonicalName
            }
        }
    }

    return $servers
}

# ===========================================================================
# REGION: TEMPLATE MAP
# ===========================================================================

function Get-CertificateTemplateMap
{
    # Build a lookup of certificate template identities from Active Directory.
    # The V2 template extension on a certificate stores the template OID (which
    # equals msPKI-Cert-Template-OID); the V1 extension stores the common name
    # (cn). Both are mapped here to the template's friendly displayName so the
    # scan can resolve a readable name regardless of which extension a cert
    # carries. Returns an object with two hashtables: ByOid and ByCn.
    Write-Log "Active Directory Template Discovery" -Header -HeaderColor Cyan

    Import-Module ActiveDirectory -ErrorAction Stop

    $byOid = @{}
    $byCn  = @{}

    try
    {
        $configNC    = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

        $getParams = @{
            SearchBase  = $templatesDN
            LDAPFilter  = '(objectClass=pKICertificateTemplate)'
            Properties  = @('cn','displayName','msPKI-Cert-Template-OID')
            ErrorAction = 'Stop'
        }

        $templates = Get-ADObject @getParams

        foreach ($t in $templates)
        {
            $cn       = [string]$t.cn
            $friendly = [string]$t.displayName
            $oid      = [string]$t.'msPKI-Cert-Template-OID'

            $entry = [pscustomobject]@{
                CommonName   = $cn
                FriendlyName = $friendly
            }

            if ($oid -and -not $byOid.ContainsKey($oid))
            {
                $byOid[$oid] = $entry
            }

            if ($cn -and -not $byCn.ContainsKey($cn))
            {
                $byCn[$cn] = $entry
            }
        }

        Write-Log ("Certificate templates mapped: {0}" -f $byOid.Count)
    }
    catch
    {
        Write-Log ("Template map build failed: {0}" -f $_.Exception.Message) -Color Yellow
    }

    return [pscustomobject]@{
        ByOid = $byOid
        ByCn  = $byCn
    }
}

# ===========================================================================
# REGION: RUNSPACE SCAN
# ===========================================================================

function Invoke-CertScan
{
    param($Servers,$TemplateMap)

    $pool = [runspacefactory]::CreateRunspacePool(1,$ThrottleLimit)
    $pool.Open()

    $jobs = New-Object System.Collections.Generic.List[object]
    $bag  = New-Object System.Collections.Concurrent.ConcurrentBag[object]

    foreach($s in $Servers)
    {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        $ps.AddScript({
            param($server,$serverOU,$path,$now,$days,$templateMap)

            # ----- WinRM reachability gate (authoritative) -----
            $winrmOk    = $true
            $winrmError = ''

            try
            {
                Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
            }
            catch
            {
                $winrmOk    = $false
                $winrmError = $_.Exception.Message
            }

            if (-not $winrmOk)
            {
                # WinRM is the authoritative gate; we are here because it failed.
                # Run an independent diagnostic battery so the report can flag every
                # category that applies to this server (DNS / ICMP / WinRM).
                $notInDns  = $false
                $noPing    = $false
                $winrmDown = $true

                try
                {
                    [void][System.Net.Dns]::GetHostAddresses($server)
                }
                catch
                {
                    $notInDns = $true
                }

                if (-not $notInDns)
                {
                    $pingOk = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue

                    if (-not $pingOk)
                    {
                        $noPing = $true
                    }
                }

                return [pscustomobject]@{
                    ComputerName = $server
                    Result       = 'Unreachable'
                    NotInDns     = $notInDns
                    NoPing       = $noPing
                    WinRMDown    = $winrmDown
                    OU           = $serverOU
                    Detail       = $winrmError
                }
            }

            try{
                $certs = Invoke-Command -ComputerName $server -ScriptBlock {
                    param($p)

                    Get-ChildItem $p | ForEach-Object {
                        $cert = $_

                        # ----- Certificate template identity -----
                        # The V2 template-information extension carries the
                        # template OID (not its friendly name); the V1 extension
                        # carries the template common name as text. Capture the
                        # raw OID and/or raw name here and resolve the friendly
                        # name on the calling side, where AD is reachable.
                        $templateOid     = ''
                        $templateNameRaw = ''

                        foreach ($ext in $cert.Extensions)
                        {
                            if ($ext.Oid.Value -eq '1.3.6.1.4.1.311.21.7')
                            {
                                $asn       = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
                                $formatted = $asn.Format($false)

                                # When the OID resolves locally it appears in
                                # parentheses after the friendly name; otherwise
                                # the bare OID is the value. Capture the OID in
                                # either case.
                                if ($formatted -match '\(([\d\.]+)\)')
                                {
                                    $templateOid = $matches[1]
                                }
                                elseif ($formatted -match '(\d+\.\d+\.\d+[\d\.]+)')
                                {
                                    $templateOid = $matches[1]
                                }

                                break
                            }
                            elseif ($ext.Oid.Value -eq '1.3.6.1.4.1.311.20.2')
                            {
                                $asn             = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
                                $templateNameRaw = $asn.Format($false).Trim()

                                break
                            }
                        }

                        # ----- EKU usage classification -----
                        $usage = ''
                        foreach ($eku in $cert.EnhancedKeyUsageList)
                        {
                            if ($eku.FriendlyName -eq 'Server Authentication')
                            {
                                $usage = 'Server'
                            }
                            elseif ($eku.FriendlyName -eq 'Client Authentication' -and $usage -ne 'Server')
                            {
                                $usage = 'Client'
                            }
                        }

                        [pscustomobject]@{
                            Issuer          = $cert.Issuer
                            Subject         = $cert.Subject
                            NotAfter        = $cert.NotAfter
                            Usage           = $usage
                            TemplateOid     = $templateOid
                            TemplateNameRaw = $templateNameRaw
                        }
                    }
                } -ArgumentList $path

                foreach($c in $certs)
                {
                    $usage = $c.Usage

                    $d=($c.NotAfter-$now).Days

                    if($usage -and ($c.NotAfter -lt $now -or $d -le $days))
                    {
                        # ----- Resolve the template friendly name -----
                        # Prefer the AD displayName (friendly), then the cn
                        # (common name); fall back to the raw extension value,
                        # then 'N/A'. Lookup keys come from the remote cert: the
                        # V2 OID first, then the V1 common name.
                        $templateDisplay = ''

                        if ($c.TemplateOid -and $templateMap.ByOid.ContainsKey($c.TemplateOid))
                        {
                            $entry = $templateMap.ByOid[$c.TemplateOid]

                            if ($entry.FriendlyName)
                            {
                                $templateDisplay = $entry.FriendlyName
                            }
                            elseif ($entry.CommonName)
                            {
                                $templateDisplay = $entry.CommonName
                            }
                        }
                        elseif ($c.TemplateNameRaw -and $templateMap.ByCn.ContainsKey($c.TemplateNameRaw))
                        {
                            $entry = $templateMap.ByCn[$c.TemplateNameRaw]

                            if ($entry.FriendlyName)
                            {
                                $templateDisplay = $entry.FriendlyName
                            }
                            elseif ($entry.CommonName)
                            {
                                $templateDisplay = $entry.CommonName
                            }
                        }

                        if (-not $templateDisplay -and $c.TemplateNameRaw)
                        {
                            $templateDisplay = $c.TemplateNameRaw
                        }

                        if (-not $templateDisplay)
                        {
                            $templateDisplay = 'N/A'
                        }

                        [pscustomobject]@{
                            ComputerName=$server
                            IssuerCN=($c.Issuer -split ',')[0] -replace '^CN='
                            SubjectCN=($c.Subject -split ',')[0] -replace '^CN='
                            TemplateName=$templateDisplay
                            ExpirationDate=$c.NotAfter
                            DaysRemaining=$d
                            Usage=$usage
                            Status=if($c.NotAfter -lt $now){'Expired'}else{'ExpiringSoon'}
                            Result='Success'
                        }
                    }
                }
            }catch{
                [pscustomobject]@{
                    ComputerName = $server
                    Result       = 'Failed'
                    Reason       = 'Certificate retrieval failed'
                    Detail       = $_.Exception.Message
                }
            }
        }) | Out-Null

        [void]$ps.AddArgument($s.Name)
        [void]$ps.AddArgument($s.OU)
        [void]$ps.AddArgument($StorePath)
        [void]$ps.AddArgument($Now)
        [void]$ps.AddArgument($DaysThreshold)
        [void]$ps.AddArgument($TemplateMap)

        $jobs.Add(@{Pipe=$ps;Handle=$ps.BeginInvoke()})
    }

    $total=$jobs.Count
    $done=0

    while($jobs.Count -gt 0)
    {
        for($i=$jobs.Count-1;$i -ge 0;$i--)
        {
            if($jobs[$i].Handle.IsCompleted)
            {
                $out=$jobs[$i].Pipe.EndInvoke($jobs[$i].Handle)
                foreach($o in @($out)){ if($o){$bag.Add($o)} }

                $jobs[$i].Pipe.Dispose()
                $jobs.RemoveAt($i)

                $done++
                $pct=[math]::Min(100,($done/$total)*100)

                Write-Progress -Activity $ProgressActivity -Status "$done of $total complete" -PercentComplete $pct
            }
        }
        Start-Sleep -Milliseconds 100
    }

    Write-Progress -Activity $ProgressActivity -Completed

    return $bag.ToArray()
}

# ===========================================================================
# REGION: REPORT
# ===========================================================================

function Write-Report
{
    param($Report)

    Write-Host ""
    Write-Log "Certificate Report" -Header -HeaderColor Cyan
    Write-Host ""

    if (-not $Report)
    {
        return
    }

    $prepared = foreach ($r in $Report)
    {
        $issuerRaw  = $r.IssuerCN  -replace '\b\d{1,3}(\.\d{1,3}){3}\b',''
        $subjectRaw = $r.SubjectCN -replace '\b\d{1,3}(\.\d{1,3}){3}\b',''

        if ($issuerRaw -eq $subjectRaw)
        {
            $issuerRaw  = $issuerRaw  -replace '^/',''
            $subjectRaw = $subjectRaw -replace '^/',''
        }

        [pscustomobject]@{
            ComputerName   = [string]$r.ComputerName
            IssuerCN       = [string]$issuerRaw
            SubjectCN      = [string]$subjectRaw
            Usage          = [string]$r.Usage
            ExpirationDate = $r.ExpirationDate
            ExpirationStr  = $r.ExpirationDate.ToString('yyyy-MM-dd')
            DaysRemaining  = [string]$r.DaysRemaining
            Status         = $r.Status
        }
    }

    function Get-MaxWidth
    {
        param($Values, $Header)

        $max = ($Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum

        if (-not $max)
        {
            $max = 0
        }

        return [math]::Max($max, $Header.Length) + 2
    }

    $wServer  = Get-MaxWidth ($prepared.ComputerName)  "Server"
    $wIssuer  = Get-MaxWidth ($prepared.IssuerCN)      "Issuer"
    $wSubject = Get-MaxWidth ($prepared.SubjectCN)     "Subject"
    $wUsage   = Get-MaxWidth ($prepared.Usage)         "Usage"
    $wDate    = Get-MaxWidth ($prepared.ExpirationStr) "Expiration"
    $wDays    = Get-MaxWidth ($prepared.DaysRemaining) "Days"

    $hServer  = "{0,-$wServer}"  -f "Server"
    $hIssuer  = "{0,-$wIssuer}"  -f "Issuer"
    $hSubject = "{0,-$wSubject}" -f "Subject"
    $hUsage   = "{0,-$wUsage}"   -f "Usage"
    $hDate    = "{0,-$wDate}"    -f "Expiration"
    $hDays    = "{0,-$wDays}"    -f "Days"

    Write-Host -NoNewline $hServer  -ForegroundColor Cyan
    Write-Host -NoNewline $hIssuer  -ForegroundColor Cyan
    Write-Host -NoNewline $hSubject -ForegroundColor Cyan
    Write-Host -NoNewline $hUsage   -ForegroundColor Cyan
    Write-Host -NoNewline $hDate    -ForegroundColor Cyan
    Write-Host              $hDays  -ForegroundColor Cyan

    Write-Host -NoNewline ("-" * $wServer)  -ForegroundColor DarkGray
    Write-Host -NoNewline ("-" * $wIssuer)  -ForegroundColor DarkGray
    Write-Host -NoNewline ("-" * $wSubject) -ForegroundColor DarkGray
    Write-Host -NoNewline ("-" * $wUsage)   -ForegroundColor DarkGray
    Write-Host -NoNewline ("-" * $wDate)    -ForegroundColor DarkGray
    Write-Host              ("-" * $wDays)  -ForegroundColor DarkGray

    $sorted = $prepared | Sort-Object @{
        Expression = { $_.Status -eq 'Expired' }
        Descending = $true
    }, IssuerCN, ExpirationDate, ComputerName

    foreach ($r in $sorted)
    {
        if ($r.IssuerCN -like "*$ExpectedIssuer*")
        {
            $issuerColor = 'White'
        }
        elseif ($r.IssuerCN -eq $r.SubjectCN)
        {
            $issuerColor = 'Gray'
        }
        else
        {
            $issuerColor = 'Magenta'
        }

        $statusColor = if ($r.Status -eq 'Expired')
        {
            'Red'
        }
        elseif ($r.Status -eq 'ExpiringSoon')
        {
            'Yellow'
        }
        else
        {
            'Gray'
        }

        $server  = "{0,-$wServer}"  -f $r.ComputerName
        $issuer  = "{0,-$wIssuer}"  -f $r.IssuerCN
        $subject = "{0,-$wSubject}" -f $r.SubjectCN
        $usage   = "{0,-$wUsage}"   -f $r.Usage
        $date    = "{0,-$wDate}"    -f $r.ExpirationStr
        $days    = "{0,-$wDays}"    -f $r.DaysRemaining

        Write-Host -NoNewline $server  -ForegroundColor White
        Write-Host -NoNewline $issuer  -ForegroundColor $issuerColor
        Write-Host -NoNewline $subject -ForegroundColor White
        Write-Host -NoNewline $usage   -ForegroundColor White
        Write-Host -NoNewline $date    -ForegroundColor $statusColor
        Write-Host              $days  -ForegroundColor White
    }
}

# ===========================================================================
# REGION: SUMMARY
# ===========================================================================

function Write-Summary
{
    param($Results,$Report,$InputCount,$Duration)

    Write-Host ""
    Write-Log "Execution Summary" -Header -HeaderColor Cyan
    
    $valid=$Results|Where-Object{$_.ComputerName}
    $unique=@($valid|Select-Object -Expand ComputerName -Unique)

    function Show-Line
    {
        param($Label,$Value,$Color)

        if ($Color)
        {
            Write-Host ("{0,-43} : {1}" -f $Label,$Value) -ForegroundColor $Color
        }
        else
        {
            Write-Host ("{0,-43} : {1}" -f $Label,$Value)
        }
    }

    Show-Line "Servers in List" $InputCount
    Show-Line "Total Servers Processed" $unique.Count
    Show-Line "Successful Scans" @($valid | Where-Object { $_.Result -eq 'Success' }).Count 'Green'
    Show-Line "Unreachable Servers" @($valid | Where-Object { $_.Result -eq 'Unreachable' }).Count 'Red'
    Show-Line "Failed Scans" @($valid | Where-Object { $_.Result -eq 'Failed' }).Count 'Red'
    Show-Line "UH Server Certs Expiring Soon (<=45 days)" @($Report | Where-Object { $_.Status -eq 'ExpiringSoon' -and $_.Usage -eq 'Server' -and $_.IssuerCN -like "*$ExpectedIssuer*" }).Count 'Yellow'
    Show-Line "Total Certificates" @($Report).Count
    Show-Line "Duration" $Duration.ToString('hh\:mm\:ss')
    Write-Host ""
}

# ===========================================================================
# REGION: EXCEL EXPORT
# ===========================================================================

function Export-ExcelReport
{
    param(
        $Report,
        $Results,
        $InputCount,
        $Duration,
        [string]$Path
    )

    # Verify Python + openpyxl are available before proceeding
    $pyCheck = & python -c "import openpyxl" 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        Write-Log "Excel export skipped: Python/openpyxl not available. Install with: pip install openpyxl" -Color Yellow
        return $false
    }

    Write-Log "Generating Excel report..." -Color Cyan

    # =========================
    # BUILD CERT DATA JSON
    # =========================

    $certRows = foreach ($r in ($Report | Sort-Object @{
        Expression = { $_.Status -eq 'Expired' }
        Descending = $true
    }, IssuerCN, ExpirationDate, ComputerName))
    {
        $issuerClean  = $r.IssuerCN  -replace '\b\d{1,3}(\.\d{1,3}){3}\b','' -replace "'",'`'
        $subjectClean = $r.SubjectCN -replace '\b\d{1,3}(\.\d{1,3}){3}\b','' -replace "'",'`'
        $serverClean  = $r.ComputerName -replace "'",'`'

        # Issuer category for color mapping
        $issuerCat = if ($r.IssuerCN -like "*$ExpectedIssuer*") { 'UH' }
                     elseif ($r.IssuerCN -eq $r.SubjectCN)      { 'Self' }
                     else                                         { 'Other' }

        @{
            Server        = $serverClean
            IssuerCN      = $issuerClean
            SubjectCN     = $subjectClean
            Usage         = $r.Usage
            Expiration    = $r.ExpirationDate.ToString('yyyy-MM-dd')
            DaysRemaining = [int]$r.DaysRemaining
            Status        = $r.Status
            IssuerCat     = $issuerCat
        }
    }

    # =========================
    # BUILD SUMMARY DATA
    # =========================

    $valid  = $Results | Where-Object { $_.ComputerName }
    $unique = @($valid | Select-Object -Expand ComputerName -Unique)

    $summaryData = @{
        ServersInList    = $InputCount
        ServersProcessed = @($unique).Count
        Successful       = @($valid | Where-Object { $_.Result -eq 'Success'     }).Count
        Unreachable      = @($valid | Where-Object { $_.Result -eq 'Unreachable' }).Count
        Failed           = @($valid | Where-Object { $_.Result -eq 'Failed'      }).Count
        ExpiringSoon     = @($Report | Where-Object {
                               $_.Status   -eq 'ExpiringSoon' -and
                               $_.Usage    -eq 'Server'       -and
                               $_.IssuerCN -like "*$ExpectedIssuer*"
                           }).Count
        TotalCerts       = @($Report).Count
        Duration         = $Duration.ToString('hh\:mm\:ss')
        GeneratedAt      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    # =========================
    # SERIALIZE TO JSON TEMPFILE
    # =========================

    $jsonTempPath = "$OutputPath\CertReport_tmp_$TimeStamp.json"

    $payload = @{
        certs   = @($certRows)
        summary = $summaryData
        xlsxPath = $Path
    } | ConvertTo-Json -Depth 5

    $payload | Set-Content -Path $jsonTempPath -Encoding UTF8

    # =========================
    # EMBEDDED PYTHON SCRIPT
    # =========================

$pyScript = @'
import json
import sys
from openpyxl import Workbook
from openpyxl.styles import (Font, PatternFill, Alignment,
                              Border, Side)
from openpyxl.utils import get_column_letter

with open(sys.argv[1], encoding='utf-8-sig') as f:
    data = json.load(f)

certs   = data['certs']
summary = data['summary']
out     = data['xlsxPath']

wb = Workbook()

# -------------------------------------------------------
# SHEET 1: Certificate Report
# -------------------------------------------------------

ws = wb.active
ws.title = 'Certificate Report'

HEADER_FONT   = Font(name='Arial', bold=True, color='FFFFFF', size=10)
HEADER_FILL   = PatternFill('solid', fgColor='1F4E79')
HEADER_ALIGN  = Alignment(horizontal='center', vertical='center')
DATA_FONT     = Font(name='Arial', size=10)
DATA_FONT_B   = Font(name='Arial', size=10, bold=True)
THIN          = Side(style='thin', color='AAAAAA')
BORDER        = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

# Row / col fills
FILL_EXPIRED    = PatternFill('solid', fgColor='FF6666')   # red
FILL_EXPIRING   = PatternFill('solid', fgColor='FFFF99')   # yellow
FILL_UHISSUER   = PatternFill('solid', fgColor='E8F5E9')   # light green
FILL_SELFISSUER = PatternFill('solid', fgColor='EEEEEE')   # gray
FILL_OTHISSUER  = PatternFill('solid', fgColor='FFE6FF')   # light magenta

# Days-remaining urgency fills (override row fill for Days column)
FILL_DAYS_CRIT  = PatternFill('solid', fgColor='CC0000')   # dark red  < 5
FILL_DAYS_HIGH  = PatternFill('solid', fgColor='FF4D4D')   # red       < 10
FILL_DAYS_MED   = PatternFill('solid', fgColor='FFFF66')   # yellow   <= 20
FILL_DAYS_OK    = PatternFill('solid', fgColor='66FF66')   # green     > 20

headers = ['Server','Issuer','Subject','Usage','Expiration','Days Remaining','Status']
col_widths = [28, 34, 34, 10, 14, 16, 14]

for col, (h, w) in enumerate(zip(headers, col_widths), start=1):
    cell = ws.cell(row=1, column=col, value=h)
    cell.font      = HEADER_FONT
    cell.fill      = HEADER_FILL
    cell.alignment = HEADER_ALIGN
    cell.border    = BORDER
    ws.column_dimensions[get_column_letter(col)].width = w

ws.row_dimensions[1].height = 20
ws.freeze_panes = 'A2'
ws.auto_filter.ref = f'A1:G1'

for row_idx, r in enumerate(certs, start=2):
    vals = [
        r['Server'],
        r['IssuerCN'],
        r['SubjectCN'],
        r['Usage'],
        r['Expiration'],
        r['DaysRemaining'],
        r['Status'],
    ]

    # Choose row base fill
    if r['Status'] == 'Expired':
        row_fill = None
        txt_color = 'CC0000'
    else:
        # ExpiringSoon - shade by issuer category
        if r['IssuerCat'] == 'UH':
            row_fill = FILL_UHISSUER
        elif r['IssuerCat'] == 'Self':
            row_fill = FILL_SELFISSUER
        else:
            row_fill = FILL_OTHISSUER
        txt_color = '000000'

    for col_idx, val in enumerate(vals, start=1):
        cell = ws.cell(row=row_idx, column=col_idx, value=val)
        cell.font      = Font(
            name='Arial',
            size=10,
            bold=(col_idx == 1),
            color=txt_color
        )

    if row_fill is not None:
        cell.fill = row_fill

    cell.border    = BORDER
    cell.alignment = Alignment(vertical='center')


    # Override Days Remaining column (col 6) with urgency color
    days_cell = ws.cell(row=row_idx, column=6)
    d = r['DaysRemaining']
    if d < 5:
        days_cell.fill = FILL_DAYS_CRIT
        days_cell.font = Font(name='Arial', size=10, bold=True, color='FFFFFF')
    elif d < 10:
        days_cell.fill = FILL_DAYS_HIGH
        days_cell.font = Font(name='Arial', size=10, bold=True, color='000000')
    elif d <= 20:
        days_cell.fill = FILL_DAYS_MED
        days_cell.font = Font(name='Arial', size=10, color='000000')
    else:
        days_cell.fill = FILL_DAYS_OK
        days_cell.font = Font(name='Arial', size=10, color='000000')

# -------------------------------------------------------
# SHEET 2: Execution Summary
# -------------------------------------------------------

ws2 = wb.create_sheet('Execution Summary')

SUMM_HEADER_FONT = Font(name='Arial', bold=True, color='FFFFFF', size=11)
SUMM_HEADER_FILL = PatternFill('solid', fgColor='1F4E79')
SUMM_LABEL_FONT  = Font(name='Arial', bold=True, size=10)
SUMM_VAL_FONT    = Font(name='Arial', size=10)

FILL_GREEN  = PatternFill('solid', fgColor='C6EFCE')
FILL_RED    = PatternFill('solid', fgColor='FFC7CE')
FILL_YELLOW = PatternFill('solid', fgColor='FFEB9C')
FILL_PLAIN  = PatternFill('solid', fgColor='F2F2F2')

ws2.column_dimensions['A'].width = 46
ws2.column_dimensions['B'].width = 20

# Title
title = ws2.cell(row=1, column=1, value='Execution Summary')
title.font      = SUMM_HEADER_FONT
title.fill      = SUMM_HEADER_FILL
title.alignment = Alignment(horizontal='left', vertical='center')
ws2.merge_cells('A1:B1')
ws2.row_dimensions[1].height = 22

rows = [
    ('Servers in List',                        str(summary['ServersInList']),    FILL_PLAIN,  None),
    ('Total Servers Processed',                str(summary['ServersProcessed']), FILL_PLAIN,  None),
    ('Successful Scans',                       str(summary['Successful']),       FILL_GREEN,  '006100'),
    ('Unreachable Servers',                    str(summary['Unreachable']),      FILL_RED,    '9C0006'),
    ('Failed Scans',                           str(summary['Failed']),           FILL_RED,    '9C0006'),
    ('UH Server Certs Expiring Soon (<=45d)',  str(summary['ExpiringSoon']),     FILL_YELLOW, '9C6500'),
    ('Total Certificates',                     str(summary['TotalCerts']),       FILL_PLAIN,  None),
    ('Duration',                               summary['Duration'],              FILL_PLAIN,  None),
    ('Generated At',                           summary['GeneratedAt'],           FILL_PLAIN,  None),
]

for i, (label, value, fill, val_color) in enumerate(rows, start=2):
    lc = ws2.cell(row=i, column=1, value=label)
    lc.font      = SUMM_LABEL_FONT
    lc.fill      = fill
    lc.border    = BORDER
    lc.alignment = Alignment(vertical='center')

    vc = ws2.cell(row=i, column=2, value=value)
    vc.fill      = fill
    vc.border    = BORDER
    vc.alignment = Alignment(horizontal='center', vertical='center')
    if val_color:
        vc.font = Font(name='Arial', size=10, bold=True, color=val_color)
    else:
        vc.font = SUMM_VAL_FONT

wb.save(out)
print("OK")
'@

    $pyTempPath = "$OutputPath\CertReport_gen_$TimeStamp.py"

    try
    {
        $pyScript | Set-Content -Path $pyTempPath -Encoding UTF8

        $result = & python $pyTempPath $jsonTempPath 2>&1

        if ($LASTEXITCODE -ne 0 -or $result -notmatch 'OK')
        {
            Write-Log ("Excel generation failed: {0}" -f ($result -join ' ')) -Color Red
            return $false
        }

        Write-Log ("Excel report saved: {0}" -f $Path) -Color Green
        return $true
    }
    catch
    {
        Write-Log ("Excel export exception: {0}" -f $_.Exception.Message) -Color Red
        return $false
    }
    finally
    {
        # Clean up temp files
        if (Test-Path $pyTempPath)   { Remove-Item $pyTempPath   -Force -ErrorAction SilentlyContinue }
        if (Test-Path $jsonTempPath) { Remove-Item $jsonTempPath -Force -ErrorAction SilentlyContinue }
    }
}

# ===========================================================================
# REGION: UNREACHABLE HTML TABLE
# ===========================================================================

function Write-UnreachableHtmlTable
{
    param(
        [Parameter(Mandatory)]
        $Unreachable,

        [Parameter(Mandatory)]
        [string]$Path
    )

    # Reduce to unique server names (first record wins per server)
    $unique = @($Unreachable |
        Group-Object ComputerName |
        ForEach-Object { $_.Group | Select-Object -First 1 } |
        Sort-Object ComputerName)

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $checkMark   = '&#10004;'

    $onStyle  = "background-color:#f8d7da;color:#cc0000;font-weight:bold;text-align:center;font-size:14px;"
    $offStyle = "background-color:#eafaf0;text-align:center;color:#bbbbbb;"

    $bodyRows = foreach ($u in $unique)
    {
        $dnsCell   = if ($u.NotInDns)  { "<td style='$onStyle'>$checkMark</td>" } else { "<td style='$offStyle'></td>" }
        $pingCell  = if ($u.NoPing)    { "<td style='$onStyle'>$checkMark</td>" } else { "<td style='$offStyle'></td>" }
        $winrmCell = if ($u.WinRMDown) { "<td style='$onStyle'>$checkMark</td>" } else { "<td style='$offStyle'></td>" }

        $detailText = if ($u.Detail) { $u.Detail } else { '' }
        $ouText     = if ($u.OU)     { $u.OU }     else { '' }

        "<tr>" +
            "<td style='font-weight:bold;padding:4px 8px;'>$($u.ComputerName)</td>" +
            $dnsCell +
            $pingCell +
            $winrmCell +
            "<td style='font-size:11px;color:#333333;padding:4px 8px;'>$ouText</td>" +
            "<td style='font-size:11px;color:#555555;padding:4px 8px;'>$detailText</td>" +
        "</tr>"
    }

    $html = @"
<html>
<head>
<style>
body  { font-family:Segoe UI, Arial, sans-serif; font-size:13px; color:#222222; }
table { border-collapse:collapse; width:100%; }
th    { background-color:#1F4E79; color:#FFFFFF; padding:6px 8px; text-align:center; }
th.server, th.detail { text-align:left; }
th.ou { text-align:left; }
td    { border:1px solid #cccccc; }
caption { caption-side:top; text-align:left; font-size:11px; color:#777777; padding-bottom:6px; }
</style>
</head>
<body>

<h2 style="color:#cc0000;">Unreachable Servers ($($unique.Count))</h2>
<p>A checkmark indicates that the listed failure category applies to that server.
WinRM is the authoritative reachability gate, so every unreachable server is
flagged under <b>WinRM Not Responding</b>; the DNS and Ping columns identify the
underlying root cause. Detail shows the WinRM error returned for the host.</p>

<table border="1" cellpadding="5" cellspacing="0">
<caption>Generated $generatedAt</caption>
<tr>
<th class="server">Server</th>
<th>Not in DNS</th>
<th>No Ping</th>
<th>WinRM Not Responding</th>
<th class="ou">OU</th>
<th class="detail">Detail</th>
</tr>
$($bodyRows -join "`n")
</table>

</body>
</html>
"@

    $html | Set-Content -Path $Path -Encoding UTF8

    return $unique
}

# ===========================================================================
# REGION: CERT REPORT HTML
# ===========================================================================

function Write-CertReportHtml
{
    param(
        [Parameter(Mandatory)]
        $Report,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Sort order:
    #   1. Non-expired certs first (positive/zero days), then expired (negative).
    #   2. Within non-expired: days ascending (1, 2, ... soonest first).
    #   3. Within expired: closest-to-zero first, so -1919 sorts before -2905
    #      (achieved by ordering on the absolute days-expired, ascending).
    #   4. ComputerName alphabetical for ties.
    $sortOrder = @(
        @{ Expression = { [int]($_.DaysRemaining -lt 0) }; Descending = $false },
        @{ Expression = { if ($_.DaysRemaining -lt 0) { - $_.DaysRemaining } else { $_.DaysRemaining } }; Descending = $false },
        @{ Expression = { $_.ComputerName }; Descending = $false }
    )

    $sorted = @($Report | Sort-Object $sortOrder)

    $bodyRows = foreach ($r in $sorted)
    {
        # Row color follows the same day-based scale used in the email body.
        if ($r.Status -eq 'Expired')
        {
            $bg = "background-color:#cc0000;color:#ffffff;font-weight:bold;"
        }
        elseif ($r.DaysRemaining -lt 5)
        {
            $bg = "background-color:#cc0000;color:#ffffff;font-weight:bold;"
        }
        elseif ($r.DaysRemaining -lt 10)
        {
            $bg = "background-color:#ff4d4d;"
        }
        elseif ($r.DaysRemaining -le 20)
        {
            $bg = "background-color:#ffff66;"
        }
        else
        {
            $bg = "background-color:#66ff66;"
        }

        "<tr style='$bg'>" +
            "<td style='font-weight:bold;'>$($r.ComputerName)</td>" +
            "<td>$($r.SubjectCN)</td>" +
            "<td>$($r.IssuerCN)</td>" +
            "<td>$($r.TemplateName)</td>" +
            "<td style='text-align:center;'>$($r.Usage)</td>" +
            "<td style='text-align:center;'>$($r.DaysRemaining)</td>" +
            "<td>$($r.ExpirationDate.ToString('yyyy-MM-dd HH:mm:ss'))</td>" +
            "<td style='text-align:center;'>$($r.Status)</td>" +
        "</tr>"
    }

    $html = @"
<html>
<head>
<style>
body  { font-family:Segoe UI, Arial, sans-serif; font-size:12px; color:#222222; }
table { border-collapse:collapse; width:100%; }
th    { background-color:#1F4E79; color:#FFFFFF; padding:2px 6px; text-align:left; font-size:12px; line-height:1.1; }
td    { border:1px solid #cccccc; padding:1px 6px; font-size:12px; line-height:1.1; white-space:nowrap; }
caption { caption-side:top; text-align:left; font-size:11px; color:#777777; padding-bottom:4px; }
</style>
</head>
<body>

<h2>UH Certificate Expiry Report ($($sorted.Count))</h2>
<p>Certificates that are expired or expiring within the configured threshold,
across all scanned servers. Row color reflects urgency by days remaining.</p>

<table border="1" cellpadding="2" cellspacing="0">
<caption>Generated $generatedAt</caption>
<tr>
<th>Server</th>
<th>Subject</th>
<th>Issuer</th>
<th>Template Name</th>
<th>Usage</th>
<th>Days</th>
<th>Expiration</th>
<th>Status</th>
</tr>
$($bodyRows -join "`n")
</table>

</body>
</html>
"@

    $html | Set-Content -Path $Path -Encoding UTF8
}

# ===========================================================================
# REGION: EMAIL
# ===========================================================================

function Send-EmailReport
{
    param($Results,$Report,$InputCount,$Duration)

    # =========================
    # FILTER
    # =========================

    $filtered = $Report | Where-Object {
        $_.Status   -eq 'ExpiringSoon' -and
        $_.IssuerCN -like "*$ExpectedIssuer*" -and
        $_.Usage    -eq 'Server'
    }

    # =========================
    # SUMMARY DATA
    # =========================

    $valid  = $Results | Where-Object { $_.ComputerName }
    $unique = @($valid | Select-Object -Expand ComputerName -Unique)

    $serversInList = $InputCount
    $success = @($valid | Where-Object { $_.Result -eq 'Success' }).Count
    $unreach = @($valid | Where-Object { $_.Result -eq 'Unreachable' }).Count
    $failed  = @($valid | Where-Object { $_.Result -eq 'Failed' }).Count

    $expSoon = @($Report | Where-Object {
        $_.Status -eq 'ExpiringSoon' -and
        $_.Usage  -eq 'Server'       -and
        $_.IssuerCN -like "*$ExpectedIssuer*"
    }).Count

    $affectedServers = @($filtered | Select-Object -Expand ComputerName -Unique).Count

    # =========================
    # UNREACHABLE DATA
    # =========================

    $unreachableList = @($Results |
        Where-Object { $_.Result -eq 'Unreachable' } |
        Group-Object ComputerName |
        ForEach-Object { $_.Group | Select-Object -First 1 } |
        Sort-Object ComputerName)

    $dnsCount   = @($unreachableList | Where-Object { $_.NotInDns  }).Count
    $pingCount  = @($unreachableList | Where-Object { $_.NoPing    }).Count
    $winrmCount = @($unreachableList | Where-Object { $_.WinRMDown }).Count

    # =========================
    # TABLE ROWS
    # =========================

    $sortOrder = @(
        @{ Expression = { $_.DaysRemaining }; Descending = $true  },
        @{ Expression = { $_.ComputerName  }; Descending = $false }
    )

$rows = foreach ($r in ($filtered | Sort-Object $sortOrder))
    {
        if ($r.DaysRemaining -lt 5)
        {
            $bg = "background-color:#cc0000;color:white;font-weight:bold;"
        }
        elseif ($r.DaysRemaining -lt 10)
        {
            $bg = "background-color:#ff4d4d;"
        }
        elseif ($r.DaysRemaining -le 20)
        {
            $bg = "background-color:#ffff66;"
        }
        else
        {
            $bg = "background-color:#66ff66;"
        }

        "<tr style='$bg'>" +
            "<td style='white-space:nowrap;'><b>$($r.ComputerName)</b></td>" +
            "<td style='white-space:nowrap;'>$($r.IssuerCN)</td>" +
            "<td style='white-space:nowrap;'>$($r.DaysRemaining)</td>" +
            "<td style='white-space:nowrap;'>$($r.ExpirationDate.ToString('yyyy-MM-dd HH:mm:ss'))</td>" +
            "<td style='white-space:nowrap;'>$($r.TemplateName)</td>" +
        "</tr>"
    }

# ===========================================================================
# REGION: EXECUTION SUMMARY HTML
# ===========================================================================

$summaryHtml = @"
<br><br>
<h3>Execution Summary</h3>
<table border="1" cellpadding="5" cellspacing="0">
<tr><td>Servers in List</td><td>$serversInList</td></tr>
<tr><td>Total Servers Processed</td><td>$($unique.Count)</td></tr>
<tr><td>Successful Scans</td><td style='color:green;'>$success</td></tr>
<tr><td>Unreachable Servers</td><td style='color:red;'>$unreach</td></tr>
<tr><td>Failed Scans</td><td style='color:red;'>$failed</td></tr>
<tr><td>UH Server Certs Expiring Soon (&lt;=45 days)</td><td style='color:orange;'>$expSoon</td></tr>
<tr><td>Total Certificates</td><td>$(@($Report).Count)</td></tr>
<tr><td>Duration</td><td>$($Duration.ToString('hh\:mm\:ss'))</td></tr>
</table>
"@

# ===========================================================================
# REGION: UNREACHABLE SERVERS HTML
# ===========================================================================

if ($unreachableList)
{
    $unreachableHtml = @"
<br><br>
<h3 style="color:#cc0000;">Unreachable Servers ($($unreachableList.Count))</h3>
<p>These servers could not be scanned. A color-coded per-server matrix (a checkmark for each failed category) is attached as an HTML file.</p>
<table border="1" cellpadding="5" cellspacing="0">
<tr><th>Failure Category</th><th>Servers</th></tr>
<tr><td>Not in DNS</td><td style='text-align:center;'>$dnsCount</td></tr>
<tr><td>No Ping</td><td style='text-align:center;'>$pingCount</td></tr>
<tr><td>WinRM Not Responding</td><td style='text-align:center;'>$winrmCount</td></tr>
</table>
"@
}
else
{
    $unreachableHtml = @"
<br><br>
<h3 style="color:green;">Unreachable Servers (0)</h3>
<p>All discovered servers were reachable.</p>
"@
}

# ===========================================================================
# REGION: FINAL EMAIL BODY
# ===========================================================================

$body = @"
<html>
<body>

<h2>UH Server Certificates Expiring Within 45 Days</h2>

<table border="1" cellpadding="5" cellspacing="0">
<tr>
<th style="white-space:nowrap;">Server</th>
<th style="white-space:nowrap;">Issuer</th>
<th style="white-space:nowrap;">Days</th>
<th style="white-space:nowrap;">Expiration</th>
<th style="white-space:nowrap;">Template Name</th>
</tr>
$($rows -join "`n")
</table>

$summaryHtml

$unreachableHtml

</body>
</html>
"@

    # =========================
    # BUILD ATTACHMENT LIST
    # =========================

    $attachments = @()

    if (Test-Path $XlsxPath)
    {
        $attachments += $XlsxPath
    }

    # Write a color-coded HTML version of the certificate report (includes the
    # Template Name column) and attach it alongside the Excel workbook.
    Write-CertReportHtml -Report $Report -Path $CertReportHtmlPath

    if (Test-Path $CertReportHtmlPath)
    {
        $attachments += $CertReportHtmlPath
    }

    # Write a color-coded HTML matrix of unreachable servers (one row per unique
    # server, a checkmark per failed category) and attach it so the on-call
    # engineer gets an at-a-glance diagnostic grid.
    if ($unreachableList)
    {
        [void](Write-UnreachableHtmlTable -Unreachable $unreachableList -Path $UnreachablePath)

        if (Test-Path $UnreachablePath)
        {
            $attachments += $UnreachablePath
        }
    }

    # =========================
    # SEND EMAIL
    # =========================

    $EmailTimeStamp = (Get-Date).ToString('yyyy-MM-dd HH:mm')

    $params = @{
        To          = $EmailTo
        From        = $EmailFrom
        Subject     = ("Certificate Report - {0} Servers Affected - {1}" -f $affectedServers, $EmailTimeStamp)
        Body        = $body
        BodyAsHtml  = $true
        SmtpServer  = $SMTPServer
        Attachments = $attachments
    }

    try
    {
        Send-MailMessage @params
        Write-Host ""
        Write-Host "Email sent to Jeff Altomari and Alan Phillips" -ForegroundColor Green
        Write-Log "Email sent to Jeff Altomari and Alan Phillips" -VerboseOnly
    }
    catch
    {
        Write-Log "Email failed"
    }
}

# ===========================================================================
# REGION: MAIN
# ===========================================================================

if(-not(Test-ScriptDrift -ScriptPath $MyInvocation.MyCommand.Path)){return}

$txt="CERTIFICATE EXPIRATION SCAN"
$width=60
$pad=[math]::Floor(($width-$txt.Length)/2)
$line="="*$width

Write-Host ""
Write-Host $line -ForegroundColor Green
Write-Host ((" "*$pad)+$txt) -ForegroundColor Green
Write-Host $line -ForegroundColor Green

$servers=@(Get-ServerList)
if(!$servers){return}

$templateMap=Get-CertificateTemplateMap

Write-Log "Runspace Scan Phase In Process" -Header -HeaderColor Yellow

Write-Log ("Servers discovered: {0}" -f $servers.Count)

$results=Invoke-CertScan -Servers $servers -TemplateMap $templateMap
$report=@($results|Where-Object{$_.Result -eq 'Success'})

Write-Log ("Certificates identified for processing: {0}" -f $report.Count)

$duration=(Get-Date)-$ScriptStartTime

Write-Report $report
Write-Summary $results $report $servers.Count $duration

$excelParams = @{
    Report     = $report
    Results    = $results
    InputCount = $servers.Count
    Duration   = $duration
    Path       = $XlsxPath
}

[void](Export-ExcelReport @excelParams)

Send-EmailReport $results $report $servers.Count $duration

Invoke-LogCleanup -Path $OutputPath -Keep 2
