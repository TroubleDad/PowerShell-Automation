# =====================================================================
# Script:        Jeffs_Certerator.ps1
# Author:        Jeff Altomari, Alan W. Phillips
# Date:          2026-06-03
# Version:       3.7
#
# Description:   Menu-driven certificate utility for University Hospitals.
#                Generates RSA private keys and Certificate Signing
#                Requests via OpenSSL, submits them to an Active Directory
#                Certificate Services CA via certreq.exe against a chosen
#                certificate template, supports extra DNS and IP Subject
#                Alternative Name entries, accepts a single server name or
#                a file of servers, and can read an existing CSR to produce
#                a renewal CSR and certificate.
#
#                The full end-to-end pipeline (re-integrated in 3.0) builds
#                the issuing/root chain and a full-chain PKCS#12 (.pfx),
#                copies the .key/.pem/.cer/.pfx artifacts to each target's
#                remote certificate directory over WinRM, imports the PFX
#                into the LocalMachine store, binds it to IIS HTTPS, and
#                verifies the deployment. Per-server work runs across a
#                throttled RunspacePool; each worker buffers its log entries
#                and the main thread replays them through the standard
#                logging helpers so all output still reaches file and
#                console with aligned prefixes. A color HTML report is
#                emailed on completion.
#
#                A password-protected Root CRL maintenance action (menu
#                option 5) ports the Update_CRL workflow: it powers on the
#                offline Root CA in vCenter when needed, generates a fresh
#                Root CRL with certutil, copies it to the Sub CA, powers the
#                Root CA back off if this tool started it, publishes the CRL
#                to Active Directory, and validates the issuer. The action
#                always performs an explanatory DryRun first and only runs
#                for real after explicit operator confirmation.
#
# Requirements:  - Windows PowerShell 5.1
#                - OpenSSL for Windows (path set in the VARIABLES region)
#                - Windows PKI client tools (certreq.exe in PATH)
#                - PowerShell Remoting (WinRM) to targets for the remote
#                  deploy / import / IIS-bind / verify stages
#                - An -sa account with rights to remote into targets and to
#                  enroll against the chosen template
#                - SMTP relay reachable at smtp.uhhs.com:25 (anonymous)
#                - Issuing CA: uhpkisub03\University Hospitals Sub CA 3
#                - For the Root CRL maintenance action (menu option 5):
#                  VMware PowerCLI (Connect-VIServer / Invoke-VMScript),
#                  network access to the vCenter server, and a valid local
#                  credential on the Root CA for guest script execution.
#
# Change Log:
#
#   1.0  2026-06-01  Jeff Altomari   Initial script — single FQDN SAN, CSR + key
#                                    generation per server, audit CSV report.
#   1.1  2026-06-01  Jeff Altomari   Added .pem private key export per server.
#                                    Added remote E:\cert directory check via WinRM
#                                    using -sa credentials. Merged PEMStatus and
#                                    RemoteCertDir into summary report.
#   1.2  2026-06-01  Jeff Altomari   Expanded SANs: primary FQDN (.uhhs.com),
#                                    alternate FQDN (.uhhospitals.org), short name,
#                                    and resolved IPv4 (when available). Added DNS
#                                    resolution helper function. Dynamic SAN block
#                                    construction.
#   1.3  2026-06-01  Jeff Altomari   Changed primary domain from uhhospitals.org to
#                                    uhhs.com. Alternate domain set to
#                                    uhhospitals.org. CN now uses uhhs.com FQDN.
#                                    Added change history to script header.
#   1.4  2026-06-01  Jeff Altomari   Corrected issuing CA to uhpkisub03. Updated
#                                    OpenSSL path to C:\Program Files\OpenSSL-Win64.
#   1.5  2026-06-01  Jeff Altomari   Added certreq submission using certificate
#                                    template. Added .cer file retrieval per server.
#                                    Handles both auto-issued and pending request
#                                    scenarios. Added CERStatus and RequestID to
#                                    report.
#   1.6  2026-06-01  Jeff Altomari   Corrected template name to exact CA display
#                                    name: __UH__Web Server___SAN__2048__V2.
#   1.7  2026-06-01  Jeff Altomari   Updated CA config to use correct PKI hostname
#                                    (uhpkisub03) and issuer common name
#                                    (University Hospitals Sub CA 3).
#   1.8  2026-06-01  Jeff Altomari   Corrected template to programmatic name from
#                                    certutil -CATemplates output:
#                                    __UH__WebServer__SAN__2048__V2 (no space in
#                                    WebServer, two underscores before SAN).
#   1.9  2026-06-01  Jeff Altomari   Fixed PS 5.1 parse error: wrapped inline if/else
#                                    expressions in $() within hashtable literals.
#                                    Ensured here-string terminators at column 0.
#   2.0  2026-06-01  Jeff Altomari   Auto-create E:\cert on remote servers if missing.
#                                    Deploy .key, .pem, and .cer to each server's
#                                    E:\cert directory via PS remoting after
#                                    generation. Added DeployStatus to report.
#   2.1  2026-06-01  Jeff Altomari   Added post-deployment verification phase.
#                                    Reconnects to each server and confirms files
#                                    exist in E:\cert with file size comparison
#                                    against local source. Added VerifyStatus to
#                                    summary report and CSV.
#   2.2  2026-06-01  Jeff Altomari   Added PFX bundle creation from .key + .cer via
#                                    OpenSSL. Handles DER-to-PEM cert conversion for
#                                    compatibility. Added PFX import into
#                                    LocalMachine\My cert store on remote servers.
#                                    Added IIS HTTPS binding to Default Web Site
#                                    (port 443) using imported certificate.
#                                    Verification now checks IIS binding thumbprint.
#                                    Added PFXStatus and IISBindStatus to report.
#   2.3  2026-06-01  Jeff Altomari   Set PFX password to standard org credential
#                                    instead of ephemeral GUID. Stored in
#                                    $PFXPassword configuration variable.
#   2.4  2026-06-02  Alan W Phillips Applied standard header block and formatting
#                                    standards: Allman brace style, explicit section
#                                    banners, and removal of backtick line
#                                    continuations in favor of splatted hashtables
#                                    and native-command argument arrays. No functional
#                                    logic changes. Original script authored by
#                                    Jeff Altomari.
#   2.5  2026-06-02  Alan W Phillips Enhancements:
#                                    (#2)  Full-chain PFX — builds the issuing/root
#                                          chain from the issued certificate via .NET
#                                          X509Chain and passes it to OpenSSL with
#                                          -certfile. Optional $CAChainFile override.
#                                    (#4)  Added Write-Status / Write-Banner helpers
#                                          and an HTML email report (CSV attached)
#                                          relayed through smtp.uhhs.com.
#                                    (#5)  Wrapped execution with explicit exit codes
#                                          (0 = success, 1 = failure); pending CA
#                                          approvals are not treated as failures.
#                                    (#6)  Fail-fast pre-flight: certificate template
#                                          publication check (certutil -CATemplates)
#                                          and per-server WinRM reachability probe
#                                          (Test-WSMan); unreachable hosts are skipped.
#                                    (#8)  Parallelized per-server processing across a
#                                          throttled RunspacePool with a ConcurrentBag
#                                          result collector and buffered per-server
#                                          color-coded output. Original logic and
#                                          report schema preserved.
#   2.6  2026-06-02  Alan W Phillips  Renamed from New-WebServerCertificates.ps1.
#                                     Rebuilt as a menu-driven tool: template
#                                     selection, extra DNS/IP SAN entry,
#                                     single-name or file-based server input,
#                                     and CSR-renewal mode. Re-implemented
#                                     against the canonical logging, region,
#                                     and helper-function standard.
#   2.7  2026-06-02  Alan W Phillips  Set $CAConfig to the University Hospitals
#                                     Sub CA 3. Split each menu template into a
#                                     displayed FriendlyName and a submitted
#                                     CommonName so certreq receives the correct
#                                     space-free internal identifier (notably
#                                     the Domain Controller Authentication V2
#                                     template).
#   3.0  2026-06-02  Alan W Phillips  Re-integrated the prior pipeline stages:
#                                     full-chain PFX export (.NET X509Chain or
#                                     $CAChainFile override), remote E:\cert
#                                     deploy over WinRM, PFX import + IIS HTTPS
#                                     binding, and post-deploy verification.
#                                     Per-server processing now runs through a
#                                     throttled RunspacePool with logs buffered
#                                     in each worker and replayed on the main
#                                     thread via the standard logging helpers.
#                                     Each remote stage is independently
#                                     toggleable in the VARIABLES region.
#   3.1  2026-06-02  Alan W Phillips  Reworded the WinRM pre-flight output for an
#                                     unreachable target to a WARN line
#                                     ("<fqdn> is not a valid destination at this
#                                     time.") followed by an INFO line noting that
#                                     remote stages will be skipped.
#   3.2  2026-06-02  Alan W Phillips  Detect templates requiring CA certificate
#                                     manager approval. A pending submission
#                                     (exit 0 with a RequestId but no issued
#                                     cert, or "pending"/"taken under submission"
#                                     output) now logs two INFO lines noting the
#                                     request awaits approval in Pending Requests
#                                     and points to the logfile, and is reported
#                                     as "Pending Approval" (amber) rather than a
#                                     WARN failure. Genuine failures are now
#                                     reported as "Failed".
#   3.3  2026-06-03  Alan W Phillips  Added two menu actions. "Inspect a PFX"
#                                     loads a .pfx (prompting for its password),
#                                     exports DER (.cer) and PEM (.crt) copies,
#                                     and displays the certificate template,
#                                     Common Name, full Subject locale fields
#                                     (C/ST/L/O/OU/E), and the SAN DNS/IP
#                                     entries. "Modify a certificate and create
#                                     a new one" reads those same details from a
#                                     source .pfx, lets each Subject field and the
#                                     SAN lists be edited in place, then drives the
#                                     existing CSR/submit/chain/PFX pipeline to
#                                     issue a fresh certificate from the modified
#                                     data. Added Read-WithDefault,
#                                     Read-PfxFilePassword, the PFX INSPECTION
#                                     region helpers, and certificate-extension
#                                     OID variables in the VARIABLES region.
#   3.4  2026-06-03  Alan W Phillips  Remote stages no longer force a credential
#                                     prompt. Request-RemoteCredential now runs
#                                     whoami (Test-CurrentUserIsSA); if the
#                                     interactive user is already logged on under
#                                     an -sa account, it offers to use that current
#                                     logon for remote operations and skip the
#                                     Get-Credential prompt. The choice is carried
#                                     in $UseCurrentIdentity and passed to the
#                                     worker, which opens PSSessions without an
#                                     explicit -Credential when it is set.
#   3.5  2026-06-03  Alan W Phillips  Added a password-protected "Update Root
#                                     CRL" menu action (option 5) that ports the
#                                     Update_CRL.ps1 workflow into the canonical
#                                     helper-function / logging model. A masked
#                                     password prompt (up to three attempts)
#                                     gates the action. On success the workflow
#                                     always runs in DryRun first, narrating every
#                                     action it would take (vCenter connect, VM
#                                     pre-flight, Root CA power-on + VMware Tools
#                                     wait, certutil -crl generation, CRL copy to
#                                     the Sub CA share and CertEnroll, Root CA
#                                     power-off, certutil -dspublish to AD, issuer
#                                     validation, and vCenter disconnect). The
#                                     operator is then prompted (defaulting to No)
#                                     and the identical logic executes for real
#                                     only on an explicit Yes. Added the CRL
#                                     MAINTENANCE region helpers, the CRL
#                                     configuration block in VARIABLES, and the
#                                     Test-CrlMenuPassword / Invoke-UpdateCrl /
#                                     Invoke-CrlMaintenance functions. Remote
#                                     script bodies are built with token-replaced
#                                     single-quoted here-strings (no backticks).
#                                     Renumbered Exit to option 6.
#   3.6  2026-06-03  Alan W Phillips  Corrected the menu option 1 web server
#                                     template. FriendlyName is now
#                                     "__UH__Web Server__SAN__2048__V2" and the
#                                     submitted CommonName is
#                                     "__UH__WebServer__SAN__2048__V2" (no space
#                                     in WebServer, V2 suffix), matching the
#                                     template published on the Sub CA.
#   3.7  2026-06-03  Alan W Phillips  Fixed the HTML email body heading. It read
#                                     "Jeffs_Certerator <?> Certificate Report"
#                                     because the script name carried an
#                                     underscore and the em dash did not survive
#                                     mail encoding. Added a $ReportTitle variable
#                                     ("Jeff's Certerator Certificate Report") and
#                                     used it for the <h2>. Also replaced the em
#                                     dash in the DryRun note banner with an ASCII
#                                     hyphen so it no longer renders as "?".
#
# =====================================================================

# ============================================================
# REGION: VARIABLES
# ============================================================

# --- Identity / dates ---
$ScriptName   = 'Jeffs_Certerator'
$ReportTitle  = "Jeff's Certerator Certificate Report"   # Heading shown in the HTML email body.
$FriendlyDate = Get-Date -Format 'dddd, MMMM dd, yyyy'
$RunStamp     = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# --- Behavior toggles ---
$DryRun           = $false   # $true = log intended actions only; no writes, no submission, no remote ops.
$SendEmail        = $true    # $true = email the HTML report on completion.
$UseParallel      = $true    # $true = process servers via RunspacePool; $false = sequential.
$ExportPfx        = $true    # $true = build full-chain PFX from key + issued cert.
$DeployToRemote   = $true    # $true = copy artifacts to each target's remote cert directory.
$BindIis          = $true    # $true = import PFX and bind to IIS HTTPS on each target.
$VerifyDeployment = $true    # $true = re-check deployed files and IIS binding after deploy.

# --- Parallelism ---
$MaxConcurrency = 5          # Maximum concurrent server runspaces.

# --- SMTP / email (open relay, no authentication) ---
$SmtpServer = 'smtp.uhhs.com'
$SmtpPort   = 25
$MailFrom   = 'Certerator@uhhs.com'
$MailTo     = @(
    'Alan.Phillips@UHhospitals.org'
    'Jeffrey.Altomari@UHhospitals.org'
)

# --- Filesystem / logging paths ---
$OutputRoot = 'C:\Temp\Certerator'
$LogRoot    = Join-Path -Path $OutputRoot -ChildPath 'Logs'
$LogFile    = Join-Path -Path $LogRoot -ChildPath ('{0}_{1}.log' -f $ScriptName, $RunStamp)

# --- OpenSSL / PKI tooling ---
$OpenSSLPath = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$KeyLength   = 2048

# --- Issuing CA ---
# Format: "CAHostName\CA Common Name". If left blank, the script prompts
# for it at runtime.
$CAConfig = 'uhpkisub03\University Hospitals Sub CA 3'

# --- Remote deployment / IIS ---
$RemoteCertDir = 'E:\cert'              # Target directory on each remote server.
$IISSiteName   = 'Default Web Site'     # IIS site to bind the certificate to.
$IISBindPort   = 443                    # HTTPS binding port.

# --- PFX / chain ---
# $PFXPassword is left blank; if blank and $ExportPfx is $true the script
# prompts for it once as a SecureString. $CAChainFile, if set to a PEM file
# holding the issuing + root certificates, overrides the .NET chain build.
$PFXPassword = ''
$CAChainFile = ''

# --- DNS domains used to build default SAN entries ---
$PrimaryDomain   = 'uhhs.com'           # CN / primary FQDN domain
$AlternateDomain = 'uhhospitals.org'    # additional default SAN domain

# --- Subject Distinguished Name fields ---
$Country      = 'US'
$State        = 'Ohio'
$Locality     = 'Cleveland'
$Organization = 'University Hospitals'
$OrgUnit      = 'Information Technology'

# --- Certificate templates offered in the menu ---
# FriendlyName is shown in the menu; CommonName is what certreq submits via
# "CertificateTemplate:<name>". These differ when a template's display name
# contains spaces (the CA expects the space-free internal CN). Confirm any
# additional templates with: certutil -template
$CertTemplates = [ordered]@{
    '1' = [PSCustomObject]@{
        FriendlyName = '__UH__Web Server__SAN__2048__V2'
        CommonName   = '__UH__WebServer__SAN__2048__V2'
    }
    '2' = [PSCustomObject]@{
        FriendlyName = '__UH__Domain Controller Authentication__SAN__2048__V2'
        CommonName   = '__UH__DomainControllerAuthentication__SAN__2048__V2'
    }
    '3' = [PSCustomObject]@{
        FriendlyName = '__UH__RDS__Authentication'
        CommonName   = '__UH__RDS__Authentication'
    }
}

# --- Console color map for log levels ---
$LevelColors = @{
    'INFO '  = 'Cyan'
    'OK   '  = 'Green'
    'WARN '  = 'Yellow'
    'ERROR'  = 'Red'
    'DRYRUN' = 'Magenta'
}

# --- Runtime-populated holders (set during a run) ---
$SACred  = $null    # PSCredential for remote operations.
$PfxPlain = $null   # Plaintext PFX password marshalled into worker config.
$UseCurrentIdentity = $false   # $true = run remote stages as the current -sa logon (no prompt).

# --- PFX inspection / re-issue ---
$InspectRoot = Join-Path -Path $OutputRoot -ChildPath 'Inspect'   # CER/CRT export target.

# --- Certificate extension OIDs (used to read template + SAN data) ---
$OidTemplateInfo   = '1.3.6.1.4.1.311.21.7'   # Certificate Template Information (V2+).
$OidTemplateNameV1 = '1.3.6.1.4.1.311.20.2'   # Certificate Template Name (V1).
$OidSubjectAltName = '2.5.29.17'              # Subject Alternative Name.

# --- Root CRL maintenance (menu option 5) ---
# Hidden password gating the CRL update action; the workflow always performs
# an explanatory DryRun first and only executes after operator confirmation.
$CrlMenuPassword     = '1001001SOS'                       # Masked-entry password for the CRL action.
$CrlMenuMaxAttempts  = 3                                  # Password attempts before returning to the menu.
$vCenterServer       = 'UHVSPHCON01.uhhs.com'             # vCenter managing the CA virtual machines.
$RootCAServer        = 'UHPKIROOT02'                      # Offline Root CA VM name (vCenter inventory).
$SubCAServer         = 'UHPKISUB03'                       # Issuing Sub CA VM name (vCenter inventory).
$RootUsername        = 'Administrator'                    # Local Root CA account for Invoke-VMScript.
$RootPassword        = 'bCoF5N53'                         # Local Root CA password (guest credential).
$ToolsTimeoutSeconds = 600                                # Max seconds to wait for VMware Tools.
$RootCaIssuerName    = 'University Hospitals Root CA 2'    # Expected CRL issuer used for validation.

# --- Root CRL maintenance: OS-derived paths (resolved on this host) ---
$CrlSystemRoot     = $env:SystemRoot
$CrlSystemDrive    = $env:SystemDrive.TrimEnd('\')
$CrlSystemRootName = Split-Path -Path $CrlSystemRoot -Leaf
$CrlSystem32Path   = Join-Path -Path $CrlSystemRoot -ChildPath 'System32'

# --- Root CRL maintenance: PKI paths ---
$CertEnrollPath       = Join-Path -Path $CrlSystem32Path -ChildPath 'CertSrv\CertEnroll'
$CRLNamePattern       = 'University Hospitals Root CA 2*.crl'
$CRLSharePath         = '\\{0}\{1}$\pki\crl' -f $SubCAServer, $CrlSystemDrive.TrimEnd(':')
$CRLSubCertEnrollPath = '\\{0}\{1}$\{2}\System32\CertSrv\CertEnroll' -f $SubCAServer, $CrlSystemDrive.TrimEnd(':'), $CrlSystemRootName
$SubCACRLPath         = 'E:\pki\crl\University Hospitals Root CA 2.crl'

# ============================================================
# REGION: LOGGING FUNCTIONS
# ============================================================

function Write-Log
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Tag = 'INFO '
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry     = '{0} [{1}] {2}' -f $Timestamp, $Tag, $Message

    try
    {
        Add-Content -LiteralPath $script:LogFile -Value $Entry -Encoding UTF8 -ErrorAction Stop
    }
    catch
    {
        Write-Host ('[ERROR] Unable to write to log file {0}: {1}' -f $script:LogFile, $_.Exception.Message) -ForegroundColor Red
    }
}

function Write-InfoMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ('[INFO ] {0}' -f $Message) -ForegroundColor $script:LevelColors['INFO ']
    Write-Log -Message $Message -Tag 'INFO '
}

function Write-SuccessMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ('[OK   ] {0}' -f $Message) -ForegroundColor $script:LevelColors['OK   ']
    Write-Log -Message $Message -Tag 'OK   '
}

function Write-WarnMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ('[WARN ] {0}' -f $Message) -ForegroundColor $script:LevelColors['WARN ']
    Write-Log -Message $Message -Tag 'WARN '
}

function Write-ErrorMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ('[ERROR] {0}' -f $Message) -ForegroundColor $script:LevelColors['ERROR']
    Write-Log -Message $Message -Tag 'ERROR'
}

function Write-DryRunMsg
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ('[DRYRUN] {0}' -f $Message) -ForegroundColor $script:LevelColors['DRYRUN']
    Write-Log -Message $Message -Tag 'DRYRUN'
}

function Write-BufferedEntry
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Tag,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    switch ($Tag)
    {
        'OK   '  { Write-SuccessMsg $Message }
        'WARN '  { Write-WarnMsg    $Message }
        'ERROR'  { Write-ErrorMsg   $Message }
        'DRYRUN' { Write-DryRunMsg  $Message }
        default  { Write-InfoMsg    $Message }
    }
}

# ============================================================
# REGION: HELPER FUNCTIONS
# ============================================================

function Get-EmailSubject
{
    $DateStamp = Get-Date -Format 'MM-dd-yyyy'
    return ('{0} - {1}' -f $script:ScriptName, $DateStamp)
}

function Initialize-Logging
{
    foreach ($Dir in @($script:OutputRoot, $script:LogRoot))
    {
        if (-not (Test-Path -LiteralPath $Dir))
        {
            $null = New-Item -Path $Dir -ItemType Directory -Force
        }
    }

    Write-InfoMsg ('{0} started on {1}' -f $script:ScriptName, $script:FriendlyDate)
    Write-InfoMsg ('Log file: {0}' -f $script:LogFile)

    if ($script:DryRun)
    {
        Write-DryRunMsg 'DryRun mode is ENABLED. No files will be written, nothing will be submitted, and no remote operations will run.'
    }
}

function Test-Prerequisites
{
    $AllOk = $true

    if (Test-Path -LiteralPath $script:OpenSSLPath)
    {
        Write-SuccessMsg ('OpenSSL found: {0}' -f $script:OpenSSLPath)
    }
    else
    {
        Write-ErrorMsg ('OpenSSL not found at {0}. Update $OpenSSLPath in the VARIABLES region.' -f $script:OpenSSLPath)
        $AllOk = $false
    }

    $CertReq = (Get-Command -Name 'certreq.exe' -ErrorAction SilentlyContinue).Source
    if ($CertReq)
    {
        Write-SuccessMsg ('certreq.exe found: {0}' -f $CertReq)
    }
    else
    {
        Write-ErrorMsg 'certreq.exe was not found in PATH. Windows PKI client tools are required.'
        $AllOk = $false
    }

    if ([string]::IsNullOrWhiteSpace($script:CAConfig))
    {
        Write-WarnMsg 'No CA configuration is set in the VARIABLES region.'
        $Entered = Read-Host 'Enter the issuing CA config string ("CAHost\CA Common Name")'
        if ([string]::IsNullOrWhiteSpace($Entered))
        {
            Write-ErrorMsg 'A CA configuration string is required to submit requests.'
            $AllOk = $false
        }
        else
        {
            $script:CAConfig = $Entered.Trim()
            Write-InfoMsg ('CA configuration set to: {0}' -f $script:CAConfig)
        }
    }
    else
    {
        Write-InfoMsg ('CA configuration: {0}' -f $script:CAConfig)
    }

    if ($script:CAChainFile -ne '' -and -not (Test-Path -LiteralPath $script:CAChainFile))
    {
        Write-WarnMsg ('Configured $CAChainFile not found: {0}. Falling back to .NET chain build.' -f $script:CAChainFile)
    }

    return $AllOk
}

function Read-DelimitedInput
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    $Raw = Read-Host $Prompt

    if ([string]::IsNullOrWhiteSpace($Raw))
    {
        return @()
    }

    $Items = $Raw -split '[,;]' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' }

    return @($Items)
}

function Get-ShortNameFromValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $Trimmed = $Value.Trim()
    if ($Trimmed -match '\.')
    {
        return ($Trimmed -split '\.')[0]
    }

    return $Trimmed
}

function Read-WithDefault
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [string]$Default = ''
    )

    $Suffix = if ([string]::IsNullOrWhiteSpace($Default)) { '' } else { (' [{0}]' -f $Default) }
    $Raw    = Read-Host (('{0}{1}' -f $Prompt, $Suffix))

    if ([string]::IsNullOrWhiteSpace($Raw))
    {
        return $Default
    }

    return $Raw.Trim()
}

function Read-PfxFilePassword
{
    $Secure = Read-Host -Prompt 'Enter the password for the PFX file' -AsSecureString

    if (-not $Secure -or $Secure.Length -eq 0)
    {
        Write-WarnMsg 'No password was entered; attempting to open the PFX with an empty password.'
        return (New-Object System.Security.SecureString)
    }

    return $Secure
}

function Test-RemoteStageEnabled
{
    return ($script:DeployToRemote -or $script:BindIis -or $script:VerifyDeployment)
}

function Test-CurrentUserIsSA
{
    $Identity = ''

    try
    {
        $Identity = (& whoami 2>$null | Select-Object -First 1)
    }
    catch
    {
        $Identity = ''
    }

    if ([string]::IsNullOrWhiteSpace($Identity))
    {
        $Identity = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
    }

    $Identity = $Identity.Trim()
    $UserPart = if ($Identity.Contains('\')) { ($Identity -split '\\')[-1] } else { $Identity }
    $IsSA     = ($UserPart -match '(?i)-sa$')

    return [PSCustomObject]@{
        Identity = $Identity
        UserPart = $UserPart
        IsSA     = $IsSA
    }
}

function Request-RemoteCredential
{
    if ($script:SACred -or $script:UseCurrentIdentity)
    {
        return $true
    }

    # Bypass the credential prompt when the interactive user is already logged
    # on under an -sa account; remote stages then run under the current logon
    # via integrated Windows authentication.
    $Current = Test-CurrentUserIsSA
    if ($Current.IsSA)
    {
        Write-InfoMsg ('Current logon is {0}, which appears to be an -sa account.' -f $Current.Identity)
        $Answer = Read-Host 'Use this logon for remote operations and skip the credential prompt? (Y/N) [Y]'

        if ([string]::IsNullOrWhiteSpace($Answer) -or $Answer.Trim() -match '(?i)^y')
        {
            $script:UseCurrentIdentity = $true
            Write-SuccessMsg ('Remote operations will run as the current logon: {0}' -f $Current.Identity)
            return $true
        }

        Write-InfoMsg 'Current logon will not be used; prompting for an -sa credential instead.'
    }

    Write-InfoMsg 'Remote operations are enabled; an -sa credential is required.'
    $Cred = Get-Credential -Message 'Enter your -sa account credentials (e.g. DOMAIN\jaltoma1-sa)'

    if (-not $Cred)
    {
        Write-ErrorMsg 'No credential provided. Remote stages cannot run.'
        return $false
    }

    $script:SACred = $Cred
    Write-SuccessMsg ('Credential captured for: {0}' -f $Cred.UserName)
    return $true
}

function Request-PfxPassword
{
    if (-not [string]::IsNullOrWhiteSpace($script:PfxPlain))
    {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($script:PFXPassword))
    {
        $script:PfxPlain = $script:PFXPassword
        return $true
    }

    Write-InfoMsg 'A PFX export password is required.'
    $Secure = Read-Host -Prompt 'Enter the PFX export password' -AsSecureString

    if (-not $Secure -or $Secure.Length -eq 0)
    {
        Write-ErrorMsg 'No PFX password provided. PFX export cannot run.'
        return $false
    }

    $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try
    {
        $script:PfxPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
    }

    Write-SuccessMsg 'PFX password captured.'
    return $true
}

function Test-ServerReachable
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$WorkItems
    )

    $Reachable = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Item in $WorkItems)
    {
        $Fqdn = '{0}.{1}' -f $Item.ShortName, $script:PrimaryDomain
        $Ok   = Test-WSMan -ComputerName $Fqdn -ErrorAction SilentlyContinue

        if ($Ok)
        {
            Write-SuccessMsg ('WinRM reachable: {0}' -f $Fqdn)
            $Reachable.Add($Item)
        }
        else
        {
            Write-WarnMsg ('{0} is not a valid destination at this time.' -f $Fqdn)
            Write-InfoMsg 'Remote stages will be skipped for this destination'
            $Item | Add-Member -NotePropertyName 'RemoteSkipped' -NotePropertyValue $true -Force
            $Reachable.Add($Item)
        }
    }

    return $Reachable
}

# ============================================================
# REGION: SAN AND CONFIG FUNCTIONS
# ============================================================

function Build-SanList
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ShortName,

        [string[]]$ExtraDns = @(),

        [string[]]$ExtraIp = @()
    )

    $PrimaryFqdn   = '{0}.{1}' -f $ShortName, $script:PrimaryDomain
    $AlternateFqdn = '{0}.{1}' -f $ShortName, $script:AlternateDomain

    $DnsNames = [System.Collections.Generic.List[string]]::new()
    foreach ($Name in @($PrimaryFqdn, $AlternateFqdn, $ShortName) + $ExtraDns)
    {
        $Clean = $Name.Trim()
        if ($Clean -ne '' -and -not $DnsNames.Contains($Clean))
        {
            $DnsNames.Add($Clean)
        }
    }

    $IpAddresses = [System.Collections.Generic.List[string]]::new()
    foreach ($Ip in $ExtraIp)
    {
        $Clean = $Ip.Trim()
        if ($Clean -ne '' -and -not $IpAddresses.Contains($Clean))
        {
            $IpAddresses.Add($Clean)
        }
    }

    return [PSCustomObject]@{
        CommonName  = $PrimaryFqdn
        DnsNames    = $DnsNames
        IpAddresses = $IpAddresses
    }
}

# ============================================================
# REGION: CSR READING (RENEWAL)
# ============================================================

function Read-ExistingCsr
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$CsrPath
    )

    $ReadArgs = @(
        'req'
        '-in', $CsrPath
        '-noout'
        '-text'
    )

    $Text = & $script:OpenSSLPath @ReadArgs 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        Write-ErrorMsg ('OpenSSL could not parse the CSR {0}.' -f $CsrPath)
        return $null
    }

    $Joined = ($Text | Out-String)

    $CommonName = $null
    $CnMatch = [regex]::Match($Joined, 'CN\s*=\s*([^,\r\n]+)')
    if ($CnMatch.Success)
    {
        $CommonName = $CnMatch.Groups[1].Value.Trim()
    }

    $DnsNames    = [System.Collections.Generic.List[string]]::new()
    $IpAddresses = [System.Collections.Generic.List[string]]::new()

    foreach ($DnsHit in [regex]::Matches($Joined, 'DNS:([^,\s]+)'))
    {
        $Value = $DnsHit.Groups[1].Value.Trim()
        if ($Value -ne '' -and -not $DnsNames.Contains($Value))
        {
            $DnsNames.Add($Value)
        }
    }

    foreach ($IpHit in [regex]::Matches($Joined, 'IP Address:([^,\s]+)'))
    {
        $Value = $IpHit.Groups[1].Value.Trim()
        if ($Value -ne '' -and -not $IpAddresses.Contains($Value))
        {
            $IpAddresses.Add($Value)
        }
    }

    if (-not $CommonName)
    {
        Write-ErrorMsg ('No Common Name (CN) was found in {0}.' -f $CsrPath)
        return $null
    }

    Write-InfoMsg ('Parsed CSR CN: {0}' -f $CommonName)
    Write-InfoMsg ('Parsed DNS SANs: {0}' -f (($DnsNames -join ', ')))
    if ($IpAddresses.Count -gt 0)
    {
        Write-InfoMsg ('Parsed IP SANs: {0}' -f (($IpAddresses -join ', ')))
    }

    return [PSCustomObject]@{
        CommonName  = $CommonName
        DnsNames    = $DnsNames
        IpAddresses = $IpAddresses
    }
}

# ============================================================
# REGION: PFX INSPECTION
# ============================================================

function Import-PfxCertificateObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PfxPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )

    $Flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

    try
    {
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxPath, $Password, $Flags)
        Write-SuccessMsg ('PFX loaded: {0}' -f $PfxPath)
        return $Cert
    }
    catch
    {
        Write-ErrorMsg ('Unable to open PFX {0}: {1}' -f $PfxPath, $_.Exception.Message)
        Write-InfoMsg  'Verify the file path and the password and try again.'
        return $null
    }
}

function ConvertFrom-X500Name
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$Name
    )

    $Fields = [ordered]@{}

    $Formatted = $Name.Format($true)
    $Lines     = $Formatted -split '\r?\n' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' }

    foreach ($Line in $Lines)
    {
        $SplitAt = $Line.IndexOf('=')
        if ($SplitAt -lt 1)
        {
            continue
        }

        $Key   = $Line.Substring(0, $SplitAt).Trim().ToUpperInvariant()
        $Value = $Line.Substring($SplitAt + 1).Trim()

        if (-not $Fields.Contains($Key))
        {
            $Fields[$Key] = $Value
        }
    }

    return $Fields
}

function Get-SubjectFieldValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Fields,

        [Parameter(Mandatory = $true)]
        [string[]]$Keys,

        [string]$Default = ''
    )

    foreach ($Key in $Keys)
    {
        $Upper = $Key.ToUpperInvariant()
        if ($Fields.Contains($Upper) -and -not [string]::IsNullOrWhiteSpace([string]$Fields[$Upper]))
        {
            return [string]$Fields[$Upper]
        }
    }

    return $Default
}

function Get-CertificateTemplateName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    foreach ($Oid in @($script:OidTemplateInfo, $script:OidTemplateNameV1))
    {
        $Ext = $Cert.Extensions |
            Where-Object { $_.Oid.Value -eq $Oid } |
            Select-Object -First 1

        if ($Ext)
        {
            $Formatted = ($Ext.Format($true) -split '\r?\n' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne '' }) -join '; '

            $NameMatch = [regex]::Match($Formatted, 'Template=([^(;\r\n]+)')
            if ($NameMatch.Success)
            {
                return $NameMatch.Groups[1].Value.Trim()
            }

            return $Formatted
        }
    }

    return 'Not present'
}

function Get-CertificateSan
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    $DnsNames    = [System.Collections.Generic.List[string]]::new()
    $IpAddresses = [System.Collections.Generic.List[string]]::new()

    $Ext = $Cert.Extensions |
        Where-Object { $_.Oid.Value -eq $script:OidSubjectAltName } |
        Select-Object -First 1

    if ($Ext)
    {
        $Formatted = $Ext.Format($true)

        foreach ($DnsHit in [regex]::Matches($Formatted, 'DNS Name=([^,\r\n]+)'))
        {
            $Value = $DnsHit.Groups[1].Value.Trim()
            if ($Value -ne '' -and -not $DnsNames.Contains($Value))
            {
                $DnsNames.Add($Value)
            }
        }

        foreach ($IpHit in [regex]::Matches($Formatted, 'IP Address=([^,\r\n]+)'))
        {
            $Value = $IpHit.Groups[1].Value.Trim()
            if ($Value -ne '' -and -not $IpAddresses.Contains($Value))
            {
                $IpAddresses.Add($Value)
            }
        }
    }

    return [PSCustomObject]@{
        DnsNames    = $DnsNames
        IpAddresses = $IpAddresses
    }
}

function Export-CerAndCrt
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

        [Parameter(Mandatory = $true)]
        [string]$BaseName
    )

    if (-not (Test-Path -LiteralPath $script:InspectRoot))
    {
        $null = New-Item -Path $script:InspectRoot -ItemType Directory -Force
    }

    $CerPath = Join-Path -Path $script:InspectRoot -ChildPath ('{0}.cer' -f $BaseName)
    $CrtPath = Join-Path -Path $script:InspectRoot -ChildPath ('{0}.crt' -f $BaseName)

    $DerBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($CerPath, $DerBytes)
    Write-SuccessMsg ('DER certificate written: {0}' -f $CerPath)

    $B64    = [Convert]::ToBase64String($Cert.RawData, 'InsertLineBreaks')
    $PemTxt = '-----BEGIN CERTIFICATE-----' + [Environment]::NewLine + $B64 + [Environment]::NewLine + '-----END CERTIFICATE-----'
    $PemTxt | Out-File -FilePath $CrtPath -Encoding ASCII -Force
    Write-SuccessMsg ('PEM certificate written: {0}' -f $CrtPath)

    return [PSCustomObject]@{
        CerPath = $CerPath
        CrtPath = $CrtPath
    }
}

function Show-CertificateDetails
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    $SubjectFields = ConvertFrom-X500Name -Name $Cert.SubjectName
    $IssuerFields  = ConvertFrom-X500Name -Name $Cert.IssuerName
    $Template      = Get-CertificateTemplateName -Cert $Cert
    $San           = Get-CertificateSan -Cert $Cert

    $CommonName   = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('CN')               -Default 'N/A'
    $Country      = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('C')                -Default ''
    $State        = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('S', 'ST')          -Default ''
    $Locality     = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('L')                -Default ''
    $Organization = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('O')                -Default ''
    $OrgUnit      = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('OU')               -Default ''
    $Email        = Get-SubjectFieldValue -Fields $SubjectFields -Keys @('E', 'EMAILADDRESS') -Default ''
    $IssuerCn     = Get-SubjectFieldValue -Fields $IssuerFields  -Keys @('CN')               -Default $Cert.Issuer

    Write-Host ''
    Write-Host '===================== Certificate Details =====================' -ForegroundColor Cyan

    Write-InfoMsg ('Template            : {0}' -f $Template)
    Write-InfoMsg ('Common Name (CN)    : {0}' -f $CommonName)
    Write-InfoMsg ('Country (C)         : {0}' -f $Country)
    Write-InfoMsg ('State / Province (S): {0}' -f $State)
    Write-InfoMsg ('Locality (L)        : {0}' -f $Locality)
    Write-InfoMsg ('Organization (O)    : {0}' -f $Organization)
    Write-InfoMsg ('Org. Unit (OU)      : {0}' -f $OrgUnit)

    if (-not [string]::IsNullOrWhiteSpace($Email))
    {
        Write-InfoMsg ('Email (E)           : {0}' -f $Email)
    }

    Write-InfoMsg ('Issuer CN           : {0}' -f $IssuerCn)
    Write-InfoMsg ('Serial Number       : {0}' -f $Cert.SerialNumber)
    Write-InfoMsg ('Thumbprint          : {0}' -f $Cert.Thumbprint)
    Write-InfoMsg ('Valid From          : {0}' -f $Cert.NotBefore)
    Write-InfoMsg ('Valid To            : {0}' -f $Cert.NotAfter)

    if ($San.DnsNames.Count -gt 0)
    {
        Write-InfoMsg ('DNS SANs            : {0}' -f ($San.DnsNames -join ', '))
    }
    else
    {
        Write-InfoMsg 'DNS SANs            : (none)'
    }

    if ($San.IpAddresses.Count -gt 0)
    {
        Write-InfoMsg ('IP SANs             : {0}' -f ($San.IpAddresses -join ', '))
    }
    else
    {
        Write-InfoMsg 'IP SANs             : (none)'
    }

    Write-Host '===============================================================' -ForegroundColor Cyan

    return [PSCustomObject]@{
        Template     = $Template
        CommonName   = $CommonName
        Country      = $Country
        State        = $State
        Locality     = $Locality
        Organization = $Organization
        OrgUnit      = $OrgUnit
        Email        = $Email
        DnsNames     = $San.DnsNames
        IpAddresses  = $San.IpAddresses
    }
}

# ============================================================
# REGION: SERVER PIPELINE (WORKER)
# ============================================================

# Self-contained per-server pipeline. It must not call script-scope logging
# helpers or touch the shared log file, because it also runs inside isolated
# RunspacePool threads. Instead it buffers structured log entries (Tag +
# Message) into the returned result; the main thread replays them through the
# standard Write-*Msg helpers so output still reaches file and console.
$ServerWorker = {
    param
    (
        [PSCustomObject]$WorkItem,
        [hashtable]$Config,
        [System.Management.Automation.PSCredential]$SACred,
        [string]$PfxPlain
    )

    $LogEntries = [System.Collections.Generic.List[object]]::new()

    function Add-WorkerLog
    {
        param
        (
            [string]$Message,
            [string]$Tag = 'INFO '
        )

        $LogEntries.Add([PSCustomObject]@{ Tag = $Tag; Message = $Message })
    }

    $ShortName     = $WorkItem.ShortName
    $CommonName    = $WorkItem.CommonName
    $DnsNames      = $WorkItem.DnsNames
    $IpAddresses   = $WorkItem.IpAddresses
    $Template      = $WorkItem.Template
    $RunMode       = $WorkItem.RunMode
    $RemoteSkipped = ($WorkItem.PSObject.Properties.Name -contains 'RemoteSkipped' -and $WorkItem.RemoteSkipped)

    $PrimaryFqdn = '{0}.{1}' -f $ShortName, $Config.PrimaryDomain
    $ServerDir   = Join-Path -Path $Config.OutputRoot -ChildPath $ShortName

    $ConfigFile = Join-Path -Path $ServerDir -ChildPath ('{0}.cnf' -f $ShortName)
    $KeyFile    = Join-Path -Path $ServerDir -ChildPath ('{0}.key' -f $ShortName)
    $PemFile    = Join-Path -Path $ServerDir -ChildPath ('{0}.pem' -f $ShortName)
    $CsrFile    = Join-Path -Path $ServerDir -ChildPath ('{0}.csr' -f $ShortName)
    $CerFile    = Join-Path -Path $ServerDir -ChildPath ('{0}.cer' -f $ShortName)
    $CerPemFile = Join-Path -Path $ServerDir -ChildPath ('{0}-cert.pem' -f $ShortName)
    $ChainFile  = Join-Path -Path $ServerDir -ChildPath ('{0}-chain.pem' -f $ShortName)
    $PfxFile    = Join-Path -Path $ServerDir -ChildPath ('{0}.pfx' -f $ShortName)
    $ErrLog     = Join-Path -Path $ServerDir -ChildPath ('{0}-openssl.log' -f $ShortName)
    $SubmitLog  = Join-Path -Path $ServerDir -ChildPath ('{0}-certreq.log' -f $ShortName)

    $Result = [PSCustomObject]@{
        Server          = $ShortName
        CommonName      = $CommonName
        RunMode         = $RunMode
        Template        = $Template
        DnsSans         = ($DnsNames -join ', ')
        IpSans          = ($IpAddresses -join ', ')
        CsrStatus       = 'Pending'
        SubmitStatus    = 'Skipped'
        RequestId       = 'N/A'
        ChainStatus     = 'Skipped'
        PfxStatus       = 'Skipped'
        RemoteDirStatus = 'Skipped'
        DeployStatus    = 'Skipped'
        IisBindStatus   = 'Skipped'
        VerifyStatus    = 'Skipped'
        Thumbprint      = 'N/A'
        LogEntries      = $LogEntries
    }

    Add-WorkerLog ('Processing {0} (CN: {1}, mode: {2})' -f $ShortName, $CommonName, $RunMode)

    if ($IpAddresses.Count -gt 0)
    {
        Add-WorkerLog 'IP SANs were supplied; some CA templates reject IP address SANs. Verify issuance.' 'WARN '
    }

    # ----- DryRun short-circuit -----
    if ($Config.DryRun)
    {
        Add-WorkerLog ('Would create config/key/CSR under {0}' -f $ServerDir) 'DRYRUN'
        Add-WorkerLog ('Would submit to CA {0} using template "{1}"' -f $Config.CAConfig, $Template) 'DRYRUN'
        if ($Config.ExportPfx)      { Add-WorkerLog 'Would build chain and export full-chain PFX.' 'DRYRUN' }
        if ($Config.DeployToRemote) { Add-WorkerLog ('Would deploy artifacts to {0} on {1}' -f $Config.RemoteCertDir, $PrimaryFqdn) 'DRYRUN' }
        if ($Config.BindIis)        { Add-WorkerLog ('Would import PFX and bind IIS {0}:{1} on {2}' -f $Config.IISSiteName, $Config.IISBindPort, $PrimaryFqdn) 'DRYRUN' }
        if ($Config.VerifyDeployment) { Add-WorkerLog 'Would verify deployed files and IIS binding.' 'DRYRUN' }

        $Result.CsrStatus    = 'DryRun'
        $Result.SubmitStatus = 'DryRun'
        return $Result
    }

    # ----- Ensure local server directory -----
    if (-not (Test-Path -LiteralPath $ServerDir))
    {
        $null = New-Item -Path $ServerDir -ItemType Directory -Force
    }

    # ----- Build OpenSSL config -----
    $SanLines = [System.Collections.Generic.List[string]]::new()
    $DnsIndex = 1
    foreach ($Dns in $DnsNames)
    {
        $SanLines.Add(('DNS.{0} = {1}' -f $DnsIndex, $Dns))
        $DnsIndex++
    }
    $IpIndex = 1
    foreach ($Ip in $IpAddresses)
    {
        $SanLines.Add(('IP.{0} = {1}' -f $IpIndex, $Ip))
        $IpIndex++
    }
    $SanBlock = $SanLines -join [Environment]::NewLine

    $ConfigText = @"
[req]
prompt             = no
default_md         = sha256
default_bits       = $($Config.KeyLength)
distinguished_name = dn
req_extensions     = v3_req

[dn]
C  = $($Config.Country)
ST = $($Config.State)
L  = $($Config.Locality)
O  = $($Config.Organization)
OU = $($Config.OrgUnit)
CN = $CommonName

[v3_req]
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth
subjectAltName     = @alt_names

[alt_names]
$SanBlock
"@

    $ConfigText | Out-File -FilePath $ConfigFile -Encoding ASCII -Force
    Add-WorkerLog ('Config written: {0}' -f $ConfigFile)
    foreach ($Line in $SanLines)
    {
        Add-WorkerLog ('    {0}' -f $Line)
    }

    # ----- Generate key + CSR -----
    $OpenSslArgs = @(
        'req'
        '-new'
        '-newkey', ('rsa:{0}' -f $Config.KeyLength)
        '-nodes'
        '-keyout', $KeyFile
        '-out', $CsrFile
        '-config', $ConfigFile
    )

    $CsrProc = @{
        FilePath              = $Config.OpenSSLPath
        ArgumentList          = $OpenSslArgs
        NoNewWindow           = $true
        Wait                  = $true
        PassThru              = $true
        RedirectStandardError = $ErrLog
    }

    $Proc = Start-Process @CsrProc

    if ($Proc.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $CsrFile))
    {
        Add-WorkerLog ('OpenSSL CSR generation failed (exit {0}). See {1}' -f $Proc.ExitCode, $ErrLog) 'ERROR'
        $Result.CsrStatus = 'Failed'
        return $Result
    }

    Add-WorkerLog ('CSR generated: {0}' -f $CsrFile) 'OK   '
    Add-WorkerLog ('Key generated: {0}' -f $KeyFile) 'OK   '
    $Result.CsrStatus = 'Success'

    # ----- Generate PKCS#1 .pem copy of the private key -----
    $PemArgs = @(
        'rsa'
        '-in', $KeyFile
        '-out', $PemFile
    )
    $PemProc = @{
        FilePath              = $Config.OpenSSLPath
        ArgumentList          = $PemArgs
        NoNewWindow           = $true
        Wait                  = $true
        PassThru              = $true
        RedirectStandardError = $ErrLog
    }
    $PemResult = Start-Process @PemProc
    if ($PemResult.ExitCode -eq 0)
    {
        Add-WorkerLog ('PEM key written: {0}' -f $PemFile) 'OK   '
    }
    else
    {
        Add-WorkerLog ('PKCS#1 PEM export failed (exit {0}).' -f $PemResult.ExitCode) 'WARN '
    }

    # ----- Submit CSR to CA -----
    Add-WorkerLog ('Submitting {0} to CA {1} (template: {2})' -f $CsrFile, $Config.CAConfig, $Template)

    $CertReqArgs = @(
        '-submit'
        '-config', $Config.CAConfig
        '-attrib', ('CertificateTemplate:{0}' -f $Template)
        $CsrFile
        $CerFile
    )

    $CertReqOutput = & certreq.exe @CertReqArgs 2>&1
    $CertReqExit   = $LASTEXITCODE
    $CertReqOutput | Out-File -FilePath $SubmitLog -Encoding UTF8 -Force

    $IdMatch = $CertReqOutput | Select-String -Pattern 'RequestId:\s*(\d+)' | Select-Object -First 1
    if ($IdMatch)
    {
        $Result.RequestId = $IdMatch.Matches[0].Groups[1].Value
    }

    if ($CertReqExit -ne 0 -or -not (Test-Path -LiteralPath $CerFile))
    {
        $CertReqText = ($CertReqOutput | Out-String)
        $IsPending   = ($CertReqText -match '(?i)pending|taken under submission') -or
                       ($CertReqExit -eq 0 -and $Result.RequestId -ne 'N/A')

        if ($IsPending)
        {
            Add-WorkerLog 'Certificate submitted to CA for Approval.  Checking in Pending Requests.'
            Add-WorkerLog ('See logfile:  {0}' -f $SubmitLog)
            $Result.SubmitStatus = ('Pending Approval (RequestId: {0})' -f $Result.RequestId)
        }
        else
        {
            Add-WorkerLog ('Submission did not return an issued certificate (exit {0}, RequestId: {1}). See {2}' -f $CertReqExit, $Result.RequestId, $SubmitLog) 'WARN '
            $Result.SubmitStatus = 'Failed'
        }

        return $Result
    }

    Add-WorkerLog ('Certificate issued: {0} (RequestId: {1})' -f $CerFile, $Result.RequestId) 'OK   '
    $Result.SubmitStatus = 'Issued'

    # ----- Load issued certificate (.NET) -----
    try
    {
        $Leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CerFile
        $Result.Thumbprint = $Leaf.Thumbprint
    }
    catch
    {
        Add-WorkerLog ('Unable to load issued certificate: {0}' -f $_.Exception.Message) 'ERROR'
        return $Result
    }

    # Write a PEM copy of the leaf for OpenSSL consumption.
    $LeafB64 = [Convert]::ToBase64String($Leaf.RawData, 'InsertLineBreaks')
    $LeafPem = '-----BEGIN CERTIFICATE-----' + [Environment]::NewLine + $LeafB64 + [Environment]::NewLine + '-----END CERTIFICATE-----'
    $LeafPem | Out-File -FilePath $CerPemFile -Encoding ASCII -Force

    # ----- Build issuing/root chain -----
    $HaveChain = $false
    if ($Config.ExportPfx)
    {
        if ($Config.CAChainFile -ne '' -and (Test-Path -LiteralPath $Config.CAChainFile))
        {
            Copy-Item -LiteralPath $Config.CAChainFile -Destination $ChainFile -Force
            $HaveChain = $true
            $Result.ChainStatus = 'From $CAChainFile'
            Add-WorkerLog ('Chain sourced from configured file: {0}' -f $Config.CAChainFile) 'OK   '
        }
        else
        {
            try
            {
                $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $null = $Chain.Build($Leaf)

                if ($Chain.ChainElements.Count -gt 1)
                {
                    $ChainSb = New-Object System.Text.StringBuilder
                    for ($i = 1; $i -lt $Chain.ChainElements.Count; $i++)
                    {
                        $ElementCert = $Chain.ChainElements[$i].Certificate
                        $ElementB64  = [Convert]::ToBase64String($ElementCert.RawData, 'InsertLineBreaks')
                        [void]$ChainSb.AppendLine('-----BEGIN CERTIFICATE-----')
                        [void]$ChainSb.AppendLine($ElementB64)
                        [void]$ChainSb.AppendLine('-----END CERTIFICATE-----')
                    }
                    $ChainSb.ToString() | Out-File -FilePath $ChainFile -Encoding ASCII -Force
                    $HaveChain = $true
                    $Result.ChainStatus = ('Built ({0} CA cert(s))' -f ($Chain.ChainElements.Count - 1))
                    Add-WorkerLog ('Chain built via .NET X509Chain: {0}' -f $ChainFile) 'OK   '
                }
                else
                {
                    $Result.ChainStatus = 'Leaf only (no chain resolved)'
                    Add-WorkerLog 'Chain could not be resolved beyond the leaf certificate.' 'WARN '
                }
            }
            catch
            {
                $Result.ChainStatus = ('Build failed: {0}' -f $_.Exception.Message)
                Add-WorkerLog ('Chain build failed: {0}' -f $_.Exception.Message) 'WARN '
            }
        }
    }

    # ----- Export full-chain PFX -----
    if ($Config.ExportPfx)
    {
        $EnvName = ('JEFFSPFXPW_{0}' -f $ShortName)
        Set-Item -Path ('Env:\{0}' -f $EnvName) -Value $PfxPlain

        $PfxArgs = [System.Collections.Generic.List[string]]::new()
        $PfxArgs.Add('pkcs12')
        $PfxArgs.Add('-export')
        $PfxArgs.Add('-inkey'); $PfxArgs.Add($KeyFile)
        $PfxArgs.Add('-in');    $PfxArgs.Add($CerPemFile)
        if ($HaveChain)
        {
            $PfxArgs.Add('-certfile'); $PfxArgs.Add($ChainFile)
        }
        $PfxArgs.Add('-out');     $PfxArgs.Add($PfxFile)
        $PfxArgs.Add('-name');    $PfxArgs.Add($CommonName)
        $PfxArgs.Add('-passout'); $PfxArgs.Add(('env:{0}' -f $EnvName))

        $PfxProc = @{
            FilePath              = $Config.OpenSSLPath
            ArgumentList          = $PfxArgs.ToArray()
            NoNewWindow           = $true
            Wait                  = $true
            PassThru              = $true
            RedirectStandardError = $ErrLog
        }

        $PfxResult = Start-Process @PfxProc
        Remove-Item -Path ('Env:\{0}' -f $EnvName) -ErrorAction SilentlyContinue

        if ($PfxResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $PfxFile))
        {
            $Result.PfxStatus = if ($HaveChain) { 'Full-chain PFX' } else { 'Leaf-only PFX' }
            Add-WorkerLog ('PFX exported: {0}' -f $PfxFile) 'OK   '
        }
        else
        {
            $Result.PfxStatus = ('Failed (exit {0})' -f $PfxResult.ExitCode)
            Add-WorkerLog ('PFX export failed (exit {0}). See {1}' -f $PfxResult.ExitCode, $ErrLog) 'WARN '
        }
    }

    # ----- Remote operations (deploy / import / bind / verify) -----
    $WantRemote = ($Config.DeployToRemote -or $Config.BindIis -or $Config.VerifyDeployment)
    if (-not $WantRemote)
    {
        return $Result
    }

    if ($RemoteSkipped)
    {
        Add-WorkerLog ('Skipping remote stages — {0} was unreachable during pre-flight.' -f $PrimaryFqdn) 'WARN '
        $Result.RemoteDirStatus = 'Unreachable'
        $Result.DeployStatus    = 'Unreachable'
        $Result.IisBindStatus   = 'Unreachable'
        $Result.VerifyStatus    = 'Unreachable'
        return $Result
    }

    if (-not $SACred -and -not $Config.UseCurrentIdentity)
    {
        Add-WorkerLog 'No -sa credential available; remote stages skipped.' 'WARN '
        return $Result
    }

    $Session = $null
    try
    {
        if ($Config.UseCurrentIdentity)
        {
            $Session = New-PSSession -ComputerName $PrimaryFqdn -ErrorAction Stop
            Add-WorkerLog ('PSSession opened as current logon: {0}' -f $PrimaryFqdn) 'OK   '
        }
        else
        {
            $Session = New-PSSession -ComputerName $PrimaryFqdn -Credential $SACred -ErrorAction Stop
            Add-WorkerLog ('PSSession opened: {0}' -f $PrimaryFqdn) 'OK   '
        }
    }
    catch
    {
        Add-WorkerLog ('Failed to open PSSession to {0}: {1}' -f $PrimaryFqdn, $_.Exception.Message) 'ERROR'
        $Result.RemoteDirStatus = 'Session failed'
        return $Result
    }

    try
    {
        # --- Ensure remote certificate directory ---
        $DirResult = Invoke-Command -Session $Session -ScriptBlock {
            param($Dir)
            if (Test-Path -LiteralPath $Dir)
            {
                return 'Exists'
            }
            New-Item -Path $Dir -ItemType Directory -Force | Out-Null
            return 'Created'
        } -ArgumentList $Config.RemoteCertDir

        $Result.RemoteDirStatus = $DirResult
        Add-WorkerLog ('Remote {0}: {1}' -f $Config.RemoteCertDir, $DirResult) 'OK   '

        # --- Deploy artifacts ---
        if ($Config.DeployToRemote)
        {
            $FilesToCopy = @($KeyFile, $PemFile, $CerFile, $PfxFile) |
                Where-Object { Test-Path -LiteralPath $_ }

            Copy-Item -Path $FilesToCopy -Destination $Config.RemoteCertDir -ToSession $Session -Force -ErrorAction Stop
            $Result.DeployStatus = ('Copied {0} file(s)' -f $FilesToCopy.Count)
            Add-WorkerLog ('Deployed {0} file(s) to {1}:{2}' -f $FilesToCopy.Count, $PrimaryFqdn, $Config.RemoteCertDir) 'OK   '
        }

        # --- Import PFX + bind IIS ---
        if ($Config.BindIis)
        {
            $PfxSecure   = ConvertTo-SecureString -String $PfxPlain -AsPlainText -Force
            $RemotePfx   = Join-Path -Path $Config.RemoteCertDir -ChildPath ('{0}.pfx' -f $ShortName)

            $IisResult = Invoke-Command -Session $Session -ScriptBlock {
                param($PfxPath, $PfxSecure, $SiteName, $Port)

                $Status = [PSCustomObject]@{
                    Imported   = $false
                    Bound      = $false
                    Thumbprint = $null
                    Error      = $null
                }

                try
                {
                    $ImportParams = @{
                        FilePath          = $PfxPath
                        CertStoreLocation = 'Cert:\LocalMachine\My'
                        Password          = $PfxSecure
                        Exportable        = $true
                        ErrorAction       = 'Stop'
                    }
                    $Cert = Import-PfxCertificate @ImportParams
                    $Status.Imported   = $true
                    $Status.Thumbprint = $Cert.Thumbprint

                    Import-Module WebAdministration -ErrorAction Stop

                    $Binding = Get-WebBinding -Name $SiteName -Protocol 'https' -Port $Port -ErrorAction SilentlyContinue
                    if (-not $Binding)
                    {
                        New-WebBinding -Name $SiteName -IPAddress '*' -Port $Port -Protocol 'https' -ErrorAction Stop
                    }

                    $SslPath = "IIS:\SslBindings\0.0.0.0!$Port"
                    if (Test-Path $SslPath)
                    {
                        Remove-Item $SslPath -Force
                    }
                    $CertObj = Get-Item ("Cert:\LocalMachine\My\{0}" -f $Cert.Thumbprint)
                    New-Item $SslPath -Value $CertObj -Force -ErrorAction Stop | Out-Null
                    $Status.Bound = $true
                }
                catch
                {
                    $Status.Error = $_.Exception.Message
                }

                return $Status
            } -ArgumentList $RemotePfx, $PfxSecure, $Config.IISSiteName, $Config.IISBindPort

            if ($IisResult.Imported -and $IisResult.Bound)
            {
                $Result.Thumbprint    = $IisResult.Thumbprint
                $Result.IisBindStatus = ('Bound (Thumbprint: {0})' -f $IisResult.Thumbprint)
                Add-WorkerLog ('PFX imported, thumbprint {0}' -f $IisResult.Thumbprint) 'OK   '
                Add-WorkerLog ('IIS bound: {0}:{1}' -f $Config.IISSiteName, $Config.IISBindPort) 'OK   '
            }
            elseif ($IisResult.Imported)
            {
                $Result.Thumbprint    = $IisResult.Thumbprint
                $Result.IisBindStatus = ('Import OK, bind failed: {0}' -f $IisResult.Error)
                Add-WorkerLog ('IIS bind failed: {0}' -f $IisResult.Error) 'WARN '
            }
            else
            {
                $Result.IisBindStatus = ('Import failed: {0}' -f $IisResult.Error)
                Add-WorkerLog ('PFX import failed: {0}' -f $IisResult.Error) 'WARN '
            }
        }

        # --- Verify deployment ---
        if ($Config.VerifyDeployment)
        {
            $ExpectedFiles = @($KeyFile, $PemFile, $CerFile, $PfxFile) |
                Where-Object { Test-Path -LiteralPath $_ } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name = Split-Path -Path $_ -Leaf
                        Size = (Get-Item -LiteralPath $_).Length
                    }
                }

            $VerifyResult = Invoke-Command -Session $Session -ScriptBlock {
                param($Dir, $Expected, $Thumbprint, $Port)

                $Missing  = [System.Collections.Generic.List[string]]::new()
                $SizeBad  = [System.Collections.Generic.List[string]]::new()

                foreach ($File in $Expected)
                {
                    $Path = Join-Path -Path $Dir -ChildPath $File.Name
                    if (-not (Test-Path -LiteralPath $Path))
                    {
                        $Missing.Add($File.Name)
                    }
                    elseif ((Get-Item -LiteralPath $Path).Length -ne $File.Size)
                    {
                        $SizeBad.Add($File.Name)
                    }
                }

                $BindingOk = $false
                if ($Thumbprint)
                {
                    $SslPath = "IIS:\SslBindings\0.0.0.0!$Port"
                    if (Test-Path $SslPath)
                    {
                        $BoundThumb = (Get-Item $SslPath).Thumbprint
                        $BindingOk  = ($BoundThumb -eq $Thumbprint)
                    }
                }

                return [PSCustomObject]@{
                    Missing   = $Missing
                    SizeBad   = $SizeBad
                    BindingOk = $BindingOk
                }
            } -ArgumentList $Config.RemoteCertDir, $ExpectedFiles, $Result.Thumbprint, $Config.IISBindPort

            $VerifyNotes = [System.Collections.Generic.List[string]]::new()
            if ($VerifyResult.Missing.Count -gt 0)
            {
                $VerifyNotes.Add(('missing: {0}' -f ($VerifyResult.Missing -join ', ')))
            }
            if ($VerifyResult.SizeBad.Count -gt 0)
            {
                $VerifyNotes.Add(('size mismatch: {0}' -f ($VerifyResult.SizeBad -join ', ')))
            }
            if ($Config.BindIis -and -not $VerifyResult.BindingOk)
            {
                $VerifyNotes.Add('IIS binding thumbprint mismatch')
            }

            if ($VerifyNotes.Count -eq 0)
            {
                $Result.VerifyStatus = 'Verified'
                Add-WorkerLog 'Verification passed (files present, sizes match, binding confirmed).' 'OK   '
            }
            else
            {
                $Result.VerifyStatus = ('Issues: {0}' -f ($VerifyNotes -join '; '))
                Add-WorkerLog ('Verification issues: {0}' -f ($VerifyNotes -join '; ')) 'WARN '
            }
        }
    }
    catch
    {
        Add-WorkerLog ('Remote stage error on {0}: {1}' -f $PrimaryFqdn, $_.Exception.Message) 'ERROR'
    }
    finally
    {
        if ($Session)
        {
            Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
        }
    }

    return $Result
}

# ============================================================
# REGION: ORCHESTRATION FUNCTIONS
# ============================================================

function Get-WorkerConfig
{
    return @{
        OpenSSLPath      = $script:OpenSSLPath
        KeyLength        = $script:KeyLength
        CAConfig         = $script:CAConfig
        OutputRoot       = $script:OutputRoot
        RemoteCertDir    = $script:RemoteCertDir
        IISSiteName      = $script:IISSiteName
        IISBindPort      = $script:IISBindPort
        CAChainFile      = $script:CAChainFile
        PrimaryDomain    = $script:PrimaryDomain
        AlternateDomain  = $script:AlternateDomain
        Country          = $script:Country
        State            = $script:State
        Locality         = $script:Locality
        Organization     = $script:Organization
        OrgUnit          = $script:OrgUnit
        DryRun           = $script:DryRun
        ExportPfx        = $script:ExportPfx
        DeployToRemote   = $script:DeployToRemote
        BindIis          = $script:BindIis
        VerifyDeployment   = $script:VerifyDeployment
        UseCurrentIdentity = $script:UseCurrentIdentity
    }
}

function Invoke-Pipeline
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$WorkItems
    )

    $WorkerConfig = Get-WorkerConfig
    $Results      = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($script:UseParallel -and $WorkItems.Count -gt 1 -and -not $script:DryRun)
    {
        Write-InfoMsg ('Processing {0} server(s) across up to {1} parallel runspaces.' -f $WorkItems.Count, $script:MaxConcurrency)

        $Pool = [runspacefactory]::CreateRunspacePool(1, $script:MaxConcurrency)
        $Pool.Open()

        $Jobs = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($Item in $WorkItems)
        {
            $PS = [powershell]::Create()
            $PS.RunspacePool = $Pool
            [void]$PS.AddScript($script:ServerWorker.ToString())
            [void]$PS.AddArgument($Item)
            [void]$PS.AddArgument($WorkerConfig)
            [void]$PS.AddArgument($script:SACred)
            [void]$PS.AddArgument($script:PfxPlain)

            $Jobs.Add([PSCustomObject]@{
                Server = $Item.ShortName
                PS     = $PS
                Handle = $PS.BeginInvoke()
            })
        }

        foreach ($Job in $Jobs)
        {
            try
            {
                $Output = $Job.PS.EndInvoke($Job.Handle)
                foreach ($Item in $Output)
                {
                    if ($Item -is [PSCustomObject] -and $Item.PSObject.Properties.Name -contains 'LogEntries')
                    {
                        $Results.Add($Item)
                    }
                }
            }
            catch
            {
                Write-ErrorMsg ('Runspace for {0} failed: {1}' -f $Job.Server, $_.Exception.Message)
            }
            finally
            {
                $Job.PS.Dispose()
            }
        }

        $Pool.Close()
        $Pool.Dispose()
    }
    else
    {
        if ($script:UseParallel -and $script:DryRun)
        {
            Write-DryRunMsg 'Parallelism is bypassed under DryRun; processing sequentially.'
        }

        foreach ($Item in $WorkItems)
        {
            $Output = & $script:ServerWorker $Item $WorkerConfig $script:SACred $script:PfxPlain
            foreach ($Single in $Output)
            {
                if ($Single -is [PSCustomObject] -and $Single.PSObject.Properties.Name -contains 'LogEntries')
                {
                    $Results.Add($Single)
                }
            }
        }
    }

    return $Results
}

function Show-ResultLogs
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$Results
    )

    foreach ($Item in $Results)
    {
        Write-Host ''
        Write-Host ('----- {0} ({1}) -----' -f $Item.Server, $Item.CommonName) -ForegroundColor Cyan
        Write-Log -Message ('----- {0} ({1}) -----' -f $Item.Server, $Item.CommonName) -Tag 'INFO '

        foreach ($Entry in $Item.LogEntries)
        {
            Write-BufferedEntry -Tag $Entry.Tag -Message $Entry.Message
        }
    }
}

# ============================================================
# REGION: REPORTING FUNCTIONS
# ============================================================

function Build-HtmlReport
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$Results,

        [Parameter(Mandatory = $true)]
        [string]$RunMode
    )

    $Rows = [System.Collections.Generic.List[string]]::new()

    foreach ($Item in $Results)
    {
        $CsrColor = if ($Item.CsrStatus -eq 'Success' -or $Item.CsrStatus -eq 'DryRun') { '#1a7f37' } else { '#b42318' }

        switch -Wildcard ($Item.SubmitStatus)
        {
            'Issued'   { $SubColor = '#1a7f37' }
            'DryRun'   { $SubColor = '#8a2be2' }
            'Pending*' { $SubColor = '#8a6d00' }
            'Skipped'  { $SubColor = '#8a6d00' }
            default    { $SubColor = '#b42318' }
        }

        $Row = @"
<tr>
  <td>$($Item.Server)</td>
  <td>$($Item.CommonName)</td>
  <td>$($Item.Template)</td>
  <td>$($Item.DnsSans)</td>
  <td>$($Item.IpSans)</td>
  <td style="color:$CsrColor;font-weight:bold;">$($Item.CsrStatus)</td>
  <td style="color:$SubColor;font-weight:bold;">$($Item.SubmitStatus)</td>
  <td>$($Item.RequestId)</td>
  <td>$($Item.ChainStatus)</td>
  <td>$($Item.PfxStatus)</td>
  <td>$($Item.RemoteDirStatus)</td>
  <td>$($Item.DeployStatus)</td>
  <td>$($Item.IisBindStatus)</td>
  <td>$($Item.VerifyStatus)</td>
  <td>$($Item.Thumbprint)</td>
</tr>
"@
        $Rows.Add($Row)
    }

    $RowsHtml = $Rows -join [Environment]::NewLine
    $DryNote  = if ($script:DryRun) { '<p style="color:#8a2be2;font-weight:bold;">DRYRUN MODE - no files were written, nothing was submitted, and no remote operations ran.</p>' } else { '' }

    $Html = @"
<html>
<head>
<style>
    body  { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; color: #1f2328; }
    h2    { color: #0b3d91; margin-bottom: 2px; }
    .meta { color: #57606a; font-size: 12px; margin-top: 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th    { background: #0b3d91; color: #ffffff; text-align: left; padding: 6px 8px; font-size: 11px; }
    td    { border: 1px solid #d0d7de; padding: 5px 8px; vertical-align: top; }
    tr:nth-child(even) td { background: #f6f8fa; }
</style>
</head>
<body>
    <h2>$($script:ReportTitle)</h2>
    <p class="meta">Run mode: $RunMode &nbsp;|&nbsp; Generated: $($script:FriendlyDate) &nbsp;|&nbsp; CA: $($script:CAConfig) &nbsp;|&nbsp; Parallel: $($script:UseParallel)</p>
    $DryNote
    <table>
        <tr>
            <th>Server</th>
            <th>Common Name</th>
            <th>Template</th>
            <th>DNS SANs</th>
            <th>IP SANs</th>
            <th>CSR</th>
            <th>Submission</th>
            <th>Request ID</th>
            <th>Chain</th>
            <th>PFX</th>
            <th>Remote Dir</th>
            <th>Deploy</th>
            <th>IIS Bind</th>
            <th>Verify</th>
            <th>Thumbprint</th>
        </tr>
        $RowsHtml
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

    if (-not $script:SendEmail)
    {
        Write-InfoMsg 'Email reporting is disabled ($SendEmail = $false). Skipping send.'
        return
    }

    $Subject = Get-EmailSubject

    if ($script:DryRun)
    {
        Write-DryRunMsg ('Would send HTML report "{0}" to: {1}' -f $Subject, ($script:MailTo -join ', '))
        return
    }

    $MailSplat = @{
        SmtpServer = $script:SmtpServer
        Port       = $script:SmtpPort
        From       = $script:MailFrom
        To         = $script:MailTo
        Subject    = $Subject
        Body       = $HtmlBody
        BodyAsHtml = $true
    }

    try
    {
        Send-MailMessage @MailSplat -ErrorAction Stop
        Write-SuccessMsg ('Report emailed to: {0}' -f ($script:MailTo -join ', '))
    }
    catch
    {
        Write-ErrorMsg ('Failed to send report email: {0}' -f $_.Exception.Message)
    }
}

function Complete-Run
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$WorkItems,

        [Parameter(Mandatory = $true)]
        [string]$RunMode
    )

    if ($WorkItems.Count -eq 0)
    {
        Write-WarnMsg 'No servers to process. Returning to the main menu.'
        return
    }

    # Acquire credentials / secrets only when a stage needs them.
    if ((Test-RemoteStageEnabled) -and -not $script:DryRun)
    {
        if (-not (Request-RemoteCredential))
        {
            return
        }
    }

    if ($script:ExportPfx -and -not $script:DryRun)
    {
        if (-not (Request-PfxPassword))
        {
            return
        }
    }

    # WinRM pre-flight for remote stages.
    $ToProcess = $WorkItems
    if ((Test-RemoteStageEnabled) -and -not $script:DryRun)
    {
        $ToProcess = Test-ServerReachable -WorkItems $WorkItems
    }

    $Results = Invoke-Pipeline -WorkItems $ToProcess
    Show-ResultLogs -Results $Results

    $Html = Build-HtmlReport -Results $Results -RunMode $RunMode
    Send-ReportEmail -HtmlBody $Html
}

# ============================================================
# REGION: CRL MAINTENANCE
# ============================================================

function Test-CrlMenuPassword
{
    for ($Attempt = 1; $Attempt -le $script:CrlMenuMaxAttempts; $Attempt++)
    {
        $Secure = Read-Host -Prompt 'Enter the CRL maintenance password' -AsSecureString
        $Plain  = ''
        $Bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)

        try
        {
            $Plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        }
        finally
        {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        }

        $Match = ($Plain -eq $script:CrlMenuPassword)
        $Plain = $null

        if ($Match)
        {
            Write-SuccessMsg 'CRL maintenance password accepted.'
            return $true
        }

        Write-WarnMsg ('Incorrect password (attempt {0} of {1}).' -f $Attempt, $script:CrlMenuMaxAttempts)
    }

    Write-ErrorMsg 'CRL maintenance password validation failed. Returning to the main menu.'
    return $false
}

function Get-RootCaCredential
{
    $Secure = ConvertTo-SecureString -String $script:RootPassword -AsPlainText -Force
    return (New-Object System.Management.Automation.PSCredential($script:RootUsername, $Secure))
}

function Get-RootCrlScript
{
    $Template = @'
$ErrorActionPreference = 'Stop'

certutil -crl
if ($LASTEXITCODE -ne 0)
{
    throw "certutil -crl failed with exit code $LASTEXITCODE"
}

$CRL = Get-ChildItem -Path '@@CERT_ENROLL@@' -Filter '@@CRL_PATTERN@@' |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 1

Copy-Item -Path $CRL.FullName -Destination '@@CRL_SHARE@@' -Force
Copy-Item -Path $CRL.FullName -Destination '@@CRL_SUB_CERTENROLL@@' -Force
'@

    $Text = $Template
    $Text = $Text.Replace('@@CERT_ENROLL@@',        $script:CertEnrollPath)
    $Text = $Text.Replace('@@CRL_PATTERN@@',        $script:CRLNamePattern)
    $Text = $Text.Replace('@@CRL_SHARE@@',          $script:CRLSharePath)
    $Text = $Text.Replace('@@CRL_SUB_CERTENROLL@@', $script:CRLSubCertEnrollPath)

    return $Text
}

function Get-PublishCrlScript
{
    $Template = @'
$ErrorActionPreference = 'Stop'

certutil -dspublish -f '@@SUB_CRL@@' '@@ROOT_CA@@'
if ($LASTEXITCODE -ne 0)
{
    throw "certutil -dspublish failed with exit code $LASTEXITCODE"
}

$Dump = certutil -dump '@@SUB_CRL@@'
if ($Dump -notmatch '@@ISSUER@@')
{
    throw 'CRL issuer does not match expected Root CA.'
}
'@

    $Text = $Template
    $Text = $Text.Replace('@@SUB_CRL@@', $script:SubCACRLPath)
    $Text = $Text.Replace('@@ROOT_CA@@', $script:RootCAServer)
    $Text = $Text.Replace('@@ISSUER@@',  $script:RootCaIssuerName)

    return $Text
}

function Connect-PkiVCenter
{
    Write-InfoMsg ('Connecting to vCenter {0}' -f $script:vCenterServer)
    $null = Connect-VIServer -Server $script:vCenterServer
    Write-SuccessMsg 'vCenter connection established.'
}

function Disconnect-PkiVCenter
{
    Write-InfoMsg ('Disconnecting from vCenter {0}' -f $script:vCenterServer)
    Disconnect-VIServer -Confirm:$false
    Write-SuccessMsg 'vCenter connection closed.'
}

function Get-PkiVm
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $Vm)
    {
        throw ('VM "{0}" not found in vCenter.' -f $Name)
    }

    return $Vm
}

function Start-RootCa
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$RootVM
    )

    Write-InfoMsg ('Powering on {0}' -f $script:RootCAServer)
    $null = Start-VM -VM $RootVM -Confirm:$false

    Write-InfoMsg ('Waiting up to {0} seconds for VMware Tools on {1}' -f $script:ToolsTimeoutSeconds, $script:RootCAServer)
    Wait-Tools -VM $RootVM -TimeoutSeconds $script:ToolsTimeoutSeconds

    $Refreshed = Get-VM -Name $script:RootCAServer

    if ($Refreshed.ExtensionData.Guest.ToolsStatus -ne 'toolsOk')
    {
        throw ('VMware Tools did not report healthy status on {0}.' -f $script:RootCAServer)
    }

    Write-SuccessMsg ('{0} is powered on and VMware Tools report healthy.' -f $script:RootCAServer)
    return $Refreshed
}

function Stop-RootCa
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$RootVM
    )

    Write-InfoMsg ('Powering off {0}' -f $script:RootCAServer)
    $null = Stop-VM -VM $RootVM -Confirm:$false
    Write-SuccessMsg ('{0} powered off.' -f $script:RootCAServer)
}

function Invoke-RootCrlGeneration
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$RootVM,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$RootCred
    )

    Write-InfoMsg ('Executing Root CRL generation on {0}' -f $script:RootCAServer)

    $ScriptText = Get-RootCrlScript
    $VMScriptSplat = @{
        VM              = $RootVM
        ScriptType      = 'PowerShell'
        ScriptText      = $ScriptText
        GuestCredential = $RootCred
    }

    $null = Invoke-VMScript @VMScriptSplat
    Write-SuccessMsg 'Root CRL generated and copied to the Sub CA share and CertEnroll directory.'
}

function Invoke-RootCrlPublication
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$SubVM
    )

    Write-InfoMsg ('Publishing Root CRL to Active Directory and validating issuer on {0}' -f $script:SubCAServer)

    $ScriptText = Get-PublishCrlScript
    $VMScriptSplat = @{
        VM         = $SubVM
        ScriptType = 'PowerShell'
        ScriptText = $ScriptText
    }

    $null = Invoke-VMScript @VMScriptSplat
    Write-SuccessMsg ('Root CRL published to AD and issuer validated against "{0}".' -f $script:RootCaIssuerName)
}

function Show-CrlVerificationMenu
{
    Write-Host ''
    Write-Host '=============== MANUAL VERIFICATION ===============' -ForegroundColor Cyan
    Write-Host ('  1. Open pkiview.msc on {0}' -f $script:SubCAServer)            -ForegroundColor White
    Write-Host ('  2. Confirm "{0}" shows GREEN' -f $script:RootCaIssuerName)     -ForegroundColor White
    Write-Host '  3. Verify Next Update is approximately 6 months + 1 day'        -ForegroundColor White
    Write-Host '===================================================' -ForegroundColor Cyan
    Write-Host ''

    Write-Log -Message 'Displayed manual verification menu for Sub CA pkiview checks.' -Tag 'INFO '
}

function Show-CrlDryRunPlan
{
    Write-DryRunMsg 'The following actions WOULD be performed for the Root CRL update. No changes will be made during this dry run.'
    Write-DryRunMsg ('Step 1  : Build a Root CA guest credential for "{0}" to authenticate Invoke-VMScript on {1}.' -f $script:RootUsername, $script:RootCAServer)
    Write-DryRunMsg ('Step 2  : Connect to vCenter server {0}.' -f $script:vCenterServer)
    Write-DryRunMsg ('Step 3  : Validate that the VMs "{0}" and "{1}" exist in vCenter inventory.' -f $script:RootCAServer, $script:SubCAServer)
    Write-DryRunMsg ('Step 4  : Read the power state of {0}. If it is powered off, power it on, wait up to {1} seconds for VMware Tools, and confirm Tools report "toolsOk".' -f $script:RootCAServer, $script:ToolsTimeoutSeconds)
    Write-DryRunMsg ('Step 5  : On {0}, run "certutil -crl" to generate a fresh Root CRL.' -f $script:RootCAServer)
    Write-DryRunMsg ('Step 5a : Locate the newest CRL matching "{0}" under {1}.' -f $script:CRLNamePattern, $script:CertEnrollPath)
    Write-DryRunMsg ('Step 5b : Copy that CRL to {0}.' -f $script:CRLSharePath)
    Write-DryRunMsg ('Step 5c : Copy that CRL to {0}.' -f $script:CRLSubCertEnrollPath)
    Write-DryRunMsg ('Step 6  : If this tool powered {0} on in Step 4, power it back off afterward.' -f $script:RootCAServer)
    Write-DryRunMsg ('Step 7  : On {0}, publish the CRL to Active Directory: certutil -dspublish -f "{1}" "{2}".' -f $script:SubCAServer, $script:SubCACRLPath, $script:RootCAServer)
    Write-DryRunMsg ('Step 7a : Dump {0} and confirm the issuer contains "{1}".' -f $script:SubCACRLPath, $script:RootCaIssuerName)
    Write-DryRunMsg ('Step 8  : Display the manual verification menu (pkiview.msc checks on {0}).' -f $script:SubCAServer)
    Write-DryRunMsg ('Step 9  : Disconnect from vCenter {0}. This always runs, even on error.' -f $script:vCenterServer)
}

function Invoke-CrlMaintenance
{
    param
    (
        [Parameter(Mandatory = $true)]
        [bool]$DryRun
    )

    if ($DryRun)
    {
        Show-CrlDryRunPlan
        return
    }

    if (-not (Get-Command -Name 'Connect-VIServer' -ErrorAction SilentlyContinue))
    {
        Write-ErrorMsg 'VMware PowerCLI is not available in this session (Connect-VIServer not found). Import VMware.PowerCLI and retry.'
        return
    }

    # Fail-fast within this operation only; scope is local to the function.
    $ErrorActionPreference = 'Stop'

    $RootCred    = Get-RootCaCredential
    $Connected   = $false
    $StartedRoot = $false

    try
    {
        Connect-PkiVCenter
        $Connected = $true

        $RootVM = Get-PkiVm -Name $script:RootCAServer
        $SubVM  = Get-PkiVm -Name $script:SubCAServer
        Write-SuccessMsg 'VM pre-flight validation successful.'

        $RootOriginallyPoweredOn = ($RootVM.PowerState -eq 'PoweredOn')

        if (-not $RootOriginallyPoweredOn)
        {
            $RootVM      = Start-RootCa -RootVM $RootVM
            $StartedRoot = $true
        }
        else
        {
            Write-InfoMsg ('{0} is already powered on; leaving its power state unchanged.' -f $script:RootCAServer)
        }

        Invoke-RootCrlGeneration -RootVM $RootVM -RootCred $RootCred

        if ($StartedRoot)
        {
            Stop-RootCa -RootVM $RootVM
        }
        else
        {
            Write-InfoMsg ('{0} was already running before this run; leaving it powered on.' -f $script:RootCAServer)
        }

        Invoke-RootCrlPublication -SubVM $SubVM

        Show-CrlVerificationMenu

        Write-SuccessMsg 'PKI Root CRL maintenance completed successfully.'
    }
    catch
    {
        Write-ErrorMsg ('Root CRL maintenance failed: {0}' -f $_.Exception.Message)
    }
    finally
    {
        if ($Connected)
        {
            try
            {
                Disconnect-PkiVCenter
            }
            catch
            {
                Write-WarnMsg ('vCenter disconnect reported an issue: {0}' -f $_.Exception.Message)
            }
        }
    }
}

# ============================================================
# REGION: MENU FUNCTIONS
# ============================================================

function Show-MainMenu
{
    Write-Host ''
    Write-Host '==================== Jeffs_Certerator ====================' -ForegroundColor Cyan
    Write-Host '  1. Create new certificate(s)'                            -ForegroundColor White
    Write-Host '  2. Renew a certificate from an existing CSR'             -ForegroundColor White
    Write-Host '  3. Inspect a PFX (export CER/CRT, show details)'         -ForegroundColor White
    Write-Host '  4. Modify a certificate and create a new one'            -ForegroundColor White
    Write-Host '  5. Update Root CRL (password protected)'                 -ForegroundColor White
    Write-Host '  6. Exit'                                                 -ForegroundColor White
    Write-Host '==========================================================' -ForegroundColor Cyan
    return (Read-Host 'Select an option')
}

function Select-Template
{
    Write-Host ''
    Write-Host '----- Certificate Template -----' -ForegroundColor Cyan
    foreach ($Key in $script:CertTemplates.Keys)
    {
        Write-Host ('  {0}. {1}' -f $Key, $script:CertTemplates[$Key].FriendlyName) -ForegroundColor White
    }
    Write-Host '--------------------------------' -ForegroundColor Cyan

    while ($true)
    {
        $Choice = Read-Host 'Select a template'
        if ($script:CertTemplates.Contains($Choice))
        {
            $Friendly = $script:CertTemplates[$Choice].FriendlyName
            $Submit   = $script:CertTemplates[$Choice].CommonName
            Write-InfoMsg ('Template selected: {0} (submitting as: {1})' -f $Friendly, $Submit)
            return $Submit
        }

        Write-WarnMsg 'Invalid template selection. Try again.'
    }
}

function Get-ServerList
{
    Write-Host ''
    Write-Host '----- Server Input -----' -ForegroundColor Cyan
    Write-Host '  1. Enter a single server name' -ForegroundColor White
    Write-Host '  2. Read a list of servers from a file' -ForegroundColor White
    Write-Host '------------------------' -ForegroundColor Cyan

    $Mode    = Read-Host 'Select an input method'
    $Servers = [System.Collections.Generic.List[string]]::new()

    switch ($Mode)
    {
        '1'
        {
            $Name  = Read-Host 'Enter the server short name (or FQDN)'
            $Short = Get-ShortNameFromValue -Value $Name
            if ($Short -ne '')
            {
                $Servers.Add($Short)
            }
        }

        '2'
        {
            $Path = Read-Host 'Enter the full path to the server list file (one name per line)'
            if (Test-Path -LiteralPath $Path)
            {
                $Lines = Get-Content -LiteralPath $Path |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -ne '' -and $_ -notmatch '^\s*#' }

                foreach ($Line in $Lines)
                {
                    $Short = Get-ShortNameFromValue -Value $Line
                    if ($Short -ne '' -and -not $Servers.Contains($Short))
                    {
                        $Servers.Add($Short)
                    }
                }

                Write-InfoMsg ('Loaded {0} server(s) from {1}' -f $Servers.Count, $Path)
            }
            else
            {
                Write-ErrorMsg ('Server list file not found: {0}' -f $Path)
            }
        }

        default
        {
            Write-WarnMsg 'Invalid input method selection.'
        }
    }

    return $Servers
}

function Invoke-CreateCertificates
{
    $Template = Select-Template
    $Servers  = Get-ServerList

    if ($Servers.Count -eq 0)
    {
        Write-WarnMsg 'No servers were provided. Returning to the main menu.'
        return
    }

    Write-Host ''
    Write-Host 'Extra Subject Alternative Names are added in addition to the' -ForegroundColor DarkGray
    Write-Host 'short name, FQDN, and <short>.uhhospitals.org defaults.'       -ForegroundColor DarkGray
    $ExtraDns = Read-DelimitedInput -Prompt 'Extra DNS SAN entries (comma-separated, blank for none)'
    $ExtraIp  = Read-DelimitedInput -Prompt 'Extra IP SAN entries (comma-separated, blank for none)'

    $WorkItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Server in $Servers)
    {
        $San = Build-SanList -ShortName $Server -ExtraDns $ExtraDns -ExtraIp $ExtraIp

        $WorkItems.Add([PSCustomObject]@{
            ShortName   = $Server
            CommonName  = $San.CommonName
            DnsNames    = $San.DnsNames
            IpAddresses = $San.IpAddresses
            Template    = $Template
            RunMode     = 'Create'
        })
    }

    Complete-Run -WorkItems $WorkItems -RunMode 'Create'
}

function Invoke-RenewFromCsr
{
    $CsrPath = Read-Host 'Enter the full path to the existing CSR file'

    if (-not (Test-Path -LiteralPath $CsrPath))
    {
        Write-ErrorMsg ('CSR file not found: {0}' -f $CsrPath)
        return
    }

    $Parsed = Read-ExistingCsr -CsrPath $CsrPath
    if (-not $Parsed)
    {
        Write-ErrorMsg 'Unable to build a renewal from the supplied CSR.'
        return
    }

    $Template = Select-Template

    Write-Host ''
    Write-Host 'You may add extra SANs to the renewal in addition to those' -ForegroundColor DarkGray
    Write-Host 'carried over from the original CSR.'                        -ForegroundColor DarkGray
    $ExtraDns = Read-DelimitedInput -Prompt 'Additional DNS SAN entries (comma-separated, blank for none)'
    $ExtraIp  = Read-DelimitedInput -Prompt 'Additional IP SAN entries (comma-separated, blank for none)'

    $ShortName = Get-ShortNameFromValue -Value $Parsed.CommonName

    $DnsNames = [System.Collections.Generic.List[string]]::new()
    if (-not $DnsNames.Contains($Parsed.CommonName))
    {
        $DnsNames.Add($Parsed.CommonName)
    }
    foreach ($Name in @($Parsed.DnsNames) + $ExtraDns)
    {
        $Clean = $Name.Trim()
        if ($Clean -ne '' -and -not $DnsNames.Contains($Clean))
        {
            $DnsNames.Add($Clean)
        }
    }

    $IpAddresses = [System.Collections.Generic.List[string]]::new()
    foreach ($Ip in @($Parsed.IpAddresses) + $ExtraIp)
    {
        $Clean = $Ip.Trim()
        if ($Clean -ne '' -and -not $IpAddresses.Contains($Clean))
        {
            $IpAddresses.Add($Clean)
        }
    }

    $WorkItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $WorkItems.Add([PSCustomObject]@{
        ShortName   = $ShortName
        CommonName  = $Parsed.CommonName
        DnsNames    = $DnsNames
        IpAddresses = $IpAddresses
        Template    = $Template
        RunMode     = 'Renew'
    })

    Complete-Run -WorkItems $WorkItems -RunMode 'Renew'
}

function Invoke-InspectPfx
{
    $PfxPath = Read-Host 'Enter the full path to the PFX file'

    if (-not (Test-Path -LiteralPath $PfxPath))
    {
        Write-ErrorMsg ('PFX file not found: {0}' -f $PfxPath)
        return
    }

    $Password = Read-PfxFilePassword
    $Cert     = Import-PfxCertificateObject -PfxPath $PfxPath -Password $Password

    if (-not $Cert)
    {
        return
    }

    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($PfxPath)

    try
    {
        $null = Export-CerAndCrt -Cert $Cert -BaseName $BaseName
    }
    catch
    {
        Write-WarnMsg ('CER/CRT export failed: {0}' -f $_.Exception.Message)
    }

    $null = Show-CertificateDetails -Cert $Cert
}

function Invoke-ModifyAndRecreate
{
    $PfxPath = Read-Host 'Enter the full path to the source PFX file'

    if (-not (Test-Path -LiteralPath $PfxPath))
    {
        Write-ErrorMsg ('PFX file not found: {0}' -f $PfxPath)
        return
    }

    $Password = Read-PfxFilePassword
    $Cert     = Import-PfxCertificateObject -PfxPath $PfxPath -Password $Password

    if (-not $Cert)
    {
        return
    }

    $Details = Show-CertificateDetails -Cert $Cert

    Write-Host ''
    Write-Host '----- Modify Certificate Data -----' -ForegroundColor Cyan
    Write-Host 'Press Enter to keep the current value shown in brackets.' -ForegroundColor DarkGray

    $NewCommonName = Read-WithDefault -Prompt 'Common Name (CN)' -Default $Details.CommonName
    if ([string]::IsNullOrWhiteSpace($NewCommonName))
    {
        Write-ErrorMsg 'A Common Name is required to build a new certificate.'
        return
    }

    $CountryDefault = if ([string]::IsNullOrWhiteSpace($Details.Country))      { $script:Country }      else { $Details.Country }
    $StateDefault   = if ([string]::IsNullOrWhiteSpace($Details.State))        { $script:State }        else { $Details.State }
    $LocalDefault   = if ([string]::IsNullOrWhiteSpace($Details.Locality))     { $script:Locality }     else { $Details.Locality }
    $OrgDefault     = if ([string]::IsNullOrWhiteSpace($Details.Organization)) { $script:Organization } else { $Details.Organization }
    $OuDefault      = if ([string]::IsNullOrWhiteSpace($Details.OrgUnit))      { $script:OrgUnit }      else { $Details.OrgUnit }

    $NewCountry      = Read-WithDefault -Prompt 'Country (C)'          -Default $CountryDefault
    $NewState        = Read-WithDefault -Prompt 'State / Province (S)' -Default $StateDefault
    $NewLocality     = Read-WithDefault -Prompt 'Locality (L)'         -Default $LocalDefault
    $NewOrganization = Read-WithDefault -Prompt 'Organization (O)'     -Default $OrgDefault
    $NewOrgUnit      = Read-WithDefault -Prompt 'Org. Unit (OU)'       -Default $OuDefault

    $DnsDefault = ($Details.DnsNames -join ', ')
    $IpDefault  = ($Details.IpAddresses -join ', ')

    Write-Host ''
    Write-Host 'Enter the full SAN lists below (comma-separated). The current' -ForegroundColor DarkGray
    Write-Host 'values are pre-filled as the default; edit them as needed.'    -ForegroundColor DarkGray

    $DnsRaw = Read-WithDefault -Prompt 'DNS SAN entries' -Default $DnsDefault
    $IpRaw  = Read-WithDefault -Prompt 'IP SAN entries'  -Default $IpDefault

    $DnsNames = [System.Collections.Generic.List[string]]::new()
    if (-not $DnsNames.Contains($NewCommonName))
    {
        $DnsNames.Add($NewCommonName)
    }
    foreach ($Item in ($DnsRaw -split '[,;]'))
    {
        $Clean = $Item.Trim()
        if ($Clean -ne '' -and -not $DnsNames.Contains($Clean))
        {
            $DnsNames.Add($Clean)
        }
    }

    $IpAddresses = [System.Collections.Generic.List[string]]::new()
    foreach ($Item in ($IpRaw -split '[,;]'))
    {
        $Clean = $Item.Trim()
        if ($Clean -ne '' -and -not $IpAddresses.Contains($Clean))
        {
            $IpAddresses.Add($Clean)
        }
    }

    $Template  = Select-Template
    $ShortName = Get-ShortNameFromValue -Value $NewCommonName

    $WorkItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $WorkItems.Add([PSCustomObject]@{
        ShortName   = $ShortName
        CommonName  = $NewCommonName
        DnsNames    = $DnsNames
        IpAddresses = $IpAddresses
        Template    = $Template
        RunMode     = 'Recreate'
    })

    # Temporarily override the script-level Subject locale fields so the
    # existing pipeline emits the modified Distinguished Name, then restore
    # the originals once the run completes.
    $SavedCountry      = $script:Country
    $SavedState        = $script:State
    $SavedLocality     = $script:Locality
    $SavedOrganization = $script:Organization
    $SavedOrgUnit      = $script:OrgUnit

    try
    {
        $script:Country      = $NewCountry
        $script:State        = $NewState
        $script:Locality     = $NewLocality
        $script:Organization = $NewOrganization
        $script:OrgUnit      = $NewOrgUnit

        Write-InfoMsg ('Re-issuing certificate for CN: {0}' -f $NewCommonName)
        Complete-Run -WorkItems $WorkItems -RunMode 'Recreate'
    }
    finally
    {
        $script:Country      = $SavedCountry
        $script:State        = $SavedState
        $script:Locality     = $SavedLocality
        $script:Organization = $SavedOrganization
        $script:OrgUnit      = $SavedOrgUnit
    }
}

function Invoke-UpdateCrl
{
    if (-not (Test-CrlMenuPassword))
    {
        return
    }

    Write-InfoMsg 'Starting Root CRL maintenance in DRYRUN mode. The steps below will only be described; nothing will be changed yet.'
    Invoke-CrlMaintenance -DryRun $true

    Write-Host ''
    $Answer = Read-Host 'The dry run above lists every action. Perform the Root CRL update for real now? (Y/N) [N]'

    if ([string]::IsNullOrWhiteSpace($Answer) -or $Answer.Trim() -notmatch '(?i)^y')
    {
        Write-InfoMsg 'Root CRL update cancelled by operator. No changes were made.'
        return
    }

    Write-InfoMsg 'Operator confirmed. Executing the Root CRL update for real.'
    Invoke-CrlMaintenance -DryRun $false
}

# ============================================================
# REGION: MAIN
# ============================================================

Initialize-Logging

if (-not (Test-Prerequisites))
{
    Write-ErrorMsg 'Prerequisite checks failed. Resolve the issues above and re-run.'
    exit 1
}

try
{
    $Running = $true
    while ($Running)
    {
        $Selection = Show-MainMenu

        switch ($Selection)
        {
            '1'
            {
                Invoke-CreateCertificates
            }

            '2'
            {
                Invoke-RenewFromCsr
            }

            '3'
            {
                Invoke-InspectPfx
            }

            '4'
            {
                Invoke-ModifyAndRecreate
            }

            '5'
            {
                Invoke-UpdateCrl
            }

            '6'
            {
                $Running = $false
            }

            default
            {
                Write-WarnMsg 'Invalid selection. Choose 1, 2, 3, 4, 5, or 6.'
            }
        }
    }

    exit 0
}
catch
{
    Write-ErrorMsg ('Unhandled error: {0}' -f $_.Exception.Message)
    exit 1
}
