# =====================================================================
# Script      : Templatorator.ps1
# Author      : Alan W. Phillips
# Date        : 06-19-2026
# Version     : 1.3.6
#
# Description : Interactive AD CS certificate-template creator. Prompts an
#               operator for a template definition - base template (chosen
#               from a runtime picker of existing templates), CN, display
#               name, EKU set, subject-name source, minimum key size,
#               enrollment principal, and publish target - then clones the
#               base pKICertificateTemplate object directly in Active
#               Directory over plain LDAP against the Configuration
#               partition (no Global Catalog dependency). Base attributes
#               are copied verbatim (including the binary validity-period
#               values), a unique template OID is minted under the forest
#               signature discovered at runtime and its msPKI-Enterprise-Oid
#               object created, and the chosen deltas are applied. Read +
#               Enroll (optionally AutoEnroll) is granted via PSPKI, and the
#               template is optionally published to the issuing CA with
#               graceful deferral when the running account lacks the
#               Enrollment Services write. A separate -DelegatePublishRights
#               mode (run once as Enterprise Admin) grants the service
#               account Write [certificateTemplates] on the CA's Enrollment
#               Services object so subsequent publishes succeed under the SA.
#               Built on the proven engine from New-UHMDMWiFiTemplate.ps1.
#
# Requirements: PowerShell 5.1; PSPKI module (auto-installed from PSGallery);
#               System.DirectoryServices (built into .NET); Enterprise
#               Admin (or delegated) rights on the Configuration partition
#               to author templates; for -DelegatePublishRights, WRITE_DAC
#               on the CA Enrollment Services object (Enterprise Admin);
#               LDAP access to a DC and network access to smtp.uhhs.com:25.
#
# Change Log:#
#   1.0.0 - 2026-06-19 - Initial release. Generalized, prompted-interactive
#                        template creator derived from the New-UHMDMWiFiTemplate
#                        LDAP engine. Adds a runtime base-template picker,
#                        validated prompts with policy guardrails (naming
#                        pattern, 2048 key floor), a confirmation summary, and
#                        a -DelegatePublishRights mode that grants the service
#                        account a least-privilege Write on the certificateTemplates
#                        attribute of the CA Enrollment Services object. Reuses
#                        the verbatim logging, helpers, OID minting, ACL grant,
#                        insufficient-rights detection, publish-with-deferral,
#                        and email-report code from New-UHMDMWiFiTemplate 3.0.3.
#   1.1.0 - 2026-06-19 - Enrollment rights now accept one or more principals.
#                        The single enrollment-principal prompt was replaced by
#                        a Read-EnrollmentGrants loop that collects multiple AD
#                        accounts or groups, each validated with Resolve-AdPrincipal
#                        (NTAccount-to-SID resolution; unresolvable or duplicate
#                        entries are rejected) and each offered AutoEnroll. The
#                        definition now carries a Grants list; the summary, email
#                        report, and grant loop iterate every principal.
#   1.2.0 - 2026-06-19 - Menu-driven. The default mode now launches a loop:
#                        1 Create, 2 Modify, 3 Delete, Q Exit, sending one
#                        accumulated email report per session. Added
#                        Invoke-ModifyTemplate (edit display name, EKUs, key
#                        size, subject source; add enrollment grants; publish;
#                        bumps msPKI-Template-Minor-Revision) and
#                        Invoke-DeleteTemplate (type-the-CN confirmation;
#                        unpublishes from the CA, deletes the template object
#                        and optionally its OID object), plus supporting helpers
#                        (Get-TemplateRecords, Select-ExistingTemplate,
#                        Get-TemplateEntryByCn, Remove-TemplateFromCA,
#                        Remove-TemplateOidObject). The -DelegatePublishRights
#                        mode is unchanged. All new operations honor -DryRun.
#   1.3.0 - 2026-06-19 - Delete can now unpublish from every CA that lists the
#                        template, not just the configured one. Added a prompt
#                        (all CAs vs configured CA), Remove-TemplateFromAllCAs
#                        (a resilient sweep over Get-CertificationAuthority that
#                        defers per CA on missing rights and skips unreachable
#                        CAs without aborting), and Get-PublishingCANames for a
#                        read-only DryRun preview naming the affected CAs.
#   1.3.1 - 2026-06-19 - Renamed the script to Templatorator.ps1. ScriptName
#                        updated accordingly, which carries through to the log
#                        file name, the email subject, and the report footer.
#                        No functional change.
#   1.3.2 - 2026-06-19 - Menu header retitled to 'Templatorator Menu' (==== in
#                        cyan, title in yellow). A blank line is now written
#                        before every option/number prompt. Email From address
#                        changed to Templatorator@UHhospitals.org.
#   1.3.3 - 2026-06-19 - Menu Layout and Color Changes
#   1.3.4 - 2026-06-19 - Fixed an array-flattening defect in the email
#                        report. The Q-exit and -DelegatePublishRights modes
#                        built RunContext.Summary as a newline-separated
#                        inline array literal, which PowerShell enumerated
#                        into a single flat string list instead of preserving
#                        the key/value pairs. Build-HtmlReport then indexed
#                        each one-character value past its end, and under
#                        Set-StrictMode -Version Latest that threw 'Index was
#                        outside the bounds of the array' during report send
#                        on a clean exit (and silently rendered wrong text in
#                        the delegate report). Both summaries now build via a
#                        List[object] + ToArray(), matching the Create path.
#   1.3.5 - 2026-06-19 - The report email is now skipped when no actions were
#                        performed. Exiting the menu with Q without running a
#                        Create/Modify/Delete left the action ledger empty but
#                        still attempted a send, which logged an error when the
#                        SMTP host was unreachable. The finally block now sends
#                        only when the ledger has entries (real work or a
#                        captured run error) and otherwise logs a single INFO.
#   1.3.6 - 2026-06-19 - Embedded the approved Templatorator logo at the top of
#                        the HTML report body. Added the $EmailLogo* variables
#                        (enabled flag, content id, 360x240 dimensions, the
#                        image/jpeg MIME type, and the Base64 payload) to the
#                        VARIABLES region. Send-ReportEmail was rebuilt on the
#                        System.Net.Mail API (MailMessage + AlternateView +
#                        LinkedResource) because Send-MailMessage cannot carry
#                        an inline cid: resource; the logo is attached as a
#                        LinkedResource whose ContentId matches the cid: img in
#                        the body. A Test-EmailLogoEmbeddable predicate gates
#                        the embed: when the logo is disabled, unset, still the
#                        placeholder, or not valid Base64, the report sends
#                        without the image (one WARN) instead of a broken icon.
# =====================================================================

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [switch]$DelegatePublishRights,

    [Parameter(Mandatory = $false)]
    [string]$DelegateToPrincipal,

    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $false,

    [Parameter(Mandatory = $false)]
    [bool]$AutoInstallModules = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================
# REGION: VARIABLES
# ============================================================

# --- Script identity / timestamps ---
$ScriptName   = 'Templatorator'
$FriendlyDate = Get-Date -Format 'MM-dd-yyyy'
$RunTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# --- Logging paths ---
$LogDir  = Join-Path -Path $env:ProgramData -ChildPath 'UH\Logs'
$LogFile = Join-Path -Path $LogDir -ChildPath ('{0}_{1}.log' -f $ScriptName, (Get-Date -Format 'yyyyMMdd'))

# --- Console icon toggle ---
$UseConsoleIcons = $false
$ConsoleIcons = @{
    INFO   = [char]::ConvertFromUtf32(0x2139)    # information
    OK     = [char]::ConvertFromUtf32(0x2705)    # check mark
    WARN   = [char]::ConvertFromUtf32(0x26A0)    # warning sign
    ERROR  = [char]::ConvertFromUtf32(0x274C)    # cross mark
    DRYRUN = [char]::ConvertFromUtf32(0x1F7E1)   # yellow circle
}

# --- SMTP / email (open relay, no authentication) ---
$SmtpServer = 'smtp.uhhs.com'
$SmtpPort   = 25
$MailFrom   = 'Templatorator@UHhospitals.org'
$MailTo     = @(
    'Alan.Phillips@UHhospitals.org'
    'Jeffrey.Altomari@UHhospitals.org'
)

# --- Email approved logo ---
# Embedded as Base64 and delivered as a System.Net.Mail LinkedResource
# referenced by a cid: URI; data: URIs are not honored by Outlook desktop.
# Setting $EmailLogoEnabled to $false suppresses both the inline image and
# the linked resource. The byte content is JPEG (despite any .png source
# filename), so the MIME type is image/jpeg - Outlook keys off the
# LinkedResource content type, not a filename. The full 45,240-character
# value lives in EmailLogo_Block.ps1; paste it over the placeholder below.
# While the value still ends in '...', the report is sent without the inline
# logo (a single WARN is logged) rather than producing a broken image.
$EmailLogoEnabled   = $true
$EmailLogoContentId = 'templatoratorlogo'
$EmailLogoWidth     = 360
$EmailLogoHeight    = 240
$EmailLogoMimeType  = 'image/jpeg'
$EmailLogoBase64    = '/9j/4AAQSkZJRgABAQAAAQAB...'   # <-- PASTE full base64 from EmailLogo_Block.ps1 (45,240 chars)

# --- Issuing CA (CAHostName\CA Common Name) used for publication ---
$CAConfig = 'uhpkisub03\University Hospitals Sub CA 3'

# --- Module dependency ---
$PSPKIModuleName = 'PSPKI'

# --- Policy guardrails for interactive input ---
$MinimumKeySize     = 2048                  # RSA minimum key-size floor enforced at the prompt
$TemplateNamePattern = '^[A-Za-z0-9_\-]+$'  # CN must be letters, numbers, underscore, hyphen (no spaces)

# --- EKU / application policy OIDs ---
$EkuClientAuth = '1.3.6.1.5.5.7.3.2'
$EkuServerAuth = '1.3.6.1.5.5.7.3.1'

# --- msPKI-Certificate-Name-Flag deltas. CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and
#     CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME. Assigned (not OR-ed onto the
#     base) so the base template's build-from-AD subject bits are cleared. ---
$NameFlagEnrolleeSuppliesSubject = 0x00000001
$NameFlagEnrolleeSuppliesSan     = 0x00010000

# --- Active Directory PKI container leaf names (combined at runtime with
#     the Configuration naming context read from RootDSE) ---
$PkiServicesPath  = 'CN=Public Key Services,CN=Services'
$TemplatesLeaf    = 'CN=Certificate Templates'
$OidContainerLeaf = 'CN=OID'

# --- Microsoft enterprise certificate-template OID arc. New template OIDs
#     live under <arc>.<forest-signature>.<unique>; the forest signature is
#     discovered at runtime from existing templates, so nothing is hardcoded. ---
$MsEnterpriseTemplateArc = '1.3.6.1.4.1.311.21.8'

# --- New-template revision baseline (mirrors the MMC Duplicate action) ---
$NewTemplateMajorRevision = 100
$NewTemplateMinorRevision = 0

# --- Base-template attributes copied verbatim to the clone. Identity, OID,
#     security descriptor, key size, name flag, and the EKU / application
#     policy are handled explicitly and are intentionally excluded here. ---
$BaseCopyAttributes = @(
    'flags'
    'pKIDefaultKeySpec'
    'pKIKeyUsage'
    'pKIMaxIssuingDepth'
    'pKICriticalExtensions'
    'pKIExpirationPeriod'
    'pKIOverlapPeriod'
    'pKIDefaultCSPs'
    'msPKI-RA-Signature'
    'msPKI-Enrollment-Flag'
    'msPKI-Private-Key-Flag'
    'msPKI-Template-Schema-Version'
    'msPKI-RA-Application-Policies'
)

# --- Per-run context for the email report (populated by the active mode) ---
$Script:RunContext = $null

# --- Action ledger for the email report ---
$Script:ActionLedger = New-Object System.Collections.Generic.List[pscustomobject]

# ============================================================
# REGION: LOGGING
# ============================================================

function Write-Log
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Line
    )

    try
    {
        if (-not (Test-Path -LiteralPath $LogDir))
        {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }

        Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8
    }
    catch
    {
        # File logging must never break the run; surface to console only.
        Write-Host ("[LOGFAIL] Unable to write to {0}: {1}" -f $LogFile, $_.Exception.Message) -ForegroundColor DarkYellow
    }
}

function Write-ConsoleLine
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Tag,

        [Parameter(Mandatory)]
        [System.ConsoleColor]$Color,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $icon  = ''

    if ($UseConsoleIcons -and $ConsoleIcons.ContainsKey($Level))
    {
        $icon = '{0} ' -f $ConsoleIcons[$Level]
    }

    $consoleText = '{0}[{1}] {2}{3}' -f $icon, $stamp, $Tag, $Message
    $fileText    = '[{0}] {1}{2}' -f $stamp, $Tag, $Message

    Write-Host $consoleText -ForegroundColor $Color
    Write-Log -Line $fileText
}

function Write-InfoMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ConsoleLine -Level 'INFO' -Tag '[INFO ] ' -Color Cyan -Message $Message
}

function Write-SuccessMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ConsoleLine -Level 'OK' -Tag '[OK   ] ' -Color Green -Message $Message
}

function Write-WarnMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ConsoleLine -Level 'WARN' -Tag '[WARN ] ' -Color Yellow -Message $Message
}

function Write-ErrorMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ConsoleLine -Level 'ERROR' -Tag '[ERROR] ' -Color Red -Message $Message
}

function Write-DryRunMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-ConsoleLine -Level 'DRYRUN' -Tag '[DRYRUN] ' -Color Magenta -Message $Message
}

# ============================================================
# REGION: HELPERS
# ============================================================

function Get-AdProp
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [AllowNull()]
        $Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object)
    {
        return $null
    }

    $member = $Object.PSObject.Properties[$Name]

    if ($null -ne $member)
    {
        return $member.Value
    }

    return $null
}

function Add-LedgerEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [string]$Detail = ''
    )

    $entry = [pscustomobject]@{
        Action = $Action
        Result = $Result
        Detail = $Detail
    }

    $Script:ActionLedger.Add($entry)
}

function Get-EmailSubject
{
    [CmdletBinding()]
    param()

    return ('{0} - {1}' -f $ScriptName, $FriendlyDate)
}

function Install-PSPKIModule
{
    [CmdletBinding()]
    param()

    Write-WarnMsg -Message ('Module [{0}] is not installed. Attempting a quiet install from the PowerShell Gallery.' -f $PSPKIModuleName)

    $previousProgress = $ProgressPreference
    $previousSecurity = [System.Net.ServicePointManager]::SecurityProtocol

    try
    {
        # PowerShell 5.1 defaults to protocols the gallery rejects, so TLS 1.2
        # must be enabled, and the progress bar is silenced (it also slows
        # downloads dramatically on 5.1).
        $ProgressPreference = 'SilentlyContinue'
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        # AllUsers when elevated (server / service context); CurrentUser otherwise.
        $identity    = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal   = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList $identity
        $isElevated  = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $installScope = if ($isElevated) { 'AllUsers' } else { 'CurrentUser' }

        Write-InfoMsg -Message ('Install scope resolved to [{0}] (elevated = {1}).' -f $installScope, $isElevated)

        # Bootstrap the NuGet provider so Install-Module does not prompt for it.
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if ((-not $nuget) -or ($nuget.Version -lt [version]'2.8.5.201'))
        {
            Write-InfoMsg -Message 'Bootstrapping NuGet package provider.'
            $nugetParams = @{
                Name           = 'NuGet'
                MinimumVersion = '2.8.5.201'
                Scope          = $installScope
                Force          = $true
                ErrorAction    = 'Stop'
            }
            Install-PackageProvider @nugetParams | Out-Null
        }

        # -Force suppresses the untrusted-repository confirmation prompt.
        $installParams = @{
            Name         = $PSPKIModuleName
            Scope        = $installScope
            Repository   = 'PSGallery'
            Force        = $true
            AllowClobber = $true
            Confirm      = $false
            ErrorAction  = 'Stop'
        }

        # -AcceptLicense only exists on newer PowerShellGet; add it when present.
        if ((Get-Command -Name Install-Module).Parameters.ContainsKey('AcceptLicense'))
        {
            $installParams['AcceptLicense'] = $true
        }

        Install-Module @installParams
        Write-SuccessMsg -Message ('Installed module [{0}] from the PowerShell Gallery.' -f $PSPKIModuleName)
    }
    finally
    {
        $ProgressPreference = $previousProgress
        [System.Net.ServicePointManager]::SecurityProtocol = $previousSecurity
    }
}

function Initialize-PSPKI
{
    [CmdletBinding()]
    param()

    if (Get-Module -Name $PSPKIModuleName)
    {
        return
    }

    $available = Get-Module -ListAvailable -Name $PSPKIModuleName |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($null -eq $available)
    {
        if (-not $AutoInstallModules)
        {
            throw ('Module [{0}] is not installed and -AutoInstallModules is disabled. Install it with: Install-Module {0} -Scope CurrentUser' -f $PSPKIModuleName)
        }

        Install-PSPKIModule

        $available = Get-Module -ListAvailable -Name $PSPKIModuleName |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if ($null -eq $available)
        {
            throw ('Module [{0}] could not be installed automatically. Install it manually: Install-Module {0} -Scope CurrentUser' -f $PSPKIModuleName)
        }
    }

    Import-Module $PSPKIModuleName -ErrorAction Stop | Out-Null
    Write-SuccessMsg -Message ('Loaded module [{0}] version [{1}].' -f $available.Name, $available.Version)
}

# ============================================================
# REGION: LDAP CLONE ENGINE
# ============================================================

function Get-ConfigNamingContext
{
    [CmdletBinding()]
    param()

    $rootDse  = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://RootDSE')
    $configNc = [string]$rootDse.Properties['configurationNamingContext'].Value

    if ([string]::IsNullOrWhiteSpace($configNc))
    {
        throw 'Unable to read configurationNamingContext from RootDSE.'
    }

    return $configNc
}

function Get-PkiContainerDNs
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ConfigNc
    )

    $servicesDN = '{0},{1}' -f $PkiServicesPath, $ConfigNc

    return [pscustomobject]@{
        TemplatesDN = '{0},{1}' -f $TemplatesLeaf, $servicesDN
        OidDN       = '{0},{1}' -f $OidContainerLeaf, $servicesDN
    }
}

function Get-BaseTemplateEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$TemplatesDN,

        [Parameter(Mandatory)]
        [string]$BaseName
    )

    # The base is matched on either its cn or its displayName, because built-in
    # templates frequently differ between the two (the cn of 'Workstation
    # Authentication' is 'Workstation'). Plain LDAP, no Global Catalog.
    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $TemplatesDN)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(&(objectClass=pKICertificateTemplate)(|(cn={0})(displayName={0})))' -f $BaseName

    $result = $searcher.FindOne()

    if ($null -eq $result)
    {
        throw ('Base template [{0}] was not found under [{1}].' -f $BaseName, $TemplatesDN)
    }

    return $result.GetDirectoryEntry()
}

function New-TemplateCertificateOid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$TemplatesDN,

        [Parameter(Mandatory)]
        [string]$OidDN
    )

    # Discover the forest-specific arc as the longest common dotted prefix of
    # every existing enterprise template OID. All templates in a forest share
    # the same signature, so the common prefix is exactly that signature.
    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $TemplatesDN)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(objectClass=pKICertificateTemplate)'
    $searcher.PageSize    = 200
    [void]$searcher.PropertiesToLoad.Add('msPKI-Cert-Template-OID')

    $prefixArc      = '{0}.' -f $MsEnterpriseTemplateArc
    $enterpriseOids = New-Object System.Collections.Generic.List[string]

    foreach ($item in $searcher.FindAll())
    {
        if ($item.Properties.Contains('mspki-cert-template-oid'))
        {
            $value = [string]$item.Properties['mspki-cert-template-oid'][0]

            if ($value.StartsWith($prefixArc))
            {
                $enterpriseOids.Add($value)
            }
        }
    }

    if ($enterpriseOids.Count -eq 0)
    {
        throw ('No enterprise templates found under arc [{0}]; cannot derive the forest OID signature. Duplicate any template once in the Certificate Templates console to seed it, then re-run.' -f $MsEnterpriseTemplateArc)
    }

    $split = New-Object System.Collections.Generic.List[string[]]

    foreach ($oidValue in $enterpriseOids)
    {
        $split.Add(($oidValue -split '\.'))
    }

    $minLen = [int]::MaxValue

    foreach ($parts in $split)
    {
        if ($parts.Length -lt $minLen)
        {
            $minLen = $parts.Length
        }
    }

    $commonParts = New-Object System.Collections.Generic.List[string]

    for ($idx = 0; $idx -lt $minLen; $idx++)
    {
        $token    = $split[0][$idx]
        $allMatch = $true

        foreach ($parts in $split)
        {
            if ($parts[$idx] -ne $token)
            {
                $allMatch = $false
                break
            }
        }

        if (-not $allMatch)
        {
            break
        }

        $commonParts.Add($token)
    }

    $forestArc = $commonParts -join '.'

    if (-not $forestArc.StartsWith($MsEnterpriseTemplateArc))
    {
        throw ('Derived forest arc [{0}] does not extend the expected enterprise arc [{1}].' -f $forestArc, $MsEnterpriseTemplateArc)
    }

    # Mint two random positive components and confirm the OID is unused.
    $rng          = New-Object System.Random
    $candidateOid = $null
    $candidateCn  = $null

    for ($attempt = 0; $attempt -lt 20; $attempt++)
    {
        $part1  = $rng.Next(1000000, [int]::MaxValue)
        $part2  = $rng.Next(1000000, [int]::MaxValue)
        $tryOid = '{0}.{1}.{2}' -f $forestArc, $part1, $part2

        $checkRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $OidDN)

        $checker             = New-Object System.DirectoryServices.DirectorySearcher
        $checker.SearchRoot  = $checkRoot
        $checker.SearchScope = 'OneLevel'
        $checker.Filter      = '(msPKI-Cert-Template-OID={0})' -f $tryOid

        if ($null -eq $checker.FindOne())
        {
            $candidateOid = $tryOid
            $candidateCn  = '{0}.{1}' -f $part1, $part2
            break
        }
    }

    if ($null -eq $candidateOid)
    {
        throw 'Unable to mint a unique template OID after 20 attempts.'
    }

    return [pscustomobject]@{
        Oid       = $candidateOid
        Cn        = $candidateCn
        ForestArc = $forestArc
    }
}

function New-TemplateOidObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$OidDN,

        [Parameter(Mandatory)]
        [string]$OidValue,

        [Parameter(Mandatory)]
        [string]$OidCn,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $container = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $OidDN)
    $child     = $container.Children.Add(('CN={0}' -f $OidCn), 'msPKI-Enterprise-Oid')

    $child.Properties['flags'].Value                   = 1
    $child.Properties['displayName'].Value             = $DisplayName
    $child.Properties['msPKI-Cert-Template-OID'].Value = $OidValue
    $child.CommitChanges()

    return $child
}

function New-CertificateTemplateFromBase
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$BaseName,

        [Parameter(Mandatory)]
        [string]$ShortName,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string[]]$EkuList,

        [Parameter(Mandatory)]
        [int]$NameFlag,

        [Parameter(Mandatory)]
        [int]$MinKeySize
    )

    # $NameFlag of -1 means inherit the base template's subject behavior; any
    # value >= 0 is assigned to msPKI-Certificate-Name-Flag, clearing the base
    # build-from-AD bits.
    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc
    $newDN      = 'CN={0},{1}' -f $ShortName, $containers.TemplatesDN

    Write-InfoMsg -Message ('Reading base template [{0}] from [{1}].' -f $BaseName, $containers.TemplatesDN)
    $baseEntry = Get-BaseTemplateEntry -TemplatesDN $containers.TemplatesDN -BaseName $BaseName

    if ($DryRun)
    {
        Write-DryRunMsg -Message ('Would create template object [{0}].' -f $newDN)
        Write-DryRunMsg -Message ('Would copy base attributes: {0}.' -f ($BaseCopyAttributes -join ', '))
        Write-DryRunMsg -Message ('Would set displayName=[{0}], revision=[{1}.{2}], msPKI-Minimal-Key-Size=[{3}].' -f $DisplayName, $NewTemplateMajorRevision, $NewTemplateMinorRevision, $MinKeySize)

        if ($NameFlag -ge 0)
        {
            Write-DryRunMsg -Message ('Would set msPKI-Certificate-Name-Flag=[0x{0:X8}].' -f $NameFlag)
        }
        else
        {
            Write-DryRunMsg -Message 'Would inherit the base template msPKI-Certificate-Name-Flag (subject built as the base defines).'
        }

        Write-DryRunMsg -Message ('Would set pKIExtendedKeyUsage / msPKI-Certificate-Application-Policy=[{0}].' -f ($EkuList -join ', '))
        Write-DryRunMsg -Message 'Would mint a unique template OID under the forest arc and create its msPKI-Enterprise-Oid object.'
        Write-DryRunMsg -Message 'Would inherit the default object security descriptor; the enrollment grant is applied in the ACL step.'
        Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'DryRun' -Detail $ShortName
        return $null
    }

    Write-InfoMsg -Message 'Minting a unique template OID from the forest signature.'
    $oid = New-TemplateCertificateOid -TemplatesDN $containers.TemplatesDN -OidDN $containers.OidDN
    Write-InfoMsg -Message ('Minted template OID [{0}] (forest arc [{1}]).' -f $oid.Oid, $oid.ForestArc)

    Write-InfoMsg -Message 'Creating the template OID object.'
    [void](New-TemplateOidObject -OidDN $containers.OidDN -OidValue $oid.Oid -OidCn $oid.Cn -DisplayName $DisplayName)

    Write-InfoMsg -Message ('Creating template object [{0}].' -f $newDN)
    $container = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $containers.TemplatesDN)
    $new       = $container.Children.Add(('CN={0}' -f $ShortName), 'pKICertificateTemplate')

    # Copy the base attributes verbatim. The binary pKIExpirationPeriod /
    # pKIOverlapPeriod come across as byte arrays, which sidesteps any ADCS
    # validity-period encoding math.
    foreach ($attr in $BaseCopyAttributes)
    {
        if ($baseEntry.Properties.Contains($attr))
        {
            foreach ($value in @($baseEntry.Properties[$attr]))
            {
                [void]$new.Properties[$attr].Add($value)
            }
        }
    }

    # Identity, OID linkage, and minimum key size.
    $new.Properties['displayName'].Value                   = $DisplayName
    $new.Properties['revision'].Value                      = $NewTemplateMajorRevision
    $new.Properties['msPKI-Template-Minor-Revision'].Value = $NewTemplateMinorRevision
    $new.Properties['msPKI-Cert-Template-OID'].Value       = $oid.Oid
    $new.Properties['msPKI-Minimal-Key-Size'].Value        = $MinKeySize

    # Subject name source: assign the chosen flag, or inherit the base value.
    if ($NameFlag -ge 0)
    {
        $new.Properties['msPKI-Certificate-Name-Flag'].Value = $NameFlag
    }
    elseif ($baseEntry.Properties.Contains('msPKI-Certificate-Name-Flag'))
    {
        $new.Properties['msPKI-Certificate-Name-Flag'].Value = $baseEntry.Properties['msPKI-Certificate-Name-Flag'][0]
    }

    # EKU and application-policy deltas.
    foreach ($eku in $EkuList)
    {
        [void]$new.Properties['pKIExtendedKeyUsage'].Add($eku)
        [void]$new.Properties['msPKI-Certificate-Application-Policy'].Add($eku)
    }

    $new.CommitChanges()

    Write-SuccessMsg -Message ('Created template [{0}].' -f $ShortName)
    Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'Created' -Detail ('{0} from {1}; OID {2}' -f $ShortName, $BaseName, $oid.Oid)

    # Allow replication / PSPKI cache a moment, then verify.
    Start-Sleep -Seconds 3
    $newTemplate = Get-CertificateTemplate -Name $ShortName -ErrorAction SilentlyContinue

    if (-not $newTemplate)
    {
        Start-Sleep -Seconds 5
        $newTemplate = Get-CertificateTemplate -Name $ShortName -ErrorAction SilentlyContinue
    }

    if (-not $newTemplate)
    {
        throw ('Template [{0}] was not found via PSPKI after creation.' -f $ShortName)
    }

    Write-SuccessMsg -Message 'Verified the new template is present in AD DS.'
    return $newTemplate
}

# ============================================================
# REGION: ACL / PUBLISH
# ============================================================

function Grant-TemplateEnrollmentRights
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName,

        [Parameter(Mandatory)]
        [string]$Principal,

        [Parameter(Mandatory)]
        [bool]$AddAutoEnroll
    )

    # PSPKI 3.7+ (incl. 4.x) renamed the ACL principal parameter from -User to
    # -Identity. Read + Enroll (optionally Autoenroll) is staged on the ACL
    # object, then written back with Set-CertificateTemplateAcl.
    $template = Get-CertificateTemplate -Name $ShortName

    if ($AddAutoEnroll)
    {
        $acl = $template |
            Get-CertificateTemplateAcl |
            Add-CertificateTemplateAcl -Identity $Principal -AccessType Allow -AccessMask Read, Enroll, Autoenroll
    }
    else
    {
        $acl = $template |
            Get-CertificateTemplateAcl |
            Add-CertificateTemplateAcl -Identity $Principal -AccessType Allow -AccessMask Read, Enroll
    }

    $acl | Set-CertificateTemplateAcl | Out-Null
}

function Invoke-EnrollmentGrant
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName,

        [Parameter(Mandatory = $false)]
        [string]$Principal,

        [Parameter(Mandatory = $false)]
        [bool]$AddAutoEnroll = $false
    )

    if ([string]::IsNullOrWhiteSpace($Principal))
    {
        Write-InfoMsg -Message 'No enrollment principal specified; skipping the rights grant.'
        Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Skipped' -Detail 'No principal specified'
        return
    }

    if ($DryRun)
    {
        if ($AddAutoEnroll)
        {
            $autoText = ' + AutoEnroll'
        }
        else
        {
            $autoText = ''
        }

        Write-DryRunMsg -Message ('Would grant Read + Enroll{0} to [{1}] on template [{2}].' -f $autoText, $Principal, $ShortName)
        Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'DryRun' -Detail $Principal
        return
    }

    Write-InfoMsg -Message ('Granting Read + Enroll rights to [{0}] on template [{1}].' -f $Principal, $ShortName)
    Grant-TemplateEnrollmentRights -ShortName $ShortName -Principal $Principal -AddAutoEnroll $AddAutoEnroll

    Write-SuccessMsg -Message ('Granted template permissions to [{0}].' -f $Principal)
    Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Created' -Detail $Principal
}

function Test-InsufficientRights
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # Detects an Active Directory access-denied anywhere in the exception chain.
    # The write can surface as a COMException, an ADSI DirectoryServicesCOMException,
    # or an UnauthorizedAccessException, so both the HRESULT and the message text are
    # tested. 0x80072098 = E_ADS_INSUFFICIENT_RIGHTS, 0x80070005 = E_ACCESSDENIED.
    $deniedHResults = @(-2147016552, -2147024891)
    $deniedPatterns = @('insufficient access rights', 'access is denied', 'access denied')

    $exception = $ErrorRecord.Exception

    while ($null -ne $exception)
    {
        if ($deniedHResults -contains $exception.HResult)
        {
            return $true
        }

        if (-not [string]::IsNullOrEmpty($exception.Message))
        {
            foreach ($pattern in $deniedPatterns)
            {
                if ($exception.Message -match $pattern)
                {
                    return $true
                }
            }
        }

        $exception = $exception.InnerException
    }

    return $false
}

function Publish-TemplateToCA
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    $caHost = ($CAConfig -split '\\')[0]

    Write-InfoMsg -Message ('Connecting to issuing CA [{0}].' -f $caHost)
    $ca = Connect-CertificationAuthority -ComputerName $caHost

    # Get-CATemplate returns the CA's assigned-template collection (the object
    # that Add-CATemplate / Set-CATemplate consume as -InputObject). Inspect its
    # Templates for an existing assignment before adding a duplicate.
    $caTemplates = $ca | Get-CATemplate
    $assigned    = @(Get-AdProp -Object $caTemplates -Name 'Templates')

    if ($assigned | Where-Object { $_.Name -eq $ShortName })
    {
        Write-SuccessMsg -Message ('Template [{0}] is already published on [{1}].' -f $ShortName, $caHost)
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Already published' -Detail $ShortName
        return
    }

    # Add-CATemplate only stages the assignment in memory; Set-CATemplate writes
    # it back to the CA. The write lands on the Enrollment Services CA object, so a
    # delegated template author may lack rights there; that case is deferred, not failed.
    $template = Get-CertificateTemplate -Name $ShortName

    try
    {
        $caTemplates |
            Add-CATemplate -Template $template |
            Set-CATemplate -ErrorAction Stop | Out-Null
    }
    catch
    {
        if (Test-InsufficientRights -ErrorRecord $_)
        {
            Write-WarnMsg -Message ('Template [{0}] was created and secured, but publishing it to [{1}] needs CA-manager rights (Enterprise Admin, or delegated write on the Enrollment Services object). The current account lacks them; publish deferred to a CA administrator.' -f $ShortName, $caHost)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'Publish deferred' -Detail ('{0} - current account lacks publish rights on [{1}]' -f $ShortName, $caHost)
            return
        }

        throw
    }

    Write-SuccessMsg -Message ('Published template [{0}] to [{1}].' -f $ShortName, $caHost)
    Add-LedgerEntry -Action 'Publish to CA' -Result 'Published' -Detail $ShortName
}

# ============================================================
# REGION: INTERACTIVE INPUT
# ============================================================

function Read-NonEmpty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter(Mandatory = $false)]
        [string]$Default = '',

        [Parameter(Mandatory = $false)]
        [switch]$AllowEmpty
    )

    while ($true)
    {
        if ([string]::IsNullOrWhiteSpace($Default))
        {
            $entry = Read-Host -Prompt $Prompt
        }
        else
        {
            $entry = Read-Host -Prompt ('{0} [{1}]' -f $Prompt, $Default)
        }

        if ([string]::IsNullOrWhiteSpace($entry))
        {
            if (-not [string]::IsNullOrWhiteSpace($Default))
            {
                return $Default
            }

            if ($AllowEmpty)
            {
                return ''
            }

            Write-Host '  A value is required.' -ForegroundColor Yellow
            continue
        }

        return $entry.Trim()
    }
}

function Read-YesNo
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter(Mandatory = $false)]
        [bool]$Default = $false
    )

    if ($Default)
    {
        $hint = 'Y/n'
    }
    else
    {
        $hint = 'y/N'
    }

    while ($true)
    {
        $entry = Read-Host -Prompt ('{0} [{1}]' -f $Prompt, $hint)

        if ([string]::IsNullOrWhiteSpace($entry))
        {
            return $Default
        }

        switch -Regex ($entry.Trim())
        {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host '  Please answer y or n.' -ForegroundColor Yellow }
        }
    }
}

function Read-MenuChoice
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string[]]$Items
    )

    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan

    for ($i = 0; $i -lt $Items.Count; $i++)
    {
        Write-Host ('  {0,3}. {1}' -f ($i + 1), $Items[$i])
    }

    Write-Host ''

    while ($true)
    {
        $entry  = Read-Host -Prompt 'Select a number'
        $number = 0

        if ([int]::TryParse($entry, [ref]$number) -and $number -ge 1 -and $number -le $Items.Count)
        {
            return $number
        }

        Write-Host '  Enter a number from the list.' -ForegroundColor Yellow
    }
}

function Select-BaseTemplate
{
    [CmdletBinding()]
    param()

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc

    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $containers.TemplatesDN)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(objectClass=pKICertificateTemplate)'
    $searcher.PageSize    = 500
    [void]$searcher.PropertiesToLoad.Add('cn')
    [void]$searcher.PropertiesToLoad.Add('displayName')

    $templates = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($item in $searcher.FindAll())
    {
        $cn = ''
        $dn = ''

        if ($item.Properties.Contains('cn'))
        {
            $cn = [string]$item.Properties['cn'][0]
        }

        if ($item.Properties.Contains('displayname'))
        {
            $dn = [string]$item.Properties['displayname'][0]
        }

        $templates.Add([pscustomobject]@{ Cn = $cn; DisplayName = $dn })
    }

    $ordered = @($templates | Sort-Object DisplayName)

    if ($ordered.Count -eq 0)
    {
        throw 'No certificate templates were found in Active Directory to clone from.'
    }

    $labels = @($ordered | ForEach-Object { '{0}   (cn: {1})' -f $_.DisplayName, $_.Cn })

    $choice   = Read-MenuChoice -Title 'Select the base template to clone from:' -Items $labels
    $selected = $ordered[$choice - 1]

    Write-InfoMsg -Message ('Base template selected: [{0}] (cn [{1}]).' -f $selected.DisplayName, $selected.Cn)

    # Return the display name; Get-BaseTemplateEntry matches cn or displayName.
    return $selected.DisplayName
}

function Resolve-AdPrincipal
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Name
    )

    # Validate by resolving the name to a SID (works for users and groups,
    # domain or built-in). Returns the canonical NTAccount form and SID, or
    # $null when the name cannot be resolved.
    try
    {
        $account   = New-Object System.Security.Principal.NTAccount ($Name)
        $sid       = $account.Translate([System.Security.Principal.SecurityIdentifier])
        $canonical = $sid.Translate([System.Security.Principal.NTAccount]).Value

        return [pscustomobject]@{
            Name = $canonical
            Sid  = $sid.Value
        }
    }
    catch
    {
        return $null
    }
}

function Read-EnrollmentGrants
{
    [CmdletBinding()]
    param()

    $grants = New-Object System.Collections.Generic.List[pscustomobject]

    Write-Host ''
    Write-Host 'AD accounts or groups to grant Read + Enroll (validated; blank to finish).' -ForegroundColor Cyan

    while ($true)
    {
        if ($grants.Count -eq 0)
        {
            $prompt = 'Account or group (DOMAIN\name, blank to skip all)'
        }
        else
        {
            $prompt = 'Another account or group (blank to finish)'
        }

        $entry = Read-NonEmpty -Prompt $prompt -AllowEmpty

        if ([string]::IsNullOrWhiteSpace($entry))
        {
            break
        }

        $resolved = Resolve-AdPrincipal -Name $entry

        if ($null -eq $resolved)
        {
            Write-Host ('  [{0}] could not be resolved in Active Directory; try again.' -f $entry) -ForegroundColor Yellow
            continue
        }

        $duplicate = $grants | Where-Object { $_.Principal -eq $resolved.Name }

        if ($duplicate)
        {
            Write-Host ('  [{0}] is already in the list.' -f $resolved.Name) -ForegroundColor Yellow
            continue
        }

        $auto = Read-YesNo -Prompt ('Also grant AutoEnroll to [{0}]?' -f $resolved.Name) -Default $false

        if ($auto)
        {
            $autoNote = ' (+ AutoEnroll)'
        }
        else
        {
            $autoNote = ''
        }

        $grants.Add([pscustomobject]@{
            Principal  = $resolved.Name
            Sid        = $resolved.Sid
            AutoEnroll = $auto
        })

        Write-Host ('  Added [{0}]{1}.' -f $resolved.Name, $autoNote) -ForegroundColor Green
    }

    return $grants.ToArray()
}

function Read-TemplateDefinition
{
    [CmdletBinding()]
    param()

    $baseName = Select-BaseTemplate

    Write-Host ''
    $shortName = Read-NonEmpty -Prompt 'New template name (CN, no spaces)'

    while ($shortName -notmatch $TemplateNamePattern)
    {
        Write-Host ('  Name must match {0} (letters, numbers, underscore, hyphen; no spaces).' -f $TemplateNamePattern) -ForegroundColor Yellow
        $shortName = Read-NonEmpty -Prompt 'New template name (CN, no spaces)'
    }

    $displayName = Read-NonEmpty -Prompt 'Display name'

    $ekuChoice = Read-MenuChoice -Title 'Extended Key Usage:' -Items @(
        'Client Authentication'
        'Server Authentication'
        'Client + Server Authentication'
    )

    switch ($ekuChoice)
    {
        1 { $ekuList = @($EkuClientAuth) }
        2 { $ekuList = @($EkuServerAuth) }
        3 { $ekuList = @($EkuClientAuth, $EkuServerAuth) }
    }

    $nameChoice = Read-MenuChoice -Title 'Subject name source:' -Items @(
        'Supplied in the request - subject only'
        'Supplied in the request - subject and SAN'
        'Built from Active Directory (inherit base behavior)'
    )

    switch ($nameChoice)
    {
        1 { $nameFlag = $NameFlagEnrolleeSuppliesSubject }
        2 { $nameFlag = ($NameFlagEnrolleeSuppliesSubject -bor $NameFlagEnrolleeSuppliesSan) }
        3 { $nameFlag = -1 }
    }

    $keyText = Read-NonEmpty -Prompt 'Minimum key size' -Default ([string]$MinimumKeySize)
    $minKey  = 0

    while ((-not [int]::TryParse($keyText, [ref]$minKey)) -or ($minKey -lt $MinimumKeySize))
    {
        Write-Host ('  Enter a whole number >= {0}.' -f $MinimumKeySize) -ForegroundColor Yellow
        $keyText = Read-NonEmpty -Prompt 'Minimum key size' -Default ([string]$MinimumKeySize)
    }

    $grants  = Read-EnrollmentGrants
    $publish = Read-YesNo -Prompt ('Publish to issuing CA [{0}]?' -f $CAConfig) -Default $false

    return [pscustomobject]@{
        BaseName    = $baseName
        ShortName   = $shortName
        DisplayName = $displayName
        EkuList     = $ekuList
        NameFlag    = $nameFlag
        MinKeySize  = $minKey
        Grants      = $grants
        Publish     = $publish
    }
}

function Show-DefinitionSummary
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [pscustomobject]$Definition
    )

    if ($Definition.NameFlag -ge 0)
    {
        $nameText = 'Supplied in request (0x{0:X8})' -f $Definition.NameFlag
    }
    else
    {
        $nameText = 'Inherited from base template'
    }

    if ($Definition.Publish)
    {
        $publishText = $CAConfig
    }
    else
    {
        $publishText = 'No'
    }

    Write-Host ''
    Write-Host '==== Template definition ====' -ForegroundColor Cyan
    Write-Host ('  Base template : {0}' -f $Definition.BaseName)
    Write-Host ('  CN            : {0}' -f $Definition.ShortName)
    Write-Host ('  Display name  : {0}' -f $Definition.DisplayName)
    Write-Host ('  EKU           : {0}' -f ($Definition.EkuList -join ', '))
    Write-Host ('  Subject       : {0}' -f $nameText)
    Write-Host ('  Min key size  : {0}' -f $Definition.MinKeySize)

    if ($Definition.Grants.Count -eq 0)
    {
        Write-Host  '  Enrollment    : None'
    }
    else
    {
        Write-Host  '  Enrollment    :'

        foreach ($grant in $Definition.Grants)
        {
            if ($grant.AutoEnroll)
            {
                $rightsText = 'Read + Enroll + AutoEnroll'
            }
            else
            {
                $rightsText = 'Read + Enroll'
            }

            Write-Host ('                  - {0} ({1})' -f $grant.Principal, $rightsText)
        }
    }

    Write-Host ('  Publish to CA : {0}' -f $publishText)
    Write-Host ''
}

# ============================================================
# REGION: DELEGATION
# ============================================================

function Get-AttributeSchemaGuid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$LdapDisplayName
    )

    $rootDse  = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://RootDSE')
    $schemaNc = [string]$rootDse.Properties['schemaNamingContext'].Value

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $schemaNc)
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(lDAPDisplayName={0})' -f $LdapDisplayName
    [void]$searcher.PropertiesToLoad.Add('schemaIDGUID')

    $result = $searcher.FindOne()

    if ($null -eq $result)
    {
        throw ('Schema attribute [{0}] was not found.' -f $LdapDisplayName)
    }

    $bytes = [byte[]]$result.Properties['schemaidguid'][0]
    return (New-Object System.Guid (, $bytes))
}

function Get-EnrollmentServiceEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$CaCommonName
    )

    $configNc    = Get-ConfigNamingContext
    $esContainer = 'CN=Enrollment Services,{0},{1}' -f $PkiServicesPath, $configNc

    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $esContainer)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(&(objectClass=pKIEnrollmentService)(cn={0}))' -f $CaCommonName

    $result = $searcher.FindOne()

    if ($null -eq $result)
    {
        throw ('Enrollment Services object for CA [{0}] was not found under [{1}].' -f $CaCommonName, $esContainer)
    }

    return $result.GetDirectoryEntry()
}

function Grant-PublishRights
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Principal
    )

    $caCommonName = ($CAConfig -split '\\')[1]
    $esEntry      = Get-EnrollmentServiceEntry -CaCommonName $caCommonName

    # Limit the read/write to the DACL so CommitChanges does not touch the owner
    # or SACL, which would require additional privileges.
    $esEntry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl

    $esDN = [string]$esEntry.Properties['distinguishedName'].Value

    $account = New-Object System.Security.Principal.NTAccount ($Principal)
    $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier])

    # Least-privilege: WriteProperty scoped to the certificateTemplates attribute
    # only, rather than write on the whole CA object.
    $guid  = Get-AttributeSchemaGuid -LdapDisplayName 'certificateTemplates'
    $write = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    if ($DryRun)
    {
        Write-DryRunMsg -Message ('Would grant Write [certificateTemplates] to [{0}] on [{1}].' -f $Principal, $esDN)
        Add-LedgerEntry -Action 'Delegate publish rights' -Result 'DryRun' -Detail ('{0} on {1}' -f $Principal, $caCommonName)
        return
    }

    Write-InfoMsg -Message ('Granting Write [certificateTemplates] to [{0}] on [{1}].' -f $Principal, $esDN)

    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, $write, $allow, $guid)
    $esEntry.ObjectSecurity.AddAccessRule($rule)
    $esEntry.CommitChanges()

    Write-SuccessMsg -Message ('Delegated publish rights to [{0}] on CA [{1}].' -f $Principal, $caCommonName)
    Add-LedgerEntry -Action 'Delegate publish rights' -Result 'Created' -Detail ('{0} on {1}' -f $Principal, $caCommonName)
}

# ============================================================
# REGION: EMAIL REPORT
# ============================================================

function Test-EmailLogoEmbeddable
{
    [CmdletBinding()]
    param()

    if (-not $EmailLogoEnabled)
    {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($EmailLogoBase64))
    {
        Write-WarnMsg -Message 'Email logo is enabled but no base64 value is set; sending report without the inline logo.'
        return $false
    }

    if ($EmailLogoBase64 -match '\.\.\.\s*$')
    {
        Write-WarnMsg -Message 'Email logo base64 is still the placeholder; sending report without the inline logo.'
        return $false
    }

    try
    {
        [void][System.Convert]::FromBase64String($EmailLogoBase64)
    }
    catch
    {
        Write-WarnMsg -Message ('Email logo base64 failed to decode ({0}); sending report without the inline logo.' -f $_.Exception.Message)
        return $false
    }

    return $true
}

function Build-HtmlReport
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ModeText,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeLogo = $false
    )

    $rows = ''

    foreach ($item in $Script:ActionLedger)
    {
        $color = switch ($item.Result)
        {
            'Created'           { '#1a7f37' }
            'Published'         { '#1a7f37' }
            'Passed'            { '#1a7f37' }
            'Already published' { '#0a66c2' }
            'DryRun'            { '#9a3412' }
            'Publish deferred'  { '#9a3412' }
            'Skipped'           { '#9a3412' }
            default             { '#333333' }
        }

        $rows += ('<tr><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">{0}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:{1};font-weight:600;">{2}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:#444;">{3}</td></tr>' -f $item.Action, $color, $item.Result, $item.Detail)
    }

    if (-not $rows)
    {
        $rows = '<tr><td colspan="3" style="padding:6px 12px;color:#777;">No actions recorded.</td></tr>'
    }

    $heading     = 'Certificate Template Tool'
    $summaryRows = ''

    if ($null -ne $Script:RunContext)
    {
        $heading = $Script:RunContext.Heading

        foreach ($pair in $Script:RunContext.Summary)
        {
            $summaryRows += ('<tr><td style="padding:4px 12px;color:#666;">{0}</td><td style="padding:4px 12px;font-weight:600;">{1}</td></tr>' -f $pair[0], $pair[1])
        }
    }

    $logoHtml = ''

    if ($IncludeLogo)
    {
        $logoHtml = ('<img src="cid:{0}" width="{1}" height="{2}" alt="{3}" style="display:block;border:0;margin-bottom:14px;" />' -f $EmailLogoContentId, $EmailLogoWidth, $EmailLogoHeight, $ScriptName)
    }

    $html = @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;">
  $logoHtml
  <h2 style="color:#0b3d6e;margin-bottom:4px;">$heading</h2>
  <div style="color:#666;margin-bottom:16px;">$ModeText &mdash; $RunTimestamp</div>

  <table style="border-collapse:collapse;margin-bottom:18px;">
    $summaryRows
  </table>

  <table style="border-collapse:collapse;width:100%;max-width:760px;">
    <thead>
      <tr style="background:#0b3d6e;color:#fff;">
        <th style="padding:8px 12px;text-align:left;">Action</th>
        <th style="padding:8px 12px;text-align:left;">Result</th>
        <th style="padding:8px 12px;text-align:left;">Detail</th>
      </tr>
    </thead>
    <tbody>
      $rows
    </tbody>
  </table>

  <p style="color:#999;font-size:12px;margin-top:18px;">Generated by $ScriptName.ps1</p>
</body>
</html>
"@

    return $html
}

function Send-ReportEmail
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$HtmlBody,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeLogo = $false
    )

    $message = $null
    $client  = $null

    try
    {
        $message            = New-Object System.Net.Mail.MailMessage
        $message.From       = New-Object System.Net.Mail.MailAddress ($MailFrom)
        $message.Subject    = (Get-EmailSubject)
        $message.IsBodyHtml = $true

        foreach ($recipient in $MailTo)
        {
            [void]$message.To.Add($recipient)
        }

        $htmlView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($HtmlBody, $null, 'text/html')

        if ($IncludeLogo)
        {
            $logoBytes  = [System.Convert]::FromBase64String($EmailLogoBase64)
            $logoStream = New-Object System.IO.MemoryStream (,$logoBytes)

            $linkedLogo                  = New-Object System.Net.Mail.LinkedResource ($logoStream, $EmailLogoMimeType)
            $linkedLogo.ContentId        = $EmailLogoContentId
            $linkedLogo.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64

            [void]$htmlView.LinkedResources.Add($linkedLogo)
        }

        [void]$message.AlternateViews.Add($htmlView)

        $client = New-Object System.Net.Mail.SmtpClient ($SmtpServer, $SmtpPort)
        $client.Send($message)

        Write-SuccessMsg -Message ('Report email sent to: {0}' -f ($MailTo -join ', '))
    }
    finally
    {
        if ($null -ne $client)
        {
            $client.Dispose()
        }

        if ($null -ne $message)
        {
            $message.Dispose()
        }
    }
}

# ============================================================
# REGION: MODIFY / DELETE
# ============================================================

function Get-TemplateRecords
{
    [CmdletBinding()]
    param()

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc

    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $containers.TemplatesDN)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(objectClass=pKICertificateTemplate)'
    $searcher.PageSize    = 500
    [void]$searcher.PropertiesToLoad.Add('cn')
    [void]$searcher.PropertiesToLoad.Add('displayName')

    $records = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($item in $searcher.FindAll())
    {
        $cn = ''
        $dn = ''

        if ($item.Properties.Contains('cn'))
        {
            $cn = [string]$item.Properties['cn'][0]
        }

        if ($item.Properties.Contains('displayname'))
        {
            $dn = [string]$item.Properties['displayname'][0]
        }

        $records.Add([pscustomobject]@{ Cn = $cn; DisplayName = $dn })
    }

    return @($records | Sort-Object DisplayName)
}

function Select-ExistingTemplate
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ActionLabel
    )

    $records = Get-TemplateRecords

    if ($records.Count -eq 0)
    {
        throw 'No certificate templates were found in Active Directory.'
    }

    $labels = @($records | ForEach-Object { '{0}   (cn: {1})' -f $_.DisplayName, $_.Cn })

    $choice = Read-MenuChoice -Title ('Select the template to {0}:' -f $ActionLabel) -Items $labels
    return $records[$choice - 1]
}

function Get-TemplateEntryByCn
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Cn
    )

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc
    $dn         = 'CN={0},{1}' -f $Cn, $containers.TemplatesDN

    return (New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $dn))
}

function Remove-TemplateFromCA
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    $caHost = ($CAConfig -split '\\')[0]

    try
    {
        $ca          = Connect-CertificationAuthority -ComputerName $caHost
        $caTemplates = $ca | Get-CATemplate
        $assigned    = @(Get-AdProp -Object $caTemplates -Name 'Templates')

        if (-not ($assigned | Where-Object { $_.Name -eq $ShortName }))
        {
            Write-InfoMsg -Message ('Template [{0}] is not published on [{1}]; nothing to unpublish.' -f $ShortName, $caHost)
            return
        }

        Write-InfoMsg -Message ('Unpublishing [{0}] from [{1}].' -f $ShortName, $caHost)

        $caTemplates |
            Remove-CATemplate -Name $ShortName |
            Set-CATemplate -ErrorAction Stop | Out-Null

        Write-SuccessMsg -Message ('Unpublished [{0}] from [{1}].' -f $ShortName, $caHost)
        Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Created' -Detail $ShortName
    }
    catch
    {
        if (Test-InsufficientRights -ErrorRecord $_)
        {
            Write-WarnMsg -Message ('Could not unpublish [{0}] - the current account lacks publish rights on [{1}]. Unpublish manually or via -DelegatePublishRights.' -f $ShortName, $caHost)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail $ShortName
            return
        }

        throw
    }
}

function Get-PublishingCANames
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    # Read-only: returns the display names of every enterprise CA whose
    # certificateTemplates currently lists the template. Used for the DryRun
    # preview and ignores any CA that cannot be read.
    $names = New-Object System.Collections.Generic.List[string]

    foreach ($ca in @(Get-CertificationAuthority))
    {
        $caName = Get-AdProp -Object $ca -Name 'DisplayName'

        if ([string]::IsNullOrWhiteSpace($caName))
        {
            $caName = Get-AdProp -Object $ca -Name 'Name'
        }

        try
        {
            $caTemplates = $ca | Get-CATemplate
            $assigned    = @(Get-AdProp -Object $caTemplates -Name 'Templates')

            if ($assigned | Where-Object { $_.Name -eq $ShortName })
            {
                $names.Add($caName)
            }
        }
        catch
        {
            # Unreadable / unreachable CA - skip it in the read-only preview.
            continue
        }
    }

    return $names.ToArray()
}

function Remove-TemplateFromAllCAs
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    $cas = @(Get-CertificationAuthority)

    if ($cas.Count -eq 0)
    {
        Write-WarnMsg -Message 'No enterprise CAs were found in Active Directory.'
        return
    }

    $found = $false

    foreach ($ca in $cas)
    {
        $caName = Get-AdProp -Object $ca -Name 'DisplayName'

        if ([string]::IsNullOrWhiteSpace($caName))
        {
            $caName = Get-AdProp -Object $ca -Name 'Name'
        }

        try
        {
            $caTemplates = $ca | Get-CATemplate
            $assigned    = @(Get-AdProp -Object $caTemplates -Name 'Templates')

            if (-not ($assigned | Where-Object { $_.Name -eq $ShortName }))
            {
                continue
            }

            $found = $true
            Write-InfoMsg -Message ('Unpublishing [{0}] from [{1}].' -f $ShortName, $caName)

            $caTemplates |
                Remove-CATemplate -Name $ShortName |
                Set-CATemplate -ErrorAction Stop | Out-Null

            Write-SuccessMsg -Message ('Unpublished [{0}] from [{1}].' -f $ShortName, $caName)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Created' -Detail ('{0} on {1}' -f $ShortName, $caName)
        }
        catch
        {
            if (Test-InsufficientRights -ErrorRecord $_)
            {
                Write-WarnMsg -Message ('Could not unpublish [{0}] from [{1}] - the current account lacks publish rights there.' -f $ShortName, $caName)
                Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail ('{0} on {1}' -f $ShortName, $caName)
                continue
            }

            Write-WarnMsg -Message ('Could not process CA [{0}]: {1}' -f $caName, $_.Exception.Message)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Skipped' -Detail ('{0} on {1}: {2}' -f $ShortName, $caName, $_.Exception.Message)
            continue
        }
    }

    if (-not $found)
    {
        Write-InfoMsg -Message ('Template [{0}] was not published on any CA; nothing to unpublish.' -f $ShortName)
    }
}

function Remove-TemplateOidObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$OidValue
    )

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc

    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $containers.OidDN)

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $searchRoot
    $searcher.SearchScope = 'OneLevel'
    $searcher.Filter      = '(msPKI-Cert-Template-OID={0})' -f $OidValue

    $result = $searcher.FindOne()

    if ($null -eq $result)
    {
        Write-InfoMsg -Message ('No OID object found for [{0}]; nothing to delete.' -f $OidValue)
        return
    }

    $oidEntry = $result.GetDirectoryEntry()
    $oidEntry.DeleteTree()

    Write-SuccessMsg -Message ('Deleted OID object for [{0}].' -f $OidValue)
    Add-LedgerEntry -Action 'Delete OID object' -Result 'Created' -Detail $OidValue
}

function Invoke-ModifyTemplate
{
    [CmdletBinding()]
    param()

    $record = Select-ExistingTemplate -ActionLabel 'modify'
    $entry  = Get-TemplateEntryByCn -Cn $record.Cn

    $changes = @{}
    $grants  = @()
    $publish = $false

    while ($true)
    {
        Write-Host ''
        Write-Host ('==== Modify [{0}] ====' -f $record.DisplayName) -ForegroundColor Cyan
        Write-Host '  1. Display name'
        Write-Host '  2. Extended Key Usage'
        Write-Host '  3. Minimum key size'
        Write-Host '  4. Subject name source'
        Write-Host '  5. Add enrollment principals (Read + Enroll)'
        Write-Host '  6. Publish to issuing CA'
        Write-Host '  A. Apply changes'
        Write-Host '  Q. Cancel'
        Write-Host ''
        $sel   = Read-Host -Prompt 'Select an option'
        $apply = $false

        switch ($sel.Trim().ToUpper())
        {
            '1' {
                $changes['displayName'] = Read-NonEmpty -Prompt 'New display name'
            }
            '2' {
                $ekuChoice = Read-MenuChoice -Title 'Extended Key Usage:' -Items @(
                    'Client Authentication'
                    'Server Authentication'
                    'Client + Server Authentication'
                )

                switch ($ekuChoice)
                {
                    1 { $changes['eku'] = @($EkuClientAuth) }
                    2 { $changes['eku'] = @($EkuServerAuth) }
                    3 { $changes['eku'] = @($EkuClientAuth, $EkuServerAuth) }
                }
            }
            '3' {
                $keyText = Read-NonEmpty -Prompt 'Minimum key size' -Default ([string]$MinimumKeySize)
                $k       = 0

                while ((-not [int]::TryParse($keyText, [ref]$k)) -or ($k -lt $MinimumKeySize))
                {
                    Write-Host ('  Enter a whole number >= {0}.' -f $MinimumKeySize) -ForegroundColor Yellow
                    $keyText = Read-NonEmpty -Prompt 'Minimum key size' -Default ([string]$MinimumKeySize)
                }

                $changes['keySize'] = $k
            }
            '4' {
                $nameChoice = Read-MenuChoice -Title 'Subject name source:' -Items @(
                    'Supplied in the request - subject only'
                    'Supplied in the request - subject and SAN'
                    'Built from Active Directory (leave unchanged)'
                )

                switch ($nameChoice)
                {
                    1 { $changes['nameFlag'] = $NameFlagEnrolleeSuppliesSubject }
                    2 { $changes['nameFlag'] = ($NameFlagEnrolleeSuppliesSubject -bor $NameFlagEnrolleeSuppliesSan) }
                    3 { [void]$changes.Remove('nameFlag') }
                }
            }
            '5' {
                $grants = Read-EnrollmentGrants
            }
            '6' {
                $publish = $true
                Write-Host ('  Will publish to [{0}] on apply.' -f $CAConfig) -ForegroundColor Green
            }
            'A' {
                $apply = $true
            }
            'Q' {
                Write-WarnMsg -Message ('Modify cancelled for [{0}].' -f $record.Cn)
                Add-LedgerEntry -Action 'Modify template' -Result 'Skipped' -Detail ('Cancelled: {0}' -f $record.Cn)
                return 'Modify cancelled'
            }
            default {
                Write-Host '  Please choose 1-6, A, or Q.' -ForegroundColor Yellow
            }
        }

        if ($apply)
        {
            break
        }
    }

    if (($changes.Count -eq 0) -and ($grants.Count -eq 0) -and (-not $publish))
    {
        Write-WarnMsg -Message 'No changes were selected.'
        Add-LedgerEntry -Action 'Modify template' -Result 'Skipped' -Detail ('No changes: {0}' -f $record.Cn)
        return 'No changes'
    }

    $detailParts = New-Object System.Collections.Generic.List[string]

    foreach ($key in $changes.Keys)
    {
        $detailParts.Add($key)
    }

    if ($grants.Count -gt 0)
    {
        $detailParts.Add(('{0} grant(s)' -f $grants.Count))
    }

    if ($publish)
    {
        $detailParts.Add('publish')
    }

    $detail = '{0}: {1}' -f $record.Cn, ($detailParts -join ', ')

    if ($DryRun)
    {
        foreach ($key in $changes.Keys)
        {
            Write-DryRunMsg -Message ('Would change [{0}] on template [{1}].' -f $key, $record.Cn)
        }

        if ($changes.Count -gt 0)
        {
            Write-DryRunMsg -Message ('Would increment msPKI-Template-Minor-Revision on [{0}].' -f $record.Cn)
        }

        Add-LedgerEntry -Action 'Modify template' -Result 'DryRun' -Detail $detail
    }
    else
    {
        $confirm = Read-YesNo -Prompt ('Apply these changes to [{0}]?' -f $record.Cn) -Default $false

        if (-not $confirm)
        {
            Write-WarnMsg -Message 'Modify cancelled at the apply step.'
            Add-LedgerEntry -Action 'Modify template' -Result 'Skipped' -Detail ('Cancelled at apply: {0}' -f $record.Cn)
            return 'Modify cancelled'
        }

        if ($changes.Count -gt 0)
        {
            if ($changes.ContainsKey('displayName'))
            {
                $entry.Properties['displayName'].Value = $changes['displayName']
            }

            if ($changes.ContainsKey('keySize'))
            {
                $entry.Properties['msPKI-Minimal-Key-Size'].Value = $changes['keySize']
            }

            if ($changes.ContainsKey('nameFlag'))
            {
                $entry.Properties['msPKI-Certificate-Name-Flag'].Value = $changes['nameFlag']
            }

            if ($changes.ContainsKey('eku'))
            {
                [void]$entry.Properties['pKIExtendedKeyUsage'].Clear()
                [void]$entry.Properties['msPKI-Certificate-Application-Policy'].Clear()

                foreach ($eku in $changes['eku'])
                {
                    [void]$entry.Properties['pKIExtendedKeyUsage'].Add($eku)
                    [void]$entry.Properties['msPKI-Certificate-Application-Policy'].Add($eku)
                }
            }

            # Bump the minor revision so enrolled clients pick up the change.
            $minor = 0

            if ($entry.Properties.Contains('msPKI-Template-Minor-Revision'))
            {
                $minor = [int]$entry.Properties['msPKI-Template-Minor-Revision'][0]
            }

            $entry.Properties['msPKI-Template-Minor-Revision'].Value = ($minor + 1)
            $entry.CommitChanges()

            Write-SuccessMsg -Message ('Applied attribute changes to [{0}] (minor revision now {1}).' -f $record.Cn, ($minor + 1))
        }

        Add-LedgerEntry -Action 'Modify template' -Result 'Created' -Detail $detail
    }

    foreach ($grant in $grants)
    {
        Invoke-EnrollmentGrant -ShortName $record.Cn -Principal $grant.Principal -AddAutoEnroll $grant.AutoEnroll
    }

    if ($publish)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $record.Cn, $CAConfig)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $record.Cn
        }
        else
        {
            Publish-TemplateToCA -ShortName $record.Cn
        }
    }

    if ($DryRun)
    {
        return 'Dry run (no changes made)'
    }

    return 'Template modified'
}

function Invoke-DeleteTemplate
{
    [CmdletBinding()]
    param()

    $record = Select-ExistingTemplate -ActionLabel 'DELETE'

    Write-Host ''
    Write-Host ('==== Delete [{0}] ====' -f $record.DisplayName) -ForegroundColor Red
    Write-Host ('  CN : {0}' -f $record.Cn)
    Write-Host  '  This unpublishes the template from the CA(s) and deletes the template'
    Write-Host  '  object (and optionally its OID object) from Active Directory.'
    Write-Host  '  This action cannot be undone.' -ForegroundColor Red
    Write-Host ''

    $typed = Read-Host -Prompt ('Type the CN [{0}] exactly to confirm (blank to cancel)' -f $record.Cn)

    if ($typed.Trim() -cne $record.Cn)
    {
        Write-WarnMsg -Message ('Delete cancelled for [{0}].' -f $record.Cn)
        Add-LedgerEntry -Action 'Delete template' -Result 'Skipped' -Detail ('Cancelled: {0}' -f $record.Cn)
        return 'Delete cancelled'
    }

    $allCAs    = Read-YesNo -Prompt ('Unpublish from ALL CAs that list it? (No = only [{0}])' -f $CAConfig) -Default $true
    $deleteOid = Read-YesNo -Prompt 'Also delete the associated template OID object?' -Default $true

    $entry    = Get-TemplateEntryByCn -Cn $record.Cn
    $oidValue = ''

    if ($entry.Properties.Contains('msPKI-Cert-Template-OID'))
    {
        $oidValue = [string]$entry.Properties['msPKI-Cert-Template-OID'][0]
    }

    if ($DryRun)
    {
        if ($allCAs)
        {
            $caNames = Get-PublishingCANames -ShortName $record.Cn

            if ($caNames.Count -gt 0)
            {
                Write-DryRunMsg -Message ('Would unpublish [{0}] from: {1}.' -f $record.Cn, ($caNames -join ', '))
            }
            else
            {
                Write-DryRunMsg -Message ('Template [{0}] is not published on any CA.' -f $record.Cn)
            }
        }
        else
        {
            Write-DryRunMsg -Message ('Would unpublish [{0}] from CA [{1}].' -f $record.Cn, $CAConfig)
        }

        Write-DryRunMsg -Message ('Would delete template object [{0}].' -f $record.Cn)

        if ($deleteOid -and -not [string]::IsNullOrWhiteSpace($oidValue))
        {
            Write-DryRunMsg -Message ('Would delete the OID object for [{0}].' -f $oidValue)
        }

        Add-LedgerEntry -Action 'Delete template' -Result 'DryRun' -Detail $record.Cn
        return 'Dry run (no changes made)'
    }

    # 1. Unpublish first (defers cleanly without rights; the sweep is resilient).
    if ($allCAs)
    {
        Remove-TemplateFromAllCAs -ShortName $record.Cn
    }
    else
    {
        Remove-TemplateFromCA -ShortName $record.Cn
    }

    # 2. Delete the template object.
    Write-InfoMsg -Message ('Deleting template object [{0}].' -f $record.Cn)
    $entry.DeleteTree()
    Write-SuccessMsg -Message ('Deleted template [{0}].' -f $record.Cn)
    Add-LedgerEntry -Action 'Delete template' -Result 'Created' -Detail $record.Cn

    # 3. Optionally delete the linked OID object.
    if ($deleteOid -and -not [string]::IsNullOrWhiteSpace($oidValue))
    {
        Remove-TemplateOidObject -OidValue $oidValue
    }

    return 'Template deleted'
}

# ============================================================
# REGION: MAIN
# ============================================================

function Invoke-InteractiveCreate
{
    [CmdletBinding()]
    param()

    $def = Read-TemplateDefinition
    Show-DefinitionSummary -Definition $def

    if ($def.NameFlag -ge 0)
    {
        $subjectText = 'Supplied in request (0x{0:X8})' -f $def.NameFlag
    }
    else
    {
        $subjectText = 'Inherited from base'
    }

    if ($def.Publish)
    {
        $publishText = $CAConfig
    }
    else
    {
        $publishText = 'No'
    }

    $summary = New-Object System.Collections.Generic.List[object]
    $summary.Add(@('CN', $def.ShortName))
    $summary.Add(@('Display Name', $def.DisplayName))
    $summary.Add(@('Base Template', $def.BaseName))
    $summary.Add(@('EKU', ($def.EkuList -join ', ')))
    $summary.Add(@('Subject', $subjectText))
    $summary.Add(@('Minimum Key Size', [string]$def.MinKeySize))

    if ($def.Grants.Count -eq 0)
    {
        $summary.Add(@('Enrollment', 'None'))
    }
    else
    {
        foreach ($grant in $def.Grants)
        {
            if ($grant.AutoEnroll)
            {
                $rightsText = 'Read + Enroll + AutoEnroll'
            }
            else
            {
                $rightsText = 'Read + Enroll'
            }

            $summary.Add(@('Enrollment', ('{0} ({1})' -f $grant.Principal, $rightsText)))
        }
    }

    $summary.Add(@('Publish To', $publishText))
    $summary.Add(@('Engine', 'Direct LDAP (Configuration partition) + PSPKI'))
    $summary.Add(@('Run By', ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)))

    $Script:RunContext = [pscustomobject]@{
        Heading = 'Create Certificate Template'
        Summary = $summary.ToArray()
    }

    $confirmProceed = $true

    if (-not $DryRun)
    {
        $confirmProceed = Read-YesNo -Prompt 'Create the template with these settings?' -Default $false
    }

    if (-not $confirmProceed)
    {
        Write-WarnMsg -Message 'Creation cancelled by operator.'
        Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'Skipped' -Detail 'Cancelled by operator'
        return 'Cancelled by operator'
    }

    Write-InfoMsg -Message ('Checking whether template [{0}] already exists.' -f $def.ShortName)
    $existing = Get-CertificateTemplate -Name $def.ShortName -ErrorAction SilentlyContinue

    if (-not $existing)
    {
        $existing = Get-CertificateTemplate -DisplayName $def.DisplayName -ErrorAction SilentlyContinue
    }

    if ($existing)
    {
        Write-WarnMsg -Message ('A template named [{0}] (or display name [{1}]) already exists; skipping creation.' -f $def.ShortName, $def.DisplayName)
        Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'Skipped' -Detail 'Already exists'
        $shortForGrant = Get-AdProp -Object $existing -Name 'Name'
    }
    else
    {
        [void](New-CertificateTemplateFromBase -BaseName $def.BaseName -ShortName $def.ShortName -DisplayName $def.DisplayName -EkuList $def.EkuList -NameFlag $def.NameFlag -MinKeySize $def.MinKeySize)
        $shortForGrant = $def.ShortName
    }

    if ($def.Grants.Count -eq 0)
    {
        Write-InfoMsg -Message 'No enrollment principals specified; skipping the rights grant.'
        Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Skipped' -Detail 'No principals specified'
    }
    else
    {
        foreach ($grant in $def.Grants)
        {
            Invoke-EnrollmentGrant -ShortName $shortForGrant -Principal $grant.Principal -AddAutoEnroll $grant.AutoEnroll
        }
    }

    if ($def.Publish)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $shortForGrant, $CAConfig)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $shortForGrant
        }
        else
        {
            Publish-TemplateToCA -ShortName $shortForGrant
        }
    }

    if ($DryRun)
    {
        return 'Dry run (no changes made)'
    }

    return 'Template created'
}

function Invoke-DelegatePublishRights
{
    [CmdletBinding()]
    param()

    $principal = $DelegateToPrincipal

    if ([string]::IsNullOrWhiteSpace($principal))
    {
        $principal = Read-NonEmpty -Prompt 'Account (DOMAIN\sAMAccountName) to delegate publish rights to'
    }

    $caCommonName = ($CAConfig -split '\\')[1]

    Write-Host ''
    Write-Host '==== Delegate publish rights ====' -ForegroundColor Cyan
    Write-Host ('  Principal     : {0}' -f $principal)
    Write-Host ('  Issuing CA    : {0}' -f $caCommonName)
    Write-Host  '  Permission    : Write certificateTemplates on the Enrollment Services object'
    Write-Host ''

    $delegateSummary = New-Object System.Collections.Generic.List[object]
    $delegateSummary.Add(@('Mode', 'Delegate publish rights'))
    $delegateSummary.Add(@('Principal', $principal))
    $delegateSummary.Add(@('Issuing CA', $CAConfig))
    $delegateSummary.Add(@('Permission', 'Write certificateTemplates (Enrollment Services object)'))
    $delegateSummary.Add(@('Run By', ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)))

    $Script:RunContext = [pscustomobject]@{
        Heading = 'Delegate Publish Rights'
        Summary = $delegateSummary.ToArray()
    }

    if (-not $DryRun)
    {
        $confirm = Read-YesNo -Prompt 'Proceed with this delegation?' -Default $false

        if (-not $confirm)
        {
            Write-WarnMsg -Message 'Delegation cancelled by operator.'
            Add-LedgerEntry -Action 'Delegate publish rights' -Result 'Skipped' -Detail 'Cancelled by operator'
            return 'Cancelled by operator'
        }
    }

    Grant-PublishRights -Principal $principal

    if ($DryRun)
    {
        return 'Dry run (no changes made)'
    }

    return 'Publish rights delegated'
}

function Invoke-MainMenu
{
    [CmdletBinding()]
    param()

    $opCount = 0

    while ($true)
    {
        Write-Host ''
        Write-Host '  ====== ' -ForegroundColor Cyan -NoNewline
        Write-Host 'TEMPLATORATOR MENU' -ForegroundColor Yellow -NoNewline
        Write-Host ' ======' -ForegroundColor Cyan
        Write-Host '  1. Create a certificate template' -ForegroundColor Green
        Write-Host '  2. Modify a certificate template' -ForegroundColor White
        Write-Host '  3. DELETE a certificate template' -ForegroundColor Red
        Write-Host '  Q. Exit' -ForegroundColor White
        Write-Host '  ================================' -ForegroundColor Cyan
        Write-Host ''
        $choice = Read-Host -Prompt 'Select an option'

        switch ($choice.Trim().ToUpper())
        {
            '1' {
                [void](Invoke-InteractiveCreate)
                $opCount++
            }
            '2' {
                [void](Invoke-ModifyTemplate)
                $opCount++
            }
            '3' {
                [void](Invoke-DeleteTemplate)
                $opCount++
            }
            'Q' {
                $exitSummary = New-Object System.Collections.Generic.List[object]
                $exitSummary.Add(@('Operations', [string]$opCount))
                $exitSummary.Add(@('Engine', 'Direct LDAP (Configuration partition) + PSPKI'))
                $exitSummary.Add(@('Run By', ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)))

                $Script:RunContext = [pscustomobject]@{
                    Heading = 'Certificate Template Session'
                    Summary = $exitSummary.ToArray()
                }

                if ($opCount -eq 0)
                {
                    return 'Exited (no operations performed)'
                }

                return ('Session complete ({0} operation(s))' -f $opCount)
            }
            default {
                Write-Host '  Please choose 1, 2, 3, or Q.' -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-Main
{
    [CmdletBinding()]
    param()

    Write-InfoMsg -Message ('{0} starting (DryRun = {1}).' -f $ScriptName, $DryRun)

    Initialize-PSPKI

    if ($DelegatePublishRights)
    {
        return (Invoke-DelegatePublishRights)
    }

    return (Invoke-MainMenu)
}

# ============================================================
# REGION: ENTRY POINT
# ============================================================

$modeResult = 'Failed'

try
{
    $modeResult = Invoke-Main
}
catch
{
    Write-ErrorMsg -Message $_.Exception.Message
    Add-LedgerEntry -Action 'Run' -Result 'Skipped' -Detail $_.Exception.Message
    $modeResult = ('Error: {0}' -f $_.Exception.Message)
}
finally
{
    if ($Script:ActionLedger.Count -eq 0)
    {
        Write-InfoMsg -Message 'No actions performed; report email skipped.'
    }
    else
    {
        try
        {
            $embedLogo  = Test-EmailLogoEmbeddable
            $reportHtml = Build-HtmlReport -ModeText $modeResult -IncludeLogo $embedLogo
            Send-ReportEmail -HtmlBody $reportHtml -IncludeLogo $embedLogo
        }
        catch
        {
            Write-ErrorMsg -Message ('Failed to send report email: {0}' -f $_.Exception.Message)
        }
    }
}
