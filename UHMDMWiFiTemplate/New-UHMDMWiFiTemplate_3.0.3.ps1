# =====================================================================
# Script      : New-UHMDMWiFiTemplate.ps1
# Author      : Jeffrey Altomari
# Date        : 06-17-2026
# Version     : 3.0.3
#
# Description : Creates, validates, and optionally publishes a UH MDM /
#               WiFi device certificate template in AD CS by cloning a
#               known-good V2 base (Workstation Authentication) directly
#               in Active Directory over plain LDAP against the
#               Configuration partition (no Global Catalog dependency).
#               The base pKICertificateTemplate attributes are copied
#               verbatim (including the binary validity-period values), a
#               unique template OID is minted under the forest signature
#               discovered at runtime and its msPKI-Enterprise-Oid object
#               created, and the device-cert deltas are applied:
#               subject supplied in request (subject only), Client
#               Authentication EKU, optional Server Authentication EKU,
#               and minimum key size. Enrollment permissions are granted
#               and the template is published using the PSPKI module.
#               Original concept and field work by Jeffrey Altomari;
#               rebuilt to the UH canonical PowerShell standard.
#
# Requirements: PowerShell 5.1; PSPKI module (auto-installed from PSGallery);
#               System.DirectoryServices (built into .NET); Enterprise
#               Admin (or delegated) rights on the Configuration partition
#               to author templates; rights on the issuing CA to publish;
#               LDAP access to a DC and network access to smtp.uhhs.com:25.
#
# Change Log:#
#   1.0.0 - 2026-06-17 - Initial canonical rewrite of Jeffrey Altomari's
#                        UH-WDM-WiFi_Template_Creation.ps1.
#                        Switched default base template from User (V1) to
#                        Workstation Authentication (V2). EKU and
#                        application policy now set together and
#                        deterministically. Added file logging, six
#                        aligned log helpers, $DryRun default, HTML email
#                        report, safe AD property reads, CA-host awareness
#                        for publication, and removed runtime self-lint.
#   2.0.0 - 2026-06-17 - Rebuilt the PKI engine on the supported CertEnroll
#                        IX509CertificateTemplateWritable COM path plus the
#                        PSPKI module. Removed raw New-ADObject template and
#                        OID creation, manual OID minting, the hand-built
#                        attribute hashtable, the ADCS period byte math, the
#                        ADSI security-descriptor edits, and the
#                        ActiveDirectory / ADCSAdministration dependencies.
#                        The platform now auto-generates the template OID on
#                        Commit. Permissions use PSPKI template ACL cmdlets;
#                        publication uses PSPKI CA cmdlets. Drift validation
#                        reads the PSPKI managed template model defensively.
#   2.1.0 - 2026-06-17 - Added a quiet auto-install of the PSPKI module from
#                        the PowerShell Gallery when it is missing: TLS 1.2 is
#                        enforced, the NuGet provider is bootstrapped, the
#                        progress bar is silenced, and the install scope is
#                        chosen by elevation (AllUsers when elevated, else
#                        CurrentUser). New -AutoInstallModules switch (default
#                        true) gates the behavior for locked-down hosts.
#   2.2.0 - 2026-06-17 - Defaulted -EnrollmentPrincipal to the service account
#                        uhhs\svc_mdm_wifidevcert so it is granted Read +
#                        Enroll on the template. Refactored the grant into a
#                        shared Invoke-EnrollmentGrant helper that runs on both
#                        the create and already-exists paths (idempotent), so
#                        re-running ensures the service account retains Enroll.
#   2.2.1 - 2026-06-18 - Bug fixes. Corrected the IX509EnrollmentPolicyServer
#                        Initialize() call in Get-BaseTemplateComObject to the
#                        documented five-argument form (PolicyServerUrl,
#                        PolicyServerId, authFlags, fIsUnTrusted, context); the
#                        prior one-argument call threw "Cannot find an overload
#                        for Initialize and the argument count: 1". Corrected the
#                        EnrollmentTemplateProperty ID for EKUs (was 9, which is
#                        MinorRevision; now 3). Added the policy-server Initialize
#                        arguments to the VARIABLES region. Confirmed
#                        SubjectNameFlags = 25 for Server 2016+ (KeyUsage = 23
#                        present in the enumeration).
#   3.0.0 - 2026-06-18 - PKI engine rebuilt on direct AD LDAP. The CertEnroll
#                        writable-template COM path was removed: its put_Property
#                        only supports the security descriptor, so it cannot set
#                        CommonName, DisplayName, EKUs, or SubjectNameFlags and
#                        failed with 0x80070032 ERROR_NOT_SUPPORTED. The new
#                        engine reads the base pKICertificateTemplate object over
#                        plain LDAP (Configuration partition, no Global Catalog),
#                        copies its attributes verbatim (including the binary
#                        pKIExpirationPeriod / pKIOverlapPeriod, avoiding period
#                        math), mints a unique template OID under the forest
#                        signature it discovers at runtime, creates the matching
#                        msPKI-Enterprise-Oid object, and applies the device-cert
#                        deltas: msPKI-Certificate-Name-Flag = 0x1
#                        (ENROLLEE_SUPPLIES_SUBJECT, subject only, assigned not
#                        OR-ed so the base build-from-AD bits are cleared),
#                        pKIExtendedKeyUsage / msPKI-Certificate-Application-Policy
#                        (Client, plus Server when -IncludeServerAuthentication),
#                        and msPKI-Minimal-Key-Size. The new object inherits the
#                        default security descriptor; the existing ACL step grants
#                        the enrollment principal. COM ProgIDs, enum values, the
#                        policy-server Initialize arguments, and the
#                        EnrollmentTemplateProperty IDs were retired.
#   3.0.1 - 2026-06-18 - Bug fix. Grant-TemplateEnrollmentRights called
#                        Add-CertificateTemplateAcl with -User, which PSPKI
#                        removed in its 3.7 rewrite (failed on 4.x with "A
#                        parameter cannot be found that matches parameter name
#                        'User'"). Switched both branches to the current
#                        -Identity parameter. The template object itself was
#                        already created successfully in 3.0.0; only the ACL
#                        grant was affected.
#   3.0.2 - 2026-06-18 - Bug fix. Publish-TemplateToCA used the pre-4.x
#                        Add-CATemplate form (-CertificationAuthority with the
#                        template piped in) and omitted Set-CATemplate, so on
#                        PSPKI 4.x it would fail or silently not publish. Rebuilt
#                        on the documented pipeline: Get-CATemplate |
#                        Add-CATemplate -Template | Set-CATemplate. The
#                        already-published check now inspects the CA template
#                        collection's Templates rather than the CA object.
#   3.0.3 - 2026-06-18 - Publish step now degrades gracefully. An AD
#                        access-denied on Set-CATemplate (the write lands on
#                        the Enrollment Services CA object, which a delegated
#                        template author may not hold rights to) is caught and
#                        downgraded to a [WARN] with a 'Publish deferred' ledger
#                        result, instead of a terminating error. Any other
#                        publish failure still throws. Added Test-InsufficientRights
#                        to detect E_ADS_INSUFFICIENT_RIGHTS / E_ACCESSDENIED
#                        across the exception chain.
# =====================================================================

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [string]$BaseTemplateName = 'Workstation Authentication',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_\-]+$')]
    [string]$NewTemplateShortName = '__UH__MDM__WiFiDevice__SAN__2048__V1',

    [Parameter(Mandatory = $false)]
    [string]$NewTemplateDisplayName = 'UH-MDM-WiFi-DeviceCert',

    [Parameter(Mandatory = $false)]
    [switch]$PublishToCA,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeServerAuthentication,

    [Parameter(Mandatory = $false)]
    [string]$EnrollmentPrincipal = 'uhhs\svc_mdm_wifidevcert',

    [Parameter(Mandatory = $false)]
    [switch]$GrantAutoEnroll,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

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
$ScriptName   = 'New-UHMDMWiFiTemplate'
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
$MailFrom   = 'Certerator@uhhs.com'
$MailTo     = @(
    'Alan.Phillips@UHhospitals.org'
    'Jeffrey.Altomari@UHhospitals.org'
)

# --- Issuing CA (CAHostName\CA Common Name) used for publication ---
$CAConfig = 'uhpkisub03\University Hospitals Sub CA 3'

# --- Module dependency ---
$PSPKIModuleName = 'PSPKI'

# --- Template policy values (inherited from the V2 base unless overridden) ---
$MinimumKeySize = 2048           # RSA minimum; Workstation Authentication base already meets this
$ValidityDays   = 365            # 1-year certificate validity (inherited from base)
$RenewalDays    = 42             # overlap / renewal window (inherited from base)
$DefaultKsp     = 'Microsoft Software Key Storage Provider'

# --- DNS domains (informational; SANs are supplied per-request by WS1 UEM) ---
$PrimaryDomain   = 'uhhs.com'
$AlternateDomain = 'uhhospitals.org'

# --- EKU / application policy OIDs ---
$EkuClientAuth = '1.3.6.1.5.5.7.3.2'
$EkuServerAuth = '1.3.6.1.5.5.7.3.1'

# --- Active Directory PKI container leaf names (combined at runtime with
#     the Configuration naming context read from RootDSE) ---
$PkiServicesPath  = 'CN=Public Key Services,CN=Services'
$TemplatesLeaf    = 'CN=Certificate Templates'
$OidContainerLeaf = 'CN=OID'

# --- Microsoft enterprise certificate-template OID arc. New template OIDs
#     live under <arc>.<forest-signature>.<unique>; the forest signature is
#     discovered at runtime from existing templates, so nothing is hardcoded. ---
$MsEnterpriseTemplateArc = '1.3.6.1.4.1.311.21.8'

# --- msPKI-Certificate-Name-Flag delta: subject supplied in request, subject
#     only. CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. Assigned (not OR-ed) so the base
#     template's build-from-AD subject bits are cleared. ---
$NameFlagEnrolleeSuppliesSubject = 0x00000001

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

function New-MdmWiFiTemplate
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
        [bool]$IncludeServerAuth
    )

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc
    $newDN      = 'CN={0},{1}' -f $ShortName, $containers.TemplatesDN

    Write-InfoMsg -Message ('Reading base template [{0}] from [{1}].' -f $BaseName, $containers.TemplatesDN)
    $baseEntry = Get-BaseTemplateEntry -TemplatesDN $containers.TemplatesDN -BaseName $BaseName

    if ($IncludeServerAuth)
    {
        $ekuList = @($EkuClientAuth, $EkuServerAuth)
    }
    else
    {
        $ekuList = @($EkuClientAuth)
    }

    if ($DryRun)
    {
        Write-DryRunMsg -Message ('Would create template object [{0}].' -f $newDN)
        Write-DryRunMsg -Message ('Would copy base attributes: {0}.' -f ($BaseCopyAttributes -join ', '))
        Write-DryRunMsg -Message ('Would set displayName=[{0}], revision=[{1}.{2}], msPKI-Minimal-Key-Size=[{3}].' -f $DisplayName, $NewTemplateMajorRevision, $NewTemplateMinorRevision, $MinimumKeySize)
        Write-DryRunMsg -Message ('Would set msPKI-Certificate-Name-Flag=[0x{0:X8}] (ENROLLEE_SUPPLIES_SUBJECT, subject only).' -f $NameFlagEnrolleeSuppliesSubject)
        Write-DryRunMsg -Message ('Would set pKIExtendedKeyUsage / msPKI-Certificate-Application-Policy=[{0}].' -f ($ekuList -join ', '))
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

    # Identity and OID linkage.
    $new.Properties['displayName'].Value                   = $DisplayName
    $new.Properties['revision'].Value                      = $NewTemplateMajorRevision
    $new.Properties['msPKI-Template-Minor-Revision'].Value = $NewTemplateMinorRevision
    $new.Properties['msPKI-Cert-Template-OID'].Value       = $oid.Oid

    # Subject supplied in request (subject only) and minimum key size.
    $new.Properties['msPKI-Certificate-Name-Flag'].Value = $NameFlagEnrolleeSuppliesSubject
    $new.Properties['msPKI-Minimal-Key-Size'].Value      = $MinimumKeySize

    # EKU and application-policy deltas (Client, plus Server when requested).
    foreach ($eku in $ekuList)
    {
        [void]$new.Properties['pKIExtendedKeyUsage'].Add($eku)
        [void]$new.Properties['msPKI-Certificate-Application-Policy'].Add($eku)
    }

    $new.CommitChanges()

    Write-SuccessMsg -Message ('Created template [{0}].' -f $ShortName)

    if ($IncludeServerAuth)
    {
        Write-InfoMsg -Message 'EKUs set to Client + Server Authentication.'
    }
    else
    {
        Write-InfoMsg -Message 'EKU set to Client Authentication.'
    }

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
# REGION: DRIFT VALIDATION
# ============================================================

function Get-TemplateFacts
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        $Template
    )

    # The PSPKI managed model exposes most settings under .Settings, but
    # property names vary slightly across module versions, so every read is
    # guarded and degrades to a null / empty value rather than throwing.
    $facts = [ordered]@{
        ShortName   = $null
        DisplayName = $null
        KeyLength   = $null
        SubjectName = $null
        Ekus        = @()
        Providers   = @()
    }

    try { $facts.ShortName   = Get-AdProp -Object $Template -Name 'Name' }        catch { }
    try { $facts.DisplayName = Get-AdProp -Object $Template -Name 'DisplayName' } catch { }

    $settings = Get-AdProp -Object $Template -Name 'Settings'

    if ($null -ne $settings)
    {
        try { $facts.KeyLength   = Get-AdProp -Object $settings -Name 'MinimalKeyLength' } catch { }
        try { $facts.SubjectName = [string](Get-AdProp -Object $settings -Name 'SubjectName') } catch { }

        $eku = Get-AdProp -Object $settings -Name 'EnhancedKeyUsage'
        if ($null -ne $eku)
        {
            try { $facts.Ekus = @($eku | ForEach-Object { Get-AdProp -Object $_ -Name 'Value' }) } catch { }
        }

        $crypto = Get-AdProp -Object $settings -Name 'Cryptography'
        if ($null -ne $crypto)
        {
            $cspList = Get-AdProp -Object $crypto -Name 'CSPList'
            if ($null -ne $cspList)
            {
                try { $facts.Providers = @($cspList) } catch { }
            }
        }
    }

    return $facts
}

function Test-TemplateDrift
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        $Template,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter(Mandatory)]
        [bool]$ExpectedIncludeServerAuth
    )

    $facts    = Get-TemplateFacts -Template $Template
    $problems = New-Object System.Collections.Generic.List[string]

    if ([string]$facts.DisplayName -ne $ExpectedDisplayName)
    {
        $problems.Add(('displayName mismatch (existing=''{0}'', expected=''{1}'')' -f $facts.DisplayName, $ExpectedDisplayName))
    }

    if ($facts.SubjectName -notmatch 'EnrolleeSuppliesSubject')
    {
        $problems.Add(('subject name is ''{0}'', expected supply-in-request (EnrolleeSuppliesSubject)' -f $facts.SubjectName))
    }

    if ($null -ne $facts.KeyLength -and [int]$facts.KeyLength -lt $MinimumKeySize)
    {
        $problems.Add(('minimum key size is ''{0}'', expected >= {1}' -f $facts.KeyLength, $MinimumKeySize))
    }

    if ($EkuClientAuth -notin $facts.Ekus)
    {
        $problems.Add('Client Authentication EKU missing')
    }

    if ($ExpectedIncludeServerAuth -and ($EkuServerAuth -notin $facts.Ekus))
    {
        $problems.Add('Server Authentication EKU missing')
    }

    if ((-not $ExpectedIncludeServerAuth) -and ($EkuServerAuth -in $facts.Ekus))
    {
        $problems.Add('Server Authentication EKU present but not expected')
    }

    if (@($problems).Count -gt 0)
    {
        throw ('Template drift detected: {0}' -f ($problems -join ' | '))
    }

    Write-SuccessMsg -Message ('Existing template [{0}] passed drift check.' -f $facts.ShortName)
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
        [string]$ShortName
    )

    if (-not $EnrollmentPrincipal)
    {
        return
    }

    if ($DryRun)
    {
        $autoText = if ($GrantAutoEnroll) { ' + AutoEnroll' } else { '' }
        Write-DryRunMsg -Message ('Would grant Read + Enroll{0} to [{1}] on template [{2}].' -f $autoText, $EnrollmentPrincipal, $ShortName)
        Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'DryRun' -Detail $EnrollmentPrincipal
        return
    }

    Write-InfoMsg -Message ('Granting Read + Enroll rights to [{0}] on template [{1}].' -f $EnrollmentPrincipal, $ShortName)
    Grant-TemplateEnrollmentRights -ShortName $ShortName -Principal $EnrollmentPrincipal -AddAutoEnroll $GrantAutoEnroll.IsPresent

    Write-SuccessMsg -Message ('Granted template permissions to [{0}].' -f $EnrollmentPrincipal)
    Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Created' -Detail $EnrollmentPrincipal
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
# REGION: VALIDATION-ONLY MODE
# ============================================================

function Invoke-TemplateValidationOnly
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter(Mandatory)]
        [bool]$ExpectedIncludeServerAuth
    )

    Write-InfoMsg -Message ('VALIDATE-ONLY mode enabled. Looking up template [{0}].' -f $ShortName)

    $template = Get-CertificateTemplate -Name $ShortName -ErrorAction SilentlyContinue
    if (-not $template)
    {
        $template = Get-CertificateTemplate -DisplayName $ExpectedDisplayName -ErrorAction SilentlyContinue
    }

    if (-not $template)
    {
        throw ('VALIDATE-ONLY failed. Template [{0}] / [{1}] was not found.' -f $ShortName, $ExpectedDisplayName)
    }

    Test-TemplateDrift -Template $template -ExpectedDisplayName $ExpectedDisplayName -ExpectedIncludeServerAuth $ExpectedIncludeServerAuth

    $facts = Get-TemplateFacts -Template $template

    Write-InfoMsg -Message ('Short Name          : {0}' -f $facts.ShortName)
    Write-InfoMsg -Message ('Display Name        : {0}' -f $facts.DisplayName)
    Write-InfoMsg -Message ('Subject Name Flags  : {0}' -f $facts.SubjectName)
    Write-InfoMsg -Message ('Minimum Key Size    : {0}' -f $facts.KeyLength)
    Write-InfoMsg -Message ('EKUs                : {0}' -f ($facts.Ekus -join ', '))
    Write-InfoMsg -Message ('Provider(s)         : {0}' -f ($facts.Providers -join ', '))
    Write-InfoMsg -Message ('Server Auth Expected: {0}' -f $ExpectedIncludeServerAuth)

    Add-LedgerEntry -Action 'Validate template' -Result 'Passed' -Detail $facts.ShortName
    Write-SuccessMsg -Message ('VALIDATE-ONLY PASSED for template [{0}].' -f $facts.ShortName)
}

# ============================================================
# REGION: EMAIL REPORT
# ============================================================

function Build-HtmlReport
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ModeText
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
            'Skipped'           { '#9a3412' }
            default             { '#333333' }
        }

        $rows += ('<tr><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">{0}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:{1};font-weight:600;">{2}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:#444;">{3}</td></tr>' -f $item.Action, $color, $item.Result, $item.Detail)
    }

    if (-not $rows)
    {
        $rows = '<tr><td colspan="3" style="padding:6px 12px;color:#777;">No actions recorded.</td></tr>'
    }

    $ekuText = if ($IncludeServerAuthentication) { 'Client + Server Authentication' } else { 'Client Authentication' }

    $html = @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;">
  <h2 style="color:#0b3d6e;margin-bottom:4px;">UH MDM / WiFi Certificate Template</h2>
  <div style="color:#666;margin-bottom:16px;">$ModeText &mdash; $RunTimestamp</div>

  <table style="border-collapse:collapse;margin-bottom:18px;">
    <tr><td style="padding:4px 12px;color:#666;">Short Name</td><td style="padding:4px 12px;font-weight:600;">$NewTemplateShortName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Display Name</td><td style="padding:4px 12px;font-weight:600;">$NewTemplateDisplayName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Base Template</td><td style="padding:4px 12px;">$BaseTemplateName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Engine</td><td style="padding:4px 12px;">Direct LDAP (Configuration partition) + PSPKI</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">EKU</td><td style="padding:4px 12px;">$ekuText</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Minimum Key Size</td><td style="padding:4px 12px;">$MinimumKeySize</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Issuing CA</td><td style="padding:4px 12px;">$CAConfig</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Run By</td><td style="padding:4px 12px;">$env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME</td></tr>
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
        [string]$HtmlBody
    )

    $mailParams = @{
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        From       = $MailFrom
        To         = $MailTo
        Subject    = (Get-EmailSubject)
        Body       = $HtmlBody
        BodyAsHtml = $true
    }

    Send-MailMessage @mailParams
    Write-SuccessMsg -Message ('Report email sent to: {0}' -f ($MailTo -join ', '))
}

# ============================================================
# REGION: MAIN
# ============================================================

function Invoke-Main
{
    [CmdletBinding()]
    param()

    Write-InfoMsg -Message ('{0} starting (DryRun = {1}).' -f $ScriptName, $DryRun)

    Initialize-PSPKI

    if ($ValidateOnly)
    {
        Invoke-TemplateValidationOnly -ShortName $NewTemplateShortName -ExpectedDisplayName $NewTemplateDisplayName -ExpectedIncludeServerAuth $IncludeServerAuthentication.IsPresent
        return 'Validate-only'
    }

    Write-InfoMsg -Message ('Checking whether template [{0}] already exists.' -f $NewTemplateShortName)
    $existing = Get-CertificateTemplate -Name $NewTemplateShortName -ErrorAction SilentlyContinue
    if (-not $existing)
    {
        $existing = Get-CertificateTemplate -DisplayName $NewTemplateDisplayName -ErrorAction SilentlyContinue
    }

    if ($existing)
    {
        Write-WarnMsg -Message 'Template already exists. Running drift check instead of creating a duplicate.'

        Test-TemplateDrift -Template $existing -ExpectedDisplayName $NewTemplateDisplayName -ExpectedIncludeServerAuth $IncludeServerAuthentication.IsPresent
        Add-LedgerEntry -Action 'Clone + commit template' -Result 'Skipped' -Detail 'Already exists; passed drift check.'

        $existingShort = Get-AdProp -Object $existing -Name 'Name'

        Invoke-EnrollmentGrant -ShortName $existingShort

        if ($PublishToCA)
        {
            if ($DryRun)
            {
                Write-DryRunMsg -Message ('Would publish existing template [{0}] to CA.' -f $existingShort)
                Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $existingShort
            }
            else
            {
                Publish-TemplateToCA -ShortName $existingShort
            }
        }

        Write-SuccessMsg -Message 'No creation performed; template already exists and passed drift check.'
        return 'Drift check (existing template)'
    }

    $newTemplate = New-MdmWiFiTemplate -BaseName $BaseTemplateName -ShortName $NewTemplateShortName -DisplayName $NewTemplateDisplayName -IncludeServerAuth $IncludeServerAuthentication.IsPresent

    Invoke-EnrollmentGrant -ShortName $NewTemplateShortName

    if ($PublishToCA)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $NewTemplateShortName, $CAConfig)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $NewTemplateShortName
        }
        else
        {
            Publish-TemplateToCA -ShortName $NewTemplateShortName
        }
    }

    if ($DryRun)
    {
        return 'Dry run (no changes made)'
    }

    return 'Template created'
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
    try
    {
        $reportHtml = Build-HtmlReport -ModeText $modeResult
        Send-ReportEmail -HtmlBody $reportHtml
    }
    catch
    {
        Write-ErrorMsg -Message ('Failed to send report email: {0}' -f $_.Exception.Message)
    }
}
