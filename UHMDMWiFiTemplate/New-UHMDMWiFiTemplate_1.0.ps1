# =====================================================================
# Script      : New-UHMDMWiFiTemplate.ps1
# Author      : Jeffrey Altomari
# Date        : 06-17-2026
# Version     : 1.0.0
#
# Description : Creates, validates, and optionally publishes a UH MDM /
#               WiFi device certificate template in AD CS by cloning a
#               known-good V2 base template (Workstation Authentication),
#               minting a unique template OID, applying device-cert
#               settings (supply-in-request subject, Client Authentication
#               EKU and application policy, RSA 2048 minimum, 1-year
#               validity, Software KSP), optionally granting Read + Enroll
#               rights, and optionally publishing to the issuing CA.
#               Original concept and field work by Jeffrey Altomari;
#               rebuilt to the UH canonical PowerShell standard.
#
# Requirements: PowerShell 5.1; ActiveDirectory module (RSAT);
#               Enterprise Admin (or delegated) rights on the
#               Configuration partition; ADCSAdministration module on the
#               issuing CA host for publication; network access to a DC
#               and to smtp.uhhs.com:25.
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
    [string]$EnrollmentPrincipal,

    [Parameter(Mandatory = $false)]
    [switch]$GrantAutoEnroll,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true
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

# --- Template policy values ---
$MinimumKeySize  = 2048           # RSA minimum (was $KeyLength in Certerator)
$ValidityDays    = 365            # 1-year certificate validity
$RenewalDays     = 42             # overlap / renewal window
$DefaultKsp      = '1,Microsoft Software Key Storage Provider'

# --- DNS domains (informational; SANs are supplied per-request by WS1 UEM) ---
$PrimaryDomain   = 'uhhs.com'
$AlternateDomain = 'uhhospitals.org'

# --- EKU / application policy OIDs ---
$EkuClientAuth = '1.3.6.1.5.5.7.3.2'
$EkuServerAuth = '1.3.6.1.5.5.7.3.1'

# --- Extended-rights GUIDs for template ACLs ---
$EnrollRightGuid     = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollRightGuid = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

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

# ============================================================
# REGION: AD / PKI LOOKUPS
# ============================================================

function Get-ConfigurationNamingContext
{
    [CmdletBinding()]
    param()

    return ([ADSI]'LDAP://RootDSE').configurationNamingContext
}

function Get-TemplateContainerDN
{
    [CmdletBinding()]
    param()

    $configNC = Get-ConfigurationNamingContext
    return ('CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $configNC)
}

function Get-OidContainerDN
{
    [CmdletBinding()]
    param()

    $configNC = Get-ConfigurationNamingContext
    return ('CN=OID,CN=Public Key Services,CN=Services,{0}' -f $configNC)
}

function Convert-DaysToAdcsPeriodBytes
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [int]$Days
    )

    # AD CS validity / renewal periods are stored as negative 100ns
    # intervals in little-endian Int64.
    $ticks = -1L * $Days * 24 * 60 * 60 * 10000000L
    return [System.BitConverter]::GetBytes([Int64]$ticks)
}

function Get-TemplateByName
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $searchBase = Get-TemplateContainerDN

    $byCnParams = @{
        SearchBase  = $searchBase
        LDAPFilter  = ('(&(objectClass=pKICertificateTemplate)(cn={0}))' -f $Name)
        Properties  = '*'
        ErrorAction = 'SilentlyContinue'
    }

    $byCn = Get-ADObject @byCnParams

    if ($byCn)
    {
        return $byCn
    }

    $byDisplayParams = @{
        SearchBase  = $searchBase
        LDAPFilter  = ('(&(objectClass=pKICertificateTemplate)(displayName={0}))' -f $Name)
        Properties  = '*'
        ErrorAction = 'SilentlyContinue'
    }

    return (Get-ADObject @byDisplayParams)
}

function New-UniqueTemplateOid
{
    [CmdletBinding()]
    param()

    $oidContainer = Get-OidContainerDN

    $oidRootParams = @{
        Identity   = $oidContainer
        Properties = 'msPKI-Cert-Template-OID'
    }

    $oidRoot       = Get-ADObject @oidRootParams
    $forestBaseOid = Get-AdProp -Object $oidRoot -Name 'msPKI-Cert-Template-OID'

    if (-not $forestBaseOid)
    {
        throw ('Forest base template OID not found at [{0}].' -f $oidContainer)
    }

    do
    {
        $part1 = Get-Random -Minimum 10000000 -Maximum 99999999
        $part2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $hex32 = -join ((1..32) | ForEach-Object { '{0:X}' -f (Get-Random -Minimum 0 -Maximum 16) })

        $templateOid = '{0}.{1}.{2}' -f $forestBaseOid, $part1, $part2
        $oidCn       = '{0}.{1}' -f $part2, $hex32

        $collisionParams = @{
            SearchBase  = $oidContainer
            LDAPFilter  = ('(&(objectClass=msPKI-Enterprise-Oid)(cn={0}))' -f $oidCn)
            ErrorAction = 'SilentlyContinue'
        }

        $collision = Get-ADObject @collisionParams
    }
    until (-not $collision)

    return [pscustomobject]@{
        OidCn       = $oidCn
        TemplateOid = $templateOid
    }
}

# ============================================================
# REGION: ATTRIBUTE BUILD
# ============================================================

function Get-CloneableTemplateAttributes
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADObject]$SourceTemplate
    )

    # Identity, system, and AD-module synthetic members are excluded.
    # Everything else (flags, revision, schema version, key usage,
    # CSPs, application policy, etc.) is inherited from the V2 base so
    # the clone starts from a known-good machine template.
    $exclude = @(
        'distinguishedName','DistinguishedName','cn','CN','name','Name',
        'displayName','objectGUID','ObjectGUID','objectSid','objectClass',
        'ObjectClass','objectCategory','ObjectCategory','instanceType',
        'whenCreated','whenChanged','uSNCreated','uSNChanged','created',
        'createTimeStamp','modified','modifyTimeStamp','CanonicalName',
        'dSCorePropagationData','lastKnownParent','nTSecurityDescriptor',
        'sDRightsEffective','Deleted','msPKI-Cert-Template-OID',
        'PropertyNames','PropertyCount','AddedProperties','RemovedProperties',
        'ModifiedProperties','showInAdvancedViewOnly'
    )

    $clone = @{}

    foreach ($prop in $SourceTemplate.PSObject.Properties)
    {
        $propName = $prop.Name

        if ($exclude -contains $propName)
        {
            continue
        }

        if ($null -eq $prop.Value)
        {
            continue
        }

        if ($prop.Value -is [System.Array])
        {
            $clone[$propName] = @($prop.Value)
        }
        else
        {
            $clone[$propName] = $prop.Value
        }
    }

    return $clone
}

function Get-DesiredTemplateAttributes
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [hashtable]$SourceAttributes,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string]$TemplateOid,

        [Parameter(Mandatory)]
        [bool]$IncludeServerAuth
    )

    $attrs = @{}

    foreach ($key in $SourceAttributes.Keys)
    {
        $attrs[$key] = $SourceAttributes[$key]
    }

    # --- Identity ---
    $attrs['displayName']             = $DisplayName
    $attrs['msPKI-Cert-Template-OID'] = $TemplateOid

    # --- Subject name = supply in the request (MDM supplies subject/SAN) ---
    $attrs['msPKI-Certificate-Name-Flag'] = 1

    # --- EKU and application policy (kept in lock-step) ---
    $ekuList = New-Object System.Collections.Generic.List[string]
    $ekuList.Add($EkuClientAuth)

    if ($IncludeServerAuth)
    {
        $ekuList.Add($EkuServerAuth)
    }

    $attrs['pKIExtendedKeyUsage']               = @($ekuList.ToArray())
    $attrs['msPKI-Certificate-Application-Policy'] = @($ekuList.ToArray())

    # --- Key usage = Digital Signature (0x80) + Key Encipherment (0x20) ---
    $attrs['pKIKeyUsage'] = [byte[]](0xA0, 0x00)

    # --- RSA minimum key size ---
    $attrs['msPKI-Minimal-Key-Size'] = $MinimumKeySize

    # --- Validity and renewal window ---
    $attrs['pKIExpirationPeriod'] = Convert-DaysToAdcsPeriodBytes -Days $ValidityDays
    $attrs['pKIOverlapPeriod']    = Convert-DaysToAdcsPeriodBytes -Days $RenewalDays

    # --- Prefer Software KSP ---
    $attrs['pKIDefaultCSPs'] = @($DefaultKsp)

    # --- No key archival / no manager approval unless inherited intentionally ---
    if (-not $attrs.ContainsKey('msPKI-Private-Key-Flag'))
    {
        $attrs['msPKI-Private-Key-Flag'] = 0
    }

    return $attrs
}

# ============================================================
# REGION: DRIFT VALIDATION
# ============================================================

function Test-TemplateDrift
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADObject]$ExistingTemplate,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter(Mandatory)]
        [bool]$ExpectedIncludeServerAuth
    )

    $problems = New-Object System.Collections.Generic.List[string]

    $existingDisplay = [string](Get-AdProp -Object $ExistingTemplate -Name 'displayName')
    if ($existingDisplay -ne $ExpectedDisplayName)
    {
        $problems.Add(('displayName mismatch (existing=''{0}'', expected=''{1}'')' -f $existingDisplay, $ExpectedDisplayName))
    }

    $nameFlag = [int](Get-AdProp -Object $ExistingTemplate -Name 'msPKI-Certificate-Name-Flag')
    if ($nameFlag -ne 1)
    {
        $problems.Add(('msPKI-Certificate-Name-Flag is ''{0}'', expected ''1'' (supply in request)' -f $nameFlag))
    }

    $keySize = [int](Get-AdProp -Object $ExistingTemplate -Name 'msPKI-Minimal-Key-Size')
    if ($keySize -lt $MinimumKeySize)
    {
        $problems.Add(('msPKI-Minimal-Key-Size is ''{0}'', expected >= {1}' -f $keySize, $MinimumKeySize))
    }

    $ekuSet = @(Get-AdProp -Object $ExistingTemplate -Name 'pKIExtendedKeyUsage')

    if ($EkuClientAuth -notin $ekuSet)
    {
        $problems.Add('Client Authentication EKU missing')
    }

    if ($ExpectedIncludeServerAuth -and ($EkuServerAuth -notin $ekuSet))
    {
        $problems.Add('Server Authentication EKU missing')
    }

    if ((-not $ExpectedIncludeServerAuth) -and ($EkuServerAuth -in $ekuSet))
    {
        $problems.Add('Server Authentication EKU present but not expected')
    }

    $cspSet = @(Get-AdProp -Object $ExistingTemplate -Name 'pKIDefaultCSPs')
    if ((@($cspSet).Count -gt 0) -and ($DefaultKsp -notin $cspSet))
    {
        $problems.Add('Software KSP is not configured as the default KSP')
    }

    if (@($problems).Count -gt 0)
    {
        throw ('Template drift detected: {0}' -f ($problems -join ' | '))
    }

    $templateCn = Get-AdProp -Object $ExistingTemplate -Name 'Name'
    Write-SuccessMsg -Message ('Existing template [{0}] passed drift check.' -f $templateCn)
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
        [string]$TemplateDN,

        [Parameter(Mandatory)]
        [string]$Principal,

        [Parameter(Mandatory)]
        [bool]$AddAutoEnroll
    )

    $adsi = [ADSI]('LDAP://{0}' -f $TemplateDN)
    $sec  = $adsi.psbase.ObjectSecurity

    $account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $Principal
    $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier])

    $readArgs = @(
        $sid
        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $readRule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $readArgs
    $sec.AddAccessRule($readRule)

    $enrollArgs = @(
        $sid
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        [System.Security.AccessControl.AccessControlType]::Allow
        $EnrollRightGuid
    )
    $enrollRule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $enrollArgs
    $sec.AddAccessRule($enrollRule)

    if ($AddAutoEnroll)
    {
        $autoEnrollArgs = @(
            $sid
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            [System.Security.AccessControl.AccessControlType]::Allow
            $AutoEnrollRightGuid
        )
        $autoEnrollRule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $autoEnrollArgs
        $sec.AddAccessRule($autoEnrollRule)
    }

    $adsi.psbase.ObjectSecurity = $sec
    $adsi.psbase.CommitChanges()
}

function Publish-TemplateToCA
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$TemplateShortName
    )

    $caHost = ($CAConfig -split '\\')[0]

    if ($caHost -and ($caHost -ne $env:COMPUTERNAME))
    {
        Write-WarnMsg -Message ('Publication targets CA host [{0}] but this script is running on [{1}].' -f $caHost, $env:COMPUTERNAME)
        Write-WarnMsg -Message ('Run with -PublishToCA on [{0}], or publish manually: certutil -config "{1}" -SetCATemplates +{2}' -f $caHost, $CAConfig, $TemplateShortName)
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Skipped' -Detail ('Not on CA host {0}.' -f $caHost)
        return
    }

    if (-not (Get-Module -ListAvailable -Name ADCSAdministration))
    {
        throw 'ADCSAdministration module not found. Cannot publish template automatically on this host.'
    }

    Import-Module ADCSAdministration -ErrorAction Stop | Out-Null

    $published = Get-CATemplate | Where-Object { $_.Name -eq $TemplateShortName }
    if ($published)
    {
        Write-SuccessMsg -Message ('Template [{0}] is already published on this CA.' -f $TemplateShortName)
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Already published' -Detail $TemplateShortName
        return
    }

    Add-CATemplate -Name $TemplateShortName -Force
    Write-SuccessMsg -Message ('Published template [{0}] to the CA.' -f $TemplateShortName)
    Add-LedgerEntry -Action 'Publish to CA' -Result 'Published' -Detail $TemplateShortName
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
        [string]$TemplateName,

        [Parameter(Mandatory)]
        [string]$ExpectedDisplayName,

        [Parameter(Mandatory)]
        [bool]$ExpectedIncludeServerAuth
    )

    Write-InfoMsg -Message ('VALIDATE-ONLY mode enabled. Looking up template [{0}].' -f $TemplateName)

    $template = Get-TemplateByName -Name $TemplateName
    if (-not $template)
    {
        $template = Get-TemplateByName -Name $ExpectedDisplayName
    }

    if (-not $template)
    {
        throw ('VALIDATE-ONLY failed. Template [{0}] / [{1}] was not found.' -f $TemplateName, $ExpectedDisplayName)
    }

    Test-TemplateDrift -ExistingTemplate $template -ExpectedDisplayName $ExpectedDisplayName -ExpectedIncludeServerAuth $ExpectedIncludeServerAuth

    $shortName   = Get-AdProp -Object $template -Name 'Name'
    $displayName = Get-AdProp -Object $template -Name 'displayName'
    $subjectFlag = Get-AdProp -Object $template -Name 'msPKI-Certificate-Name-Flag'
    $minKeySize  = Get-AdProp -Object $template -Name 'msPKI-Minimal-Key-Size'
    $ekuSet      = @(Get-AdProp -Object $template -Name 'pKIExtendedKeyUsage')
    $kspSet      = @(Get-AdProp -Object $template -Name 'pKIDefaultCSPs')

    Write-InfoMsg -Message ('Short Name          : {0}' -f $shortName)
    Write-InfoMsg -Message ('Display Name        : {0}' -f $displayName)
    Write-InfoMsg -Message ('Subject Supply Flag : {0}' -f $subjectFlag)
    Write-InfoMsg -Message ('Minimum Key Size    : {0}' -f $minKeySize)
    Write-InfoMsg -Message ('EKUs                : {0}' -f ($ekuSet -join ', '))
    Write-InfoMsg -Message ('Default KSP(s)      : {0}' -f ($kspSet -join ', '))
    Write-InfoMsg -Message ('Server Auth Expected: {0}' -f $ExpectedIncludeServerAuth)

    Add-LedgerEntry -Action 'Validate template' -Result 'Passed' -Detail $shortName
    Write-SuccessMsg -Message ('VALIDATE-ONLY PASSED for template [{0}].' -f $shortName)
}

# ============================================================
# REGION: TEMPLATE CREATION
# ============================================================

function New-MdmWiFiTemplate
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADObject]$BaseTemplate
    )

    $sourceAttributes = Get-CloneableTemplateAttributes -SourceTemplate $BaseTemplate
    $oidInfo          = New-UniqueTemplateOid

    Write-InfoMsg -Message ('Generated unique template OID [{0}].' -f $oidInfo.TemplateOid)

    $desiredAttributes = Get-DesiredTemplateAttributes -SourceAttributes $sourceAttributes -DisplayName $NewTemplateDisplayName -TemplateOid $oidInfo.TemplateOid -IncludeServerAuth $IncludeServerAuthentication.IsPresent

    $templateContainer = Get-TemplateContainerDN
    $oidContainer      = Get-OidContainerDN

    if ($DryRun)
    {
        Write-DryRunMsg -Message ('Would create OID object [{0}] in [{1}].' -f $oidInfo.OidCn, $oidContainer)
        Write-DryRunMsg -Message ('Would create template [{0}] (display ''{1}'') in [{2}].' -f $NewTemplateShortName, $NewTemplateDisplayName, $templateContainer)
        Add-LedgerEntry -Action 'Create OID object' -Result 'DryRun' -Detail $oidInfo.OidCn
        Add-LedgerEntry -Action 'Create template' -Result 'DryRun' -Detail $NewTemplateShortName
        return $null
    }

    $oidParams = @{
        Name            = $oidInfo.OidCn
        Type            = 'msPKI-Enterprise-Oid'
        Path            = $oidContainer
        OtherAttributes = @{
            displayName               = $NewTemplateDisplayName
            'msPKI-Cert-Template-OID' = $oidInfo.TemplateOid
            flags                     = 1
        }
    }

    New-ADObject @oidParams | Out-Null
    Write-SuccessMsg -Message ('Created OID object [{0}].' -f $oidInfo.OidCn)
    Add-LedgerEntry -Action 'Create OID object' -Result 'Created' -Detail $oidInfo.OidCn

    $templateParams = @{
        Name            = $NewTemplateShortName
        Type            = 'pKICertificateTemplate'
        Path            = $templateContainer
        OtherAttributes = $desiredAttributes
    }

    New-ADObject @templateParams | Out-Null
    Write-SuccessMsg -Message ('Created template [{0}].' -f $NewTemplateShortName)
    Add-LedgerEntry -Action 'Create template' -Result 'Created' -Detail ('{0} (OID {1})' -f $NewTemplateShortName, $oidInfo.TemplateOid)

    Start-Sleep -Seconds 3

    $newTemplate = Get-TemplateByName -Name $NewTemplateShortName
    if (-not $newTemplate)
    {
        throw ('Template [{0}] was not found after creation.' -f $NewTemplateShortName)
    }

    Write-SuccessMsg -Message 'Verified template exists in AD DS.'
    return $newTemplate
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
            'Created'          { '#1a7f37' }
            'Published'        { '#1a7f37' }
            'Passed'           { '#1a7f37' }
            'Already published'{ '#0a66c2' }
            'DryRun'           { '#9a3412' }
            'Skipped'          { '#9a3412' }
            default            { '#333333' }
        }

        $rows += ('<tr><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;">{0}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:{1};font-weight:600;">{2}</td><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;color:#444;">{3}</td></tr>' -f $item.Action, $color, $item.Result, $item.Detail)
    }

    if (-not $rows)
    {
        $rows = '<tr><td colspan="3" style="padding:6px 12px;color:#777;">No actions recorded.</td></tr>'
    }

    $serverAuth = if ($IncludeServerAuthentication) { 'Client + Server Authentication' } else { 'Client Authentication' }

    $html = @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;">
  <h2 style="color:#0b3d6e;margin-bottom:4px;">UH MDM / WiFi Certificate Template</h2>
  <div style="color:#666;margin-bottom:16px;">$ModeText &mdash; $RunTimestamp</div>

  <table style="border-collapse:collapse;margin-bottom:18px;">
    <tr><td style="padding:4px 12px;color:#666;">Short Name</td><td style="padding:4px 12px;font-weight:600;">$NewTemplateShortName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Display Name</td><td style="padding:4px 12px;font-weight:600;">$NewTemplateDisplayName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Base Template</td><td style="padding:4px 12px;">$BaseTemplateName</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">EKU / App Policy</td><td style="padding:4px 12px;">$serverAuth</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Minimum Key Size</td><td style="padding:4px 12px;">$MinimumKeySize</td></tr>
    <tr><td style="padding:4px 12px;color:#666;">Validity / Renewal</td><td style="padding:4px 12px;">$ValidityDays days / $RenewalDays days</td></tr>
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

    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

    if ($ValidateOnly)
    {
        Invoke-TemplateValidationOnly -TemplateName $NewTemplateShortName -ExpectedDisplayName $NewTemplateDisplayName -ExpectedIncludeServerAuth $IncludeServerAuthentication.IsPresent
        return 'Validate-only'
    }

    Write-InfoMsg -Message ('Looking up base template [{0}].' -f $BaseTemplateName)
    $baseTemplate = Get-TemplateByName -Name $BaseTemplateName
    if (-not $baseTemplate)
    {
        throw ('Base template [{0}] was not found.' -f $BaseTemplateName)
    }

    $baseCn      = Get-AdProp -Object $baseTemplate -Name 'Name'
    $baseDisplay = Get-AdProp -Object $baseTemplate -Name 'displayName'
    Write-SuccessMsg -Message ('Base template found: CN=[{0}] DisplayName=[{1}]' -f $baseCn, $baseDisplay)

    $existing = Get-TemplateByName -Name $NewTemplateShortName
    if (-not $existing)
    {
        $existing = Get-TemplateByName -Name $NewTemplateDisplayName
    }

    if ($existing)
    {
        Write-WarnMsg -Message 'Template already exists. Running drift check instead of creating a duplicate.'

        Test-TemplateDrift -ExistingTemplate $existing -ExpectedDisplayName $NewTemplateDisplayName -ExpectedIncludeServerAuth $IncludeServerAuthentication.IsPresent
        Add-LedgerEntry -Action 'Create template' -Result 'Skipped' -Detail 'Already exists; passed drift check.'

        if ($PublishToCA)
        {
            $existingCn = Get-AdProp -Object $existing -Name 'Name'
            if ($DryRun)
            {
                Write-DryRunMsg -Message ('Would publish existing template [{0}] to CA.' -f $existingCn)
                Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $existingCn
            }
            else
            {
                Publish-TemplateToCA -TemplateShortName $existingCn
            }
        }

        Write-SuccessMsg -Message 'No creation performed; template already exists and passed drift check.'
        return 'Drift check (existing template)'
    }

    $newTemplate = New-MdmWiFiTemplate -BaseTemplate $baseTemplate

    if ($EnrollmentPrincipal)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would grant Read + Enroll{0} to [{1}].' -f $(if ($GrantAutoEnroll) { ' + AutoEnroll' } else { '' }), $EnrollmentPrincipal)
            Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'DryRun' -Detail $EnrollmentPrincipal
        }
        elseif ($null -ne $newTemplate)
        {
            Write-InfoMsg -Message ('Granting Read + Enroll rights to [{0}].' -f $EnrollmentPrincipal)
            $templateDn = Get-AdProp -Object $newTemplate -Name 'DistinguishedName'

            Grant-TemplateEnrollmentRights -TemplateDN $templateDn -Principal $EnrollmentPrincipal -AddAutoEnroll $GrantAutoEnroll.IsPresent
            Write-SuccessMsg -Message ('Granted template permissions to [{0}].' -f $EnrollmentPrincipal)
            Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Created' -Detail $EnrollmentPrincipal
        }
    }

    if ($PublishToCA)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $NewTemplateShortName, $CAConfig)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'DryRun' -Detail $NewTemplateShortName
        }
        else
        {
            Publish-TemplateToCA -TemplateShortName $NewTemplateShortName
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
