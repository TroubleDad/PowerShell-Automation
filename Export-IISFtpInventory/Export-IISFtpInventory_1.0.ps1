# =================================================================================================
# Script Name:     Export-IISFtpInventory.ps1
#
# Author:          Alan Phillips
# Date:            06/22/2026
# Version:         1.0
#
# Purpose:         Export IIS FTP inventory including:
#                  - FTP Site Name
#                  - FTP Bindings
#                  - Root and child virtual directory physical paths
#                  - Connect As usernames
#                  - Optional decrypted Connect As passwords
#                  - FTP authorization rules (users, roles, access type, permissions)
#                  - FTP authentication settings
#                  - FTP user isolation mode
#
# Notes:
#                  - Run elevated.
#                  - Password export is OFF by default for safety.
#                  - Designed for IIS / WebAdministration environments.
# =================================================================================================

[CmdletBinding()]
param ()

# =================================================================================================
# VARIABLES
# =================================================================================================

$IncludeDecryptedPasswords = $false
$TimeStamp                 = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutputFolder              = Join-Path -Path $PSScriptRoot -ChildPath 'Exports'
$SiteSummaryCsvPath        = Join-Path -Path $OutputFolder -ChildPath ("IIS_FTP_SiteSummary_{0}.csv" -f $TimeStamp)
$VirtualDirectoryCsvPath   = Join-Path -Path $OutputFolder -ChildPath ("IIS_FTP_VirtualDirectoryDetail_{0}.csv" -f $TimeStamp)
$JsonExportPath            = Join-Path -Path $OutputFolder -ChildPath ("IIS_FTP_FullExport_{0}.json" -f $TimeStamp)

# =================================================================================================
# FUNCTIONS
# =================================================================================================

function Test-IsAdministrator
{
    [CmdletBinding()]
    param ()

    $CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

    return $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-OutputFolder
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path))
    {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Escape-IisFilterValue
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

function Get-ConfigAttributeValue
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$AttributeName
    )

    if ($null -eq $InputObject)
    {
        return $null
    }

    $Property = $InputObject.PSObject.Properties[$AttributeName]

    if ($null -ne $Property)
    {
        return $Property.Value
    }

    try
    {
        return $InputObject.GetAttributeValue($AttributeName)
    }
    catch
    {
        try
        {
            if ($null -ne $InputObject.Attributes -and $null -ne $InputObject.Attributes[$AttributeName])
            {
                return $InputObject.Attributes[$AttributeName].Value
            }
        }
        catch
        {
        }
    }

    return $null
}

function Convert-FtpPermissionValue
{
    [CmdletBinding()]
    param (
        [Parameter()]
        $PermissionValue
    )

    if ($null -eq $PermissionValue)
    {
        return $null
    }

    $StringValue = [string]$PermissionValue

    switch ($StringValue)
    {
        '0' { return 'None' }
        '1' { return 'Read' }
        '2' { return 'Write' }
        '3' { return 'Read,Write' }
        default
        {
            return $StringValue
        }
    }
}

function Get-FtpBindingsForSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Site
    )

    $Bindings = @()

    foreach ($Binding in $Site.Bindings.Collection)
    {
        if ($Binding.protocol -eq 'ftp')
        {
            $Bindings += $Binding.bindingInformation
        }
    }

    return $Bindings
}

function Get-FtpAuthenticationSettings
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteName
    )

    $AnonymousEnabled = $null
    $BasicEnabled     = $null

    try
    {
        $AnonymousEnabled = Get-WebConfigurationProperty `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.ftpServer/security/authentication/anonymousAuthentication" `
            -Location $SiteName `
            -Name "enabled"
    }
    catch
    {
    }

    try
    {
        $BasicEnabled = Get-WebConfigurationProperty `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.ftpServer/security/authentication/basicAuthentication" `
            -Location $SiteName `
            -Name "enabled"
    }
    catch
    {
    }

    [pscustomobject]@{
        AnonymousAuthenticationEnabled = $AnonymousEnabled
        BasicAuthenticationEnabled     = $BasicEnabled
    }
}

function Get-FtpUserIsolationMode
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteName
    )

    try
    {
        return Get-WebConfigurationProperty `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.applicationHost/sites/site[@name='$SiteName']/ftpServer/userIsolation" `
            -Name "mode"
    }
    catch
    {
        return $null
    }
}

function Get-FtpAuthorizationRules
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteName
    )

    $Rules = @()

    try
    {
        $AuthorizationEntries = Get-WebConfiguration `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.ftpServer/security/authorization/*" `
            -Location $SiteName
    }
    catch
    {
        $AuthorizationEntries = @()
    }

    foreach ($Entry in $AuthorizationEntries)
    {
        $Rules += [pscustomobject]@{
            AccessType  = Get-ConfigAttributeValue -InputObject $Entry -AttributeName 'accessType'
            Users       = Get-ConfigAttributeValue -InputObject $Entry -AttributeName 'users'
            Roles       = Get-ConfigAttributeValue -InputObject $Entry -AttributeName 'roles'
            Permissions = Convert-FtpPermissionValue -PermissionValue (Get-ConfigAttributeValue -InputObject $Entry -AttributeName 'permissions')
        }
    }

    return $Rules
}

function Get-IisApplicationsForSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteName
    )

    $EscapedSiteName = Escape-IisFilterValue -Value $SiteName

    try
    {
        return Get-WebConfiguration `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.applicationHost/sites/site[@name='$EscapedSiteName']/application"
    }
    catch
    {
        return @()
    }
}

function Get-IisVirtualDirectoriesForApplication
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteName,

        [Parameter(Mandatory = $true)]
        [string]$ApplicationPath
    )

    $EscapedSiteName     = Escape-IisFilterValue -Value $SiteName
    $EscapedAppPath      = Escape-IisFilterValue -Value $ApplicationPath

    try
    {
        return Get-WebConfiguration `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter "system.applicationHost/sites/site[@name='$EscapedSiteName']/application[@path='$EscapedAppPath']/virtualDirectory"
    }
    catch
    {
        return @()
    }
}

function Get-PathType
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path))
    {
        return 'Unknown'
    }

    if ($Path -like '\\*')
    {
        return 'UNC'
    }

    return 'Local'
}

function Join-AuthorizationRules
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Rules
    )

    if ($null -eq $Rules -or $Rules.Count -eq 0)
    {
        return $null
    }

    $RuleStrings = foreach ($Rule in $Rules)
    {
        "AccessType={0}; Users={1}; Roles={2}; Permissions={3}" -f `
            $Rule.AccessType,
            $Rule.Users,
            $Rule.Roles,
            $Rule.Permissions
    }

    return ($RuleStrings -join ' | ')
}

# =================================================================================================
# PREREQUISITES
# =================================================================================================

if (-not (Test-IsAdministrator))
{
    throw "This script must be run from an elevated PowerShell session."
}

Import-Module WebAdministration -ErrorAction Stop
New-OutputFolder -Path $OutputFolder

# =================================================================================================
# ENUMERATE FTP SITES
# =================================================================================================

$AllSites = Get-Website

$FtpSites = foreach ($Site in $AllSites)
{
    $FtpBindings = Get-FtpBindingsForSite -Site $Site

    if ($FtpBindings.Count -gt 0)
    {
        $Site
    }
}

$SiteSummaryRows      = New-Object System.Collections.Generic.List[object]
$VirtualDirectoryRows = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " IIS FTP Inventory Export" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($FtpSites.Count -eq 0)
{
    Write-Host "⚠️  No IIS FTP sites were found." -ForegroundColor Yellow
}
else
{
    Write-Host ("✅ Found {0} FTP site(s)." -f $FtpSites.Count) -ForegroundColor Green
    Write-Host ""
}

# =================================================================================================
# PROCESS SITES
# =================================================================================================

foreach ($Site in $FtpSites)
{
    $SiteName      = $Site.Name
    $SiteId        = $Site.ID
    $SiteState     = $Site.State
    $FtpBindings   = Get-FtpBindingsForSite -Site $Site
    $AuthSettings  = Get-FtpAuthenticationSettings -SiteName $SiteName
    $UserIsolation = Get-FtpUserIsolationMode -SiteName $SiteName
    $AuthRules     = Get-FtpAuthorizationRules -SiteName $SiteName
    $Applications  = Get-IisApplicationsForSite -SiteName $SiteName

    Write-Host ("📁 Processing site: {0}" -f $SiteName) -ForegroundColor Cyan

    $RootVirtualDirectory = $null

    foreach ($Application in $Applications)
    {
        $ApplicationPath    = [string](Get-ConfigAttributeValue -InputObject $Application -AttributeName 'path')
        $VirtualDirectories = Get-IisVirtualDirectoriesForApplication -SiteName $SiteName -ApplicationPath $ApplicationPath

        foreach ($VirtualDirectory in $VirtualDirectories)
        {
            $VirtualDirectoryPath = [string](Get-ConfigAttributeValue -InputObject $VirtualDirectory -AttributeName 'path')
            $PhysicalPath         = [string](Get-ConfigAttributeValue -InputObject $VirtualDirectory -AttributeName 'physicalPath')
            $ConnectAsUserName    = [string](Get-ConfigAttributeValue -InputObject $VirtualDirectory -AttributeName 'userName')
            $ConnectAsPassword    = $null
            $LogonMethod          = [string](Get-ConfigAttributeValue -InputObject $VirtualDirectory -AttributeName 'logonMethod')
            $PathType             = Get-PathType -Path $PhysicalPath

            if ($IncludeDecryptedPasswords)
            {
                $ConnectAsPassword = [string](Get-ConfigAttributeValue -InputObject $VirtualDirectory -AttributeName 'password')
            }

            if ($ApplicationPath -eq '/' -and $VirtualDirectoryPath -eq '/')
            {
                $RootVirtualDirectory = [pscustomobject]@{
                    VirtualDirectoryPath = $VirtualDirectoryPath
                    PhysicalPath         = $PhysicalPath
                    ConnectAsUserName    = $ConnectAsUserName
                    ConnectAsPassword    = $ConnectAsPassword
                    LogonMethod          = $LogonMethod
                    PathType             = $PathType
                }
            }

            if ($AuthRules.Count -eq 0)
            {
                $VirtualDirectoryRows.Add(
                    [pscustomobject]@{
                        SiteName                        = $SiteName
                        SiteId                          = $SiteId
                        SiteState                       = $SiteState
                        FtpBindings                     = ($FtpBindings -join '; ')
                        ApplicationPath                 = $ApplicationPath
                        VirtualDirectoryPath            = $VirtualDirectoryPath
                        PhysicalPath                    = $PhysicalPath
                        PathType                        = $PathType
                        ConnectAsUserName               = $ConnectAsUserName
                        ConnectAsPassword               = $ConnectAsPassword
                        LogonMethod                     = $LogonMethod
                        AnonymousAuthenticationEnabled  = $AuthSettings.AnonymousAuthenticationEnabled
                        BasicAuthenticationEnabled      = $AuthSettings.BasicAuthenticationEnabled
                        UserIsolationMode               = $UserIsolation
                        AuthorizationAccessType         = $null
                        AuthorizationUsers              = $null
                        AuthorizationRoles              = $null
                        AuthorizationPermissions        = $null
                    }
                ) | Out-Null
            }
            else
            {
                foreach ($Rule in $AuthRules)
                {
                    $VirtualDirectoryRows.Add(
                        [pscustomobject]@{
                            SiteName                        = $SiteName
                            SiteId                          = $SiteId
                            SiteState                       = $SiteState
                            FtpBindings                     = ($FtpBindings -join '; ')
                            ApplicationPath                 = $ApplicationPath
                            VirtualDirectoryPath            = $VirtualDirectoryPath
                            PhysicalPath                    = $PhysicalPath
                            PathType                        = $PathType
                            ConnectAsUserName               = $ConnectAsUserName
                            ConnectAsPassword               = $ConnectAsPassword
                            LogonMethod                     = $LogonMethod
                            AnonymousAuthenticationEnabled  = $AuthSettings.AnonymousAuthenticationEnabled
                            BasicAuthenticationEnabled      = $AuthSettings.BasicAuthenticationEnabled
                            UserIsolationMode               = $UserIsolation
                            AuthorizationAccessType         = $Rule.AccessType
                            AuthorizationUsers              = $Rule.Users
                            AuthorizationRoles              = $Rule.Roles
                            AuthorizationPermissions        = $Rule.Permissions
                        }
                    ) | Out-Null
                }
            }
        }
    }

    $SiteSummaryRows.Add(
        [pscustomobject]@{
            SiteName                        = $SiteName
            SiteId                          = $SiteId
            SiteState                       = $SiteState
            FtpBindings                     = ($FtpBindings -join '; ')
            RootVirtualDirectoryPath        = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.VirtualDirectoryPath } else { $null }
            RootPhysicalPath                = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.PhysicalPath } else { $null }
            RootPathType                    = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.PathType } else { $null }
            RootConnectAsUserName           = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.ConnectAsUserName } else { $null }
            RootConnectAsPassword           = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.ConnectAsPassword } else { $null }
            RootLogonMethod                 = if ($null -ne $RootVirtualDirectory) { $RootVirtualDirectory.LogonMethod } else { $null }
            AnonymousAuthenticationEnabled  = $AuthSettings.AnonymousAuthenticationEnabled
            BasicAuthenticationEnabled      = $AuthSettings.BasicAuthenticationEnabled
            UserIsolationMode               = $UserIsolation
            AuthorizationRules              = Join-AuthorizationRules -Rules $AuthRules
        }
    ) | Out-Null
}

# =================================================================================================
# EXPORT RESULTS
# =================================================================================================

$SiteSummaryRows |
    Sort-Object SiteName |
    Export-Csv -Path $SiteSummaryCsvPath -NoTypeInformation -Encoding UTF8

$VirtualDirectoryRows |
    Sort-Object SiteName, ApplicationPath, VirtualDirectoryPath |
    Export-Csv -Path $VirtualDirectoryCsvPath -NoTypeInformation -Encoding UTF8

[pscustomobject]@{
    ExportDateTimeUtc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    IncludePasswords       = $IncludeDecryptedPasswords
    SiteSummaryCount       = $SiteSummaryRows.Count
    VirtualDirectoryCount  = $VirtualDirectoryRows.Count
    SiteSummary            = $SiteSummaryRows
    VirtualDirectoryDetail = $VirtualDirectoryRows
} |
    ConvertTo-Json -Depth 8 |
    Set-Content -Path $JsonExportPath -Encoding UTF8

# =================================================================================================
# REVIEW OUTPUT
# =================================================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Export Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ("📄 Site Summary CSV        : {0}" -f $SiteSummaryCsvPath) -ForegroundColor Green
Write-Host ("📄 Virtual Directory CSV   : {0}" -f $VirtualDirectoryCsvPath) -ForegroundColor Green
Write-Host ("📄 Full JSON Export        : {0}" -f $JsonExportPath) -ForegroundColor Green
Write-Host ""

$SiteSummaryRows |
    Sort-Object SiteName |
    Format-Table SiteName, FtpBindings, RootPhysicalPath, RootConnectAsUserName, UserIsolationMode -AutoSize