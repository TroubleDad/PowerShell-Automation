# =====================================================================
# Script      : Promote_DC.ps1
# Author      : Alan W. Phillips
# Date        : 06-11-2026
# Version     : 5.4.0
# Description : Promote a previously prepped, domain-joined member server
#               into a replacement Active Directory Domain Controller,
#               driven remotely from a healthy management DC (intended to
#               run locally on UHSVRDC08, a Windows Server 2022 Desktop
#               Experience DC). The workflow generates Install From Media
#               (IFM) locally on the host DC via ntdsutil (run inline in
#               the elevated session, output captured to the log),
#               robocopies it to
#               C:\IFM on the destination server, and remotely runs
#               Install-ADDSDomainController against that IFM media -
#               replicating from UHSVRDC08. Promotion includes reactive
#               password-policy relaxation (with backup/restore) so the
#               8-character UH-standard DSRM password is accepted, AD-site
#               auto-detection from the target's IPv4, and InfoBlox-aware
#               DNS handling (no DNS delegation is created; DCs forward to
#               InfoBlox). After a controlled remote reboot the target is
#               health-checked (NTDS / DFSR / SYSVOL / GUID CNAME /
#               replication), the IFM directories on both the host and the
#               target are cleaned up, and a color HTML status report is
#               emailed. Behavior is variable-driven with a $DryRun toggle.
# Requirements:
#               - Run locally on a healthy Domain Controller (UHSVRDC08)
#               - Run as an Enterprise Admin (SA) account in an ELEVATED
#                 PowerShell / ISE session (launch with "Run as
#                 administrator"). A fail-closed startup gate verifies both
#                 elevation and Domain Admins + Enterprise Admins membership
#                 before any change is made.
#               - PowerShell 5.1
#               - ActiveDirectory and ADDSDeployment modules
#               - WinRM reachable on the target server
#               - Target already domain-joined, not yet a DC, prepped
#               - Windows Server 2016 or higher (host and target)
# Change Log:#
#               5.4.0 - Reworked the privilege, output and credential model to
#                       match Remove_DC_Remote.ps1 and to fix three faults seen
#                       on the v5.3.0 run.
#                       (1) FALSE "not an Enterprise Admin": the v5.2.0/5.3.0
#                       check read the CURRENT PROCESS TOKEN, but the session
#                       ran non-elevated and UAC token filtering strips the
#                       Domain Admins / Enterprise Admins / Administrators SIDs
#                       from a filtered token - so a genuine EA was reported as
#                       not a member. Membership is now read from Active
#                       Directory via the tokenGroups constructed attribute
#                       keyed by the account SID (RID 512 / 519), which is
#                       elevation-independent (Test-HasRequiredAdminGroups).
#                       (2) UAC POPUP WINDOWS and lost output: the per-step
#                       Start-Process -Verb RunAs helper (Invoke-ElevatedScript)
#                       opened a visible console for IFM generation and for the
#                       robocopy, and streamed a transcript into the log. That
#                       whole self-elevation model is removed. The script now
#                       requires an already-elevated session (Assert-Execution-
#                       Privileges gate) and runs ntdsutil and robocopy INLINE,
#                       in-process, with output captured to the log and a
#                       colorized robocopy summary - exactly like
#                       Generate_IFM.ps1. Restored Test-DiskSpace, Test-VssHealth
#                       and Test-IfmMedia as first-class helper functions.
#                       (3) DOUBLE-HOP promotion failure: the explicit promotion
#                       credential is now MANDATORY by default
#                       ($UseExplicitPromotionCredential = $true) and is captured
#                       AND validated up front (Initialize-PromotionCredential /
#                       Test-PromotionCredential) before the long IFM generate
#                       and copy, instead of being optional and prompted mid-flow.
#                       A blank $PromotionCredentialUser now prompts pre-filled
#                       with the current SA identity (zero-config). The credential
#                       is threaded into Install-ADDSDomainController -Credential
#                       so the target authenticates onward to the forest with a
#                       materialized credential rather than the absent delegated
#                       identity. Added Get-LaunchContext / launch advisory and a
#                       per-check capability message, ported from
#                       Remove_DC_Remote.ps1.
#               5.3.0 - Added an optional explicit promotion credential to
#                       mitigate the Kerberos double-hop on the remote promotion.
#                       The promotion runs on the target via Invoke-Command and
#                       then has to make a second hop from the target back to the
#                       forest / replication source DC; under default Kerberos
#                       that second hop carries no credentials, which can surface
#                       as "ldap_search() failed ... a successful bind must be
#                       completed ... insufficient credentials for a remote
#                       operation." A new $PromotionCredentialUser variable (blank
#                       by default) and a Get-PromotionCredential helper prompt
#                       once for that account's password and pass the resulting
#                       credential to Install-ADDSDomainController via the -Credential
#                       parameter, so the promotion authenticates with a
#                       materialized credential inside the remote session instead
#                       of the absent delegated identity. Left blank, behavior is
#                       unchanged (the session's own identity is used). The
#                       promotion report now records which credential was used.
#               5.2.0 - Reworked the privilege model so the script no longer
#                       needs to be launched elevated. It is now run as the SA
#                       (Enterprise Admin) account in a normal, non-elevated
#                       session, so the remote Install-ADDSDomainController call
#                       carries Enterprise Admin rights - fixing the prior
#                       "ldap_search() failed ... a successful bind must be
#                       completed on the connection / insufficient credentials
#                       for a remote operation" failure that hit the promotion
#                       when the earlier elevated-but-non-EA session reached it.
#                       The local ntdsutil IFM generation, the host-side
#                       robocopy of the media to the target, and the host IFM
#                       cleanup now each run in a separate elevated child process
#                       (Start-Process -Verb RunAs) via a new Invoke-ElevatedScript
#                       helper, instead of requiring the whole session to be
#                       elevated. Removed the hard Administrator gate in
#                       Test-LocalPrerequisites and replaced it with an
#                       Enterprise Admins membership check that warns (but does
#                       not block) when the running account is not an EA. Folded
#                       the retired local helpers (Test-DiskSpace, Test-VssHealth,
#                       Test-IfmMedia, Remove-IfmDirectoryLocal) into the elevated
#                       payloads.
#               5.1.0 - Fixed Test-IfmMedia clean-shutdown check that always
#                       failed: esentutl /mh returns a multi-line string array,
#                       so "-notmatch" filtered elements (always non-empty /
#                       truthy) instead of returning a boolean, aborting every
#                       run after the IFM media was already built. Output is now
#                       collapsed with Out-String and matched as a scalar with a
#                       case-insensitive anchored pattern. Split the single
#                       operator confirmation into two gates via a new
#                       Confirm-Step helper: gate 1 confirms IFM generation +
#                       copy, gate 2 confirms the promotion once IFM is staged on
#                       the target (declining gate 2 cleans up IFM on both hosts).
#               5.0.0 - Full rewrite of the prior local-only 4.6.0 draft to
#                       canonical standards and a remote management model.
#                       The script now runs on UHSVRDC08 and promotes a
#                       remote target via Invoke-Command rather than running
#                       locally on the server being promoted. Added:
#                       VARIABLES region with all config hoisted (SMTP,
#                       MailTo, paths, toggles, DSRM password, $DryRun);
#                       six aligned file+console logging helpers; local IFM
#                       generation via ntdsutil with VSS / disk-space /
#                       clean-shutdown validation (from Generate_IFM.ps1);
#                       robocopy of IFM to the target's C$ admin share with
#                       pre-copy cleanup; remote promotion with secedit
#                       password-policy relax/restore retry (from
#                       Remove_DC_Remote.ps1) so the 8-char UH$197HS DSRM
#                       password is accepted; ReplicationSourceDC pinned to
#                       UHSVRDC08; AD-site auto-detection from the target
#                       IPv4; InfoBlox-aware DNS (CreateDnsDelegation:$false);
#                       controlled remote reboot with WinRM wait; remote
#                       post-reboot health checks; IFM cleanup on both host
#                       and target; color HTML email report. Removed all
#                       backtick line continuations (splatting only) and the
#                       command-line param block (variable-driven instead).
# =====================================================================

# ============================================================
# REGION: VARIABLES
# ============================================================

# ----- Target (SET THIS before running) -----
# Short name or FQDN of the prepped member server to promote to a DC.
$TargetServer = ''

# ----- Replication source -----
# The healthy DC the new DC will replicate from. We replicate from UHSVRDC08
# and the IFM media is generated locally on this same host.
$ReplicationSourceDC = 'UHSVRDC08.uhhs.com'

# ----- Behavior switches -----
$DryRun                    = $true   # $true = log/simulate only, change nothing. SET TO $false TO ACTUALLY PROMOTE.
$RequireConfirmation       = $true   # $true = prompt Y/N before the promotion proceeds
$InstallAddsRoleIfMissing  = $true   # $true = install AD-Domain-Services on the target if it is not present
$InstallDnsRole            = $true   # $true = install the DNS Server role on the new DC (forwards to InfoBlox)
$CreateDnsDelegation       = $false  # $false = do NOT create a DNS delegation (DNS is handled by InfoBlox)
$MakeGlobalCatalog         = $true   # $true = promote as a Global Catalog (environment default)
$CleanupIfmOnSuccess       = $true   # $true = remove C:\IFM from host and target after successful promotion

# ----- Privilege gate (fail-closed startup checks) -----
# This script runs ntdsutil, robocopy of the protected IFM media, and the remote
# promotion. It must be launched in an ELEVATED session (Run as administrator) by
# the SA account. These switches drive Assert-ExecutionPrivileges; both should stay
# $true in production. Leaving them on means the IFM generation and robocopy run
# inline in this elevated session - no UAC pop-up windows and no lost output.
$RequireElevation          = $true   # $true = require a full (elevated) administrator token
$RequireEnterpriseAdmin    = $true   # $true = require the logon account to be in Domain Admins AND Enterprise Admins

# ----- DSRM / Safe Mode Administrator password applied during promotion -----
# UH standard (8 characters). This is shorter than a hardened default-domain
# minimum, so the promotion reactively relaxes the target's local security
# policy (SECURITYPOLICY area), runs the promotion, then restores the original
# policy. Plaintext is acceptable per operator direction (local, ad-hoc use);
# it is converted to a SecureString on the target inside the remote session.
$DsrmPasswordPlain = 'UH$197HS'

# ----- Promotion credential (Kerberos double-hop mitigation) -----
# The remote Install-ADDSDomainController call has to make a second network hop
# from the target back to the forest / replication source DC. Under default
# Kerberos that second hop has no credentials (the classic double-hop), which
# surfaces as "ldap_search() failed ... a successful bind must be completed on the
# connection / insufficient credentials for a remote operation" when the promotion
# reaches it. Elevation does NOT fix this - it is a delegation problem, not a token
# problem. Passing an explicit -Credential makes the promotion authenticate with a
# materialized credential object inside the remote session (a fresh network logon
# on the target) instead of relying on the absent delegated identity.
#
# $UseExplicitPromotionCredential = $true (default) makes the credential MANDATORY:
# it is captured AND validated once, up front, before the long IFM generate/copy,
# so a wrong password or missing rights fails in seconds rather than ~10 minutes in.
# This is the SA account the script is already running as.
#
# $PromotionCredentialUser controls only the user name the prompt is pre-filled
# with. Leave it BLANK to pre-fill with the current (SA) identity - the zero-config
# path: just type your password at the one prompt. Set it (for example 'UHHS\your-sa'
# or 'your-sa@uhhs.com') only to override that default. No password is stored here.
#
# Set $UseExplicitPromotionCredential = $false ONLY to fall back to the session
# identity / default Kerberos (subject to the double-hop) - not recommended.
$UseExplicitPromotionCredential = $true
$PromotionCredentialUser        = ''

# ----- Script-scope state (do not edit) -----
$Script:PrivilegesAsserted = $false   # set once Assert-ExecutionPrivileges passes
$Script:PromotionCredential = $null   # cached PSCredential from Initialize-PromotionCredential

# ----- IFM paths -----
$IfmPath        = 'C:\IFM'                       # IFM directory on the host (UHSVRDC08) and the target
$IfmMinFreeGB   = 10                             # minimum free space required for IFM (host and target)

# ----- Identity / timing -----
$ScriptName    = 'Promote_DC.ps1'
$ScriptVersion = '5.3.0'
$RunStamp      = (Get-Date).ToString('yyyyMMdd_HHmmss')
$FriendlyDate  = (Get-Date).ToString('dddd, MMMM dd, yyyy HH:mm:ss')

# ----- Logging / output paths -----
$LogDirectory  = 'C:\Temp\Logs'
$LogBaseName   = ($ScriptName -replace '\.ps1$', '')
$LogPath       = Join-Path -Path $LogDirectory -ChildPath "$($LogBaseName)_$RunStamp.log"
$RobocopyLog   = Join-Path -Path $LogDirectory -ChildPath "$($LogBaseName)_IFMCopy_$RunStamp.log"

# ----- Reboot / wait tuning -----
$RebootWaitTimeoutMinutes = 20    # how long to wait for the target's WinRM to return after reboot
$RebootPollSeconds        = 20    # interval between WinRM reachability polls

# ----- SMTP / email -----
$SmtpServer = 'smtp.uhhs.com'
$SmtpPort   = 25
$MailFrom   = 'ADAutomation@uhhs.com'
$MailTo     =
@(
    'Alan.Phillips@UHhospitals.org'
    # Additional recipients - remove the leading "#" to re-enable.
    # Note: in @(...) newlines already separate elements, so commas are optional.
    # Leading commas are used here so any subset can be uncommented safely; a
    # trailing comma before ")" would be a syntax error when others are disabled.
    #,'Jeffrey.Altomari@UHhospitals.org'
    #,'Randall.Richards@UHhospitals.org'
    #,'David.Butcher@UHhospitals.org'
)

# ============================================================
# REGION: LOGGING
# ============================================================

function Write-Log
{
    param
    (
        [string]$Text
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "$stamp  $Text"

    try
    {
        Add-Content -Path $LogPath -Value $line -ErrorAction Stop
    }
    catch
    {
        Write-Host "[ERROR] Unable to write log file '${LogPath}': $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Write-InfoMsg
{
    param
    (
        [string]$Message
    )

    Write-Host "[INFO ] $Message" -ForegroundColor Cyan
    Write-Log  "[INFO ] $Message"
}

function Write-SuccessMsg
{
    param
    (
        [string]$Message
    )

    Write-Host "[OK   ] $Message" -ForegroundColor Green
    Write-Log  "[OK   ] $Message"
}

function Write-WarnMsg
{
    param
    (
        [string]$Message
    )

    Write-Host "[WARN ] $Message" -ForegroundColor Yellow
    Write-Log  "[WARN ] $Message"
}

function Write-ErrorMsg
{
    param
    (
        [string]$Message
    )

    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Write-Log  "[ERROR] $Message"
}

function Write-DryRunMsg
{
    param
    (
        [string]$Message
    )

    Write-Host "[DRYRUN] $Message" -ForegroundColor Magenta
    Write-Log  "[DRYRUN] $Message"
}

function Initialize-Logging
{
    if (-not (Test-Path -Path $LogDirectory))
    {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    Write-Log "===== $ScriptName v$ScriptVersion started ($FriendlyDate) ====="
}

# ============================================================
# REGION: PRIVILEGES AND CREDENTIALS
# ============================================================

function Test-IsElevated
{
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-HasRequiredAdminGroups
{
    # Authoritatively determines whether the LOGON ACCOUNT carries Domain Admins (RID 512) and
    # Enterprise Admins (RID 519), independent of the process elevation state. This must NOT read
    # the current process token: UAC token filtering strips high-privilege group SIDs (Domain
    # Admins, Enterprise Admins, local Administrators) from the filtered token of a non-elevated
    # process, so a token-based check returns a FALSE "not a member" for an account that genuinely
    # holds those groups whenever the console was not launched elevated. That false negative is
    # exactly what the earlier privilege model produced. Instead the account's transitive group
    # set is read from Active Directory via the tokenGroups constructed attribute (which expands
    # nested membership exactly as a real logon token would), keyed by the account's own SID (the
    # user SID is never filtered, so it is reliable even unelevated). RIDs are matched rather than
    # names so a renamed or localized group still resolves. A process-token fallback is used only
    # if the directory query cannot be performed, and is flagged as elevation-sensitive.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid  = $identity.User.Value

    $hasDomainAdmins     = $false
    $hasEnterpriseAdmins = $false
    $source              = 'Active Directory (tokenGroups)'

    try
    {
        $account = Get-ADUser -Identity $userSid -Properties tokenGroups -ErrorAction Stop

        foreach ($sid in $account.tokenGroups)
        {
            $value = $sid.Value

            if ($value -match '-512$')
            {
                $hasDomainAdmins = $true
            }

            if ($value -match '-519$')
            {
                $hasEnterpriseAdmins = $true
            }
        }
    }
    catch
    {
        # Directory query failed (account not a user object, RSAT issue, no DC reachable). Fall back
        # to the process token and flag the result as elevation-sensitive: on a non-elevated console
        # the admin group SIDs are filtered out and this fallback can under-report membership.
        Write-WarnMsg "Could not read group membership from Active Directory for SID '$userSid' ($($_.Exception.Message)). Falling back to the process token (elevation-sensitive)."
        $source = 'process token (elevation-sensitive fallback)'

        $sids = New-Object System.Collections.Generic.List[string]

        foreach ($group in $identity.Groups)
        {
            try
            {
                $sids.Add($group.Translate([System.Security.Principal.SecurityIdentifier]).Value)
            }
            catch
            {
                $sids.Add($group.Value)
            }
        }

        $hasDomainAdmins     = [bool]($sids | Where-Object { $_ -match '-512$' })
        $hasEnterpriseAdmins = [bool]($sids | Where-Object { $_ -match '-519$' })
    }

    return [pscustomobject]@{
        HasDomainAdmins     = $hasDomainAdmins
        HasEnterpriseAdmins = $hasEnterpriseAdmins
        Satisfied           = ($hasDomainAdmins -and $hasEnterpriseAdmins)
        Source              = $source
    }
}

function Get-LaunchContext
{
    # Distinguishes "SA IS the interactive desktop logon" from "an SA-token process was launched
    # (RunAs / Run as different user) inside another account's session." The process token user is
    # identical in both cases, so the reliable signal is the OWNER of the interactive desktop
    # (explorer.exe in this session) versus the owner of THIS process. Win32_ComputerSystem.UserName
    # is captured as a corroborating console-session signal and a fallback when no desktop shell is
    # found. Returns LaunchedViaRunAs = $true (secondary logon), $false (interactive), or $null
    # (undetermined - e.g. session 0, Server Core with no shell, or a service/scheduled task).
    $processUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $sessionId   = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $desktopUser = $null

    try
    {
        $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction Stop |
                    Where-Object { $_.SessionId -eq $sessionId } |
                    Select-Object -First 1

        if ($explorer)
        {
            $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction Stop

            if ($owner -and $owner.User)
            {
                $desktopUser = '{0}\{1}' -f $owner.Domain, $owner.User
            }
        }
    }
    catch
    {
        $desktopUser = $null
    }

    $consoleUser = $null

    try
    {
        $consoleUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    }
    catch
    {
        $consoleUser = $null
    }

    if ($desktopUser)
    {
        $launchedViaRunAs = ($desktopUser -ne $processUser)
        $basis            = 'desktop owner (explorer.exe in this session)'
    }
    elseif ($consoleUser)
    {
        $launchedViaRunAs = ($consoleUser -ne $processUser)
        $basis            = 'console session owner (Win32_ComputerSystem)'
    }
    else
    {
        $launchedViaRunAs = $null
        $basis            = 'undetermined (no interactive desktop owner found)'
    }

    return [pscustomobject]@{
        ProcessUser      = $processUser
        DesktopUser      = $desktopUser
        ConsoleUser      = $consoleUser
        SessionId        = $sessionId
        LaunchedViaRunAs = $launchedViaRunAs
        Basis            = $basis
    }
}

function Write-LaunchContextAdvisory
{
    # Emits a single startup advisory describing HOW the elevated session was launched - SA logged
    # on interactively versus an SA-token process started with RunAs / Run as different user inside
    # another account's session - by delegating the detection to Get-LaunchContext. Purely
    # informational: it logs and returns, and never gates execution.
    $ctx             = Get-LaunchContext
    $interactiveUser = if ($ctx.DesktopUser) { $ctx.DesktopUser } else { $ctx.ConsoleUser }

    if ($ctx.LaunchedViaRunAs -eq $true)
    {
        Write-WarnMsg "Launch context: secondary logon detected - process runs as '$($ctx.ProcessUser)' but the interactive desktop belongs to '$interactiveUser'. This is a RunAs / 'Run as different user' launch (basis: $($ctx.Basis))."
    }
    elseif ($ctx.LaunchedViaRunAs -eq $false)
    {
        Write-InfoMsg "Launch context: running interactively as '$($ctx.ProcessUser)' - this account owns the desktop session (basis: $($ctx.Basis))."
    }
    else
    {
        Write-InfoMsg "Launch context: could not be determined for '$($ctx.ProcessUser)' (basis: $($ctx.Basis))."
    }
}

function Write-PromotionCapabilityMsg
{
    # Emits one capability line per privilege check that states, in remote-DC-promotion terms,
    # whether that requirement is satisfied: an [OK   ] line (with the reason it enables the remote
    # promotion) when granted, or an [ERROR] line (with the reason it blocks the remote promotion)
    # when not. Keeps the per-check messaging in Assert-ExecutionPrivileges consistent and free of
    # repetition. Purely informational; the caller still owns the pass/fail decision.
    param
    (
        [bool]$Granted,
        [string]$GrantedMessage,
        [string]$BlockedMessage
    )

    if ($Granted)
    {
        Write-SuccessMsg "  -> Remote DC promotion: $GrantedMessage"
    }
    else
    {
        Write-ErrorMsg "  -> Remote DC promotion: $BlockedMessage"
    }
}

function Assert-ExecutionPrivileges
{
    # Fail-closed startup guard. Verifies (per the configured switches) that the session holds a
    # full elevated token and that the logon account carries Domain Admins and Enterprise Admins.
    # The result is cached for the session so a later call stays quiet after the first success.
    # Replaces the old "this session does not need to be elevated" model: because the session is
    # elevated, ntdsutil and robocopy run inline (no UAC pop-ups), and the elevated full token
    # reports the account's true admin group membership.
    if ($Script:PrivilegesAsserted)
    {
        return $true
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ok       = $true

    Write-InfoMsg "Verifying execution privileges for '$($identity.Name)'."
    Write-LaunchContextAdvisory

    if ($RequireElevation)
    {
        if (Test-IsElevated)
        {
            Write-SuccessMsg "Process is running with an elevated (full) administrator token."
            Write-PromotionCapabilityMsg -Granted $true -GrantedMessage "PERMITTED by this check - the full token lets ntdsutil and the robocopy of the protected IFM media run inline in this session, with no UAC pop-up windows." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Process is NOT elevated. Re-launch PowerShell (or the ISE) with 'Run as administrator' before running this script."
            Write-InfoMsg "Note: a non-elevated token has its Domain Admins / Enterprise Admins / local Administrators SIDs filtered out by UAC. The group-membership check below reads Active Directory directly, so it still reports the account's true membership regardless of elevation."
            Write-PromotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED by this check - without an elevated token ntdsutil and the IFM robocopy cannot read the protected media in-session."
            $ok = $false
        }
    }

    if ($RequireEnterpriseAdmin)
    {
        $groups = Test-HasRequiredAdminGroups

        Write-InfoMsg "Group membership resolved via $($groups.Source)."

        if ($groups.HasDomainAdmins)
        {
            Write-SuccessMsg "Logon account is a member of Domain Admins."
            Write-PromotionCapabilityMsg -Granted $true -GrantedMessage "Domain Admins nests into BUILTIN\Administrators on every domain controller, granting the local administrative rights the operation needs on the host DC." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Logon account is NOT a member of Domain Admins."
            Write-PromotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED - without Domain Admins the account lacks administrative rights on the host DC."
            $ok = $false
        }

        if ($groups.HasEnterpriseAdmins)
        {
            Write-SuccessMsg "Logon account is a member of Enterprise Admins."
            Write-PromotionCapabilityMsg -Granted $true -GrantedMessage "Enterprise Admins authorizes the forest-wide Configuration-partition changes a promotion makes - adding the new server's NTDS Settings and replication objects." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Logon account is NOT a member of Enterprise Admins."
            Write-PromotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED - a promotion edits the forest-wide Configuration partition; without Enterprise Admins those changes will fail."
            $ok = $false
        }
    }

    if ($ok)
    {
        $Script:PrivilegesAsserted = $true
        Write-SuccessMsg "Execution privilege checks passed."
        Write-SuccessMsg "Permission verdict: '$($identity.Name)' has the rights required to promote a remote domain controller (elevation, Domain Admins, and Enterprise Admins all satisfied)."
    }
    else
    {
        Write-ErrorMsg "Execution privilege checks failed - the promotion is blocked for this session."
        Write-ErrorMsg "Permission verdict: '$($identity.Name)' will NOT be able to promote a remote domain controller as currently launched. Resolve the item(s) flagged above - re-launch elevated and/or use an account that is in both Domain Admins and Enterprise Admins."
    }

    return $ok
}

function Get-PromotionCredential
{
    # Returns (and session-caches) the PSCredential threaded into the remote
    # Install-ADDSDomainController -Credential to defeat the WinRM double-hop from the target back
    # to the forest / replication source DC. Prompts once per session. A blank
    # $PromotionCredentialUser pre-fills the prompt with the current (SA) identity - the zero-config
    # path. Returns $null if the operator cancels the prompt.
    if ($Script:PromotionCredential)
    {
        return $Script:PromotionCredential
    }

    if (-not [string]::IsNullOrWhiteSpace($PromotionCredentialUser))
    {
        $userHint = $PromotionCredentialUser
    }
    else
    {
        $userHint = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    }

    Write-InfoMsg "Prompting for the Enterprise Admin credential used for the remote promotion (user hint: '$userHint')."
    $cred = Get-Credential -UserName $userHint -Message 'Enter the Domain/Enterprise Admin credential used to promote the target DC (threaded into Install-ADDSDomainController -Credential to defeat the double-hop).'

    if ($null -eq $cred)
    {
        Write-WarnMsg "Promotion credential prompt was cancelled."
        return $null
    }

    $Script:PromotionCredential = $cred
    Write-SuccessMsg "Promotion credential captured for '$($cred.UserName)' (cached for this session)."
    return $cred
}

function Test-PromotionCredential
{
    # Validates the captured promotion credential UP FRONT, before the long IFM generate and copy,
    # so a wrong password or a non-EA account fails in seconds rather than ~10 minutes in (after the
    # robocopy) the way the v5.3.0 run did. Two checks: (1) the credential must bind to the directory
    # (Get-ADDomain -Credential) - a hard failure if it does not; (2) the credential's own account
    # should carry Domain Admins (RID 512) and Enterprise Admins (RID 519) - a hard failure if the
    # membership is read and the account is NOT an EA, since the promotion would then fail at the
    # forest exam. If the membership read itself errors after a successful bind, that is downgraded
    # to a warning (the bind already proved the credential is usable).
    param
    (
        [pscredential]$Credential
    )

    if ($null -eq $Credential)
    {
        Write-ErrorMsg "No promotion credential to validate."
        return $false
    }

    # ----- 1. Bind test -----
    try
    {
        Get-ADDomain -Credential $Credential -ErrorAction Stop | Out-Null
        Write-SuccessMsg "Promotion credential '$($Credential.UserName)' authenticated to the directory."
    }
    catch
    {
        Write-ErrorMsg "Promotion credential '$($Credential.UserName)' failed to authenticate to the directory: $($_.Exception.Message)"
        return $false
    }

    # ----- 2. Enterprise Admins / Domain Admins membership of the SUPPLIED account -----
    $bareName = $Credential.UserName

    if ($bareName -match '\\')
    {
        $bareName = ($bareName -split '\\')[-1]
    }
    elseif ($bareName -match '@')
    {
        $bareName = ($bareName -split '@')[0]
    }

    try
    {
        $acct = Get-ADUser -Identity $bareName -Properties tokenGroups -Credential $Credential -ErrorAction Stop

        $credHasDa = $false
        $credHasEa = $false

        foreach ($sid in $acct.tokenGroups)
        {
            if ($sid.Value -match '-512$')
            {
                $credHasDa = $true
            }

            if ($sid.Value -match '-519$')
            {
                $credHasEa = $true
            }
        }

        if ($credHasDa -and $credHasEa)
        {
            Write-SuccessMsg "Promotion credential '$($Credential.UserName)' is a member of Domain Admins and Enterprise Admins."
            return $true
        }

        Write-ErrorMsg "Promotion credential '$($Credential.UserName)' is missing the required group(s) - Domain Admins: $credHasDa, Enterprise Admins: $credHasEa. The promotion would fail at the forest examination."
        return $false
    }
    catch
    {
        Write-WarnMsg "Could not confirm Domain Admins / Enterprise Admins membership for '$($Credential.UserName)' ($($_.Exception.Message)). The credential authenticated, so the promotion will proceed, but verify the account is an Enterprise Admin if it is rejected."
        return $true
    }
}

function Initialize-PromotionCredential
{
    # Mandatory, up-front capture and validation of the SA credential threaded into the remote
    # promotion (Install-ADDSDomainController -Credential) to defeat the WinRM double-hop. The
    # script is run AS the SA account, elevated, so the process identity already covers the first
    # WinRM hop and the local elevated tools (ntdsutil, robocopy); this explicit credential exists
    # solely so the target can authenticate ONWARD to the forest during promotion (a delegated
    # token cannot - the double-hop). Captured and validated once here so no prompt interrupts the
    # workflow later and so a bad credential fails before the long IFM generate/copy. Returns $true
    # when a validated credential is captured (or when explicit-credential use is disabled), $false
    # when the prompt is cancelled or validation fails so the caller can abort startup.
    if (-not $UseExplicitPromotionCredential)
    {
        Write-WarnMsg 'Explicit promotion credential is disabled ($UseExplicitPromotionCredential = $false) - the remote promotion will rely on the session token and is subject to the Kerberos double-hop (ldap_search bind failure). Not recommended.'
        return $true
    }

    if ($DryRun)
    {
        Write-DryRunMsg 'Would capture and validate the SA promotion credential up front (skipped in a dry run; no prompt).'
        return $true
    }

    Write-InfoMsg 'Capturing the mandatory SA promotion credential now, as the first step, so no prompt interrupts the workflow later and a bad credential fails before the IFM generate/copy.'
    $cred = Get-PromotionCredential

    if ($null -eq $cred)
    {
        Write-ErrorMsg 'The mandatory SA promotion credential was not provided. It is required to defeat the double-hop on the remote Install-ADDSDomainController. Re-run and supply the credential, or set $UseExplicitPromotionCredential = $false to rely on the session token (accepting the double-hop risk).'
        return $false
    }

    if (-not (Test-PromotionCredential -Credential $cred))
    {
        Write-ErrorMsg 'The promotion credential failed validation (see above). Aborting before any change is made. Re-run with a valid Enterprise Admin credential.'
        $Script:PromotionCredential = $null
        return $false
    }

    return $true
}

# ============================================================
# REGION: EMAIL
# ============================================================

function Get-MailSubject
{
    $datePart = (Get-Date).ToString('MM-dd-yyyy')
    return "$ScriptName - $datePart"
}

function Build-ReportHtml
{
    param
    (
        [hashtable]$TargetInfo,
        [object]$IfmGenResult,
        [object]$IfmCopyResult,
        [object]$PromotionResult,
        [object]$RebootResult,
        [object]$HealthResult,
        [object]$CleanupResult,
        [string]$OverallStatus,
        [string]$StatusColor
    )

    # ----- Target -----
    $siteText = if ($TargetInfo.Site) { $TargetInfo.Site } else { 'Auto / default' }

    # ----- IFM generation -----
    if ($IfmGenResult -and $IfmGenResult.Performed)
    {
        $genText  = if ($IfmGenResult.Success) { 'Generated' } else { 'Failed' }
        $genColor = if ($IfmGenResult.Success) { '#2e7d32' } else { '#c62828' }
    }
    else
    {
        $genText  = 'Not performed'
        $genColor = '#555555'
    }

    $genDetail = if ($IfmGenResult) { $IfmGenResult.Detail } else { 'N/A' }

    # ----- IFM copy -----
    if ($IfmCopyResult -and $IfmCopyResult.Performed)
    {
        $copyText  = if ($IfmCopyResult.Success) { 'Copied to target' } else { 'Failed' }
        $copyColor = if ($IfmCopyResult.Success) { '#2e7d32' } else { '#c62828' }
    }
    else
    {
        $copyText  = 'Not performed'
        $copyColor = '#555555'
    }

    $copyDest   = if ($IfmCopyResult) { $IfmCopyResult.Destination } else { 'N/A' }
    $copyDetail = if ($IfmCopyResult) { $IfmCopyResult.Detail } else { 'N/A' }

    # ----- Promotion -----
    if ($PromotionResult -and $PromotionResult.Attempted)
    {
        $promoText  = if ($PromotionResult.Success) { 'Succeeded' } else { 'Failed' }
        $promoColor = if ($PromotionResult.Success) { '#2e7d32' } else { '#c62828' }
    }
    else
    {
        $promoText  = 'Not attempted'
        $promoColor = '#555555'
    }

    $relaxText = if ($PromotionResult -and $PromotionResult.PolicyRelaxed) { 'Yes (relaxed then restored)' } else { 'No' }
    $dnsText   = if ($PromotionResult -and $PromotionResult.InstallDns) { 'Installed (forwarding to InfoBlox)' } else { 'Not installed' }
    $delegText = 'No delegation created (InfoBlox-managed)'
    $gcText    = if ($PromotionResult -and $PromotionResult.GlobalCatalog) { 'Yes' } else { 'No' }
    $srcText   = if ($PromotionResult) { $PromotionResult.ReplicationSourceDC } else { 'N/A' }
    $credText  = if ($PromotionResult -and $PromotionResult.CredentialUser) { $PromotionResult.CredentialUser } else { 'Session identity (default Kerberos)' }
    $promoErr  = if ($PromotionResult -and $PromotionResult.Error) { $PromotionResult.Error } else { 'None' }

    # ----- Reboot -----
    if ($RebootResult -and $RebootResult.Performed)
    {
        $rebootText  = if ($RebootResult.Success) { 'Rebooted and back online' } else { 'Reboot issue' }
        $rebootColor = if ($RebootResult.Success) { '#2e7d32' } else { '#ef6c00' }
    }
    else
    {
        $rebootText  = 'Not performed'
        $rebootColor = '#555555'
    }

    $rebootDetail = if ($RebootResult) { $RebootResult.Detail } else { 'N/A' }

    # ----- Health -----
    if ($HealthResult -and $HealthResult.Performed)
    {
        $healthText  = if ($HealthResult.AllHealthy) { 'Healthy' } else { 'Completed with warnings' }
        $healthColor = if ($HealthResult.AllHealthy) { '#2e7d32' } else { '#ef6c00' }

        $ntdsText   = if ($HealthResult.Ntds) { 'Running' } else { 'Not running' }
        $dfsrText   = if ($HealthResult.Dfsr) { 'Running' } else { 'Not running' }
        $sysvolText = if ($HealthResult.Sysvol) { 'Shared' } else { 'Missing' }
        $guidText   = if ($HealthResult.GuidDns) { 'Resolved' } else { 'Not resolved' }
        $replText   = if ($HealthResult.ReplClean) { 'Clean' } else { 'Issues reported' }
    }
    else
    {
        $healthText  = 'Not performed'
        $healthColor = '#555555'
        $ntdsText    = 'N/A'
        $dfsrText    = 'N/A'
        $sysvolText  = 'N/A'
        $guidText    = 'N/A'
        $replText    = 'N/A'
    }

    # ----- Cleanup -----
    if ($CleanupResult -and $CleanupResult.Performed)
    {
        $hostClean   = if ($CleanupResult.HostSuccess) { 'Removed' } else { 'Not removed' }
        $hostColor   = if ($CleanupResult.HostSuccess) { '#2e7d32' } else { '#c62828' }
        $targetClean = if ($CleanupResult.TargetSuccess) { 'Removed' } else { 'Not removed' }
        $targetColor = if ($CleanupResult.TargetSuccess) { '#2e7d32' } else { '#c62828' }
    }
    else
    {
        $hostClean   = 'Not performed'
        $hostColor   = '#555555'
        $targetClean = 'Not performed'
        $targetColor = '#555555'
    }

    $cleanupDetail = if ($CleanupResult) { $CleanupResult.Detail } else { 'N/A' }

    $html = @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#222;">
<h2 style="margin-bottom:4px;">Domain Controller Promotion Report</h2>
<p style="margin-top:0;color:#666;">$FriendlyDate &nbsp;|&nbsp; Run from: $($env:COMPUTERNAME)</p>

<p style="font-size:15px;">
Overall status:
<span style="color:$StatusColor;font-weight:bold;">$OverallStatus</span>
</p>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Target Server</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Host name</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.HostName)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Short name</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.ShortName)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">IPv4</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.IPv4)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detected site</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$siteText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Operating system</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.OperatingSystem)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Domain</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.DnsDomain)</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Install From Media (IFM)</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Generation (host)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$genColor;font-weight:bold;">$genText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Generation detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$genDetail</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Copy to target</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$copyColor;font-weight:bold;">$copyText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Destination</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$copyDest</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Copy detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$copyDetail</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Promotion</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Result</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$promoColor;font-weight:bold;">$promoText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Replication source</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$srcText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Promotion credential</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$credText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">DSRM password policy relaxed</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$relaxText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">DNS Server role</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$dnsText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">DNS delegation</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$delegText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Global Catalog</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$gcText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$promoErr</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Reboot and Post-Promotion Health</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Reboot</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$rebootColor;font-weight:bold;">$rebootText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Reboot detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$rebootDetail</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Overall health</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$healthColor;font-weight:bold;">$healthText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">NTDS service</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$ntdsText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">DFSR service</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$dfsrText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">SYSVOL share</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$sysvolText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">GUID CNAME (DNS)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$guidText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Replication summary</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$replText</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">IFM Cleanup</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Host ($($env:COMPUTERNAME))</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$hostColor;font-weight:bold;">$hostClean</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Target ($($TargetInfo.ShortName))</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$targetColor;font-weight:bold;">$targetClean</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$cleanupDetail</td></tr>
</table>

<p style="margin-top:18px;color:#666;">Log file: $LogPath<br/>Robocopy log: $RobocopyLog</p>
</body>
</html>
"@

    return $html
}

function Send-Report
{
    param
    (
        [string]$Html
    )

    $mailParams =
    @{
        From        = $MailFrom
        To          = $MailTo
        Subject     = (Get-MailSubject)
        Body        = $Html
        BodyAsHtml  = $true
        SmtpServer  = $SmtpServer
        Port        = $SmtpPort
        ErrorAction = 'Stop'
    }

    try
    {
        Send-MailMessage @mailParams
        Write-SuccessMsg "Status report emailed to $($MailTo.Count) recipient(s)."
    }
    catch
    {
        Write-ErrorMsg "Failed to send status report: $($_.Exception.Message)"
    }
}

# ============================================================
# REGION: VALIDATION
# ============================================================

function Test-LocalPrerequisites
{
    if ([string]::IsNullOrWhiteSpace($TargetServer))
    {
        Write-ErrorMsg 'Variable $TargetServer is not set. Edit the VARIABLES region and specify the server to promote.'
        return $false
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-InfoMsg "Running as account : $($identity.Name)"

    # Fail-closed gate: require an elevated token AND Domain Admins + Enterprise Admins. The EA/DA
    # membership is read from Active Directory (tokenGroups), not the process token, so it reports
    # true membership regardless of elevation - fixing the prior false "not an Enterprise Admin".
    # Because the session is elevated, ntdsutil and the IFM robocopy run inline (no UAC pop-ups).
    if (-not (Assert-ExecutionPrivileges))
    {
        return $false
    }

    try
    {
        $localCs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        if ($localCs.DomainRole -lt 4)
        {
            Write-ErrorMsg "This host ('$($env:COMPUTERNAME)') is not a Domain Controller. Run from a healthy DC (UHSVRDC08)."
            return $false
        }
    }
    catch
    {
        Write-ErrorMsg "Unable to determine the local machine role: $($_.Exception.Message)"
        return $false
    }

    foreach ($module in @('ActiveDirectory', 'ADDSDeployment'))
    {
        if (-not (Get-Module -ListAvailable -Name $module))
        {
            Write-ErrorMsg "Required module '$module' is not available on this host."
            return $false
        }
    }

    Write-SuccessMsg "Local prerequisites satisfied on '$($env:COMPUTERNAME)'."
    return $true
}

function Test-ReplicationSourceReachable
{
    $sourceShort = ($ReplicationSourceDC -split '\.')[0]

    if (-not (Test-Connection -ComputerName $ReplicationSourceDC -Count 1 -Quiet))
    {
        Write-ErrorMsg "Replication source '$ReplicationSourceDC' is not reachable (ping failed)."
        return $false
    }

    try
    {
        Get-ADDomainController -Identity $sourceShort -ErrorAction Stop | Out-Null
        Write-SuccessMsg "Replication source '$ReplicationSourceDC' is reachable and is a Domain Controller."
        return $true
    }
    catch
    {
        Write-ErrorMsg "Replication source '$ReplicationSourceDC' could not be validated as a DC: $($_.Exception.Message)"
        return $false
    }
}

function Get-TargetInfo
{
    param
    (
        [string]$TargetName
    )

    $resolvedHost = $TargetName
    $shortName    = ($TargetName -split '\.')[0].ToUpperInvariant()

    try
    {
        $dnsRoot = (Get-ADDomain -ErrorAction Stop).DNSRoot
    }
    catch
    {
        $dnsRoot = 'Unknown'
    }

    # Resolve a fully qualified name where possible.
    try
    {
        $entry = [System.Net.Dns]::GetHostEntry($TargetName)

        if ($entry -and -not [string]::IsNullOrWhiteSpace($entry.HostName))
        {
            $resolvedHost = $entry.HostName
        }
    }
    catch
    {
        Write-WarnMsg "Could not fully resolve '$TargetName' via DNS; continuing with the supplied name."
    }

    return @{
        ShortName       = $shortName
        HostName        = $resolvedHost
        IPv4            = 'Pending'
        Site            = $null
        OperatingSystem = 'Pending'
        DnsDomain       = $dnsRoot
    }
}

function Test-TargetReadiness
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($TargetInfo.ShortName -ieq $env:COMPUTERNAME)
    {
        Write-ErrorMsg "The target resolves to the machine running this script. Run from a different DC."
        return $false
    }

    if (-not (Test-Connection -ComputerName $TargetInfo.HostName -Count 1 -Quiet))
    {
        Write-ErrorMsg "Target '$($TargetInfo.HostName)' is not reachable (ping failed)."
        return $false
    }

    try
    {
        Test-WSMan -ComputerName $TargetInfo.HostName -ErrorAction Stop | Out-Null
        Write-SuccessMsg "WinRM reachable on '$($TargetInfo.HostName)'."
    }
    catch
    {
        Write-ErrorMsg "WinRM is not reachable on '$($TargetInfo.HostName)': $($_.Exception.Message)"
        return $false
    }

    $readinessBlock =
    {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
              Select-Object -First 1 -ExpandProperty IPAddress

        $feature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue

        [pscustomobject]@{
            PartOfDomain    = $cs.PartOfDomain
            DomainRole      = $cs.DomainRole
            OperatingSystem = $os.Caption
            IPv4            = $ip
            AddsInstalled   = [bool]($feature -and $feature.Installed)
        }
    }

    try
    {
        $state = Invoke-Command -ComputerName $TargetInfo.HostName -ScriptBlock $readinessBlock -ErrorAction Stop
    }
    catch
    {
        Write-ErrorMsg "Could not query readiness on '$($TargetInfo.HostName)': $($_.Exception.Message)"
        return $false
    }

    $TargetInfo.OperatingSystem = $state.OperatingSystem
    $TargetInfo.IPv4            = $state.IPv4

    if (-not $state.PartOfDomain)
    {
        Write-ErrorMsg "Target '$($TargetInfo.HostName)' is not domain joined."
        return $false
    }

    if ($state.DomainRole -ge 4)
    {
        Write-ErrorMsg "Target '$($TargetInfo.HostName)' is already a Domain Controller."
        return $false
    }

    Write-InfoMsg "Target OS    : $($state.OperatingSystem)"
    Write-InfoMsg "Target IPv4  : $($state.IPv4)"

    if (-not $state.AddsInstalled)
    {
        if (-not $InstallAddsRoleIfMissing)
        {
            Write-ErrorMsg "AD DS role is not installed on the target and InstallAddsRoleIfMissing is disabled."
            return $false
        }

        if ($DryRun)
        {
            Write-DryRunMsg "Would install the AD-Domain-Services role on '$($TargetInfo.HostName)'."
        }
        else
        {
            if (-not (Install-TargetAddsRole -TargetInfo $TargetInfo))
            {
                return $false
            }
        }
    }
    else
    {
        Write-SuccessMsg "AD DS role already present on the target."
    }

    Write-SuccessMsg "Target '$($TargetInfo.HostName)' is prepped and ready for promotion."
    return $true
}

function Install-TargetAddsRole
{
    param
    (
        [hashtable]$TargetInfo
    )

    Write-InfoMsg "Installing the AD-Domain-Services role on '$($TargetInfo.HostName)'."

    $installBlock =
    {
        Import-Module ServerManager -ErrorAction Stop
        $r = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop

        [pscustomobject]@{
            Success      = $r.Success
            ExitCode     = $r.ExitCode
            RestartNeeded = $r.RestartNeeded
        }
    }

    try
    {
        $result = Invoke-Command -ComputerName $TargetInfo.HostName -ScriptBlock $installBlock -ErrorAction Stop

        if ($result.Success)
        {
            Write-SuccessMsg "AD DS role installed on the target (restart needed: $($result.RestartNeeded))."
            return $true
        }

        Write-ErrorMsg "AD DS role install reported failure (exit: $($result.ExitCode))."
        return $false
    }
    catch
    {
        Write-ErrorMsg "Failed to install the AD DS role on the target: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================
# REGION: SITE DETECTION
# ============================================================

function Test-IpInSubnet
{
    param
    (
        [string]$IpAddress,
        [string]$Subnet
    )

    try
    {
        $ipObj  = [System.Net.IPAddress]::Parse($IpAddress)
        $parts  = $Subnet.Split('/')
        $netObj = [System.Net.IPAddress]::Parse($parts[0])
        $prefix = [int]$parts[1]
    }
    catch
    {
        return $false
    }

    $ipBytes  = $ipObj.GetAddressBytes()
    $netBytes = $netObj.GetAddressBytes()

    if ($ipBytes.Length -ne $netBytes.Length)
    {
        return $false
    }

    $maskBits = ('1' * $prefix).PadRight($ipBytes.Length * 8, '0')

    for ($i = 0; $i -lt $ipBytes.Length; $i++)
    {
        $mask = [Convert]::ToInt32($maskBits.Substring($i * 8, 8), 2)

        if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask))
        {
            return $false
        }
    }

    return $true
}

function Get-TargetSite
{
    param
    (
        [hashtable]$TargetInfo
    )

    $ip = $TargetInfo.IPv4

    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq 'Pending')
    {
        Write-WarnMsg "No target IPv4 available; AD site will default during promotion."
        return $null
    }

    try
    {
        $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Site -ErrorAction Stop)
    }
    catch
    {
        Write-WarnMsg "Could not enumerate AD replication subnets: $($_.Exception.Message)"
        return $null
    }

    foreach ($subnet in $subnets)
    {
        if (Test-IpInSubnet -IpAddress $ip -Subnet $subnet.Name)
        {
            if ($subnet.Site)
            {
                $siteName = (Get-ADObject -Identity $subnet.Site -Properties Name -ErrorAction SilentlyContinue).Name

                if ($siteName)
                {
                    Write-SuccessMsg "Target IP $ip maps to AD site '$siteName' (subnet $($subnet.Name))."
                    return $siteName
                }
            }
        }
    }

    Write-WarnMsg "No AD subnet matched target IP $ip; the promotion will use the default site."
    return $null
}

# ============================================================
# REGION: IFM OPERATIONS
# ============================================================

function Test-DiskSpace
{
    param
    (
        [string]$Path,
        [int]$MinimumGB = 10
    )

    $root = [System.IO.Path]::GetPathRoot($Path)

    # UNC path - query the remote host's logical disk via WMI.
    if ($root -match '^\\\\([^\\]+)\\([A-Za-z])\$')
    {
        $remoteHost  = $Matches[1]
        $driveLetter = $Matches[2]

        $wmiParams =
        @{
            Class        = 'Win32_LogicalDisk'
            ComputerName = $remoteHost
            Filter       = "DeviceID='${driveLetter}:'"
            ErrorAction  = 'Stop'
        }

        try
        {
            $disk = Get-WmiObject @wmiParams

            if ($null -eq $disk -or $disk.FreeSpace -lt ($MinimumGB * 1GB))
            {
                Write-ErrorMsg "Insufficient disk space on $remoteHost ${driveLetter}: (requires $MinimumGB GB)."
                return $false
            }
        }
        catch
        {
            Write-ErrorMsg "Unable to query disk space on remote host ${remoteHost}: $($_.Exception.Message)"
            return $false
        }
    }
    else
    {
        $driveLetter = $root.TrimEnd('\').TrimEnd(':')

        try
        {
            $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop

            if ($drive.Free -lt ($MinimumGB * 1GB))
            {
                Write-ErrorMsg "Insufficient disk space on ${driveLetter}: (requires $MinimumGB GB)."
                return $false
            }
        }
        catch
        {
            Write-ErrorMsg "Unable to query local disk space for '${driveLetter}:': $($_.Exception.Message)"
            return $false
        }
    }

    return $true
}

function Test-VssHealth
{
    Write-InfoMsg "Checking VSS writer state on '$($env:COMPUTERNAME)' (this may take a few seconds)..."

    $writers = @()

    & vssadmin list writers 2>&1 | ForEach-Object {
        Write-Log "    vssadmin: $_"
        $writers += $_
    }

    $badWriters = $writers | Where-Object {
        $_ -match 'State:' -and $_ -notmatch 'State:\s+\[1\]\s+Stable'
    }

    if ($badWriters.Count -gt 0)
    {
        Write-WarnMsg "One or more VSS writers are not in a stable state:"

        foreach ($line in $badWriters)
        {
            Write-WarnMsg "    $($line.Trim())"
        }

        return $false
    }

    Write-SuccessMsg "All VSS writers are stable."
    return $true
}

function Test-IfmMedia
{
    param
    (
        [string]$Path
    )

    if (-not (Test-Path -Path $Path))
    {
        Write-ErrorMsg "IFM path '$Path' does not exist."
        return $false
    }

    $ntds   = Join-Path -Path $Path -ChildPath 'Active Directory\ntds.dit'
    $sysvol = Join-Path -Path $Path -ChildPath 'SYSVOL'
    $reg    = Join-Path -Path $Path -ChildPath 'registry\SYSTEM'

    if (-not (Test-Path -Path $ntds))
    {
        Write-ErrorMsg "IFM validation failed: ntds.dit not found at '$ntds'."
        return $false
    }

    if (-not (Test-Path -Path $sysvol))
    {
        Write-ErrorMsg "IFM validation failed: SYSVOL folder not found at '$sysvol'."
        return $false
    }

    if (-not (Test-Path -Path $reg))
    {
        Write-ErrorMsg "IFM validation failed: registry hive not found at '$reg'."
        return $false
    }

    $file = Get-Item -Path $ntds

    if ($file.Length -lt 1MB)
    {
        Write-ErrorMsg "IFM validation failed: ntds.dit is implausibly small ($($file.Length) bytes)."
        return $false
    }

    $headerInfo = & esentutl.exe /mh $ntds 2>$null
    $headerText = ($headerInfo | Out-String)

    if ($headerText -notmatch '(?im)^\s*State:\s+Clean Shutdown')
    {
        Write-WarnMsg "ntds.dit does not report a Clean Shutdown state; review the IFM media before promoting."
        return $false
    }

    Write-SuccessMsg "IFM media validated (ntds.dit present, Clean Shutdown, SYSVOL and registry present)."
    return $true
}

function New-LocalIfm
{
    # Generates IFM locally on the host DC. Runs INLINE in this elevated session - no UAC pop-up
    # window and no self-elevated child process. ntdsutil's per-file output is written to the log
    # file only (Write-Log), not echoed to the console, so the console stays clean; a few summary
    # lines mark progress. This mirrors Generate_IFM.ps1.
    if ($DryRun)
    {
        Write-DryRunMsg "Would generate IFM via ntdsutil into '$IfmPath' on '$($env:COMPUTERNAME)'."
        return [pscustomobject]@{ Performed = $false; Success = $true; Path = $IfmPath; Detail = 'Dry run' }
    }

    if (-not (Test-DiskSpace -Path $IfmPath -MinimumGB $IfmMinFreeGB))
    {
        return [pscustomobject]@{ Performed = $true; Success = $false; Path = $IfmPath; Detail = 'Insufficient disk space on host' }
    }

    if (-not (Test-VssHealth))
    {
        return [pscustomobject]@{ Performed = $true; Success = $false; Path = $IfmPath; Detail = 'VSS writers not stable' }
    }

    # Start from a clean IFM directory so stale media is never reused.
    if (Test-Path -Path $IfmPath)
    {
        Write-InfoMsg "Removing pre-existing IFM directory '$IfmPath' before regeneration."

        if (-not (Remove-IfmDirectoryLocal -Path $IfmPath))
        {
            return [pscustomobject]@{ Performed = $true; Success = $false; Path = $IfmPath; Detail = 'Could not clear existing IFM directory' }
        }
    }

    New-Item -Path $IfmPath -ItemType Directory -Force | Out-Null
    Write-InfoMsg "IFM directory created at '$IfmPath'."

    $startTime = Get-Date
    Write-InfoMsg "Starting IFM generation via ntdsutil at $startTime (per-file detail goes to the log)."

    $createCmd = "create sysvol full nodefrag $IfmPath"
    $output    = & ntdsutil 'activate instance ntds' 'ifm' $createCmd 'quit' 'quit'

    $detectedError = $false

    foreach ($line in $output)
    {
        Write-Log "    ntdsutil: $line"

        # Console progress markers only - the full stream is in the log.
        if ($line -match '(?i)snapshot')
        {
            Write-InfoMsg "Creating VSS snapshot..."
        }
        elseif ($line -match '(?i)Copying NTDS')
        {
            Write-InfoMsg "Copying NTDS database..."
        }
        elseif ($line -match '(?i)Copying SYSVOL')
        {
            Write-InfoMsg "Copying SYSVOL..."
        }

        if ($line -match '(?i)(^error\s+\d+$)' -or
            $line -match '(?i)failed\s+with\s+error' -or
            $line -match '(?i)access\s+is\s+denied' -or
            $line -match '(?i)insufficient\s+disk\s+space')
        {
            $detectedError = $true
        }
    }

    if ($detectedError)
    {
        Write-WarnMsg "ntdsutil reported potential issues during IFM creation; review the log."
    }

    $duration = New-TimeSpan -Start $startTime -End (Get-Date)

    if (-not (Test-IfmMedia -Path $IfmPath))
    {
        return [pscustomobject]@{ Performed = $true; Success = $false; Path = $IfmPath; Detail = 'IFM media validation failed after ntdsutil' }
    }

    $detail = "Generated in {0:hh\:mm\:ss}" -f $duration
    Write-SuccessMsg "IFM generation completed ($detail)."

    return [pscustomobject]@{ Performed = $true; Success = $true; Path = $IfmPath; Detail = $detail }
}

function Write-RobocopySummary
{
    # Extracts and color-codes the trailing summary block (Dirs / Files / Bytes / Times / Ended)
    # from a robocopy log, so the operator sees a clear completion summary in the console instead
    # of a silent run. Mirrors Generate_IFM.ps1.
    param
    (
        [string]$LogFile
    )

    if (-not (Test-Path -Path $LogFile))
    {
        return
    }

    $summary = Get-Content -Path $LogFile -Tail 50 | Where-Object {
        $_ -match 'Dirs\s*:|Files\s*:|Bytes\s*:|Times\s*:|Ended\s*:'
    }

    if (-not $summary)
    {
        return
    }

    Write-Host ""
    Write-InfoMsg "Robocopy Summary:"

    foreach ($line in $summary)
    {
        if ($line -match 'Files|Bytes')
        {
            Write-Host "  $line" -ForegroundColor Green
        }
        elseif ($line -match 'Dirs|Times|Ended')
        {
            Write-Host "  $line" -ForegroundColor Cyan
        }
        else
        {
            Write-Host "  $line"
        }
    }

    Write-Host ""
}

function Copy-IfmToTarget
{
    # Copies the generated IFM media to the target's C$ admin share. Runs INLINE in this elevated
    # session - no UAC pop-up window. Robocopy's per-file output is sent to its own log; the
    # completion summary is pulled from that log and shown in the console.
    param
    (
        [hashtable]$TargetInfo
    )

    $destShare = "\\$($TargetInfo.HostName)\C$"
    $destPath  = "\\$($TargetInfo.HostName)\C$\IFM"

    if ($DryRun)
    {
        Write-DryRunMsg "Would robocopy '$IfmPath' to '$destPath'."
        return [pscustomobject]@{ Performed = $false; Success = $true; Destination = $destPath; Detail = 'Dry run' }
    }

    if (-not (Test-Path -Path $IfmPath))
    {
        Write-ErrorMsg "Source IFM path missing: $IfmPath"
        return [pscustomobject]@{ Performed = $true; Success = $false; Destination = $destPath; Detail = 'Source IFM path missing' }
    }

    if (-not (Test-Path -Path $destShare))
    {
        Write-ErrorMsg "Destination administrative share unavailable: $destShare"
        return [pscustomobject]@{ Performed = $true; Success = $false; Destination = $destPath; Detail = 'Admin share unavailable' }
    }

    if (-not (Test-DiskSpace -Path "$destShare\" -MinimumGB $IfmMinFreeGB))
    {
        return [pscustomobject]@{ Performed = $true; Success = $false; Destination = $destPath; Detail = 'Insufficient disk space on target' }
    }

    # Clear any stale IFM on the target before copying fresh media.
    Write-InfoMsg "Clearing any existing IFM on the target before copy."

    if (-not (Remove-IfmDirectory -ComputerName $TargetInfo.HostName))
    {
        Write-ErrorMsg "Pre-copy cleanup failed on '$($TargetInfo.HostName)'; aborting copy."
        return [pscustomobject]@{ Performed = $true; Success = $false; Destination = $destPath; Detail = 'Pre-copy cleanup failed' }
    }

    $startTime = Get-Date
    Write-InfoMsg "Robocopy starting at $startTime."
    Write-InfoMsg "Robocopy log: $RobocopyLog"

    $roboArgs =
    @(
        $IfmPath
        $destPath
        '/E'
        '/COPYALL'
        '/DCOPY:DAT'
        '/R:1'
        '/W:1'
        "/LOG:$RobocopyLog"
    )

    & robocopy @roboArgs | Out-Null
    $exitCode = $LASTEXITCODE

    $duration = New-TimeSpan -Start $startTime -End (Get-Date)
    Write-Log "    Robocopy exit code: $exitCode"

    Write-RobocopySummary -LogFile $RobocopyLog

    if ($exitCode -gt 7)
    {
        Write-ErrorMsg "Robocopy failed with exit code $exitCode."
        return [pscustomobject]@{ Performed = $true; Success = $false; Destination = $destPath; Detail = "Robocopy exit $exitCode" }
    }
    elseif ($exitCode -eq 0)
    {
        Write-InfoMsg "Robocopy reported no files copied (already up to date)."
    }
    elseif ($exitCode -eq 1)
    {
        Write-SuccessMsg "Robocopy copied all files successfully."
    }
    else
    {
        Write-WarnMsg "Robocopy completed with warnings (exit code $exitCode)."
    }

    $detail = "Robocopy exit $exitCode in {0:hh\:mm\:ss}" -f $duration
    Write-SuccessMsg "IFM copy to target completed ($detail)."

    return [pscustomobject]@{ Performed = $true; Success = $true; Destination = $destPath; Detail = $detail }
}

# ============================================================
# REGION: PROMOTION
# ============================================================

function Invoke-RemotePromotion
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$SiteName
    )

    if ($DryRun)
    {
        if (-not $UseExplicitPromotionCredential)
        {
            $dryCredText = 'Session identity (default Kerberos; explicit credential disabled)'
        }
        elseif ([string]::IsNullOrWhiteSpace($PromotionCredentialUser))
        {
            $dryCredText = 'Current SA identity (would prompt up front)'
        }
        else
        {
            $dryCredText = "$PromotionCredentialUser (would prompt up front)"
        }

        Write-DryRunMsg "Would remotely promote '$($TargetInfo.HostName)' via Install-ADDSDomainController (IFM: $IfmPath, source: $ReplicationSourceDC, site: $SiteName, credential: $dryCredText)."
        return [pscustomobject]@{
            Attempted           = $false
            Success             = $true
            PolicyRelaxed       = $false
            InstallDns          = $InstallDnsRole
            GlobalCatalog       = $MakeGlobalCatalog
            ReplicationSourceDC = $ReplicationSourceDC
            SiteName            = $SiteName
            CredentialUser      = $dryCredText
            Error               = 'Dry run'
        }
    }

    # The promotion credential was captured AND validated up front by
    # Initialize-PromotionCredential (cached in $Script:PromotionCredential), so no prompt
    # interrupts the workflow here and a bad credential has already aborted before the IFM work.
    $promotionCred = $Script:PromotionCredential
    $credUserText  = if ($null -ne $promotionCred) { $promotionCred.UserName } else { 'Session identity (default Kerberos)' }

    $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot

    $promoteBlock =
    {
        param
        (
            [string]$DsrmPasswordPlain,
            [string]$DomainName,
            [string]$IfmPath,
            [string]$ReplicationSourceDC,
            [string]$SiteName,
            [bool]$InstallDnsRole,
            [bool]$CreateDnsDelegation,
            [bool]$MakeGlobalCatalog,
            [pscredential]$PromotionCredential
        )

        Import-Module ADDSDeployment -ErrorAction Stop

        $securePwd     = ConvertTo-SecureString -String $DsrmPasswordPlain -AsPlainText -Force
        $policyRelaxed = $false
        $errText       = $null
        $ok            = $false

        $workDir = Join-Path -Path $env:TEMP -ChildPath 'DCPromote'
        if (-not (Test-Path -Path $workDir))
        {
            New-Item -Path $workDir -ItemType Directory -Force | Out-Null
        }

        $secBackupInf = Join-Path -Path $workDir -ChildPath 'sec_backup.inf'
        $secWorkInf   = Join-Path -Path $workDir -ChildPath 'sec_work.inf'
        $secDb        = Join-Path -Path $workDir -ChildPath 'sec_work.sdb'

        function Backup-SecurityPolicy
        {
            $exportArgs =
            @(
                '/export'
                '/cfg'
                $secBackupInf
                '/quiet'
            )

            & secedit @exportArgs | Out-Null
        }

        function Relax-SecurityPolicy
        {
            Copy-Item -Path $secBackupInf -Destination $secWorkInf -Force

            $lines = Get-Content -Path $secWorkInf | ForEach-Object {
                $_ -replace 'MinimumPasswordLength\s*=.*', 'MinimumPasswordLength = 0' -replace 'PasswordComplexity\s*=.*', 'PasswordComplexity = 0'
            }

            Set-Content -Path $secWorkInf -Value $lines -Force

            $configArgs =
            @(
                '/configure'
                '/db'
                $secDb
                '/cfg'
                $secWorkInf
                '/areas'
                'SECURITYPOLICY'
                '/quiet'
            )

            & secedit @configArgs | Out-Null
        }

        function Restore-SecurityPolicy
        {
            $restoreArgs =
            @(
                '/configure'
                '/db'
                $secDb
                '/cfg'
                $secBackupInf
                '/areas'
                'SECURITYPOLICY'
                '/quiet'
            )

            & secedit @restoreArgs | Out-Null
        }

        $baseParams =
        @{
            DomainName                    = $DomainName
            InstallationMediaPath         = $IfmPath
            ReplicationSourceDC           = $ReplicationSourceDC
            SafeModeAdministratorPassword = $securePwd
            InstallDns                    = $InstallDnsRole
            CreateDnsDelegation           = $CreateDnsDelegation
            NoGlobalCatalog               = (-not $MakeGlobalCatalog)
            NoRebootOnCompletion          = $true
            Force                         = $true
            Confirm                       = $false
            ErrorAction                   = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($SiteName))
        {
            $baseParams['SiteName'] = $SiteName
        }

        if ($null -ne $PromotionCredential)
        {
            $baseParams['Credential'] = $PromotionCredential
        }

        $maxAttempts = 3
        $attempt     = 0

        try
        {
            while ($true)
            {
                $attempt++

                if ($attempt -gt $maxAttempts)
                {
                    $errText = "Exceeded maximum promotion attempts ($maxAttempts). Last error: $errText"
                    break
                }

                try
                {
                    Install-ADDSDomainController @baseParams
                    $ok = $true
                    break
                }
                catch
                {
                    $msg     = $_.Exception.Message
                    $errText = $msg

                    if ($msg -match 'password|complex' -and -not $policyRelaxed)
                    {
                        Backup-SecurityPolicy
                        Relax-SecurityPolicy
                        $policyRelaxed = $true
                        continue
                    }

                    break
                }
            }
        }
        finally
        {
            if ($policyRelaxed)
            {
                Restore-SecurityPolicy
            }
        }

        return [pscustomobject]@{
            Attempted     = $true
            Success       = $ok
            PolicyRelaxed = $policyRelaxed
            Error         = $errText
        }
    }

    $icmParams =
    @{
        ComputerName = $TargetInfo.HostName
        ScriptBlock  = $promoteBlock
        ArgumentList = @(
            $DsrmPasswordPlain
            $domainName
            $IfmPath
            $ReplicationSourceDC
            $SiteName
            $InstallDnsRole
            $CreateDnsDelegation
            $MakeGlobalCatalog
            $promotionCred
        )
        ErrorAction  = 'Stop'
    }

    try
    {
        $result = Invoke-Command @icmParams

        if ($result.Success)
        {
            Write-SuccessMsg "Remote promotion configuration completed on '$($TargetInfo.HostName)'."

            if ($result.PolicyRelaxed)
            {
                Write-WarnMsg "Local password policy was temporarily relaxed on the target and then restored (DSRM password length)."
            }
        }
        else
        {
            Write-ErrorMsg "Remote promotion failed on '$($TargetInfo.HostName)': $($result.Error)"
        }

        return [pscustomobject]@{
            Attempted           = $result.Attempted
            Success             = $result.Success
            PolicyRelaxed       = $result.PolicyRelaxed
            InstallDns          = $InstallDnsRole
            GlobalCatalog       = $MakeGlobalCatalog
            ReplicationSourceDC = $ReplicationSourceDC
            SiteName            = $SiteName
            CredentialUser      = $credUserText
            Error               = $result.Error
        }
    }
    catch
    {
        Write-ErrorMsg "Remote promotion invocation failed: $($_.Exception.Message)"
        return [pscustomobject]@{
            Attempted           = $true
            Success             = $false
            PolicyRelaxed       = $false
            InstallDns          = $InstallDnsRole
            GlobalCatalog       = $MakeGlobalCatalog
            ReplicationSourceDC = $ReplicationSourceDC
            SiteName            = $SiteName
            CredentialUser      = $credUserText
            Error               = $_.Exception.Message
        }
    }
}

# ============================================================
# REGION: REBOOT AND HEALTH
# ============================================================

function Restart-TargetAndWait
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would reboot '$($TargetInfo.HostName)' and wait for WinRM to return."
        return [pscustomobject]@{ Performed = $false; Success = $true; Detail = 'Dry run' }
    }

    try
    {
        Restart-Computer -ComputerName $TargetInfo.HostName -Force -ErrorAction Stop
        Write-SuccessMsg "Reboot issued to '$($TargetInfo.HostName)' to complete promotion."
    }
    catch
    {
        Write-ErrorMsg "Could not reboot '$($TargetInfo.HostName)': $($_.Exception.Message)"
        return [pscustomobject]@{ Performed = $true; Success = $false; Detail = "Reboot command failed: $($_.Exception.Message)" }
    }

    Write-InfoMsg "Waiting for '$($TargetInfo.HostName)' to go down and return (timeout: $RebootWaitTimeoutMinutes min)."

    # Give the host a moment to actually begin shutting down before we poll.
    Start-Sleep -Seconds 30

    $deadline = (Get-Date).AddMinutes($RebootWaitTimeoutMinutes)
    $online   = $false

    while ((Get-Date) -lt $deadline)
    {
        Start-Sleep -Seconds $RebootPollSeconds

        try
        {
            Test-WSMan -ComputerName $TargetInfo.HostName -ErrorAction Stop | Out-Null
            $online = $true
            break
        }
        catch
        {
            Write-InfoMsg "Target not yet responding to WinRM; continuing to wait..."
        }
    }

    if (-not $online)
    {
        Write-ErrorMsg "Target '$($TargetInfo.HostName)' did not return to WinRM within $RebootWaitTimeoutMinutes minutes."
        return [pscustomobject]@{ Performed = $true; Success = $false; Detail = "WinRM did not return within $RebootWaitTimeoutMinutes min" }
    }

    # Allow AD DS services to finish starting after the reboot.
    Start-Sleep -Seconds 30
    Write-SuccessMsg "Target '$($TargetInfo.HostName)' is back online (WinRM reachable)."

    return [pscustomobject]@{ Performed = $true; Success = $true; Detail = 'Rebooted and WinRM reachable' }
}

function Test-PromotionHealth
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would run post-reboot health checks on '$($TargetInfo.HostName)'."
        return [pscustomobject]@{
            Performed  = $false
            AllHealthy = $true
            Ntds       = $true
            Dfsr       = $true
            Sysvol     = $true
            GuidDns    = $true
            ReplClean  = $true
            Detail     = 'Dry run'
        }
    }

    Write-InfoMsg "Running post-reboot health checks on '$($TargetInfo.HostName)'."

    $healthBlock =
    {
        $cs    = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $ntds  = Get-Service -Name NTDS -ErrorAction SilentlyContinue
        $dfsr  = Get-Service -Name DFSR -ErrorAction SilentlyContinue
        $share = Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue

        [pscustomobject]@{
            IsDC        = ($cs.DomainRole -ge 4)
            NtdsRunning = ($ntds -and $ntds.Status -eq 'Running')
            DfsrRunning = ($dfsr -and $dfsr.Status -eq 'Running')
            SysvolShare = [bool]$share
        }
    }

    try
    {
        $state = Invoke-Command -ComputerName $TargetInfo.HostName -ScriptBlock $healthBlock -ErrorAction Stop
    }
    catch
    {
        Write-ErrorMsg "Could not run remote health checks: $($_.Exception.Message)"
        return [pscustomobject]@{
            Performed  = $true
            AllHealthy = $false
            Ntds       = $false
            Dfsr       = $false
            Sysvol     = $false
            GuidDns    = $false
            ReplClean  = $false
            Detail     = "Remote health query failed: $($_.Exception.Message)"
        }
    }

    if ($state.IsDC) { Write-SuccessMsg "Target reports Domain Controller role." } else { Write-ErrorMsg "Target is not reporting the Domain Controller role." }
    if ($state.NtdsRunning) { Write-SuccessMsg "NTDS service is running." } else { Write-ErrorMsg "NTDS service is not running." }
    if ($state.DfsrRunning) { Write-SuccessMsg "DFSR service is running." } else { Write-WarnMsg "DFSR service is not running yet." }
    if ($state.SysvolShare) { Write-SuccessMsg "SYSVOL share is present." } else { Write-ErrorMsg "SYSVOL share is not present." }

    # ----- GUID CNAME (DNS) validation, resolved from this host -----
    $guidOk = $false

    try
    {
        $newDc      = Get-ADDomainController -Identity $TargetInfo.ShortName -Server $ReplicationSourceDC -ErrorAction Stop
        $guid       = $newDc.InvocationId
        $domainName = $TargetInfo.DnsDomain
        $guidRecord = "$guid._msdcs.$domainName"

        for ($i = 1; $i -le 5; $i++)
        {
            $check = Resolve-DnsName -Name $guidRecord -ErrorAction SilentlyContinue

            if ($check)
            {
                $guidOk = $true
                break
            }

            Start-Sleep -Seconds 5
        }

        if ($guidOk)
        {
            Write-SuccessMsg "GUID CNAME record resolved: $guidRecord"
        }
        else
        {
            Write-WarnMsg "GUID CNAME record did not resolve ($guidRecord); InfoBlox may still be converging."
        }
    }
    catch
    {
        Write-WarnMsg "Could not validate the GUID CNAME record: $($_.Exception.Message)"
    }

    # ----- Replication summary from the host -----
    $replClean = $false

    try
    {
        $repl = & repadmin /replsummary 2>&1
        foreach ($line in $repl) { Write-Log "    repadmin: $line" }

        if ($repl -match '(?i)fail|error')
        {
            Write-WarnMsg "Replication summary reported potential issues; review the log."
        }
        else
        {
            Write-SuccessMsg "Replication summary is clean."
            $replClean = $true
        }
    }
    catch
    {
        Write-WarnMsg "Could not capture replication summary: $($_.Exception.Message)"
    }

    $allHealthy = ($state.IsDC -and $state.NtdsRunning -and $state.SysvolShare -and $guidOk -and $replClean)

    return [pscustomobject]@{
        Performed  = $true
        AllHealthy = $allHealthy
        Ntds       = $state.NtdsRunning
        Dfsr       = $state.DfsrRunning
        Sysvol     = $state.SysvolShare
        GuidDns    = $guidOk
        ReplClean  = $replClean
        Detail     = "IsDC=$($state.IsDC); NTDS=$($state.NtdsRunning); DFSR=$($state.DfsrRunning); SYSVOL=$($state.SysvolShare)"
    }
}

# ============================================================
# REGION: CLEANUP
# ============================================================

function Remove-IfmDirectoryLocal
{
    param
    (
        [string]$Path
    )

    $expectedPath = 'C:\IFM'

    if ($Path -ne $expectedPath)
    {
        Write-ErrorMsg "Local IFM cleanup refused: path '$Path' is not the expected '$expectedPath'."
        return $false
    }

    if (-not (Test-Path -Path $expectedPath))
    {
        Write-InfoMsg "Local IFM directory not present - nothing to clean."
        return $true
    }

    Write-InfoMsg "Removing local IFM directory '$expectedPath' (inline; this session is elevated)."

    try
    {
        & takeown.exe /F $expectedPath /R /D Y *> $null
        & icacls.exe $expectedPath /reset /T /C *> $null
        Remove-Item -Path $expectedPath -Recurse -Force -Confirm:$false -ErrorAction Stop
    }
    catch
    {
        Write-ErrorMsg "Local IFM cleanup failed: $($_.Exception.Message)"
        return $false
    }

    Write-SuccessMsg "Local IFM directory removed from '$($env:COMPUTERNAME)'."
    return $true
}

function Remove-IfmDirectory
{
    param
    (
        [string]$ComputerName
    )

    $cleanupBlock =
    {
        $ErrorActionPreference = 'Stop'
        $expectedPath          = 'C:\IFM'

        if (-not (Test-Path -Path $expectedPath))
        {
            return 'IFM directory not present - nothing to clean.'
        }

        $resolved = (Resolve-Path -Path $expectedPath -ErrorAction Stop).Path

        if ($resolved -ne $expectedPath)
        {
            throw "Path resolved unexpectedly to '$resolved' - aborting cleanup."
        }

        & takeown.exe /F $expectedPath /R /D Y *> $null
        & icacls.exe $expectedPath /reset /T /C *> $null

        Remove-Item -Path $expectedPath -Recurse -Force -Confirm:$false -ErrorAction Stop

        return 'IFM directory removed successfully.'
    }

    try
    {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $cleanupBlock -ErrorAction Stop
        Write-SuccessMsg "[$ComputerName] $result"
        return $true
    }
    catch
    {
        Write-ErrorMsg "Cleanup failed on ${ComputerName}: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-IfmCleanup
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would remove IFM directory '$IfmPath' from host '$($env:COMPUTERNAME)' and target '$($TargetInfo.HostName)'."
        return [pscustomobject]@{ Performed = $false; HostSuccess = $true; TargetSuccess = $true; Detail = 'Dry run' }
    }

    Write-InfoMsg "Cleaning up IFM directories from host and target."

    $hostOk   = Remove-IfmDirectoryLocal -Path $IfmPath
    $targetOk = Remove-IfmDirectory -ComputerName $TargetInfo.HostName

    $detail = "Host removed=$hostOk; Target removed=$targetOk"

    return [pscustomobject]@{ Performed = $true; HostSuccess = $hostOk; TargetSuccess = $targetOk; Detail = $detail }
}

# ============================================================
# REGION: WORKFLOW
# ============================================================

function Get-OverallStatus
{
    param
    (
        [object]$PromotionResult,
        [object]$HealthResult,
        [object]$CleanupResult
    )

    if (-not ($PromotionResult -and $PromotionResult.Attempted))
    {
        if ($DryRun)
        {
            return [pscustomobject]@{ Text = 'Dry run - no changes made'; Color = '#1565c0' }
        }

        return [pscustomobject]@{ Text = 'Promotion not attempted'; Color = '#c62828' }
    }

    if (-not $PromotionResult.Success)
    {
        return [pscustomobject]@{ Text = 'Promotion FAILED'; Color = '#c62828' }
    }

    if ($HealthResult -and $HealthResult.Performed -and -not $HealthResult.AllHealthy)
    {
        return [pscustomobject]@{ Text = 'Promoted - health checks reported warnings'; Color = '#ef6c00' }
    }

    if ($CleanupResult -and $CleanupResult.Performed -and
        (-not $CleanupResult.HostSuccess -or -not $CleanupResult.TargetSuccess))
    {
        return [pscustomobject]@{ Text = 'Promoted and healthy - IFM cleanup had warnings'; Color = '#ef6c00' }
    }

    return [pscustomobject]@{ Text = 'Promotion succeeded - DC healthy'; Color = '#2e7d32' }
}

function Confirm-Step
{
    param
    (
        [string]$Title,
        [string[]]$Detail
    )

    if ($DryRun -or -not $RequireConfirmation)
    {
        return $true
    }

    Write-Host ""
    Write-Host $Title -ForegroundColor Yellow

    foreach ($line in $Detail)
    {
        Write-Host "  $line" -ForegroundColor Yellow
    }

    Write-Host "Proceed? (Y/N): " -ForegroundColor Yellow -NoNewline

    $answer = Read-Host

    return ($answer.ToUpperInvariant() -eq 'Y')
}

function Invoke-PromotionWorkflow
{
    # ----- Result placeholders so the report always renders -----
    $ifmGenResult   = $null
    $ifmCopyResult  = $null
    $promotionResult = $null
    $rebootResult   = $null
    $healthResult   = $null
    $cleanupResult  = $null

    $targetInfo = Get-TargetInfo -TargetName $TargetServer

    Write-InfoMsg "Promotion target : $($targetInfo.HostName)"
    Write-InfoMsg "Replication source: $ReplicationSourceDC"
    Write-InfoMsg "IFM path          : $IfmPath"

    if (-not (Test-LocalPrerequisites))
    {
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # Capture and validate the SA promotion credential now - before the long IFM generate/copy -
    # so a wrong password or a non-EA account fails in seconds rather than ~10 minutes in. This is
    # the credential threaded into Install-ADDSDomainController -Credential to defeat the double-hop.
    if (-not (Initialize-PromotionCredential))
    {
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    if (-not (Test-ReplicationSourceReachable))
    {
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    if (-not (Test-TargetReadiness -TargetInfo $targetInfo))
    {
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    $targetInfo.Site = Get-TargetSite -TargetInfo $targetInfo

    # ----- Gate 1: confirm IFM generation + copy -----
    $ifmDetail =
    @(
        "Target             : $($targetInfo.HostName)"
        "Replication source : $ReplicationSourceDC"
        "IFM path           : $IfmPath (host and target)"
    )

    if (-not (Confirm-Step -Title "About to generate IFM locally and copy it to the target" -Detail $ifmDetail))
    {
        Write-WarnMsg "Operation cancelled by operator before IFM generation."
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- IFM generate + copy -----
    $ifmGenResult = New-LocalIfm

    if (-not $ifmGenResult.Success)
    {
        Write-ErrorMsg "IFM generation failed; aborting before copy and promotion."
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    $ifmCopyResult = Copy-IfmToTarget -TargetInfo $targetInfo

    if (-not $ifmCopyResult.Success)
    {
        Write-ErrorMsg "IFM copy failed; aborting before promotion. Cleaning up host IFM."
        $cleanupResult = Invoke-IfmCleanup -TargetInfo $targetInfo
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- Gate 2: confirm promotion now that IFM is staged on the target -----
    $promoDetail =
    @(
        "Target             : $($targetInfo.HostName)"
        "Replication source : $ReplicationSourceDC"
        "AD site            : $(if ($targetInfo.Site) { $targetInfo.Site } else { 'default' })"
        "Install DNS role   : $InstallDnsRole (delegation: $CreateDnsDelegation)"
        "Global Catalog     : $MakeGlobalCatalog"
    )

    if (-not (Confirm-Step -Title "IFM is staged on '$($targetInfo.HostName)'. Continue with the DC promotion?" -Detail $promoDetail))
    {
        Write-WarnMsg "Promotion cancelled by operator after IFM copy. Cleaning up host and target IFM."
        $cleanupResult = Invoke-IfmCleanup -TargetInfo $targetInfo
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- Promotion -----
    $promotionResult = Invoke-RemotePromotion -TargetInfo $targetInfo -SiteName $targetInfo.Site

    if (-not $promotionResult.Success)
    {
        Write-ErrorMsg "Promotion failed; leaving IFM in place for troubleshooting."
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- Reboot + health -----
    $rebootResult = Restart-TargetAndWait -TargetInfo $targetInfo

    if ($rebootResult.Success)
    {
        $healthResult = Test-PromotionHealth -TargetInfo $targetInfo
    }
    else
    {
        Write-WarnMsg "Skipping health checks because the target did not come back online; leaving IFM in place."
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- Cleanup IFM on both servers (only after a successful, healthy promotion) -----
    if ($CleanupIfmOnSuccess)
    {
        if ($healthResult.AllHealthy)
        {
            $cleanupResult = Invoke-IfmCleanup -TargetInfo $targetInfo
        }
        else
        {
            Write-WarnMsg "Health checks reported warnings; leaving IFM directories in place for review."
        }
    }
    else
    {
        Write-InfoMsg "CleanupIfmOnSuccess is disabled; IFM directories left in place."
    }

    $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
    Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
}

function Send-FinalReport
{
    param
    (
        [hashtable]$TargetInfo,
        [object]$IfmGenResult,
        [object]$IfmCopyResult,
        [object]$PromotionResult,
        [object]$RebootResult,
        [object]$HealthResult,
        [object]$CleanupResult,
        [object]$Status
    )

    $reportParams =
    @{
        TargetInfo      = $TargetInfo
        IfmGenResult    = $IfmGenResult
        IfmCopyResult   = $IfmCopyResult
        PromotionResult = $PromotionResult
        RebootResult    = $RebootResult
        HealthResult    = $HealthResult
        CleanupResult   = $CleanupResult
        OverallStatus   = $Status.Text
        StatusColor     = $Status.Color
    }

    $reportHtml = Build-ReportHtml @reportParams
    Send-Report -Html $reportHtml
}

# ============================================================
# REGION: ENTRY POINT
# ============================================================

Initialize-Logging

try
{
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch
{
    Write-ErrorMsg "Could not import the ActiveDirectory module: $($_.Exception.Message)"
    return
}

if ($DryRun)
{
    Write-DryRunMsg 'DRY RUN enabled - no changes will be made. Set $DryRun = $false in the VARIABLES region to promote for real.'
}

Invoke-PromotionWorkflow

Write-Log "===== $ScriptName v$ScriptVersion run ended ====="
