# =====================================================================
# Script      : Demote_DC.ps1
#
# Author      : Alan W. Phillips
# Date        : 06/17/2026
# Version     : 5.9.6
#
# Description : Interactive, menu-driven tool to remotely demote and fully
#               decommission an existing Active Directory Domain Controller
#               from a separate management DC (intended to run locally on
#               UHSVRDC08, a Windows Server 2022 Datacenter (Desktop
#               Experience) DC). A shared session
#               state object lets every menu choice see what earlier choices
#               produced - notably, metadata cleanup uses the replication
#               partners captured (or re-loaded from the saved CSV) for the
#               demoted DC. Capabilities: target resolution, replication-
#               partner inventory with CSV persistence, FSMO/pre-flight
#               validation, remote demotion (graceful with reactive password-
#               policy relaxation, GC clear, and forced-removal fallback),
#               site-verified ntdsutil metadata cleanup against a surviving
#               partner, silent repadmin /syncall, computer-account removal,
#               reboot, a full automated workflow, and a color HTML email
#               report. Individual steps are also runnable on their own.
#
# Requirements:
#               - Run locally on a healthy Domain Controller (UHSVRDC08)
#               - Domain Admin / Enterprise Admin privileges
#               - Launched from an ELEVATED console (verified at startup; fails closed)
#               - Windows PowerShell console, not ISE (ntdsutil self-elevates to its own console)
#               - PowerShell 5.1
#               - ActiveDirectory and ADDSDeployment modules
#               - WinRM reachable on the target DC
#               - Windows Server 2012 R2 or higher
#
# Change Log:#
#               5.9.5 - Switched the demotion authorization model to "run AS the SA account,
#                       elevated" and removed the credential-fallback path. Rationale: a typed-in
#                       credential only flows to cmdlets you hand it to with -Credential, so it never
#                       covered repadmin, ntdsutil, or the local elevated actions - those run under
#                       the PROCESS token. The startup guard already requires elevation + Domain and
#                       Enterprise Admins; the SA credential prompt is now MANDATORY at startup
#                       (Initialize-DemotionCredential aborts the script if cancelled, unless
#                       $UseExplicitDemotionCredential = $false) and is framed strictly as the
#                       double-hop partner-handoff credential threaded into
#                       Uninstall-ADDSDomainController -Credential. Assert-DemotionReadiness no longer
#                       prompts for or proceeds on a fallback credential - every failed check is a
#                       hard stop with remediation (privilege failure -> re-launch as SA elevated).
#                       Removed Get-FallbackAdminCredential, Test-TargetWinRm, the first-hop
#                       Invoke-Command -Credential threading, the $Script:FallbackCredential state,
#                       and the $PromptCredentialOnReadinessFailure switch.
#               5.9.4 - Wired the privilege checks and the target readiness checks into one
#                       end-to-end gate (Assert-DemotionReadiness) run before every demotion, and
#                       added an SA-credential fallback. The gate aggregates elevation, Domain
#                       Admins, Enterprise Admins, prerequisites (target set / not self / WinRM
#                       reachable), FSMO safety, replication health, and the last-DC check, and
#                       reports each. If ANY check fails and $PromptCredentialOnReadinessFailure is
#                       set, it prompts once (Get-FallbackAdminCredential) for an SA credential and
#                       applies it to the steps the failed check(s) would block - the WinRM session
#                       (threaded into the demotion Invoke-Command and re-probed via Test-TargetWinRm),
#                       the AD queries, and the demotion's partner contact (adopted as the demotion
#                       credential). Hard blocks (target unset or self, FSMO role held, last DC) are
#                       state issues a credential cannot resolve and always stop the gate; a missing
#                       local elevation token is reported but the SA credential still covers the
#                       remote and AD steps. The full workflow and single demotion now route through
#                       the gate (Test-MenuPreflight delegates to it), so the credential prompt is
#                       reached instead of an early elevation abort. New switches:
#                       EnsureEndToEndReadiness, PromptCredentialOnReadinessFailure. New state field
#                       ReadinessResult.
#               5.9.3 - Each startup privilege check now states, in plain terms, whether the running
#                       context can successfully demote a REMOTE domain controller. New helper
#                       Write-DemotionCapabilityMsg emits an [OK   ] or [ERROR] capability line tied
#                       to the demotion outcome after each check: elevation (the WinRM session needs
#                       a full administrative token to run Uninstall-ADDSDomainController on the
#                       target), Domain Admins (nests into BUILTIN\Administrators on every DC,
#                       granting the local admin rights the target requires), and Enterprise Admins
#                       (authorizes the forest-wide Configuration-partition changes and metadata
#                       cleanup a demotion performs). The combined Domain/Enterprise Admins check was
#                       split so each group reports individually, and Assert-ExecutionPrivileges adds
#                       a final permission verdict naming whether the account can demote a remote DC.
#               5.9.2 - Added a startup launch-context advisory. New Get-LaunchContext compares the
#                       owner of the interactive desktop (explorer.exe in this session, with a
#                       Win32_ComputerSystem console-owner fallback) to the owner of this process;
#                       the process token user is identical whether SA is the interactive logon or
#                       an SA-token process was started with RunAs / 'Run as different user', so the
#                       desktop-vs-process comparison is the only reliable signal. Write-LaunchContext-
#                       Advisory surfaces the result as a single informational line (a warning when a
#                       secondary-logon launch is detected) and Assert-ExecutionPrivileges emits it
#                       once at startup. Purely informational - it does not gate execution.
#               5.9.1 - Moved the demotion-credential capture to startup so the credential is
#                       entered once, up front, and never mid-workflow. New Initialize-Demotion-
#                       Credential runs as the first post-privilege step and, when
#                       UseExplicitDemotionCredential is set, calls Get-DemotionCredential once and
#                       caches it in $Script:DemotionCredential; every later consumer reuses the
#                       cached PSCredential, so no prompt interrupts a demotion or the full
#                       workflow. When UseExplicitDemotionCredential is $false nothing is captured
#                       and the remote demotion relies on the session token (subject to the
#                       WinRM double-hop, which can escalate a graceful demotion to a forced one).
#               5.9.0 - Fixed the group-membership check and added post-demotion partner
#                       connection-teardown verification. (1) Test-HasRequiredAdminGroups now
#                       reads the logon account's transitive group set from Active Directory
#                       (Get-ADUser -Properties tokenGroups, keyed by the account SID) instead of
#                       the current process token. UAC token filtering strips the Domain Admins,
#                       Enterprise Admins, and local Administrators SIDs from a NON-elevated
#                       process token, so the old token-based check reported "missing Domain
#                       Admins, Enterprise Admins" for an account that genuinely held them whenever
#                       the console was not launched elevated - the membership error that appeared
#                       beside the elevation error and looked backwards. The check is now
#                       elevation-independent; a process-token fallback runs only if the directory
#                       query fails and is flagged as elevation-sensitive. Assert-ExecutionPrivileges
#                       now explains the token filtering when elevation is missing.
#                       (2) New REGION: PARTNER CONNECTION TEARDOWN with Confirm-Partner-
#                       ConnectionTeardown: after a successful demotion it optionally forces the
#                       KCC on surviving partners (repadmin /kcc) and polls until three signals
#                       clear on every reachable partner - the demoted DC's NTDS Settings object is
#                       gone (Test-TargetDsaPresent), the partner no longer lists it as an inbound
#                       replication source (Get-ADReplicationPartnerMetadata), and no nTDSConnection
#                       anywhere still references the removed DSA in fromServer (Get-StaleInbound-
#                       Connections). Runs automatically at the end of the full workflow and on
#                       demand from new menu option 15; results are added to the HTML report and the
#                       session-state view. New switches: VerifyPartnerConnectionRemoval,
#                       ConnectionTeardownForceKcc, ConnectionTeardownWaitSeconds,
#                       ConnectionTeardownPollSeconds.
#               5.8.0 - Added a fail-closed execution-privilege guard and folded in the
#                       remote second-hop fix. (1) Assert-ExecutionPrivileges runs at menu
#                       startup and at the entry of every destructive action (demotion,
#                       metadata cleanup, domain removal, full workflow): Test-IsElevated
#                       requires a full (non-filtered) administrator token and Test-Has-
#                       RequiredAdminGroups requires Domain Admins (RID 512) AND Enterprise
#                       Admins (RID 519) on the logon token (matched by RID, not name), so a
#                       session that forgot to elevate - or is running under the wrong
#                       account - is stopped before any change is made. The result is cached
#                       for the session. New switches: RequireElevation, RequireEnterpriseAdmin.
#                       (2) ntdsutil now runs via Invoke-ElevatedScript, a ShellExecute/RunAs
#                       helper that launches it in a separate elevated process with a real
#                       console (conhost) and reads its merged output and exit code back from
#                       temp files - removing the dependency on the host console and the ISE
#                       pseudo-console hang risk. (3) The remote Uninstall-ADDSDomainController
#                       can now be threaded with an explicit PSCredential (Get-Demotion-
#                       Credential, prompted once and cached) passed to the cmdlet's -Credential,
#                       so the on-target partner contact binds with fresh credentials instead of
#                       a non-delegable WinRM network token. This prevents the double-hop
#                       partner-contact failure that previously escalated a graceful demotion
#                       to ForceRemoval. New switches: UseExplicitDemotionCredential,
#                       DemotionCredentialUser. Also corrected the host description (UHSVRDC08
#                       is Windows Server 2022 Datacenter Desktop Experience, not Server Core).
#               5.7.4 - Wrapped the FSMO safety check and the menu pre-flight driver in
#                       try/catch so a transient AD query failure (e.g. Get-ADDomain /
#                       Get-ADForest throwing under -ErrorAction Stop) is reported and
#                       returns $false for that one check instead of propagating a
#                       terminating error out of the menu switch and ending the session.
#                       Test-FsmoSafety now returns $false on query failure; Test-Menu-
#                       Preflight catches any error from the underlying checks and fails
#                       closed. Behavior on the success path is unchanged.
#               5.7.3 - Hardened reachability and graceful convergence, and fixed a
#                       decommission ordering issue. (1) Reachability decisions no
#                       longer rely on ICMP alone: a new Test-PartnerReachable probes
#                       LDAP (389) then RPC endpoint mapper (135) via a short TCP
#                       connect, falling back to ping only if both are inconclusive,
#                       so a segmented network that blocks ICMP no longer marks live
#                       partners down and silently skips the cleanup sweep. All four
#                       reachability sites (partner capture, cleanup-DC fallback,
#                       Update-PartnerReachability, Scan of Last Resort) now use it.
#                       (2) Graceful convergence keyed on the wrong object: it polled
#                       the (objectClass=server) server object, which commonly lingers
#                       empty after a graceful demotion, so convergence ran to the full
#                       timeout every time. New Test-TargetDsaPresent polls the NTDS
#                       Settings (nTDSDSA) object instead - the object a graceful
#                       demotion authoritatively deletes and replicates - so the wait
#                       converges in seconds; the converged branch then runs one server-
#                       object sweep to drop any lingering empty husk. (3) In the full
#                       workflow the target was rebooted AFTER its computer account was
#                       deleted, which could break the secure channel before the reboot
#                       and leave the restart command unable to authenticate. The reboot
#                       now runs immediately after a successful graceful demotion, before
#                       account removal (which acts against a surviving partner, not the
#                       target, so it does not need the target online).
#               5.7.2 - Aligned ntdsutil messaging with what it actually binds to.
#                       ntdsutil runs on the local script-host DC and binds to
#                       localhost (the inline "on <partner>" form fails to bind a
#                       domain, per 5.4.0), but the surrounding messaging implied
#                       it used the selected cleanup partner. The ntdsutil log
#                       lines and the forced-path narration now name the local host
#                       explicitly and state that the partner-targeted authoritative
#                       Remove-ADObject step is separate; the cleanup result Detail
#                       records the ntdsutil host and the authoritative partner.
#                       Behavior unchanged - messaging only. (ntdsutil is reached
#                       only on the forced/failed path; graceful uses verify/converge.)
#               5.7.1 - Fixed the remote demotion result object being polluted by
#                       Uninstall-ADDSDomainController's own output: the cmdlet
#                       result was neither captured nor suppressed, so the
#                       scriptblock returned a multi-object collection and the
#                       parent's ForceUsed/PolicyRelaxed/GcDisabled reads were
#                       taken against a collection rather than the status object.
#                       This produced a false "forced removal" report (with the
#                       password-policy and GC-clear warnings) on a demotion whose
#                       own remediation trail showed a single graceful attempt.
#                       The cmdlet output is now suppressed ($null =) and the
#                       Invoke-Command result is normalized to the single status
#                       object. Corrected the metadata-cleanup gate accordingly:
#                       a GRACEFUL demotion already removes its metadata at the
#                       source, so cleanup now runs in a non-destructive
#                       verify/converge mode (optional syncall, then poll partner
#                       site listings until the object replicates out, falling
#                       back to authoritative object removal only if convergence
#                       times out) and never invokes ntdsutil; a FORCED removal
#                       (or a failed/explicit cleanup) still runs the full
#                       ntdsutil + authoritative removal + partner sweep. The
#                       standalone Metadata Cleanup menu action infers the mode
#                       from the recorded DemotionResult. New switches:
#                       GracefulConvergenceSyncFirst, GracefulConvergenceWaitSeconds,
#                       GracefulConvergencePollSeconds. Cleanup result gained a
#                       Mode field.
#               5.7.0 - DNS is hosted on InfoBlox (10.51.98.206/207), not on the
#                       DCs, with no programmatic write path. The script no longer
#                       attempts DC-side DNS reads/writes; instead it prints (and
#                       emails) a precise InfoBlox cleanup checklist - host/PTR,
#                       the _msdcs GUID CNAME (DSA GUID now captured before
#                       demotion), SRV and NS entries. Readiness DNS messaging
#                       updated; -IgnoreLastDNSServerForZone noted as unnecessary
#                       with external DNS. New switches: DnsManagedExternally,
#                       ExternalDnsName, ExternalDnsServers.
#               5.6.0 - Added upfront measures to favor a clean graceful demotion
#                       and avoid backing into ForceRemoval: a pre-demotion
#                       'repadmin /syncall <target>' to converge the DC, and a
#                       readiness check (last-DC guard that aborts, GC and DNS
#                       redundancy warnings, and a local-admin password length
#                       pre-check against the target's effective policy so the
#                       relaxation path is not needed). Added an opt-in
#                       -IgnoreLastDNSServerForZone for graceful demotion. New
#                       switches: EnsureDemotionReadiness, PreDemotionSync,
#                       IgnoreLastDnsServerForZone.
#               5.5.0 - Metadata cleanup now sweeps EVERY reachable replication
#                       partner (checks each, removes residual objects where
#                       present, re-verifies) regardless of the single-DC logic;
#                       per-partner results are logged and added to the report.
#                       Added menu option 14 "Scan of Last Resort": compares
#                       every DC's Sites\Servers view against the current DC list
#                       and reports any server object not matching a current DC.
#                       Entered server names are now upper-cased at the point of
#                       entry (config variable and interactive prompt).
#               5.4.0 - Demotion now records a remediation trail (each caught
#                       exception and which branch handled it), logged and
#                       returned, and warns when ForceRemoval is used. Tightened
#                       the force-escalation match to genuine partner-contact
#                       failures (RPC unavailable / could not be contacted /
#                       not operational) instead of the over-broad
#                       'denied|cannot' that caused spurious forced removals.
#                       Metadata cleanup reworked: Remove-ADObject is now the
#                       authoritative removal and ntdsutil is best-effort, run
#                       from the local DC (no "on <server>" clause, which had
#                       failed to bind a domain). Cleanup success is judged by
#                       post-removal verification, with ntdsutil's own status
#                       reported separately so a real ntdsutil error stays
#                       visible. Report gained an ntdsutil status row.
#               5.3.1 - Reduced active mail recipients to Alan W. Phillips and
#                       commented out the rest (left in place). Switched the
#                       additional recipients to toggle-safe leading commas.
#               5.3.0 - Converted to an interactive, menu-driven tool backed by
#                       a shared session-state object so every option is aware
#                       of all variables and prior results. Metadata cleanup now
#                       sources the demoted DC's replication partners from
#                       session state, falling back to the most recent saved
#                       partner CSV, and refreshes live reachability before
#                       selecting a cleanup DC. Added menu actions for each
#                       step, a full-workflow option, dry-run toggle, a
#                       variables/state viewer, and per-action confirmations.
#               5.2.0 - Added post-demotion domain removal: a silent
#                       'repadmin /syncall /AdeP' is run from the calling DC to
#                       converge the demotion/cleanup enterprise-wide, then the
#                       target's computer account is removed from the domain
#                       (with verification). Runs after a clean demotion or
#                       after metadata cleanup. New switches RemoveFromDomain,
#                       RunSyncAllBeforeRemoval, RepadminSyncAllOptions. Report
#                       gained a Replication Sync / Domain Removal section.
#                       Hardened computer-account lookups to filter by Name.
#               5.1.0 - Reinstated reactive remediation inside the remote
#                       demotion: secedit password-policy relaxation (with
#                       backup/restore) and NTDS GC options disable, now
#                       implemented correctly (full temp paths, -bnot bit
#                       clear). Default local admin password set to the UH
#                       standard. Metadata cleanup now pulls the target's
#                       site and dynamically verifies, against the chosen
#                       replication partner, whether the target server still
#                       exists in that site's Servers container before and
#                       after cleanup. Sole author attribution.
#               5.0.0 - Full rewrite to canonical standards. Added pre-demotion
#                       replication-partner inventory with CSV persistence,
#                       same-site-aware cleanup DC selection, ntdsutil-based
#                       metadata cleanup (replaces non-existent
#                       Remove-ADDomainController -MetadataCleanup), residual
#                       object/DNS cleanup, file+console logging helpers, and
#                       HTML email reporting.
#                       Fixed: backtick continuations, Allman-broken
#                       Invoke-Command -ScriptBlock bindings, bitwise GC clear
#                       bug (-not vs -bnot), $Pwd automatic-variable clobber,
#                       and fragile secedit/GC hacks (removed in favor of a
#                       deterministic graceful->forced demotion model with a
#                       supplied compliant local admin password).
#               4.0.0 - Prior incomplete revision (site-aware draft).
# =====================================================================

# ============================================================
# REGION: VARIABLES
# ============================================================

# ----- Target (SET THIS before running) -----
# Short name or FQDN of the Domain Controller to demote and remove.
$TargetDC = ''

# ----- Behavior switches -----
$DryRun                   = $true   # $true = log intended actions only, change nothing
$AbortOnReplicationErrors = $false   # $true = stop if the target has inbound replication failures
$EnableMetadataCleanup    = $true    # $true = run full ntdsutil + authoritative cleanup after a FORCED removal or a failed demotion (a graceful demotion uses verify/converge instead - see below)
$RemoveFromDomain         = $true    # $true = delete the target's computer account from AD after demotion/cleanup
$RunSyncAllBeforeRemoval  = $true    # $true = run repadmin /syncall from this DC before removing the account
$RepadminSyncAllOptions   = '/AdeP'  # /A all partitions, /d DN names in messages, /e enterprise-wide, /P push from this DC
$EnsureDemotionReadiness  = $true    # $true = run upfront readiness checks before a graceful demotion attempt
$PreDemotionSync          = $true    # $true = converge the target (repadmin /syncall <target>) before demoting

# ----- End-to-end readiness gate -----
# Assert-DemotionReadiness runs the privilege checks AND the target readiness checks as one gate
# before a demotion and reports each. Every failure is a hard stop - there is no credential
# workaround. The model is that the script is launched ELEVATED and AS an SA-class account (Domain
# Admins + Enterprise Admins): that process identity covers the first WinRM hop, the local elevated
# tools (repadmin, ntdsutil), and the AD operations, while the mandatory SA credential captured at
# startup (see UseExplicitDemotionCredential) covers only the target's onward partner-handoff (the
# double-hop). A typed-in credential cannot substitute for the process identity, so a privilege
# failure means re-launch as SA; a readiness failure (FSMO held, last DC, WinRM unreachable, target
# is self) is a state/transport issue to resolve before demoting.
$EnsureEndToEndReadiness = $true   # $true = run the combined privilege + target readiness gate before demoting
$IgnoreLastDnsServerForZone = $false # $true = pass -IgnoreLastDNSServerForZone to a graceful demotion (use only when zone redundancy is confirmed)

# ----- Execution privileges (startup guard) -----
# The intended model is that the console is launched ELEVATED and AS the SA account - one that is a
# member of Domain Admins AND Enterprise Admins - logged on to the management DC. The PROCESS
# identity (not a typed-in credential) is what carries through to the first WinRM hop, the local
# elevated tools (repadmin, ntdsutil), and the AD operations, so these switches drive a fail-closed
# startup guard (Assert-ExecutionPrivileges) that stops a session which was not launched elevated -
# or is running under an account lacking the required directory rights - before any destructive
# action, rather than failing partway through ntdsutil / metadata removal.
$RequireElevation       = $true   # $true = require a full (elevated) administrator token; fail closed if filtered
$RequireEnterpriseAdmin = $true   # $true = require Domain Admins (RID 512) AND Enterprise Admins (RID 519) on the logon token

# ----- Demotion credential (mandatory double-hop handoff) -----
# Even when the script runs AS the SA account, a remote Uninstall-ADDSDomainController must contact a
# surviving replication partner, and the on-target token cannot delegate ONWARD to that partner over
# a default WinRM/Kerberos session (the classic double-hop) - which surfaces as a partner-contact
# failure and falsely escalates a graceful demotion to ForceRemoval. Passing an explicit PSCredential
# to the cmdlet's -Credential makes the target bind to the partner with fresh credentials (not a
# delegated hop), so the graceful path holds. This credential is captured up front and is MANDATORY
# by default: with $UseExplicitDemotionCredential = $true the script aborts at startup if the prompt
# is cancelled. Set it to $false only to deliberately rely on the session token (accepting the
# double-hop / ForceRemoval risk). A blank $DemotionCredentialUser pre-fills the current logon name.
$UseExplicitDemotionCredential = $true   # $true = mandatory SA credential captured at startup and threaded into Uninstall-ADDSDomainController -Credential
$DemotionCredentialUser        = ''      # optional UPN or DOMAIN\sam to pre-fill the credential prompt (blank = current logged-on user)

# ----- Graceful-demotion convergence (verify/converge cleanup mode) -----
# A graceful Uninstall-ADDSDomainController removes the demoted DC's metadata at the SOURCE and
# relies on normal AD replication to carry those deletions to every other DC. Rather than force
# an ntdsutil pass (which is only required after a ForceRemoval that leaves metadata behind), the
# graceful path verifies that the object replicates out on its own. It optionally kicks a syncall
# to accelerate convergence, then polls each reachable partner's site listing until the object is
# gone or the timeout is reached; only on timeout does it fall back to authoritative object removal.
$GracefulConvergenceSyncFirst   = $true   # $true = run a repadmin /syncall to accelerate convergence before polling
$GracefulConvergenceWaitSeconds = 300     # maximum time to wait for graceful deletions to replicate out
$GracefulConvergencePollSeconds = 30      # interval between partner site-listing re-checks while waiting

# ----- Partner connection teardown (post-demotion confidence check) -----
# A successful demotion removes the demoted DC's NTDS Settings at the source and replicates that
# deletion out, but each surviving partner keeps its inbound nTDSConnection (and repsFrom link)
# FROM the removed DC until the KCC recomputes topology on its next pass (~15 min). These switches
# drive Confirm-PartnerConnectionTeardown, which optionally forces the KCC, then polls every
# reachable partner until three signals clear: the NTDS Settings object is gone, the partner no
# longer lists the removed server as an inbound source, and no nTDSConnection anywhere still
# references the removed DSA. It runs automatically at the end of the full workflow and on demand
# from menu option 15, so the operator has explicit confirmation before continuing.
$VerifyPartnerConnectionRemoval = $true   # $true = verify every partner has dropped its link to the demoted DC
$ConnectionTeardownForceKcc     = $true   # $true = force the KCC (repadmin /kcc) on partners to accelerate teardown
$ConnectionTeardownWaitSeconds  = 300     # maximum time to wait for partners to drop the connection
$ConnectionTeardownPollSeconds  = 30      # interval between teardown re-checks while waiting

# ----- DNS (external) -----
# DNS is hosted on InfoBlox, not on the domain controllers (the DCs forward to InfoBlox).
# There is no programmatic write path, so the script never reads or writes DNS records; after
# removal it prints a precise checklist of records to delete manually in InfoBlox.
$DnsManagedExternally = $true
$ExternalDnsName      = 'InfoBlox'
$ExternalDnsServers   =
@(
    '10.51.98.206'
    '10.51.98.207'
)

# ----- Local administrator password applied to the target as it becomes a member server -----
# UH standard. If the resulting member-server baseline enforces a longer minimum length or
# stricter complexity than this value satisfies, the demotion will reactively relax the local
# security policy (SECURITYPOLICY area), set the password, then restore the original policy.
# Plaintext is acceptable per operator direction (local, ad-hoc use); converted to a
# SecureString on the target.
$LocalAdminPasswordPlain = 'UH$197HS'

# ----- Identity / timing -----
$ScriptName    = 'Remove_DC_Remote.ps1'
$ScriptVersion = '5.9.5'
$RunStamp      = (Get-Date).ToString('yyyyMMdd_HHmmss')
$FriendlyDate  = (Get-Date).ToString('dddd, MMMM dd, yyyy HH:mm:ss')

# ----- Logging / output paths -----
$LogDirectory  = 'C:\Temp\Logs'
$LogBaseName   = ($ScriptName -replace '\.ps1$', '')
$LogPath       = Join-Path -Path $LogDirectory -ChildPath "$($LogBaseName)_$RunStamp.log"
$PartnerCsvPath = Join-Path -Path $LogDirectory -ChildPath "$($LogBaseName)_Partners_$RunStamp.csv"

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
    #,'David.Butcher@UHhospitals.org'
    #,'Mari.Eustace@UHhospitals.org'
    #,'Jeffrey.Altomari@UHhospitals.org'
    ,'Randall.Richards@UHhospitals.org'
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
    # holds those groups whenever the console was not launched elevated. Instead the account's
    # transitive group set is read from Active Directory via the tokenGroups constructed attribute
    # (which expands nested membership exactly as a real logon token would), keyed by the account's
    # own SID (the user SID is never filtered, so it is reliable even unelevated). RIDs are matched
    # rather than names so a renamed or localized group still resolves. A process-token fallback is
    # used only if the directory query cannot be performed, and is flagged as elevation-sensitive.
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

function Write-DemotionCapabilityMsg
{
    # Emits one capability line per privilege check that states, in remote-DC-demotion terms,
    # whether that requirement is satisfied: an [OK   ] line (with the reason it enables the remote
    # demotion) when granted, or an [ERROR] line (with the reason it blocks the remote demotion)
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
        Write-SuccessMsg "  -> Remote DC demotion: $GrantedMessage"
    }
    else
    {
        Write-ErrorMsg "  -> Remote DC demotion: $BlockedMessage"
    }
}

function Assert-ExecutionPrivileges
{
    # Fail-closed startup / pre-action guard. Verifies (per the configured switches) that the
    # session holds a full elevated token and that the logon account carries Domain Admins and
    # Enterprise Admins. The result is cached for the session so repeated calls from the
    # destructive menu actions stay quiet after the first successful assertion.
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
            Write-DemotionCapabilityMsg -Granted $true -GrantedMessage "PERMITTED by this check - the full token carries administrative rights, so the WinRM session to the target DC can run Uninstall-ADDSDomainController." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Process is NOT elevated. Re-launch PowerShell with 'Run as administrator' before running this script."
            Write-InfoMsg "Note: a non-elevated token has its Domain Admins / Enterprise Admins / local Administrators SIDs filtered out by UAC. The group-membership check below reads Active Directory directly, so it still reports the account's true membership regardless of elevation."
            Write-DemotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED by this check - without an elevated token the session to the target DC runs with a filtered standard-user token and Uninstall-ADDSDomainController will be denied."
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
            Write-DemotionCapabilityMsg -Granted $true -GrantedMessage "Domain Admins nests into BUILTIN\Administrators on every domain controller, granting the local administrative rights the target DC requires to accept the remote demotion." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Logon account is NOT a member of Domain Admins."
            Write-DemotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED - without Domain Admins the account has no administrative rights on the target DC, so the remote Uninstall-ADDSDomainController will be denied."
            $ok = $false
        }

        if ($groups.HasEnterpriseAdmins)
        {
            Write-SuccessMsg "Logon account is a member of Enterprise Admins."
            Write-DemotionCapabilityMsg -Granted $true -GrantedMessage "Enterprise Admins authorizes the forest-wide Configuration-partition changes a demotion makes - removing the server's NTDS Settings and server object, and any cross-site metadata cleanup." -BlockedMessage ''
        }
        else
        {
            Write-ErrorMsg "Logon account is NOT a member of Enterprise Admins."
            Write-DemotionCapabilityMsg -Granted $false -GrantedMessage '' -BlockedMessage "BLOCKED - a demotion edits the forest-wide Configuration partition; without Enterprise Admins those changes and the metadata cleanup will fail."
            $ok = $false
        }
    }

    if ($ok)
    {
        $Script:PrivilegesAsserted = $true
        Write-SuccessMsg "Execution privilege checks passed."
        Write-SuccessMsg "Permission verdict: '$($identity.Name)' has the rights required to demote a remote domain controller (elevation, Domain Admins, and Enterprise Admins all satisfied)."
    }
    else
    {
        Write-ErrorMsg "Execution privilege checks failed - destructive actions are blocked for this session."
        Write-ErrorMsg "Permission verdict: '$($identity.Name)' will NOT be able to demote a remote domain controller as currently launched. Resolve the item(s) flagged above - re-launch elevated and/or use an account that is in both Domain Admins and Enterprise Admins."
    }

    return $ok
}

function Get-DemotionCredential
{
    # Returns (and session-caches) the PSCredential threaded into the remote
    # Uninstall-ADDSDomainController -Credential to defeat the WinRM double-hop to a surviving
    # partner. Prompts once per session. Returns $null if the operator cancels the prompt.
    if ($Script:DemotionCredential)
    {
        return $Script:DemotionCredential
    }

    if (-not [string]::IsNullOrWhiteSpace($DemotionCredentialUser))
    {
        $userHint = $DemotionCredentialUser
    }
    else
    {
        $userHint = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    }

    Write-InfoMsg "Prompting for the directory credential used for the remote demotion partner contact (user hint: '$userHint')."
    $cred = Get-Credential -UserName $userHint -Message 'Enter the Domain/Enterprise Admin credential used to demote the target DC (threaded into Uninstall-ADDSDomainController -Credential).'

    if ($null -eq $cred)
    {
        Write-WarnMsg "Credential prompt was cancelled - the demotion will proceed without an explicit -Credential (subject to the double-hop)."
        return $null
    }

    $Script:DemotionCredential = $cred
    Write-SuccessMsg "Demotion credential captured for '$($cred.UserName)' (cached for this session)."
    return $cred
}

function Initialize-DemotionCredential
{
    # Mandatory, up-front capture of the SA credential threaded into the remote demotion
    # (Uninstall-ADDSDomainController -Credential) to defeat the WinRM double-hop from the target DC
    # to a surviving partner. The script is run AS the SA account, elevated, so the process identity
    # already covers the first WinRM hop, the local elevated tools (repadmin, ntdsutil), and the AD
    # operations; this explicit credential object exists solely so the target can authenticate ONWARD
    # to a partner during a graceful demotion (a delegated token cannot - the double-hop). Captured
    # once here so no prompt interrupts a demotion later, and held only for the session. Returns
    # $true when a credential is captured (or when explicit-credential use is disabled), $false when
    # the mandatory prompt is cancelled so the caller can abort startup.
    if (-not $UseExplicitDemotionCredential)
    {
        Write-WarnMsg 'Explicit demotion credential is disabled ($UseExplicitDemotionCredential = $false) - the remote demotion will rely on the session token and a partner-contact double-hop may escalate a graceful demotion to a forced removal.'
        return $true
    }

    Write-InfoMsg 'Capturing the mandatory SA demotion credential now, as the first step, so no prompt interrupts the workflow later (this is the partner-handoff credential for a graceful demotion).'
    $cred = Get-DemotionCredential

    if ($null -eq $cred)
    {
        Write-ErrorMsg 'The mandatory SA demotion credential was not provided. It is required for a clean graceful demotion (the target uses it to contact a surviving partner). Re-run and supply the credential, or set $UseExplicitDemotionCredential = $false to rely on the session token (accepting the double-hop / ForceRemoval risk).'
        return $false
    }

    return $true
}

function Invoke-ElevatedScript
{
    # Runs a scriptblock in a separate, elevated PowerShell process via ShellExecute 'RunAs'.
    # Used for native console tools (ntdsutil) that misbehave inside the ISE pseudo-console: the
    # elevated child gets a real conhost. ShellExecute/RunAs cannot redirect a child's standard
    # streams, so the bootstrap child writes its own merged output and exit code to temp files,
    # which this function reads back after the child exits. The supplied scriptblock must be
    # self-contained (it runs in a fresh process with no access to this script's functions); it
    # receives ArgumentList through its own param block and should emit results to the pipeline.
    param
    (
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    $workDir = Join-Path -Path $env:TEMP -ChildPath 'RemoveDcRemote_Elevated'

    if (-not (Test-Path -Path $workDir))
    {
        New-Item -Path $workDir -ItemType Directory -Force | Out-Null
    }

    $stamp    = (Get-Date).ToString('yyyyMMdd_HHmmss_fff')
    $argPath  = Join-Path -Path $workDir -ChildPath "args_$stamp.clixml"
    $sbPath   = Join-Path -Path $workDir -ChildPath "block_$stamp.ps1"
    $outPath  = Join-Path -Path $workDir -ChildPath "out_$stamp.log"
    $codePath = Join-Path -Path $workDir -ChildPath "code_$stamp.txt"
    $bootPath = Join-Path -Path $workDir -ChildPath "boot_$stamp.ps1"

    # The scriptblock body (its .ToString() text, including its param block) is written verbatim
    # to its own .ps1 so the bootstrap can invoke it by path with splatted args - no nested
    # here-strings and no backtick escaping required.
    Export-Clixml -Path $argPath -InputObject $ArgumentList -Depth 5
    Set-Content -Path $sbPath -Value $ScriptBlock.ToString() -Encoding UTF8

    $bootTemplate =
@'
$ErrorActionPreference = 'Continue'
$exit = 0

try
{
    $bootArgs = @(Import-Clixml -LiteralPath '__ARGPATH__')
    (& '__SBPATH__' @bootArgs) 2>&1 | Out-File -LiteralPath '__OUTPATH__' -Encoding UTF8

    if ($null -ne $LASTEXITCODE)
    {
        $exit = $LASTEXITCODE
    }
}
catch
{
    $_ | Out-String | Out-File -LiteralPath '__OUTPATH__' -Append -Encoding UTF8
    $exit = 1
}

Set-Content -LiteralPath '__CODEPATH__' -Value $exit
'@

    $bootContent = $bootTemplate.Replace('__ARGPATH__', $argPath).Replace('__SBPATH__', $sbPath).Replace('__OUTPATH__', $outPath).Replace('__CODEPATH__', $codePath)
    Set-Content -Path $bootPath -Value $bootContent -Encoding UTF8

    $startParams =
    @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $bootPath)
        Verb         = 'RunAs'
        WindowStyle  = 'Hidden'
        Wait         = $true
        PassThru     = $true
    }

    $stdOut   = @()
    $exitCode = $null

    try
    {
        $proc = Start-Process @startParams

        if (Test-Path -Path $outPath)
        {
            $stdOut = @(Get-Content -Path $outPath)
        }

        if (Test-Path -Path $codePath)
        {
            $exitCode = [int]((Get-Content -Path $codePath -Raw).Trim())
        }
        elseif ($proc)
        {
            $exitCode = $proc.ExitCode
        }
    }
    catch
    {
        return [pscustomobject]@{ Launched = $false; ExitCode = $null; StdOut = @(); Error = $_.Exception.Message }
    }
    finally
    {
        foreach ($tmp in @($argPath, $sbPath, $outPath, $codePath, $bootPath))
        {
            if (Test-Path -Path $tmp)
            {
                Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return [pscustomobject]@{ Launched = $true; ExitCode = $exitCode; StdOut = @($stdOut); Error = $null }
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
        [object]$Partners,
        [object]$DemotionResult,
        [object]$CleanupResult,
        [object]$SyncResult,
        [object]$RemovalResult,
        [object]$ConnectionResult,
        [string]$OverallStatus,
        [string]$StatusColor
    )

    $partnerRows = ''

    if ($Partners -and @($Partners).Count -gt 0)
    {
        foreach ($p in $Partners)
        {
            $reachText  = if ($p.Reachable) { 'Yes' } else { 'No' }
            $reachColor = if ($p.Reachable) { '#2e7d32' } else { '#c62828' }

            $partnerRows += @"
<tr>
<td style="padding:6px 10px;border:1px solid #d0d0d0;">$($p.PartnerHost)</td>
<td style="padding:6px 10px;border:1px solid #d0d0d0;">$($p.PartnerSite)</td>
<td style="padding:6px 10px;border:1px solid #d0d0d0;">$($p.PartnerType)</td>
<td style="padding:6px 10px;border:1px solid #d0d0d0;">$($p.Partition)</td>
<td style="padding:6px 10px;border:1px solid #d0d0d0;">$($p.LastResult)</td>
<td style="padding:6px 10px;border:1px solid #d0d0d0;color:$reachColor;font-weight:bold;">$reachText</td>
</tr>
"@
        }
    }
    else
    {
        $partnerRows = '<tr><td colspan="6" style="padding:6px 10px;border:1px solid #d0d0d0;">No replication partners were resolved.</td></tr>'
    }

    $demoteText  = if ($DemotionResult.Success) { 'Succeeded' } else { 'Failed' }
    $demoteColor = if ($DemotionResult.Success) { '#2e7d32' } else { '#c62828' }
    $forceText   = if ($DemotionResult.ForceUsed) { 'Yes (forced removal)' } else { 'No (graceful)' }
    $demoteErr   = if ($DemotionResult.Error) { $DemotionResult.Error } else { 'None' }
    $relaxText   = if ($DemotionResult.PolicyRelaxed) { 'Yes (relaxed then restored)' } else { 'No' }
    $gcText      = if ($DemotionResult.GcDisabled) { 'Yes' } else { 'No' }

    if ($CleanupResult -and $CleanupResult.Performed)
    {
        $cleanupText  = if ($CleanupResult.Success) { 'Completed' } else { 'Completed with warnings' }
        $cleanupColor = if ($CleanupResult.Success) { '#2e7d32' } else { '#ef6c00' }
        $cleanupDc    = $CleanupResult.CleanupDC
        $cleanupDetail = $CleanupResult.Detail
        $beforeText   = if ($CleanupResult.PresentBefore) { 'Present before cleanup' } else { 'Already absent' }
        $afterColor   = if ($CleanupResult.PresentAfter) { '#c62828' } else { '#2e7d32' }
        $afterText    = if ($CleanupResult.PresentAfter) { 'STILL PRESENT after cleanup' } else { 'Confirmed removed' }
        $ntdsText     = $CleanupResult.NtdsUtilStatus
        $ntdsColor    = if ($CleanupResult.NtdsUtilStatus -eq 'Failed') { '#ef6c00' } else { '#555555' }

        $partnerCheckRows = ''
        if ($CleanupResult.PartnerChecks -and @($CleanupResult.PartnerChecks).Count -gt 0)
        {
            foreach ($pc in $CleanupResult.PartnerChecks)
            {
                $pcColor = if ($pc.PresentAfter) { '#c62828' } else { '#2e7d32' }
                $pcText  = if ($pc.PresentAfter) { 'STILL PRESENT' } else { 'clear' }
                $partnerCheckRows += "<tr><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($pc.PartnerHost)</td><td style='padding:4px 10px;border:1px solid #d0d0d0;color:$pcColor;font-weight:bold;'>$pcText</td></tr>"
            }
        }
        else
        {
            $partnerCheckRows = '<tr><td colspan="2" style="padding:4px 10px;border:1px solid #d0d0d0;">No reachable partners were swept.</td></tr>'
        }
    }
    else
    {
        $cleanupText  = 'Not required'
        $cleanupColor = '#555555'
        $cleanupDc    = 'N/A'
        $cleanupDetail = 'Graceful demotion - automatic cleanup'
        $beforeText   = 'N/A'
        $afterColor   = '#555555'
        $afterText    = 'N/A'
        $ntdsText     = 'N/A'
        $ntdsColor    = '#555555'
        $partnerCheckRows = '<tr><td colspan="2" style="padding:4px 10px;border:1px solid #d0d0d0;">N/A</td></tr>'
    }

    if ($SyncResult -and $SyncResult.Ran)
    {
        $syncText  = if ($SyncResult.Success) { "Completed ($($SyncResult.Detail))" } else { "Completed with warnings ($($SyncResult.Detail))" }
        $syncColor = if ($SyncResult.Success) { '#2e7d32' } else { '#ef6c00' }
    }
    else
    {
        $syncText  = 'Not run'
        $syncColor = '#555555'
    }

    if ($RemovalResult -and $RemovalResult.Performed)
    {
        $removalText  = if ($RemovalResult.Success) { 'Removed from domain' } else { 'Not removed' }
        $removalColor = if ($RemovalResult.Success) { '#2e7d32' } else { '#c62828' }
        $removalDetail = $RemovalResult.Detail
    }
    else
    {
        $removalText  = 'Not performed'
        $removalColor = '#555555'
        $removalDetail = if ($RemovalResult) { $RemovalResult.Detail } else { 'Skipped' }
    }

    if ($DnsManagedExternally)
    {
        $fqdn  = "$($TargetInfo.ShortName).$($TargetInfo.DnsDomain)"
        $msdcs = "$($TargetInfo.DsaGuid)._msdcs.$($TargetInfo.DnsDomain)"

        $dnsCleanupBlock = @"
<h3 style="border-bottom:2px solid #c62828;padding-bottom:4px;">Manual DNS Cleanup Required ($ExternalDnsName)</h3>
<p style="margin-top:0;">DNS is hosted on $ExternalDnsName ($($ExternalDnsServers -join ', ')), not on the domain controllers. Delete these records manually:</p>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Host (A/AAAA)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$fqdn &nbsp;-&gt;&nbsp; $($TargetInfo.IPv4)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Reverse (PTR)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">PTR for $($TargetInfo.IPv4)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">_msdcs CNAME</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$msdcs</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">SRV records</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">_ldap / _kerberos / _gc and related SRV entries referencing '$($TargetInfo.ShortName)' under _msdcs.$($TargetInfo.DnsDomain) and the _sites/_tcp/_udp trees</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">NS records</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">Remove '$fqdn' from any zone name-server lists if present</td></tr>
</table>
"@
    }
    else
    {
        $dnsCleanupBlock = ''
    }

    if ($ConnectionResult -and $ConnectionResult.Checked)
    {
        $connClearText  = if ($ConnectionResult.Cleared) { 'Confirmed - all reachable partners released the demoted DC' } else { 'Pending - the KCC has not finished tearing down every link' }
        $connClearColor = if ($ConnectionResult.Cleared) { '#2e7d32' } else { '#ef6c00' }

        $connRows = ''

        if ($ConnectionResult.PartnerResults -and @($ConnectionResult.PartnerResults).Count -gt 0)
        {
            foreach ($cr in $ConnectionResult.PartnerResults)
            {
                $crColor = if ($cr.Cleared) { '#2e7d32' } else { '#c62828' }
                $crText  = if ($cr.Cleared) { 'released' } else { 'still linked' }
                $dsaCol  = if ($cr.DsaPresent) { '#c62828' } else { '#2e7d32' }
                $srcCol  = if ($cr.StillSource) { '#c62828' } else { '#2e7d32' }
                $dsaTxt  = if ($cr.DsaPresent) { 'present' } else { 'gone' }
                $srcTxt  = if ($cr.StillSource) { 'yes' } else { 'no' }

                $connRows += "<tr><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($cr.PartnerHost)</td><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($cr.PartnerSite)</td><td style='padding:4px 10px;border:1px solid #d0d0d0;color:$dsaCol;'>$dsaTxt</td><td style='padding:4px 10px;border:1px solid #d0d0d0;color:$srcCol;'>$srcTxt</td><td style='padding:4px 10px;border:1px solid #d0d0d0;color:$crColor;font-weight:bold;'>$crText</td></tr>"
            }
        }
        else
        {
            $connRows = '<tr><td colspan="5" style="padding:4px 10px;border:1px solid #d0d0d0;">No reachable partners were verified.</td></tr>'
        }

        if ($ConnectionResult.StaleConns -and @($ConnectionResult.StaleConns).Count -gt 0)
        {
            $staleRows = ''

            foreach ($sc in $ConnectionResult.StaleConns)
            {
                $staleRows += "<tr><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($sc.OwningServer)</td><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($sc.OwningSite)</td><td style='padding:4px 10px;border:1px solid #d0d0d0;'>$($sc.ConnectionDN)</td></tr>"
            }

            $staleTable = @"
<p style="margin:6px 0 4px 0;font-weight:bold;color:#c62828;">Lingering inbound connection objects referencing the demoted server:</p>
<table style="border-collapse:collapse;">
<tr style="background:#c62828;color:#fff;"><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Owning DC</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Site</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Connection DN</th></tr>
$staleRows
</table>
"@
        }
        else
        {
            $staleTable = '<p style="margin:6px 0 4px 0;color:#2e7d32;">No lingering connection objects reference the demoted server.</p>'
        }

        $connectionBlock = @"
<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Replication Partner Release</h3>
<p style="margin-top:0;">Status: <span style="color:$connClearColor;font-weight:bold;">$connClearText</span><br/>$($ConnectionResult.Detail)</p>
<table style="border-collapse:collapse;">
<tr style="background:#1565c0;color:#fff;"><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Partner</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Site</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">NTDS Settings</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Still sources target</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Verdict</th></tr>
$connRows
</table>
$staleTable
"@
    }
    else
    {
        $connectionBlock = ''
    }

    $html = @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#222;">
<h2 style="margin-bottom:4px;">Domain Controller Demotion Report</h2>
<p style="margin-top:0;color:#666;">$FriendlyDate &nbsp;|&nbsp; Run from: $($env:COMPUTERNAME)</p>

<p style="font-size:15px;">
Overall status:
<span style="color:$StatusColor;font-weight:bold;">$OverallStatus</span>
</p>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Target Domain Controller</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Host name</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.HostName)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Site</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.Site)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">IPv4</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.IPv4)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Global Catalog</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.IsGlobalCatalog)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Operating System</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.OperatingSystem)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Server object DN</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.ServerObjectDN)</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Demotion</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Result</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$demoteColor;font-weight:bold;">$demoteText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Force used</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$forceText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Password policy relaxed</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$relaxText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Global Catalog cleared</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$gcText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$demoteErr</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Metadata Cleanup</h3>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Status</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$cleanupColor;font-weight:bold;">$cleanupText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Cleanup DC</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$cleanupDc</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">ntdsutil (best-effort)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$ntdsColor;">$ntdsText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Site listing (before)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$beforeText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Site listing (after)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$afterColor;font-weight:bold;">$afterText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$cleanupDetail</td></tr>
</table>

<p style="margin:6px 0 4px 0;font-weight:bold;">All replication partners verified after cleanup:</p>
<table style="border-collapse:collapse;">
<tr style="background:#1565c0;color:#fff;"><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Partner</th><th style="padding:4px 10px;border:1px solid #d0d0d0;text-align:left;">Result</th></tr>
$partnerCheckRows
</table>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">repadmin /syncall (pre-removal)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$syncColor;font-weight:bold;">$syncText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Computer account removal</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$removalColor;font-weight:bold;">$removalText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$removalDetail</td></tr>
</table>

$connectionBlock

$dnsCleanupBlock

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Replication Partners (captured before demotion)</h3>
<table style="border-collapse:collapse;">
<tr style="background:#1565c0;color:#fff;">
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Partner Host</th>
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Site</th>
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Direction</th>
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Partition</th>
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Last Result</th>
<th style="padding:6px 10px;border:1px solid #d0d0d0;text-align:left;">Reachable</th>
</tr>
$partnerRows
</table>

<p style="margin-top:18px;color:#666;">Log file: $LogPath<br/>Partner inventory: $PartnerCsvPath</p>
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

function Test-Prerequisites
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ([string]::IsNullOrWhiteSpace($TargetDC))
    {
        Write-ErrorMsg 'Variable $TargetDC is not set. Edit the VARIABLES region and specify the DC to demote.'
        return $false
    }

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-ErrorMsg "This session is not running with elevated (Administrator) rights."
        return $false
    }

    if ($TargetInfo.HostName -ieq $env:COMPUTERNAME -or $TargetInfo.ShortName -ieq $env:COMPUTERNAME)
    {
        Write-ErrorMsg "The target resolves to the machine running this script. Run from a different DC."
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

    return $true
}

function Test-FsmoSafety
{
    param
    (
        [hashtable]$TargetInfo
    )

    try
    {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop

        $roleHolders =
        @(
            $domain.PDCEmulator
            $domain.RIDMaster
            $domain.InfrastructureMaster
            $forest.SchemaMaster
            $forest.DomainNamingMaster
        )

        foreach ($holder in $roleHolders)
        {
            if ($holder -ieq $TargetInfo.HostName)
            {
                Write-ErrorMsg "Target '$($TargetInfo.HostName)' holds one or more FSMO roles. Transfer roles before demotion."
                return $false
            }
        }

        Write-SuccessMsg "FSMO safety validated - target holds no operations master roles."
        return $true
    }
    catch
    {
        Write-ErrorMsg "FSMO safety check could not query the domain/forest: $($_.Exception.Message)"
        return $false
    }
}

function Test-TargetReplicationHealth
{
    param
    (
        [hashtable]$TargetInfo
    )

    $failures = @()

    try
    {
        $failures = @(Get-ADReplicationFailure -Target $TargetInfo.HostName -ErrorAction Stop)
    }
    catch
    {
        Write-WarnMsg "Could not query replication failures for '$($TargetInfo.HostName)': $($_.Exception.Message)"
        return $true
    }

    if ($failures.Count -gt 0)
    {
        Write-WarnMsg "Target reports $($failures.Count) replication failure(s)."

        foreach ($f in $failures)
        {
            Write-WarnMsg "    Partner: $($f.Partner) | Type: $($f.FailureType) | Count: $($f.FailureCount)"
        }

        if ($AbortOnReplicationErrors)
        {
            Write-ErrorMsg "AbortOnReplicationErrors is enabled - stopping."
            return $false
        }

        Write-WarnMsg "Continuing despite replication failures (AbortOnReplicationErrors is disabled)."
    }
    else
    {
        Write-SuccessMsg "No inbound replication failures detected on target."
    }

    return $true
}

function Invoke-PreDemotionSync
{
    # Converge the doomed DC with its partners before a graceful demotion so its final
    # changes are already replicated out and it can hand off cleanly. This is the single
    # biggest lever for avoiding a fall-back to ForceRemoval.
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would run 'repadmin /syncall $($TargetInfo.HostName) $RepadminSyncAllOptions' to converge the target before demotion."
        return
    }

    Write-InfoMsg "Pre-demotion sync: 'repadmin /syncall $($TargetInfo.HostName) $RepadminSyncAllOptions' (output captured to log)."

    $syncArgs =
    @(
        '/syncall'
        $TargetInfo.HostName
        $RepadminSyncAllOptions
    )

    try
    {
        $output = & repadmin @syncArgs 2>&1
        $exit   = $LASTEXITCODE

        foreach ($line in $output)
        {
            Write-Log "    repadmin: $line"
        }

        if (($exit -eq 0) -or ($null -eq $exit))
        {
            Write-SuccessMsg "Pre-demotion sync completed - target is converged with its partners."
        }
        else
        {
            Write-WarnMsg "Pre-demotion sync returned exit $exit - the target may be unable to reach a partner (a genuine ForceRemoval scenario)."
        }
    }
    catch
    {
        Write-WarnMsg "Pre-demotion sync failed: $($_.Exception.Message)"
    }
}

function Test-DemotionReadiness
{
    # Upfront checks that maximize the chance of a CLEAN graceful demotion. Nothing here
    # blocks except the last-DC case (force-demoting the last DC in a domain is out of
    # scope and dangerous). Everything else is reported so the operator can address it
    # before demoting - or knowingly accept the reactive fallback.
    param
    (
        [hashtable]$TargetInfo
    )

    $result = @{
        IsLastDc        = $false
        PasswordOk      = $true
        SoleForestGc    = $false
        SoleSiteGc      = $false
        HostsDnsRole    = $false
    }

    # 1. Last DC in domain?
    try
    {
        $domain        = Get-ADDomain -ErrorAction Stop
        $domainDcCount = @($domain.ReplicaDirectoryServers).Count

        if ($domainDcCount -le 1)
        {
            $result.IsLastDc = $true
            Write-ErrorMsg "Target appears to be the LAST domain controller in '$($domain.DNSRoot)'. Graceful demotion would require -LastDomainControllerInDomain; not proceeding automatically."
        }
        else
        {
            Write-InfoMsg "Domain '$($domain.DNSRoot)' has $domainDcCount domain controllers - target is not the last."
        }
    }
    catch
    {
        Write-WarnMsg "Could not determine domain controller count: $($_.Exception.Message)"
    }

    # 2. Global Catalog redundancy.
    try
    {
        if ($TargetInfo.IsGlobalCatalog)
        {
            $forestGcs = @((Get-ADForest -ErrorAction Stop).GlobalCatalogs)

            if ($forestGcs.Count -le 1)
            {
                $result.SoleForestGc = $true
                Write-WarnMsg "Target is the ONLY Global Catalog in the forest. Promote another GC before demoting."
            }

            $siteGcs = @(Get-ADDomainController -Filter { IsGlobalCatalog -eq $true } -ErrorAction Stop | Where-Object { $_.Site -eq $TargetInfo.Site })

            if ($siteGcs.Count -le 1)
            {
                $result.SoleSiteGc = $true
                Write-WarnMsg "Target is the only Global Catalog in site '$($TargetInfo.Site)'. Clients in that site will use another site's GC after removal."
            }
        }
    }
    catch
    {
        Write-WarnMsg "Could not evaluate Global Catalog redundancy: $($_.Exception.Message)"
    }

    # 3. Local admin password vs the target's effective minimum length (avoids the
    #    reactive password-policy relaxation path firing during demotion).
    try
    {
        $netOut  = Invoke-Command -ComputerName $TargetInfo.HostName -ScriptBlock { & net accounts } -ErrorAction Stop
        $minLine = $netOut | Where-Object { $_ -match 'Minimum password length' }

        if ($minLine -and ($minLine -match '(\d+)'))
        {
            $minLen = [int]$Matches[1]

            if ($LocalAdminPasswordPlain.Length -lt $minLen)
            {
                $result.PasswordOk = $false
                Write-WarnMsg "Local admin password is $($LocalAdminPasswordPlain.Length) characters but the target's effective minimum is $minLen. A longer value in the LocalAdminPasswordPlain variable demotes cleanly without triggering the policy-relaxation fallback."
            }
            else
            {
                Write-SuccessMsg "Local admin password length ($($LocalAdminPasswordPlain.Length)) meets the target minimum ($minLen)."
            }
        }
    }
    catch
    {
        Write-WarnMsg "Could not read the target's password policy: $($_.Exception.Message)"
    }

    # 4. DNS role (informational; relates to -IgnoreLastDNSServerForZone).
    if ($DnsManagedExternally)
    {
        Write-InfoMsg "DNS is managed externally ($ExternalDnsName at $($ExternalDnsServers -join ', ')) - the DCs are not authoritative, so -IgnoreLastDNSServerForZone is not needed. DNS records will be listed for manual cleanup after removal."
    }
    else
    {
        try
        {
            $dnsSvc = Invoke-Command -ComputerName $TargetInfo.HostName -ScriptBlock { Get-Service -Name DNS -ErrorAction SilentlyContinue } -ErrorAction Stop

            if ($dnsSvc -and $dnsSvc.Status -eq 'Running')
            {
                $result.HostsDnsRole = $true
                Write-WarnMsg "Target runs the DNS Server role. Confirm zone redundancy; if it is the last name server for any AD-integrated zone, enable the IgnoreLastDnsServerForZone option to demote cleanly (currently: $IgnoreLastDnsServerForZone)."
            }
        }
        catch
        {
            Write-InfoMsg "Could not check the DNS role on the target (continuing)."
        }
    }

    return $result
}

function Assert-DemotionReadiness
{
    # End-to-end, fail-closed readiness gate run before any demotion. It aggregates the privilege
    # checks (elevation + Domain Admins + Enterprise Admins - i.e. the process is running AS an
    # SA-class account) and the target readiness checks (target is a remote DC and not self, WinRM
    # reachable, no FSMO roles, replication health, not the last DC) into a single pass and reports
    # each. Every failure is a hard stop: there is no credential workaround, because a typed-in
    # credential cannot supply the PROCESS identity that repadmin, ntdsutil, the local elevated
    # actions, and the first WinRM hop all run under. A privilege failure means the session must be
    # re-launched elevated AS the SA account; a readiness failure (FSMO held, last DC, WinRM
    # unreachable, target is self) is a state/transport issue to resolve before demoting. Returns a
    # decision object - the caller proceeds only when Proceed is $true.
    param
    (
        [hashtable]$TargetInfo
    )

    Write-InfoMsg "Running end-to-end demotion readiness gate for '$($TargetInfo.HostName)'."

    $targetIsSelf = ($TargetInfo.HostName -ieq $env:COMPUTERNAME) -or ($TargetInfo.ShortName -ieq $env:COMPUTERNAME)

    if ($targetIsSelf)
    {
        Write-ErrorMsg "The target resolves to the machine running this script ('$($env:COMPUTERNAME)') - the demotion must be run remotely from a different DC."
    }

    $privilegesOk = Assert-ExecutionPrivileges
    $prereqOk     = Test-Prerequisites -TargetInfo $TargetInfo
    $fsmoOk       = Test-FsmoSafety -TargetInfo $TargetInfo
    $replOk       = Test-TargetReplicationHealth -TargetInfo $TargetInfo
    $readiness    = Test-DemotionReadiness -TargetInfo $TargetInfo
    $lastDcOk     = (-not $readiness.IsLastDc)

    $checks =
    @(
        [pscustomobject]@{ Name = 'Target is a remote DC (not the local machine)';        Passed = (-not $targetIsSelf); HardBlock = $true  }
        [pscustomobject]@{ Name = 'Privileges (elevated, running as SA: DA + EA)';         Passed = $privilegesOk;        HardBlock = $true  }
        [pscustomobject]@{ Name = 'Prerequisites (target set, not self, WinRM reachable)'; Passed = $prereqOk;            HardBlock = $true  }
        [pscustomobject]@{ Name = 'FSMO safety (no operations master roles on target)';    Passed = $fsmoOk;              HardBlock = $true  }
        [pscustomobject]@{ Name = 'Target replication health';                             Passed = $replOk;              HardBlock = $false }
        [pscustomobject]@{ Name = 'Not the last domain controller in the domain';          Passed = $lastDcOk;            HardBlock = $true  }
    )

    $failed      = @($checks | Where-Object { -not $_.Passed })
    $readinessOk = ((-not $targetIsSelf) -and $prereqOk -and $fsmoOk -and $replOk -and $lastDcOk)

    if ($failed.Count -eq 0)
    {
        Write-SuccessMsg "End-to-end readiness gate passed - all privilege and readiness checks are green for '$($TargetInfo.HostName)'."

        return [pscustomobject]@{
            Proceed      = $true
            PrivilegesOk = $true
            ReadinessOk  = $true
            HardBlock    = $false
            Checks       = $checks
        }
    }

    Write-ErrorMsg "End-to-end readiness gate: $($failed.Count) check(s) failed - not proceeding:"

    foreach ($c in $failed)
    {
        Write-ErrorMsg "    [FAIL] $($c.Name)."
    }

    if (-not $privilegesOk)
    {
        Write-ErrorMsg "Privilege check failed: this script must be launched ELEVATED and AS an SA-class account (Domain Admins + Enterprise Admins). A typed-in credential cannot substitute for the process identity - repadmin, ntdsutil, and the local elevated actions all run under the process token. Re-launch the console as the SA account using 'Run as administrator'."
    }

    return [pscustomobject]@{
        Proceed      = $false
        PrivilegesOk = $privilegesOk
        ReadinessOk  = $readinessOk
        HardBlock    = $true
        Checks       = $checks
    }
}

# ============================================================
# REGION: TARGET INVENTORY
# ============================================================

function Get-TargetInfo
{
    param
    (
        [string]$TargetName
    )

    $dc       = Get-ADDomainController -Identity $TargetName -ErrorAction Stop
    $rootDse  = Get-ADRootDSE -ErrorAction Stop
    $configNC = $rootDse.configurationNamingContext
    $dnsRoot  = (Get-ADDomain -ErrorAction Stop).DNSRoot

    $serverObjectDn = "CN=$($dc.Name),CN=Servers,CN=$($dc.Site),CN=Sites,$configNC"

    # DSA GUID = objectGUID of the NTDS Settings object; this keys the _msdcs CNAME alias.
    # Captured now (before demotion) so the DNS cleanup checklist can name it exactly.
    $dsaGuid = 'unknown'
    try
    {
        $ntds    = Get-ADObject -Identity "CN=NTDS Settings,$serverObjectDn" -Properties objectGUID -ErrorAction Stop
        $dsaGuid = $ntds.objectGUID.Guid
    }
    catch
    {
        # NTDS Settings may already be gone (e.g., re-running after removal); leave as 'unknown'.
    }

    return @{
        ShortName       = $dc.Name
        HostName        = $dc.HostName
        Site            = $dc.Site
        IPv4            = $dc.IPv4Address
        IsGlobalCatalog = $dc.IsGlobalCatalog
        OperatingSystem = $dc.OperatingSystem
        ComputerDN      = $dc.ComputerObjectDN
        ServerObjectDN  = $serverObjectDn
        ConfigNC        = $configNC
        DnsDomain       = $dnsRoot
        DsaGuid         = $dsaGuid
    }
}

# ============================================================
# REGION: REPLICATION PARTNERS
# ============================================================

function Test-PartnerReachable
{
    # Reachability for cleanup/convergence decisions. ICMP (Test-Connection) is unreliable in
    # segmented networks where ping is blocked but LDAP/RPC are open, which would wrongly mark
    # live partners as down and skip the authoritative sweep. Probe a service port instead and
    # fall back to ICMP only if the port tests are inconclusive.
    param
    (
        [string]$ComputerName
    )

    $ports = @(389, 135)

    foreach ($port in $ports)
    {
        $client = $null

        try
        {
            $client = New-Object System.Net.Sockets.TcpClient
            $async  = $client.BeginConnect($ComputerName, $port, $null, $null)
            $wait   = $async.AsyncWaitHandle.WaitOne(2000, $false)

            if ($wait -and $client.Connected)
            {
                $client.EndConnect($async)
                return $true
            }
        }
        catch
        {
            # Port not reachable; try the next one.
        }
        finally
        {
            if ($client)
            {
                $client.Close()
            }
        }
    }

    try
    {
        return [bool](Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)
    }
    catch
    {
        return $false
    }
}

function Get-TargetReplicationPartners
{
    param
    (
        [string]$TargetName
    )

    $partners = New-Object System.Collections.Generic.List[object]
    $rawMeta  = @()

    try
    {
        $rawMeta = @(Get-ADReplicationPartnerMetadata -Target $TargetName -PartnerType Both -Partition '*' -ErrorAction Stop)
    }
    catch
    {
        Write-WarnMsg "Full partner metadata query failed; retrying with defaults: $($_.Exception.Message)"

        try
        {
            $rawMeta = @(Get-ADReplicationPartnerMetadata -Target $TargetName -ErrorAction Stop)
        }
        catch
        {
            Write-WarnMsg "Replication partner metadata query failed entirely: $($_.Exception.Message)"
            $rawMeta = @()
        }
    }

    $seen = @{}

    foreach ($entry in $rawMeta)
    {
        $partnerDn = $entry.Partner

        if ([string]::IsNullOrWhiteSpace($partnerDn))
        {
            continue
        }

        $serverShort = $null
        $parts       = $partnerDn -split ','

        foreach ($p in $parts)
        {
            $trimmed = $p.Trim()

            if ($trimmed -like 'CN=*' -and $trimmed -notlike 'CN=NTDS Settings*')
            {
                $serverShort = ($trimmed -replace '^CN=', '').Trim()
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($serverShort))
        {
            continue
        }

        if ($seen.ContainsKey($serverShort))
        {
            continue
        }

        $seen[$serverShort] = $true

        $hostName = $serverShort
        $site     = 'Unknown'

        try
        {
            $pdc      = Get-ADDomainController -Identity $serverShort -ErrorAction Stop
            $hostName = $pdc.HostName
            $site     = $pdc.Site
        }
        catch
        {
            Write-WarnMsg "Could not resolve partner '$serverShort' to a domain controller object."
        }

        $reachable = $false

        try
        {
            $reachable = Test-PartnerReachable -ComputerName $hostName
        }
        catch
        {
            $reachable = $false
        }

        $partnerRecord =
        [pscustomobject]@{
            PartnerServer = $serverShort
            PartnerHost   = $hostName
            PartnerSite   = $site
            PartnerType   = $entry.PartnerType
            Partition     = ($entry.Partition -replace ',.*$', '')
            LastResult    = $entry.LastReplicationResult
            LastSuccess   = $entry.LastReplicationSuccess
            Reachable     = $reachable
        }

        $partners.Add($partnerRecord)

        $reachLabel = if ($reachable) { 'reachable' } else { 'UNREACHABLE' }
        Write-InfoMsg "    Partner: $hostName (site: $site, $reachLabel)"
    }

    return $partners
}

function Export-PartnerInventory
{
    param
    (
        [object]$Partners
    )

    if (-not $Partners -or @($Partners).Count -eq 0)
    {
        Write-WarnMsg "No replication partners to export."
        return
    }

    try
    {
        $Partners | Export-Csv -Path $PartnerCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-SuccessMsg "Replication partner inventory written to '$PartnerCsvPath'."
    }
    catch
    {
        Write-ErrorMsg "Failed to export partner inventory: $($_.Exception.Message)"
    }
}

# ============================================================
# REGION: CLEANUP DC SELECTION
# ============================================================

function Get-CleanupDC
{
    param
    (
        [object]$Partners,
        [string]$TargetHost,
        [string]$TargetSite
    )

    $sameSite = @($Partners | Where-Object { $_.Reachable -and $_.PartnerSite -eq $TargetSite -and $_.PartnerHost -ne $TargetHost })

    foreach ($c in $sameSite)
    {
        Write-SuccessMsg "Selected same-site replication partner for cleanup: $($c.PartnerHost)"
        return $c.PartnerHost
    }

    $anyPartner = @($Partners | Where-Object { $_.Reachable -and $_.PartnerHost -ne $TargetHost })

    foreach ($c in $anyPartner)
    {
        Write-SuccessMsg "Selected replication partner for cleanup: $($c.PartnerHost)"
        return $c.PartnerHost
    }

    Write-WarnMsg "No reachable replication partner found; scanning all domain controllers."

    $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop

    foreach ($dc in ($allDCs | Where-Object { $_.HostName -ne $TargetHost }))
    {
        if (Test-PartnerReachable -ComputerName $dc.HostName)
        {
            Write-SuccessMsg "Selected fallback domain controller for cleanup: $($dc.HostName)"
            return $dc.HostName
        }
    }

    throw "No reachable domain controllers are available to perform metadata cleanup."
}

# ============================================================
# REGION: METADATA CLEANUP
# ============================================================

function Remove-LeftoverObjects
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$CleanupDC
    )

    try
    {
        $comp = Get-ADComputer -Filter "Name -eq '$($TargetInfo.ShortName)'" -Server $CleanupDC -ErrorAction Stop

        if ($null -eq $comp)
        {
            Write-InfoMsg "No residual computer object to remove (already cleaned or never present)."
        }
        else
        {
            Write-WarnMsg "Residual computer object found; removing '$($comp.DistinguishedName)'."

            $removeCompParams =
            @{
                Identity    = $comp.DistinguishedName
                Server      = $CleanupDC
                Recursive   = $true
                Confirm     = $false
                ErrorAction = 'Stop'
            }

            Remove-ADObject @removeCompParams
            Write-SuccessMsg "Removed residual computer object."
        }
    }
    catch
    {
        Write-InfoMsg "No residual computer object to remove (already cleaned or never present)."
    }

    try
    {
        $srv = Get-ADObject -Identity $TargetInfo.ServerObjectDN -Server $CleanupDC -ErrorAction Stop
        Write-WarnMsg "Residual server object found; removing '$($srv.DistinguishedName)'."

        $removeSrvParams =
        @{
            Identity    = $srv.DistinguishedName
            Server      = $CleanupDC
            Recursive   = $true
            Confirm     = $false
            ErrorAction = 'Stop'
        }

        Remove-ADObject @removeSrvParams
        Write-SuccessMsg "Removed residual server object."
    }
    catch
    {
        Write-InfoMsg "No residual server object to remove (already cleaned or never present)."
    }

    if ($DnsManagedExternally)
    {
        Show-ExternalDnsCleanupReminder -TargetInfo $TargetInfo
    }
    else
    {
        try
        {
            if (Get-Module -ListAvailable -Name DnsServer)
            {
                Import-Module DnsServer -ErrorAction Stop

                $zone = $TargetInfo.DnsDomain
                $name = $TargetInfo.ShortName

                $records = @(Get-DnsServerResourceRecord -ComputerName $CleanupDC -ZoneName $zone -Name $name -RRType A -ErrorAction Stop)

                foreach ($r in $records)
                {
                    $removeDnsParams =
                    @{
                        ComputerName = $CleanupDC
                        ZoneName     = $zone
                        InputObject  = $r
                        Force        = $true
                        ErrorAction  = 'Stop'
                    }

                    Remove-DnsServerResourceRecord @removeDnsParams
                    Write-SuccessMsg "Removed DNS A record for '$name' in zone '$zone'."
                }
            }
            else
            {
                Write-InfoMsg "DnsServer module not available; skipping DNS record cleanup."
            }
        }
        catch
        {
            Write-InfoMsg "No DNS A record removed (already cleaned or not present): $($_.Exception.Message)"
        }

        Write-WarnMsg "Review DNS _msdcs SRV/CNAME records and Sites/Subnets for residual references; scavenging may be required."
    }
}

function Show-ExternalDnsCleanupReminder
{
    # DNS is hosted on InfoBlox (not the DCs) with no programmatic write path, so the records
    # below must be deleted manually. Listed explicitly because the _msdcs GUID alias in
    # particular is hard to locate after the fact.
    param
    (
        [hashtable]$TargetInfo
    )

    $fqdn   = "$($TargetInfo.ShortName).$($TargetInfo.DnsDomain)"
    $msdcs  = "$($TargetInfo.DsaGuid)._msdcs.$($TargetInfo.DnsDomain)"

    Write-WarnMsg "DNS is managed externally ($ExternalDnsName) - delete the following records manually:"
    Write-WarnMsg "    InfoBlox servers : $($ExternalDnsServers -join ', ')"
    Write-WarnMsg "    Host (A/AAAA)    : $fqdn  ->  $($TargetInfo.IPv4)"
    Write-WarnMsg "    Reverse (PTR)    : the PTR record for $($TargetInfo.IPv4)"
    Write-WarnMsg "    _msdcs CNAME     : $msdcs"
    Write-WarnMsg "    SRV records      : _ldap/_kerberos/_gc and related SRV entries referencing '$($TargetInfo.ShortName)' under _msdcs.$($TargetInfo.DnsDomain) and the _sites/_tcp/_udp trees"
    Write-WarnMsg "    NS records       : remove '$fqdn' from any zone name-server lists if present"
}

function Get-PartnerSiteServers
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$CleanupDC
    )

    # Servers container DN for the target's site = target server object DN minus its leading RDN.
    $searchBase = $TargetInfo.ServerObjectDN -replace '^CN=[^,]+,', ''

    try
    {
        $servers = @(Get-ADObject -Server $CleanupDC -SearchBase $searchBase -LDAPFilter '(objectClass=server)' -ErrorAction Stop)
        return $servers
    }
    catch
    {
        Write-WarnMsg "Could not enumerate the Servers container for site '$($TargetInfo.Site)' on '$CleanupDC': $($_.Exception.Message)"
        return @()
    }
}

function Test-TargetInPartnerSite
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$CleanupDC
    )

    $servers = Get-PartnerSiteServers -TargetInfo $TargetInfo -CleanupDC $CleanupDC
    $names   = @($servers | ForEach-Object { $_.Name })

    if ($names.Count -gt 0)
    {
        Write-InfoMsg "Servers in site '$($TargetInfo.Site)' as seen by '$CleanupDC': $($names -join ', ')"
    }
    else
    {
        Write-InfoMsg "No server objects enumerated in site '$($TargetInfo.Site)' from '$CleanupDC'."
    }

    return ($names -contains $TargetInfo.ShortName)
}

function Test-TargetDsaPresent
{
    # A graceful demotion authoritatively deletes the target's NTDS Settings (nTDSDSA) object and
    # replicates that deletion out. The parent server object can linger empty and is cleaned
    # separately, so NTDS Settings absence - not server-object absence - is the accurate "the
    # demotion has replicated to this partner" signal for convergence.
    param
    (
        [hashtable]$TargetInfo,
        [string]$CleanupDC
    )

    $ntdsDn = "CN=NTDS Settings,$($TargetInfo.ServerObjectDN)"

    try
    {
        $obj = Get-ADObject -Identity $ntdsDn -Server $CleanupDC -ErrorAction Stop
        return ($null -ne $obj)
    }
    catch
    {
        return $false
    }
}

function Invoke-NtdsUtilCleanup
{
    # Best-effort only. The authoritative removal is performed by Remove-LeftoverObjects
    # (Remove-ADObject) against the selected surviving partner. ntdsutil, by contrast, is run on
    # the LOCAL script-host DC and binds to localhost (no "on <server>" clause) because the inline
    # "on <partner>" form fails to bind a domain context ("Unable to determine the domain hosted by
    # the Active Directory Domain Controller"), as observed in the field. Messaging names the local
    # host explicitly so the bind target is never confused with the partner chosen for the
    # authoritative Remove-ADObject pass. ntdsutil is launched through Invoke-ElevatedScript so it
    # runs elevated in a separate real console (conhost) rather than in the host shell - this keeps
    # the interactive console tool out of the ISE pseudo-console, where it can hang.
    param
    (
        [hashtable]$TargetInfo
    )

    $localDc = $env:COMPUTERNAME

    $ntdsBlock =
    {
        param
        (
            [string]$ServerObjectDN
        )

        $ntdsArgs =
        @(
            'metadata cleanup'
            "remove selected server $ServerObjectDN"
            'quit'
            'quit'
        )

        & ntdsutil @ntdsArgs 2>&1
    }

    Write-InfoMsg "Launching ntdsutil elevated in a separate console (best-effort) on the local host '$localDc' for '$($TargetInfo.ServerObjectDN)'."

    try
    {
        $elevated = Invoke-ElevatedScript -ScriptBlock $ntdsBlock -ArgumentList @($TargetInfo.ServerObjectDN)

        foreach ($line in $elevated.StdOut)
        {
            Write-Log "    ntdsutil: $line"
        }

        if (-not $elevated.Launched)
        {
            Write-WarnMsg "ntdsutil could not be launched elevated on '$localDc' (best-effort): $($elevated.Error)"
            return 'Failed'
        }

        $exit     = $elevated.ExitCode
        $hadError = [bool]($elevated.StdOut | Where-Object { $_ -match 'error|failed|denied|No Such Object|Unable to' })

        if ((($exit -eq 0) -or ($null -eq $exit)) -and (-not $hadError))
        {
            Write-SuccessMsg "ntdsutil metadata cleanup reported success (best-effort; ran elevated on '$localDc')."
            return 'Succeeded'
        }

        Write-WarnMsg "ntdsutil metadata cleanup reported an error (best-effort; ran elevated on '$localDc'; see log). Authoritative removal continues."
        return 'Failed'
    }
    catch
    {
        Write-WarnMsg "ntdsutil could not be run on '$localDc' (best-effort): $($_.Exception.Message)"
        return 'Failed'
    }
}

function Invoke-PartnerCleanupSweep
{
    # Per user direction: regardless of the single-DC logic, check EVERY reachable
    # replication partner. For each, verify whether the target still appears in its
    # site listing; if so, remove the residual objects against that partner; then
    # re-verify. Returns one result object per partner that was actually checked.
    param
    (
        [hashtable]$TargetInfo,
        [object]$Partners
    )

    $checks    = New-Object System.Collections.Generic.List[object]
    $reachable = @($Partners | Where-Object { $_.Reachable -and $_.PartnerHost -ne $TargetInfo.HostName })

    if ($reachable.Count -eq 0)
    {
        Write-WarnMsg "No reachable replication partners available to sweep."
        return $checks
    }

    Write-InfoMsg "Sweeping all $($reachable.Count) reachable replication partner(s) for residual metadata."

    foreach ($p in $reachable)
    {
        $dc = $p.PartnerHost
        Write-InfoMsg "Checking partner '$dc'."
        $before = Test-TargetInPartnerSite -TargetInfo $TargetInfo -CleanupDC $dc

        if ($before)
        {
            Write-WarnMsg "Partner '$dc' still lists '$($TargetInfo.ShortName)' - removing residual objects there."
            Remove-LeftoverObjects -TargetInfo $TargetInfo -CleanupDC $dc
        }
        else
        {
            Write-InfoMsg "Partner '$dc' does not list '$($TargetInfo.ShortName)'."
        }

        $after = Test-TargetInPartnerSite -TargetInfo $TargetInfo -CleanupDC $dc

        if ($after)
        {
            Write-ErrorMsg "Partner '$dc' STILL lists '$($TargetInfo.ShortName)' after removal."
        }

        $checks.Add(
            [pscustomobject]@{
                PartnerHost   = $dc
                PresentBefore = $before
                PresentAfter  = $after
            }
        )
    }

    return $checks
}

function Wait-ForMetadataConvergence
{
    # Graceful-path helper. A graceful demotion removes the target's metadata at the SOURCE; this
    # waits for that deletion to replicate out to every reachable partner instead of forcing the
    # objects out. Polls each partner's site listing until the target is gone everywhere or the
    # timeout elapses. Returns Converged plus the set of partners that were still showing the
    # target when the wait ended.
    param
    (
        [hashtable]$TargetInfo,
        [object]$Partners,
        [int]$TimeoutSeconds,
        [int]$PollSeconds
    )

    $reachable = @($Partners | Where-Object { $_.Reachable -and $_.PartnerHost -ne $TargetInfo.HostName })

    if ($reachable.Count -eq 0)
    {
        Write-WarnMsg "No reachable replication partners available to confirm convergence."
        return [pscustomobject]@{ Converged = $false; Waited = 0; StillPresentOn = @() }
    }

    $deadline     = (Get-Date).AddSeconds($TimeoutSeconds)
    $elapsed      = 0
    $stillPresent = @()

    while ($true)
    {
        $stillPresent = @()

        foreach ($p in $reachable)
        {
            if (Test-TargetDsaPresent -TargetInfo $TargetInfo -CleanupDC $p.PartnerHost)
            {
                $stillPresent += $p.PartnerHost
            }
        }

        if ($stillPresent.Count -eq 0)
        {
            Write-SuccessMsg "Graceful demotion converged - '$($TargetInfo.ShortName)' is gone from all $($reachable.Count) reachable partner(s) after $elapsed second(s)."
            return [pscustomobject]@{ Converged = $true; Waited = $elapsed; StillPresentOn = @() }
        }

        if ((Get-Date) -ge $deadline)
        {
            Write-WarnMsg "Convergence timed out after $elapsed second(s); '$($TargetInfo.ShortName)' still present on: $($stillPresent -join ', ')."
            return [pscustomobject]@{ Converged = $false; Waited = $elapsed; StillPresentOn = @($stillPresent) }
        }

        Write-InfoMsg "Awaiting replication convergence; '$($TargetInfo.ShortName)' still present on $($stillPresent.Count) partner(s): $($stillPresent -join ', '). Re-checking in $PollSeconds second(s)."
        Start-Sleep -Seconds $PollSeconds
        $elapsed += $PollSeconds
    }
}

function Invoke-MetadataCleanup
{
    # -Graceful selects the verify/converge path used after a successful graceful demotion: the
    # source DC has already removed its own metadata, so this confirms the deletion replicates out
    # (optionally accelerated by a syncall) and only removes objects authoritatively if convergence
    # times out. ntdsutil is never used in graceful mode. Without -Graceful (forced removal, failed
    # demotion, or an explicit operator-driven cleanup) the full ntdsutil + authoritative removal +
    # partner sweep runs, because a ForceRemoval leaves the domain-side metadata behind.
    param
    (
        [hashtable]$TargetInfo,
        [object]$Partners,
        [switch]$Graceful
    )

    if ($DryRun)
    {
        $modeText = if ($Graceful) { 'verify/converge (graceful)' } else { 'full ntdsutil + authoritative (forced/failed)' }
        Write-DryRunMsg "Would run metadata cleanup in $modeText mode for '$($TargetInfo.ShortName)'."
        return [pscustomobject]@{ Performed = $false; Mode = $modeText; CleanupDC = $null; Success = $false; NtdsUtilStatus = 'Skipped (dry run)'; PresentBefore = $null; PresentAfter = $null; PartnerChecks = @(); Detail = 'Dry run' }
    }

    # ----- Graceful path: confirm the source-side deletions replicate out; force objects only on timeout -----
    if ($Graceful)
    {
        Write-InfoMsg "Graceful demotion path - the source DC removed its own metadata; verifying replication convergence rather than forcing an ntdsutil cleanup."

        if ($GracefulConvergenceSyncFirst)
        {
            Invoke-ReplicationSync | Out-Null
        }

        $conv = Wait-ForMetadataConvergence -TargetInfo $TargetInfo -Partners $Partners -TimeoutSeconds $GracefulConvergenceWaitSeconds -PollSeconds $GracefulConvergencePollSeconds

        if ($conv.Converged)
        {
            # NTDS Settings deletion has replicated everywhere; the empty server object can still
            # linger, so run one sweep to drop any husk. This is non-destructive to live metadata.
            Write-InfoMsg "NTDS Settings deletion has replicated to all partners; sweeping any lingering empty server object(s)."
            $partnerChecks = Invoke-PartnerCleanupSweep -TargetInfo $TargetInfo -Partners $Partners
            $stillPresent  = @($partnerChecks | Where-Object { $_.PresentAfter })
            $success       = ($stillPresent.Count -eq 0)

            if ($success)
            {
                Write-SuccessMsg "Verified: '$($TargetInfo.ShortName)' no longer appears on any swept replication partner."
            }
            else
            {
                Write-ErrorMsg "Target '$($TargetInfo.ShortName)' still appears on $($stillPresent.Count) partner(s) after the husk sweep."
            }

            return [pscustomobject]@{
                Performed      = $true
                Mode           = 'Graceful (verified converged)'
                CleanupDC      = $null
                Success        = $success
                NtdsUtilStatus = 'Skipped (graceful - source removed metadata)'
                PresentBefore  = $true
                PresentAfter   = ($stillPresent.Count -gt 0)
                PartnerChecks  = @($partnerChecks)
                Detail         = "DSA deletion converged after $($conv.Waited)s; lingering server object(s) swept; partners still present=$($stillPresent.Count)."
            }
        }

        Write-WarnMsg "Graceful deletions did not fully converge within $($GracefulConvergenceWaitSeconds)s - removing the lingering object(s) authoritatively (still no ntdsutil)."
        $partnerChecks = Invoke-PartnerCleanupSweep -TargetInfo $TargetInfo -Partners $Partners
        $stillPresent  = @($partnerChecks | Where-Object { $_.PresentAfter })
        $success       = ($stillPresent.Count -eq 0)

        if ($success)
        {
            Write-SuccessMsg "Verified: '$($TargetInfo.ShortName)' no longer appears on any swept replication partner."
        }
        else
        {
            Write-ErrorMsg "Target '$($TargetInfo.ShortName)' still appears on $($stillPresent.Count) partner(s) after authoritative removal."
        }

        return [pscustomobject]@{
            Performed      = $true
            Mode           = 'Graceful (convergence timed out; authoritative sweep)'
            CleanupDC      = $null
            Success        = $success
            NtdsUtilStatus = 'Skipped (graceful - source removed metadata)'
            PresentBefore  = $true
            PresentAfter   = ($stillPresent.Count -gt 0)
            PartnerChecks  = @($partnerChecks)
            Detail         = "Convergence timed out after $($conv.Waited)s; authoritative removal applied; partners still present=$($stillPresent.Count)."
        }
    }

    # ----- Forced / failed / explicit path: full ntdsutil + authoritative removal + partner sweep -----
    $cleanupDC = Get-CleanupDC -Partners $Partners -TargetHost $TargetInfo.HostName -TargetSite $TargetInfo.Site

    # Dynamic pre-check: does the target still exist in this partner's Servers listing for the site?
    Write-InfoMsg "Verifying whether '$($TargetInfo.ShortName)' still exists in site '$($TargetInfo.Site)' per '$cleanupDC'."
    $presentBefore = Test-TargetInPartnerSite -TargetInfo $TargetInfo -CleanupDC $cleanupDC

    $ntdsStatus = 'Skipped (target absent)'

    if ($presentBefore)
    {
        # Best-effort ntdsutil pass (status reported, never gates success). This runs on the local
        # script-host DC and binds to localhost; it is intentionally separate from the partner-
        # targeted authoritative Remove-ADObject step below.
        Write-InfoMsg "Running ntdsutil metadata cleanup (best-effort) on the local host '$($env:COMPUTERNAME)' for '$($TargetInfo.ServerObjectDN)' (authoritative Remove-ADObject runs against '$cleanupDC' next)."
        $ntdsStatus = Invoke-NtdsUtilCleanup -TargetInfo $TargetInfo
    }
    else
    {
        Write-WarnMsg "Target no longer present in the primary partner's site listing - skipping ntdsutil; running authoritative object removal only."
    }

    # Authoritative removal: server object (recursive, incl. NTDS Settings) + computer + DNS,
    # performed against the chosen surviving partner. This is the primary cleanup mechanism.
    Write-InfoMsg "Performing authoritative metadata removal via Remove-ADObject against '$cleanupDC'."
    Remove-LeftoverObjects -TargetInfo $TargetInfo -CleanupDC $cleanupDC

    # Peace-of-mind sweep: check (and clean) EVERY reachable replication partner.
    $partnerChecks = Invoke-PartnerCleanupSweep -TargetInfo $TargetInfo -Partners $Partners

    # Dynamic post-check on the primary partner.
    Write-InfoMsg "Re-verifying the primary partner's site listing after cleanup."
    $presentAfter = Test-TargetInPartnerSite -TargetInfo $TargetInfo -CleanupDC $cleanupDC

    # Success is judged by verification across the primary partner AND every swept partner,
    # NOT by ntdsutil. ntdsutil's own status is reported separately so a real ntdsutil error
    # stays visible even when the authoritative removal succeeded.
    $stillPresent = @($partnerChecks | Where-Object { $_.PresentAfter })
    $success      = (-not $presentAfter) -and ($stillPresent.Count -eq 0)

    if (-not $success)
    {
        Write-ErrorMsg "Target '$($TargetInfo.ShortName)' still appears on $($stillPresent.Count) partner(s) and/or the primary DC after cleanup."
    }
    else
    {
        Write-SuccessMsg "Verified: '$($TargetInfo.ShortName)' no longer appears on the primary DC or any swept replication partner."
    }

    if ($ntdsStatus -eq 'Failed')
    {
        Write-WarnMsg "Note: ntdsutil reported an error but the authoritative Remove-ADObject path completed the cleanup."
    }

    return [pscustomobject]@{
        Performed      = $true
        Mode           = 'Forced (ntdsutil + authoritative)'
        CleanupDC      = $cleanupDC
        Success        = $success
        NtdsUtilStatus = $ntdsStatus
        PresentBefore  = $presentBefore
        PresentAfter   = $presentAfter
        PartnerChecks  = @($partnerChecks)
        Detail         = "ntdsutil=$ntdsStatus (local host $($env:COMPUTERNAME)); authoritative partner=$cleanupDC; primary presentAfter=$presentAfter; partners still present=$($stillPresent.Count)"
    }
}

# ============================================================
# REGION: PARTNER CONNECTION TEARDOWN
# ============================================================

function Get-RemovedServerNtdsDn
{
    # The demoted DC's own NTDS Settings (nTDSDSA) DN. Every surviving partner that still
    # replicates FROM the removed DC carries this DN in the fromServer attribute of an inbound
    # nTDSConnection object until the KCC recomputes topology and tears the connection down.
    param
    (
        [hashtable]$TargetInfo
    )

    return "CN=NTDS Settings,$($TargetInfo.ServerObjectDN)"
}

function Get-StaleInboundConnections
{
    # Forest-wide topology check. Enumerates every nTDSConnection in the Configuration NC whose
    # fromServer still references the removed DC's NTDS Settings DN - i.e. a surviving DC that has
    # not yet dropped its replication link FROM the demoted server. The owning (destination) DC and
    # site are parsed from each connection's own DN so the operator sees exactly who still points at
    # the removed server. The Configuration NC is forest-replicated, so a single read against a
    # converged acting DC reflects the whole forest once convergence has occurred. The textual DN is
    # retained on the connection even after the referenced NTDS Settings object is deleted, so an
    # exact-match filter still locates the lingering connection. DC and site names in this forest do
    # not contain LDAP filter metacharacters, so the DN is used in the filter without escaping.
    param
    (
        [hashtable]$TargetInfo,
        [string]$ActingDC
    )

    $ntdsDn    = Get-RemovedServerNtdsDn -TargetInfo $TargetInfo
    $sitesBase = "CN=Sites,$($TargetInfo.ConfigNC)"
    $found     = New-Object System.Collections.Generic.List[object]
    $filter    = "(&(objectClass=nTDSConnection)(fromServer=$ntdsDn))"

    try
    {
        $conns = @(Get-ADObject -Server $ActingDC -SearchBase $sitesBase -SearchScope Subtree -LDAPFilter $filter -Properties fromServer -ErrorAction Stop)
    }
    catch
    {
        Write-WarnMsg "Could not enumerate inbound connection objects from '$ActingDC': $($_.Exception.Message)"
        return $found
    }

    foreach ($c in $conns)
    {
        $owningServer = 'Unknown'
        $owningSite   = 'Unknown'

        if ($c.DistinguishedName -match ',CN=NTDS Settings,CN=(?<srv>[^,]+),CN=Servers,CN=(?<site>[^,]+),CN=Sites,')
        {
            $owningServer = $Matches['srv']
            $owningSite   = $Matches['site']
        }

        $found.Add(
            [pscustomobject]@{
                OwningServer = $owningServer
                OwningSite   = $owningSite
                ConnectionDN = $c.DistinguishedName
                FromServer   = $c.fromServer
            }
        )
    }

    return $found
}

function Test-PartnerStillSourcesTarget
{
    # Live replication-link check for a single surviving partner. Asks the partner (via
    # Get-ADReplicationPartnerMetadata -PartnerType Inbound) for its inbound partners and reports
    # whether the removed server still appears as a source. This reflects the partner's actual
    # repsFrom state rather than only the topology objects, so it answers "has THIS partner released
    # the demoted DC?" directly. Matching is by short name and, when known, DSA GUID - which also
    # catches a deleted-object partner DN whose RDN still embeds the original name. Returns $true,
    # $false, or $null when the partner's metadata could not be read.
    param
    (
        [hashtable]$TargetInfo,
        [string]$PartnerHost
    )

    $meta = $null

    try
    {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $PartnerHost -PartnerType Inbound -Partition '*' -ErrorAction Stop)
    }
    catch
    {
        try
        {
            $meta = @(Get-ADReplicationPartnerMetadata -Target $PartnerHost -PartnerType Inbound -ErrorAction Stop)
        }
        catch
        {
            Write-WarnMsg "Could not read inbound replication metadata from '$PartnerHost': $($_.Exception.Message)"
            return $null
        }
    }

    $needleName = $TargetInfo.ShortName
    $needleGuid = $TargetInfo.DsaGuid

    foreach ($m in $meta)
    {
        $partnerDn = "$($m.Partner)"

        if ($partnerDn -match [regex]::Escape($needleName))
        {
            return $true
        }

        if (-not [string]::IsNullOrWhiteSpace($needleGuid) -and $needleGuid -ne 'unknown' -and $partnerDn -match [regex]::Escape($needleGuid))
        {
            return $true
        }
    }

    return $false
}

function Invoke-KccRefresh
{
    # Forces the KCC on each reachable surviving partner to recompute the replication topology now
    # (repadmin /kcc <partner>), which drops connection objects that reference the removed DSA
    # instead of waiting for the next scheduled KCC pass (~15 min). Honors $DryRun. Best-effort: a
    # partner that does not respond is logged and skipped. With no reachable partners it falls back
    # to an enterprise-wide 'repadmin /kcc *'.
    param
    (
        [object]$Partners
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would force the KCC (repadmin /kcc) on each reachable surviving partner to recompute topology."
        return
    }

    $reachable = @($Partners | Where-Object { $_.Reachable })

    if ($reachable.Count -eq 0)
    {
        Write-WarnMsg "No reachable partners to refresh individually - issuing enterprise-wide 'repadmin /kcc *'."
        $out = & repadmin /kcc * 2>&1

        foreach ($line in $out)
        {
            Write-Log "    repadmin /kcc *: $line"
        }

        return
    }

    foreach ($p in $reachable)
    {
        Write-InfoMsg "Forcing KCC topology recalculation on '$($p.PartnerHost)'."

        try
        {
            $out = & repadmin /kcc $p.PartnerHost 2>&1

            foreach ($line in $out)
            {
                Write-Log "    repadmin /kcc $($p.PartnerHost): $line"
            }
        }
        catch
        {
            Write-WarnMsg "Could not trigger the KCC on '$($p.PartnerHost)': $($_.Exception.Message)"
        }
    }
}

function Confirm-PartnerConnectionTeardown
{
    # Operator-confidence gate answering "have all replication partners removed their connection to
    # the demoted server?" For every surviving reachable partner it combines three independent
    # signals, plus a forest topology check:
    #   1. NTDS Settings object absent on the partner (Test-TargetDsaPresent) - the source-side
    #      deletion has replicated in.
    #   2. The partner no longer lists the removed server as an inbound replication source
    #      (Test-PartnerStillSourcesTarget) - its live repsFrom link is gone.
    #   3. No nTDSConnection anywhere still references the removed DSA in fromServer
    #      (Get-StaleInboundConnections) - the KCC has torn the topology link down.
    # Optionally forces the KCC first, then polls on an interval until everything clears or the
    # timeout elapses (companion to Wait-ForMetadataConvergence, which only watches signal 1).
    # Returns a structured result for the console summary and the email report.
    param
    (
        [hashtable]$TargetInfo,
        [object]$Partners,
        [string]$ActingDC,
        [int]$TimeoutSeconds,
        [int]$PollSeconds,
        [switch]$ForceKcc
    )

    $reachable = @($Partners | Where-Object { $_.Reachable -and $_.PartnerHost -ne $TargetInfo.HostName })

    if ($reachable.Count -eq 0)
    {
        Write-WarnMsg "No reachable replication partners available to confirm connection teardown."
        return [pscustomobject]@{
            Checked        = $false
            Cleared        = $false
            Waited         = 0
            ForcedKcc      = $false
            DsaPresentOn   = @()
            SourcingOn     = @()
            StaleConns     = @()
            PartnerResults = @()
            Detail         = 'No reachable partners to verify.'
        }
    }

    Write-InfoMsg "Verifying that all $($reachable.Count) reachable replication partner(s) have released '$($TargetInfo.ShortName)'."

    $forcedKcc = $false

    if ($ForceKcc)
    {
        Write-InfoMsg "Forcing the KCC on surviving partners to accelerate connection teardown before polling."
        Invoke-KccRefresh -Partners $reachable
        $forcedKcc = $true
    }

    $deadline       = (Get-Date).AddSeconds($TimeoutSeconds)
    $elapsed        = 0
    $dsaPresentOn   = @()
    $sourcingOn     = @()
    $staleConns     = @()
    $partnerResults = @()

    while ($true)
    {
        $dsaPresentOn   = @()
        $sourcingOn     = @()
        $partnerResults = New-Object System.Collections.Generic.List[object]

        foreach ($p in $reachable)
        {
            $dsaPresent = Test-TargetDsaPresent -TargetInfo $TargetInfo -CleanupDC $p.PartnerHost
            $sources    = Test-PartnerStillSourcesTarget -TargetInfo $TargetInfo -PartnerHost $p.PartnerHost

            if ($dsaPresent)
            {
                $dsaPresentOn += $p.PartnerHost
            }

            if ($sources -eq $true)
            {
                $sourcingOn += $p.PartnerHost
            }

            $cleared = (-not $dsaPresent) -and ($sources -ne $true)

            $partnerResults.Add(
                [pscustomobject]@{
                    PartnerHost = $p.PartnerHost
                    PartnerSite = $p.PartnerSite
                    DsaPresent  = $dsaPresent
                    StillSource = ($sources -eq $true)
                    Cleared     = $cleared
                }
            )
        }

        $staleConns = @(Get-StaleInboundConnections -TargetInfo $TargetInfo -ActingDC $ActingDC)
        $allClear   = (($dsaPresentOn.Count -eq 0) -and ($sourcingOn.Count -eq 0) -and ($staleConns.Count -eq 0))

        if ($allClear)
        {
            Write-SuccessMsg "All reachable partners have released '$($TargetInfo.ShortName)' - no residual NTDS Settings, inbound source links, or connection objects remain (after $elapsed second(s))."
            break
        }

        if ((Get-Date) -ge $deadline)
        {
            if ($dsaPresentOn.Count -gt 0)
            {
                Write-WarnMsg "NTDS Settings still present on: $($dsaPresentOn -join ', ')."
            }

            if ($sourcingOn.Count -gt 0)
            {
                Write-WarnMsg "Still listing '$($TargetInfo.ShortName)' as an inbound source: $($sourcingOn -join ', ')."
            }

            if ($staleConns.Count -gt 0)
            {
                Write-WarnMsg "Lingering inbound connection object(s) referencing '$($TargetInfo.ShortName)':"

                foreach ($sc in $staleConns)
                {
                    Write-WarnMsg "    on $($sc.OwningServer) (site $($sc.OwningSite)): $($sc.ConnectionDN)"
                }
            }

            Write-WarnMsg "Connection teardown not fully confirmed within $($TimeoutSeconds)s. The KCC removes these automatically on its next pass (~15 min); re-run this check (menu option 15) to confirm, or continue if the demotion itself succeeded."
            break
        }

        Write-InfoMsg "Teardown still pending (DSA on $($dsaPresentOn.Count), sourcing on $($sourcingOn.Count), connections $($staleConns.Count)). Re-checking in $PollSeconds second(s)."
        Start-Sleep -Seconds $PollSeconds
        $elapsed += $PollSeconds
    }

    $dsaArray     = @($dsaPresentOn)
    $sourceArray  = @($sourcingOn)
    $staleArray   = @($staleConns)
    $partnerArray = @($partnerResults)

    $cleared = (($dsaArray.Count -eq 0) -and ($sourceArray.Count -eq 0) -and ($staleArray.Count -eq 0))
    $detail  = "Reachable partners checked=$($reachable.Count); DSA still present=$($dsaArray.Count); still sourcing=$($sourceArray.Count); lingering connections=$($staleArray.Count); KCC forced=$forcedKcc; waited=${elapsed}s."

    return [pscustomobject]@{
        Checked        = $true
        Cleared        = $cleared
        Waited         = $elapsed
        ForcedKcc      = $forcedKcc
        DsaPresentOn   = $dsaArray
        SourcingOn     = $sourceArray
        StaleConns     = $staleArray
        PartnerResults = $partnerArray
        Detail         = $detail
    }
}

# ============================================================
# REGION: REMOTE DEMOTION
# ============================================================

function Invoke-RemoteDemotion
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would remotely demote '$($TargetInfo.HostName)' via Uninstall-ADDSDomainController."
        return [pscustomobject]@{ Attempted = $false; Success = $true; ForceUsed = $false; PolicyRelaxed = $false; GcDisabled = $false; Error = 'Dry run'; RemediationTrail = @() }
    }

    $demoteBlock =
    {
        param
        (
            [string]$LocalAdminPasswordPlain,
            [bool]$IgnoreLastDnsServerForZone,
            [System.Management.Automation.PSCredential]$DemotionCredential
        )

        Import-Module ADDSDeployment -ErrorAction Stop

        $securePwd     = ConvertTo-SecureString -String $LocalAdminPasswordPlain -AsPlainText -Force
        $forceUsed     = $false
        $policyRelaxed = $false
        $gcDisabled    = $false
        $errText       = $null
        $ok            = $false
        $trail         = New-Object System.Collections.Generic.List[string]

        $workDir = Join-Path -Path $env:TEMP -ChildPath 'DCDemote'
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

        function Disable-GlobalCatalog
        {
            $root = [ADSI]'LDAP://RootDSE'
            $conf = $root.configurationNamingContext
            $site = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
            $name = $env:COMPUTERNAME

            $path = "LDAP://CN=NTDS Settings,CN=$name,CN=Servers,CN=$site,CN=Sites,$conf"
            $ntds = [ADSI]$path

            $current = $ntds.options.Value
            if ($null -eq $current)
            {
                $current = 0
            }

            # Clear only the IS_GC bit (0x1); -bnot is the bitwise complement.
            $ntds.options = $current -band (-bnot 1)
            $ntds.SetInfo()
        }

        $baseParams =
        @{
            LocalAdministratorPassword   = $securePwd
            DemoteOperationMasterRole    = $true
            RemoveApplicationPartitions  = $true
            NoRebootOnCompletion         = $true
            IgnoreLastDNSServerForZone   = $IgnoreLastDnsServerForZone
            Force                        = $true
            Confirm                      = $false
            ErrorAction                  = 'Stop'
        }

        # Explicit credential defeats the WinRM double-hop: the cmdlet binds to the surviving
        # partner with these credentials directly rather than via the non-delegable session token.
        if ($DemotionCredential)
        {
            $baseParams['Credential'] = $DemotionCredential
            $trail.Add("Using explicit -Credential for partner contact (user: $($DemotionCredential.UserName))")
        }
        else
        {
            $trail.Add("No explicit -Credential supplied - partner contact relies on the session token (double-hop applies)")
        }

        $maxAttempts = 5
        $attempt     = 0

        try
        {
            while ($true)
            {
                $attempt++

                if ($attempt -gt $maxAttempts)
                {
                    $errText = "Exceeded maximum demotion attempts ($maxAttempts). Last error: $errText"
                    break
                }

                try
                {
                    $params = $baseParams.Clone()

                    if ($forceUsed)
                    {
                        $params['ForceRemoval'] = $true
                    }

                    $mode = if ($forceUsed) { 'forced' } else { 'graceful' }
                    $trail.Add("Attempt ${attempt}: ${mode} Uninstall-ADDSDomainController")

                    # Suppress the cmdlet's own result object. If left on the pipeline it becomes a
                    # second output object alongside the status object below, turning the value
                    # returned to the parent into a multi-object collection and corrupting the
                    # ForceUsed/PolicyRelaxed/GcDisabled reads taken against it.
                    $null = Uninstall-ADDSDomainController @params
                    $ok = $true
                    $trail.Add("Attempt ${attempt}: succeeded (${mode})")
                    break
                }
                catch
                {
                    $msg     = $_.Exception.Message
                    $errText = $msg
                    $trail.Add("Attempt ${attempt}: error -> $msg")

                    if ($msg -match 'password|complex' -and -not $policyRelaxed)
                    {
                        Backup-SecurityPolicy
                        Relax-SecurityPolicy
                        $policyRelaxed = $true
                        $trail.Add("Attempt ${attempt}: matched password policy -> relaxed local SECURITYPOLICY, retrying")
                        continue
                    }

                    if ($msg -match 'global catalog' -and -not $gcDisabled)
                    {
                        Disable-GlobalCatalog
                        $gcDisabled = $true
                        $trail.Add("Attempt ${attempt}: matched global catalog -> cleared GC bit, retrying")
                        continue
                    }

                    # Only escalate to ForceRemoval on genuine "cannot reach a partner"
                    # failures - not on broad words like 'denied' or 'cannot', which appear
                    # in many recoverable messages and previously caused false escalation.
                    if ($msg -match 'RPC server is unavailable|could not be contacted|cannot be contacted|will not be contacted|server is not operational|no other (Active Directory )?domain controller' -and -not $forceUsed)
                    {
                        $forceUsed = $true
                        $trail.Add("Attempt ${attempt}: matched contact-failure -> escalating to ForceRemoval, retrying")
                        continue
                    }

                    $trail.Add("Attempt ${attempt}: no remediation matched -> giving up")
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
            Attempted       = $true
            Success         = $ok
            ForceUsed       = $forceUsed
            PolicyRelaxed   = $policyRelaxed
            GcDisabled      = $gcDisabled
            Error           = $errText
            RemediationTrail = @($trail)
        }
    }

    $demotionCred = $null

    if ($UseExplicitDemotionCredential)
    {
        $demotionCred = Get-DemotionCredential
    }

    if ($demotionCred)
    {
        Write-InfoMsg "Threading explicit credential '$($demotionCred.UserName)' into the remote demotion (defeats the partner-contact double-hop)."
    }
    else
    {
        Write-WarnMsg "Proceeding without an explicit demotion credential - a partner-contact failure may escalate a graceful demotion to ForceRemoval."
    }

    $icmParams =
    @{
        ComputerName = $TargetInfo.HostName
        ScriptBlock  = $demoteBlock
        ArgumentList = @($LocalAdminPasswordPlain, $IgnoreLastDnsServerForZone, $demotionCred)
        ErrorAction  = 'Stop'
    }

    try
    {
        $result = Invoke-Command @icmParams

        # Defense in depth: if anything inside the scriptblock ever emits stray pipeline output
        # again, $result would be a collection and every property read below would operate on it
        # rather than on the status object. Collapse to the single status-shaped object.
        $result = @($result) |
                  Where-Object { $_ -and $_.PSObject.Properties.Match('Success').Count -gt 0 } |
                  Select-Object -Last 1

        if ($result.RemediationTrail)
        {
            Write-InfoMsg "Demotion remediation trail:"
            foreach ($entry in $result.RemediationTrail)
            {
                Write-InfoMsg "    $entry"
            }
        }

        if ($result.Success)
        {
            $mode = if ($result.ForceUsed) { 'forced removal' } else { 'graceful demotion' }
            Write-SuccessMsg "Remote demotion succeeded on '$($TargetInfo.HostName)' ($mode)."

            if ($result.PolicyRelaxed)
            {
                Write-WarnMsg "Local password policy was temporarily relaxed on the target and then restored."
            }

            if ($result.GcDisabled)
            {
                Write-WarnMsg "Global Catalog flag was cleared on the target during demotion."
            }

            if ($result.ForceUsed)
            {
                Write-WarnMsg "ForceRemoval was used - review the remediation trail above to confirm the escalation was warranted."
            }
        }
        else
        {
            Write-ErrorMsg "Remote demotion failed on '$($TargetInfo.HostName)': $($result.Error)"
        }

        return $result
    }
    catch
    {
        Write-ErrorMsg "Remote demotion invocation failed: $($_.Exception.Message)"
        return [pscustomobject]@{ Attempted = $true; Success = $false; ForceUsed = $false; PolicyRelaxed = $false; GcDisabled = $false; Error = $_.Exception.Message; RemediationTrail = @() }
    }
}

function Restart-TargetDC
{
    param
    (
        [hashtable]$TargetInfo
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would reboot '$($TargetInfo.HostName)' to complete demotion."
        return
    }

    try
    {
        Restart-Computer -ComputerName $TargetInfo.HostName -Force -ErrorAction Stop
        Write-SuccessMsg "Reboot issued to '$($TargetInfo.HostName)'."
    }
    catch
    {
        Write-WarnMsg "Could not reboot '$($TargetInfo.HostName)': $($_.Exception.Message)"
    }
}

# ============================================================
# REGION: REPLICATION SYNC AND DOMAIN REMOVAL
# ============================================================

function Invoke-ReplicationSync
{
    if ($DryRun)
    {
        Write-DryRunMsg "Would run 'repadmin /syncall $RepadminSyncAllOptions' from '$($env:COMPUTERNAME)'."
        return [pscustomobject]@{ Ran = $false; Success = $false; Detail = 'Dry run' }
    }

    Write-InfoMsg "Running 'repadmin /syncall $RepadminSyncAllOptions' from '$($env:COMPUTERNAME)' (output captured to log)."

    $syncArgs =
    @(
        '/syncall'
        $RepadminSyncAllOptions
    )

    try
    {
        $output = & repadmin @syncArgs 2>&1
        $exit   = $LASTEXITCODE

        foreach ($line in $output)
        {
            Write-Log "    repadmin: $line"
        }

        if (($exit -eq 0) -or ($null -eq $exit))
        {
            Write-SuccessMsg "Replication sync (syncall $RepadminSyncAllOptions) completed."
            return [pscustomobject]@{ Ran = $true; Success = $true; Detail = "exit $exit" }
        }

        Write-WarnMsg "repadmin /syncall returned exit code $exit; review the log for details."
        return [pscustomobject]@{ Ran = $true; Success = $false; Detail = "exit $exit" }
    }
    catch
    {
        Write-WarnMsg "repadmin /syncall failed: $($_.Exception.Message)"
        return [pscustomobject]@{ Ran = $true; Success = $false; Detail = $_.Exception.Message }
    }
}

function Remove-ServerFromDomain
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$ActingDC
    )

    if ($DryRun)
    {
        Write-DryRunMsg "Would remove computer account '$($TargetInfo.ShortName)' from the domain via '$ActingDC'."
        return [pscustomobject]@{ Performed = $false; Success = $false; Detail = 'Dry run' }
    }

    if ([string]::IsNullOrWhiteSpace($ActingDC))
    {
        $ActingDC = $env:COMPUTERNAME
    }

    try
    {
        $comp = Get-ADComputer -Filter "Name -eq '$($TargetInfo.ShortName)'" -Server $ActingDC -ErrorAction Stop

        if ($null -eq $comp)
        {
            Write-InfoMsg "Computer account '$($TargetInfo.ShortName)' not found via '$ActingDC' (already removed)."
            return [pscustomobject]@{ Performed = $true; Success = $true; Detail = 'Account already absent' }
        }

        Write-InfoMsg "Removing domain computer account '$($comp.DistinguishedName)' via '$ActingDC'."

        $removeParams =
        @{
            Identity    = $comp.DistinguishedName
            Server      = $ActingDC
            Recursive   = $true
            Confirm     = $false
            ErrorAction = 'Stop'
        }

        Remove-ADObject @removeParams

        $stillThere = $false

        try
        {
            $check = Get-ADComputer -Filter "Name -eq '$($TargetInfo.ShortName)'" -Server $ActingDC -ErrorAction Stop
            $stillThere = ($null -ne $check)
        }
        catch
        {
            $stillThere = $false
        }

        if ($stillThere)
        {
            Write-ErrorMsg "Computer account '$($TargetInfo.ShortName)' still present after removal attempt."
            return [pscustomobject]@{ Performed = $true; Success = $false; Detail = 'Account still present after removal' }
        }

        Write-SuccessMsg "Computer account '$($TargetInfo.ShortName)' removed from the domain."
        return [pscustomobject]@{ Performed = $true; Success = $true; Detail = "Removed via $ActingDC" }
    }
    catch
    {
        Write-WarnMsg "Could not remove computer account '$($TargetInfo.ShortName)': $($_.Exception.Message)"
        return [pscustomobject]@{ Performed = $true; Success = $false; Detail = $_.Exception.Message }
    }
}

function Invoke-PostDemotionRemoval
{
    param
    (
        [hashtable]$TargetInfo,
        [string]$ActingDC
    )

    $syncResult    = [pscustomobject]@{ Ran = $false; Success = $false; Detail = 'Not run' }
    $removalResult = [pscustomobject]@{ Performed = $false; Success = $false; Detail = 'Not performed' }

    if ($RunSyncAllBeforeRemoval)
    {
        $syncResult = Invoke-ReplicationSync
    }

    if ($RemoveFromDomain)
    {
        $removalResult = Remove-ServerFromDomain -TargetInfo $TargetInfo -ActingDC $ActingDC
    }

    return [pscustomobject]@{
        Sync    = $syncResult
        Removal = $removalResult
    }
}

# ============================================================
# REGION: SESSION STATE
# ============================================================

function New-RunState
{
    return @{
        TargetDC       = ("$TargetDC").ToUpper()
        TargetInfo     = $null
        Partners       = $null
        DemotionResult = $null
        CleanupResult  = $null
        SyncResult     = $null
        RemovalResult  = $null
        ConnectionResult = $null
        ReadinessResult = $null
        OverallStatus  = 'No actions performed yet'
        StatusColor    = '#555555'
    }
}

function Resolve-TargetState
{
    if ($Script:State.TargetInfo)
    {
        return $true
    }

    if ([string]::IsNullOrWhiteSpace($Script:State.TargetDC))
    {
        Write-WarnMsg "No target domain controller is set. Choose 'Set / change target DC' first."
        return $false
    }

    try
    {
        $Script:State.TargetInfo = Get-TargetInfo -TargetName $Script:State.TargetDC
        Write-SuccessMsg "Resolved target '$($Script:State.TargetInfo.HostName)' (site: $($Script:State.TargetInfo.Site))."
        return $true
    }
    catch
    {
        Write-ErrorMsg "Could not resolve target '$($Script:State.TargetDC)': $($_.Exception.Message)"
        return $false
    }
}

function Import-LatestPartnerInventory
{
    try
    {
        $pattern = Join-Path -Path $LogDirectory -ChildPath "$($LogBaseName)_Partners_*.csv"
        $latest  = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if ($null -eq $latest)
        {
            return @()
        }

        Write-InfoMsg "Loaded a saved replication partner inventory from '$($latest.FullName)'."
        return @(Import-Csv -Path $latest.FullName)
    }
    catch
    {
        Write-WarnMsg "Could not import a saved partner inventory: $($_.Exception.Message)"
        return @()
    }
}

function Update-PartnerReachability
{
    param
    (
        [object]$Partners
    )

    foreach ($p in $Partners)
    {
        $live = $false

        try
        {
            $live = Test-PartnerReachable -ComputerName $p.PartnerHost
        }
        catch
        {
            $live = $false
        }

        $p.Reachable = $live
    }
}

function Get-StatePartners
{
    if ($Script:State.Partners -and @($Script:State.Partners).Count -gt 0)
    {
        return $Script:State.Partners
    }

    $imported = Import-LatestPartnerInventory

    if ($imported -and @($imported).Count -gt 0)
    {
        $Script:State.Partners = $imported
        return $imported
    }

    return $null
}

function Get-Confirmation
{
    param
    (
        [string]$Prompt
    )

    if ($DryRun)
    {
        Write-DryRunMsg "DRY RUN - auto-confirming: $Prompt"
        return $true
    }

    $answer = Read-Host "$Prompt [y/N]"
    return ($answer -match '^(y|yes)$')
}

function Get-ActingDC
{
    if ($Script:State.CleanupResult -and $Script:State.CleanupResult.CleanupDC)
    {
        return $Script:State.CleanupResult.CleanupDC
    }

    return $env:COMPUTERNAME
}

# ============================================================
# REGION: MENU ACTIONS
# ============================================================

function Set-MenuTargetDC
{
    $current = if ([string]::IsNullOrWhiteSpace($Script:State.TargetDC)) { '(none)' } else { $Script:State.TargetDC }
    Write-InfoMsg "Current target DC: $current"

    $entry = Read-Host "Enter the target DC name to demote/remove"

    if ([string]::IsNullOrWhiteSpace($entry))
    {
        Write-WarnMsg "No value entered; target unchanged."
        return
    }

    $Script:State.TargetDC   = $entry.Trim().ToUpper()
    $Script:State.TargetInfo = $null
    $Script:State.Partners   = $null
    Write-SuccessMsg "Target DC set to '$($Script:State.TargetDC)'. Cached details and partners cleared."
}

function Show-TargetInfo
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    $ti = $Script:State.TargetInfo

    Write-InfoMsg "Host name      : $($ti.HostName)"
    Write-InfoMsg "Short name     : $($ti.ShortName)"
    Write-InfoMsg "Site           : $($ti.Site)"
    Write-InfoMsg "IPv4           : $($ti.IPv4)"
    Write-InfoMsg "Global Catalog : $($ti.IsGlobalCatalog)"
    Write-InfoMsg "Operating Sys  : $($ti.OperatingSystem)"
    Write-InfoMsg "Server DN      : $($ti.ServerObjectDN)"
    Write-InfoMsg "Computer DN    : $($ti.ComputerDN)"
}

function Invoke-PartnerCapture
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    Write-InfoMsg "Capturing replication partners for '$($Script:State.TargetInfo.HostName)'."
    $Script:State.Partners = Get-TargetReplicationPartners -TargetName $Script:State.TargetInfo.HostName
    Export-PartnerInventory -Partners $Script:State.Partners
    Write-SuccessMsg "Captured $(@($Script:State.Partners).Count) replication partner(s)."
}

function Test-MenuPreflight
{
    if (-not (Resolve-TargetState))
    {
        return $false
    }

    try
    {
        $ti = $Script:State.TargetInfo

        if ($EnsureEndToEndReadiness)
        {
            $gate = Assert-DemotionReadiness -TargetInfo $ti
            $Script:State.ReadinessResult = $gate
            return $gate.Proceed
        }

        $ok = $true

        if (-not (Test-Prerequisites -TargetInfo $ti))
        {
            $ok = $false
        }

        if ($ok -and -not (Test-FsmoSafety -TargetInfo $ti))
        {
            $ok = $false
        }

        if ($ok -and -not (Test-TargetReplicationHealth -TargetInfo $ti))
        {
            $ok = $false
        }

        if ($ok)
        {
            Write-SuccessMsg "All pre-flight checks passed."
        }
        else
        {
            Write-WarnMsg "One or more pre-flight checks failed."
        }

        return $ok
    }
    catch
    {
        Write-ErrorMsg "Pre-flight checks errored and were failed closed: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-MenuDemotion
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    if (-not ($Script:State.Partners -and @($Script:State.Partners).Count -gt 0))
    {
        Write-InfoMsg "No partners captured yet - capturing now so they survive the demotion."
        Invoke-PartnerCapture
    }

    if ($EnsureEndToEndReadiness)
    {
        $gate = Assert-DemotionReadiness -TargetInfo $Script:State.TargetInfo
        $Script:State.ReadinessResult = $gate

        if (-not $gate.Proceed)
        {
            Write-ErrorMsg "Demotion readiness gate did not pass - aborting."
            $Script:State.OverallStatus = 'Aborted - demotion readiness gate failed'
            $Script:State.StatusColor   = '#c62828'
            return
        }
    }
    else
    {
        if (-not (Assert-ExecutionPrivileges))
        {
            return
        }

        $readiness = Test-DemotionReadiness -TargetInfo $Script:State.TargetInfo

        if ($readiness.IsLastDc)
        {
            Write-ErrorMsg "Refusing to demote the last domain controller in the domain. Aborting."
            $Script:State.OverallStatus = 'Aborted - target is the last DC in the domain'
            $Script:State.StatusColor   = '#c62828'
            return
        }
    }

    if ($EnsureDemotionReadiness -and $PreDemotionSync)
    {
        Invoke-PreDemotionSync -TargetInfo $Script:State.TargetInfo
    }

    if (-not (Get-Confirmation "Demote domain controller '$($Script:State.TargetInfo.HostName)'?"))
    {
        Write-InfoMsg "Demotion cancelled."
        return
    }

    $Script:State.DemotionResult = Invoke-RemoteDemotion -TargetInfo $Script:State.TargetInfo

    if ($Script:State.DemotionResult.Success)
    {
        $Script:State.OverallStatus = if ($Script:State.DemotionResult.ForceUsed) { 'Demotion completed via forced removal' } else { 'Demotion completed gracefully' }
        $Script:State.StatusColor   = if ($Script:State.DemotionResult.ForceUsed) { '#ef6c00' } else { '#2e7d32' }
    }
    else
    {
        $Script:State.OverallStatus = 'Demotion failed'
        $Script:State.StatusColor   = '#c62828'
    }
}

function Invoke-MenuMetadataCleanup
{
    if (-not (Assert-ExecutionPrivileges))
    {
        return
    }

    if (-not (Resolve-TargetState))
    {
        return
    }

    $partners = Get-StatePartners

    if ($null -eq $partners -or @($partners).Count -eq 0)
    {
        Write-WarnMsg "No replication partners are known for '$($Script:State.TargetInfo.HostName)'."
        Write-WarnMsg "Cleanup will fall back to scanning all reachable domain controllers."
        $partners = New-Object System.Collections.Generic.List[object]
    }
    else
    {
        Write-InfoMsg "Using $(@($partners).Count) known replication partner(s); refreshing live reachability."
        Update-PartnerReachability -Partners $partners
    }

    $dr           = $Script:State.DemotionResult
    $gracefulMode = ($dr -and $dr.Success -and (-not $dr.ForceUsed))

    if ($gracefulMode)
    {
        Write-InfoMsg "Recorded demotion was graceful - cleanup will verify/converge (no ntdsutil) and remove objects only if convergence times out."
    }
    elseif ($dr -and $dr.ForceUsed)
    {
        Write-InfoMsg "Recorded demotion used forced removal - cleanup will run the full ntdsutil + authoritative removal."
    }
    else
    {
        Write-InfoMsg "No graceful demotion is recorded for this target - cleanup will run the full ntdsutil + authoritative removal."
    }

    if (-not (Get-Confirmation "Run metadata cleanup for '$($Script:State.TargetInfo.ShortName)'?"))
    {
        Write-InfoMsg "Metadata cleanup cancelled."
        return
    }

    if ($gracefulMode)
    {
        $Script:State.CleanupResult = Invoke-MetadataCleanup -TargetInfo $Script:State.TargetInfo -Partners $partners -Graceful
    }
    else
    {
        $Script:State.CleanupResult = Invoke-MetadataCleanup -TargetInfo $Script:State.TargetInfo -Partners $partners
    }
}

function Invoke-MenuVerifyPartnerCleanup
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    if (-not $VerifyPartnerConnectionRemoval)
    {
        Write-WarnMsg 'Partner connection-teardown verification is disabled ($VerifyPartnerConnectionRemoval = $false).'
        return
    }

    $partners = Get-StatePartners

    if ($null -eq $partners -or @($partners).Count -eq 0)
    {
        Write-WarnMsg "No replication partners are known for '$($Script:State.TargetInfo.HostName)' - querying the acting DC's live partners instead."
        $partners = Get-TargetReplicationPartners -TargetName (Get-ActingDC)
    }
    else
    {
        Update-PartnerReachability -Partners $partners
    }

    $Script:State.ConnectionResult = Confirm-PartnerConnectionTeardown -TargetInfo $Script:State.TargetInfo -Partners $partners -ActingDC (Get-ActingDC) -TimeoutSeconds $ConnectionTeardownWaitSeconds -PollSeconds $ConnectionTeardownPollSeconds -ForceKcc:$ConnectionTeardownForceKcc
}

function Invoke-MenuSyncAll
{
    $Script:State.SyncResult = Invoke-ReplicationSync
}

function Invoke-MenuDomainRemoval
{
    if (-not (Assert-ExecutionPrivileges))
    {
        return
    }

    if (-not (Resolve-TargetState))
    {
        return
    }

    if (-not (Get-Confirmation "Remove computer account '$($Script:State.TargetInfo.ShortName)' from the domain?"))
    {
        Write-InfoMsg "Domain removal cancelled."
        return
    }

    $actingDC = Get-ActingDC
    $Script:State.RemovalResult = Remove-ServerFromDomain -TargetInfo $Script:State.TargetInfo -ActingDC $actingDC
}

function Invoke-MenuReboot
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    if (-not (Get-Confirmation "Reboot '$($Script:State.TargetInfo.HostName)'?"))
    {
        Write-InfoMsg "Reboot cancelled."
        return
    }

    Restart-TargetDC -TargetInfo $Script:State.TargetInfo
}

function Invoke-ScanOfLastResort
{
    # Slow, forest-wide hunt for orphaned/lingering server metadata. For every reachable
    # domain controller, enumerate that DC's own view of CN=Servers under every site, then
    # compare each discovered server object against the authoritative list of current DCs.
    # Any server object whose name does not match a current DC is reported (it usually means
    # leftover metadata from a removed DC that did not fully clean up - possibly on just one
    # DC that has not converged).
    Write-InfoMsg "Scan of Last Resort - comparing every DC's Sites\Servers view against the current DC list."
    Write-WarnMsg "This is intentionally exhaustive and may take a while on large forests."

    try
    {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
    }
    catch
    {
        Write-ErrorMsg "Could not enumerate domain controllers: $($_.Exception.Message)"
        return
    }

    $currentDcNames = @($dcs | ForEach-Object { $_.Name.ToUpper() }) | Sort-Object -Unique
    Write-InfoMsg "Current domain controllers ($($currentDcNames.Count)): $($currentDcNames -join ', ')"

    try
    {
        $sitesBase = "CN=Sites,$((Get-ADRootDSE -ErrorAction Stop).configurationNamingContext)"
    }
    catch
    {
        Write-ErrorMsg "Could not read configuration naming context: $($_.Exception.Message)"
        return
    }

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($dc in $dcs)
    {
        $dcHost = $dc.HostName

        if (-not (Test-PartnerReachable -ComputerName $dcHost))
        {
            Write-WarnMsg "DC '$dcHost' is unreachable - its view could not be scanned."
            continue
        }

        try
        {
            $servers = @(Get-ADObject -Server $dcHost -SearchBase $sitesBase -LDAPFilter '(objectClass=server)' -ErrorAction Stop)
        }
        catch
        {
            Write-WarnMsg "Could not enumerate servers from '$dcHost': $($_.Exception.Message)"
            continue
        }

        foreach ($s in $servers)
        {
            if ($currentDcNames -contains $s.Name.ToUpper())
            {
                continue
            }

            $site = 'Unknown'
            if ($s.DistinguishedName -match ',CN=Servers,CN=(?<site>[^,]+),CN=Sites,')
            {
                $site = $Matches['site']
            }

            $findings.Add(
                [pscustomobject]@{
                    Server   = $s.Name
                    Site     = $site
                    SeenOnDC = $dc.Name
                    DN       = $s.DistinguishedName
                }
            )
        }
    }

    if ($findings.Count -eq 0)
    {
        Write-SuccessMsg "No orphaned server objects found - every server object under Sites maps to a current DC."
        return
    }

    Write-WarnMsg "Discovered $($findings.Count) server object(s) NOT matching any current DC:"

    foreach ($f in ($findings | Sort-Object Server, SeenOnDC))
    {
        Write-WarnMsg "    $($f.Server)  (site: $($f.Site))  seen on DC: $($f.SeenOnDC)"
        Write-Log "        DN: $($f.DN)"
    }

    $distinct = @($findings | Select-Object -ExpandProperty Server -Unique)
    Write-InfoMsg "Distinct orphaned server name(s): $($distinct -join ', ')"
    Write-InfoMsg "To clean one up, set it as the target DC and run metadata cleanup (option 6)."
}

function Invoke-MenuFullWorkflow
{
    if (-not (Resolve-TargetState))
    {
        return
    }

    if (-not (Get-Confirmation "Run the FULL automated demotion + cleanup + removal for '$($Script:State.TargetInfo.HostName)'?"))
    {
        Write-InfoMsg "Full workflow cancelled."
        return
    }

    if (-not (Test-MenuPreflight))
    {
        $Script:State.OverallStatus = 'Aborted - pre-flight / readiness checks failed'
        $Script:State.StatusColor   = '#c62828'
        Send-MenuReport
        return
    }

    Invoke-PartnerCapture

    if ($EnsureDemotionReadiness)
    {
        $readiness = Test-DemotionReadiness -TargetInfo $Script:State.TargetInfo

        if ($readiness.IsLastDc)
        {
            Write-ErrorMsg "Refusing to demote the last domain controller in the domain. Aborting workflow."
            $Script:State.OverallStatus = 'Aborted - target is the last DC in the domain'
            $Script:State.StatusColor   = '#c62828'
            Send-MenuReport
            return
        }

        if ($PreDemotionSync)
        {
            Invoke-PreDemotionSync -TargetInfo $Script:State.TargetInfo
        }
    }

    $Script:State.DemotionResult = Invoke-RemoteDemotion -TargetInfo $Script:State.TargetInfo

    if ($Script:State.DemotionResult.Success)
    {
        $partners = Get-StatePartners

        if ($partners)
        {
            Update-PartnerReachability -Partners $partners
        }

        if ($Script:State.DemotionResult.ForceUsed)
        {
            if ($EnableMetadataCleanup)
            {
                Write-WarnMsg "Forced removal was used - performing full ntdsutil metadata cleanup against a surviving partner."
                $Script:State.CleanupResult = Invoke-MetadataCleanup -TargetInfo $Script:State.TargetInfo -Partners $partners
            }
        }
        else
        {
            Write-InfoMsg "Graceful demotion - confirming the source-side metadata deletions replicate out (verify/converge; no ntdsutil)."
            $Script:State.CleanupResult = Invoke-MetadataCleanup -TargetInfo $Script:State.TargetInfo -Partners $partners -Graceful
        }

        # Reboot the target to finalize the member-server conversion BEFORE removing its account,
        # so the account is still valid when the box restarts and the restart command can
        # authenticate. Account removal below acts against a surviving partner, not the target,
        # so it does not require the target to be back online first.
        Restart-TargetDC -TargetInfo $Script:State.TargetInfo

        $actingDC   = Get-ActingDC
        $postResult = Invoke-PostDemotionRemoval -TargetInfo $Script:State.TargetInfo -ActingDC $actingDC
        $Script:State.SyncResult    = $postResult.Sync
        $Script:State.RemovalResult = $postResult.Removal

        if ($VerifyPartnerConnectionRemoval)
        {
            $verifyPartners = Get-StatePartners

            if ($verifyPartners)
            {
                Update-PartnerReachability -Partners $verifyPartners
            }

            $Script:State.ConnectionResult = Confirm-PartnerConnectionTeardown -TargetInfo $Script:State.TargetInfo -Partners $verifyPartners -ActingDC $actingDC -TimeoutSeconds $ConnectionTeardownWaitSeconds -PollSeconds $ConnectionTeardownPollSeconds -ForceKcc:$ConnectionTeardownForceKcc
        }

        if ($Script:State.DemotionResult.ForceUsed)
        {
            $Script:State.OverallStatus = 'Demotion completed via forced removal + metadata cleanup'
            $Script:State.StatusColor   = '#ef6c00'
        }
        else
        {
            $Script:State.OverallStatus = 'Demotion completed gracefully'
            $Script:State.StatusColor   = '#2e7d32'
        }

        if ($Script:State.ConnectionResult -and $Script:State.ConnectionResult.Checked -and (-not $Script:State.ConnectionResult.Cleared))
        {
            $Script:State.OverallStatus = "$($Script:State.OverallStatus) - partner connection teardown still pending (KCC will complete it; re-verify with menu option 15)"
            $Script:State.StatusColor   = '#ef6c00'
        }
    }
    else
    {
        if ($EnableMetadataCleanup)
        {
            Write-WarnMsg "Demotion failed - attempting metadata cleanup against a surviving partner."
            $partners = Get-StatePartners

            if ($partners)
            {
                Update-PartnerReachability -Partners $partners
            }

            $Script:State.CleanupResult = Invoke-MetadataCleanup -TargetInfo $Script:State.TargetInfo -Partners $partners
        }

        if ($Script:State.CleanupResult -and $Script:State.CleanupResult.Performed)
        {
            $actingDC   = Get-ActingDC
            $postResult = Invoke-PostDemotionRemoval -TargetInfo $Script:State.TargetInfo -ActingDC $actingDC
            $Script:State.SyncResult    = $postResult.Sync
            $Script:State.RemovalResult = $postResult.Removal
        }

        $Script:State.OverallStatus = 'Demotion failed - metadata cleanup attempted'
        $Script:State.StatusColor   = '#c62828'
    }

    Send-MenuReport
}

function Send-MenuReport
{
    $ti = $Script:State.TargetInfo

    if ($null -eq $ti)
    {
        $ti =
        @{
            HostName        = $Script:State.TargetDC
            ShortName       = $Script:State.TargetDC
            Site            = 'Unknown'
            IPv4            = 'Unknown'
            IsGlobalCatalog = 'Unknown'
            OperatingSystem = 'Unknown'
            ServerObjectDN  = 'Unknown'
            ConfigNC        = 'Unknown'
            DnsDomain       = 'Unknown'
            DsaGuid         = 'unknown'
        }
    }

    $dr = $Script:State.DemotionResult

    if ($null -eq $dr)
    {
        $dr = [pscustomobject]@{ Attempted = $false; Success = $false; ForceUsed = $false; PolicyRelaxed = $false; GcDisabled = $false; Error = 'Not executed'; RemediationTrail = @() }
    }

    $status = if ([string]::IsNullOrWhiteSpace($Script:State.OverallStatus)) { 'Manual session summary' } else { $Script:State.OverallStatus }

    $reportParams =
    @{
        TargetInfo     = $ti
        Partners       = $Script:State.Partners
        DemotionResult = $dr
        CleanupResult  = $Script:State.CleanupResult
        SyncResult     = $Script:State.SyncResult
        RemovalResult  = $Script:State.RemovalResult
        ConnectionResult = $Script:State.ConnectionResult
        OverallStatus  = $status
        StatusColor    = $Script:State.StatusColor
    }

    $reportHtml = Build-ReportHtml @reportParams
    Send-Report -Html $reportHtml
}

function Show-State
{
    $ti           = $Script:State.TargetInfo
    $partnerCount = if ($Script:State.Partners) { @($Script:State.Partners).Count } else { 0 }

    Write-Host ""
    Write-Host "  ----- Configuration variables -----" -ForegroundColor White
    Write-Host "  DryRun                   : $DryRun"
    Write-Host "  EnableMetadataCleanup    : $EnableMetadataCleanup"
    Write-Host "  RemoveFromDomain         : $RemoveFromDomain"
    Write-Host "  RunSyncAllBeforeRemoval  : $RunSyncAllBeforeRemoval"
    Write-Host "  RepadminSyncAllOptions   : $RepadminSyncAllOptions"
    Write-Host "  EnsureDemotionReadiness  : $EnsureDemotionReadiness"
    Write-Host "  PreDemotionSync          : $PreDemotionSync"
    Write-Host "  IgnoreLastDnsServerForZone : $IgnoreLastDnsServerForZone"
    Write-Host "  DnsManagedExternally     : $DnsManagedExternally (${ExternalDnsName}: $($ExternalDnsServers -join ', '))"
    Write-Host "  AbortOnReplicationErrors : $AbortOnReplicationErrors"
    Write-Host "  LocalAdminPassword       : $LocalAdminPasswordPlain"
    Write-Host "  SMTP                     : ${SmtpServer}:$SmtpPort (from $MailFrom)"
    Write-Host "  MailTo                   : $($MailTo -join ', ')"
    Write-Host "  Log file                 : $LogPath"
    Write-Host ""
    Write-Host "  ----- Session state -----" -ForegroundColor White
    Write-Host "  Target DC                : $($Script:State.TargetDC)"
    Write-Host "  Target resolved          : $([bool]$ti)"

    if ($ti)
    {
        Write-Host "  Target host / site       : $($ti.HostName) / $($ti.Site)"
        Write-Host "  Server object DN         : $($ti.ServerObjectDN)"
    }

    Write-Host "  Replication partners     : $partnerCount captured"

    if ($partnerCount -gt 0)
    {
        foreach ($p in $Script:State.Partners)
        {
            Write-Host "      - $($p.PartnerHost)  (site: $($p.PartnerSite), reachable: $($p.Reachable))"
        }
    }

    $demoteText = if ($Script:State.DemotionResult) { "Success=$($Script:State.DemotionResult.Success), Force=$($Script:State.DemotionResult.ForceUsed)" } else { 'none' }
    $cleanText  = if ($Script:State.CleanupResult) { "Performed=$($Script:State.CleanupResult.Performed), Success=$($Script:State.CleanupResult.Success)" } else { 'none' }
    $syncText   = if ($Script:State.SyncResult) { "Ran=$($Script:State.SyncResult.Ran), Success=$($Script:State.SyncResult.Success)" } else { 'none' }
    $removeText = if ($Script:State.RemovalResult) { "Performed=$($Script:State.RemovalResult.Performed), Success=$($Script:State.RemovalResult.Success)" } else { 'none' }

    $connText = if ($Script:State.ConnectionResult) { "Checked=$($Script:State.ConnectionResult.Checked), Cleared=$($Script:State.ConnectionResult.Cleared)" } else { 'none' }

    Write-Host "  Demotion result          : $demoteText"
    Write-Host "  Cleanup result           : $cleanText"
    Write-Host "  Sync result              : $syncText"
    Write-Host "  Removal result           : $removeText"
    Write-Host "  Partner release          : $connText"
    Write-Host "  Overall status           : $($Script:State.OverallStatus)"
    Write-Host ""
}

function Show-Menu
{
    $dryFlag = if ($DryRun) { '   [DRY RUN ACTIVE]' } else { '' }
    $target  = if ([string]::IsNullOrWhiteSpace($Script:State.TargetDC)) { '(not set)' } else { $Script:State.TargetDC }

    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "  Remove_DC_Remote.ps1  v$ScriptVersion$dryFlag" -ForegroundColor Cyan
    Write-Host "  Target DC: $target" -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "   1.  Set / change target DC"
    Write-Host "   2.  Show target DC details"
    Write-Host "   3.  Capture replication partners (export CSV)"
    Write-Host "   4.  Run pre-flight checks (prereqs / FSMO / replication)"
    Write-Host "   5.  Demote target DC (remote)"
    Write-Host "   6.  Run metadata cleanup (uses captured partners)"
    Write-Host "   7.  Run repadmin /syncall $RepadminSyncAllOptions"
    Write-Host "   8.  Remove server computer account from domain"
    Write-Host "   9.  Reboot target"
    Write-Host "  10.  Run FULL automated workflow"
    Write-Host "  11.  Email status report"
    Write-Host "  12.  Toggle Dry Run (currently: $DryRun)"
    Write-Host "  13.  Show current variables / session state"
    Write-Host "  14.  Scan of Last Resort (find orphaned server objects across all DCs)"
    Write-Host "  15.  Verify replication partners released the demoted DC (post-demotion confidence check)"
    Write-Host "   0.  Exit"
    Write-Host "==================================================================" -ForegroundColor Cyan
}

# ============================================================
# REGION: MENU DRIVER
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

$Script:State = New-RunState

if (-not (Assert-ExecutionPrivileges))
{
    Write-Log "===== $ScriptName v$ScriptVersion aborted - execution privilege checks failed ====="
    return
}

if ($DryRun)
{
    Write-DryRunMsg "DRY RUN enabled - destructive actions will be simulated."
}

if (-not (Initialize-DemotionCredential))
{
    Write-Log "===== $ScriptName v$ScriptVersion aborted - mandatory demotion credential not provided ====="
    return
}

$exitMenu = $false

while (-not $exitMenu)
{
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice)
    {
        '1'  { Set-MenuTargetDC }
        '2'  { Show-TargetInfo }
        '3'  { Invoke-PartnerCapture }
        '4'  { [void](Test-MenuPreflight) }
        '5'  { Invoke-MenuDemotion }
        '6'  { Invoke-MenuMetadataCleanup }
        '7'  { Invoke-MenuSyncAll }
        '8'  { Invoke-MenuDomainRemoval }
        '9'  { Invoke-MenuReboot }
        '10' { Invoke-MenuFullWorkflow }
        '11' { Send-MenuReport }
        '12'
        {
            $Script:DryRun = -not $DryRun
            Write-InfoMsg "Dry Run is now: $DryRun"
        }
        '13' { Show-State }
        '14' { Invoke-ScanOfLastResort }
        '15' { Invoke-MenuVerifyPartnerCleanup }
        '0'  { $exitMenu = $true }
        default { Write-WarnMsg "Invalid selection: '$choice'." }
    }
}

Write-Log "===== $ScriptName v$ScriptVersion menu session ended ====="
