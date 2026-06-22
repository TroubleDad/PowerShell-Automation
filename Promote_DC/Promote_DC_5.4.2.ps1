# =====================================================================
# Script      : Promote_DC.ps1
# Author      : Alan W. Phillips
# Date        : 06-18-2026
# Version     : 5.4.2
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
#               emailed. The email report now supports an inline
#               DCUpgraderator logo at the top of the HTML body via a
#               System.Net.Mail LinkedResource referenced by a cid: URI.
#               Behavior is variable-driven with a $DryRun toggle.
#
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
#
# Change Log:
#               5.4.2 - Finalized the email report. Embedded the approved
#                       DCUpgraderator PNG payload into $EmailLogoBase64 (a
#                       240x240 RGBA PNG, matching $EmailLogoMimeType /
#                       width / height). Set $MailFrom to
#                       DCUPGRADERATOR@uhhospitals.org. Corrected the report
#                       HTML for cross-client (web + Outlook desktop Word
#                       engine) rendering: added a <!DOCTYPE> and a <head>
#                       with <meta charset="utf-8">, quoted the multi-word
#                       "Segoe UI" font family (unquoted multi-word family
#                       names are invalid CSS and can be dropped), added
#                       inline width/height to the logo <img> (the Word
#                       engine honors inline style more reliably than bare
#                       attributes), and hardened the report tables with
#                       cellpadding/cellspacing/border="0" to suppress stray
#                       Word-engine spacing. Saved as UTF-8 with BOM. No
#                       logic, privilege, IFM, promotion or cid/LinkedResource
#                       wiring changed; the cid reference and the
#                       LinkedResource ContentId remain in sync.
#               5.4.1 - Added inline HTML email logo support for the
#                       DCUpgraderator report header. Integrated the
#                       EmailLogo snippet variables, added helper functions
#                       to render the cid: image markup and create a
#                       System.Net.Mail.LinkedResource from the embedded
#                       Base64 payload, and replaced Send-MailMessage with
#                       a System.Net.Mail.MailMessage / AlternateView
#                       implementation so Outlook desktop renders the logo
#                       at the top of the report body.
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
$ScriptVersion = '5.4.2'
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

# ----- Email approved logo -----
# Embedded as Base64 and delivered as a System.Net.Mail LinkedResource
# referenced by a cid: URI; data: URIs are not honored by Outlook desktop.
# Setting $EmailLogoEnabled to $false suppresses both the inline image and
# the linked resource. Use the MIME type that matches the actual encoded file.
# The DCUpgraderator source image used here is PNG with transparency.
$EmailLogoEnabled   = $true
$EmailLogoContentId = 'dcupgraderatorlogo'
$EmailLogoWidth     = 240
$EmailLogoHeight    = 240
$EmailLogoMimeType  = 'image/png'
$EmailLogoBase64    = 'iVBORw0KGgoAAAANSUhEUgAAAPAAAADwCAYAAAA+VemSAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAGHaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49J++7vycgaWQ9J1c1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCc/Pg0KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyI+PHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj48cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIj48dGlmZjpPcmllbnRhdGlvbj4xPC90aWZmOk9yaWVudGF0aW9uPjwvcmRmOkRlc2NyaXB0aW9uPjwvcmRmOlJERj48L3g6eG1wbWV0YT4NCjw/eHBhY2tldCBlbmQ9J3cnPz4slJgLAAChomNhQlgAAKGianVtYgAAAB5qdW1kYzJwYQARABCAAACqADibcQNjMnBhAAAAOvlqdW1iAAAAR2p1bWRjMm1hABEAEIAAAKoAOJtxA3Vybjp1dWlkOjBhZTczZDk4LTQyMDktNDhhMi04OGQ2LWNlM2I0NmM2Yjc3NwAAAAwranVtYgAAAClqdW1kYzJhcwARABCAAACqADibcQNjMnBhLmFzc2VydGlvbnMAAAAK9Wp1bWIAAABBanVtZGNib3IAEQAQgAAAqgA4m3ETYzJwYS5oYXNoLmJveGVzAAAAABhjMnNoUzzuuMJjoREOy/CktK3FjQAACqxjYm9yomNhbGdmc2hhMjU2ZWJveGVzmDCjZW5hbWVzgWRQTkdoZGhhc2hYIExLajvhMUq4YTi+9DFN3gIuYAlg2GiaLI+GMYAtINq2Y3BhZECjZW5hbWVzgWRJSERSZGhhc2hYIH1kSA3Hx4kkcq7i+JdHFHWBIcoAeYszm4Vf//60pgLzY3BhZECjZW5hbWVzgWRDMlBBZGhhc2hBAGNwYWRA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SSBJbWFnZUdlbmR3aGVudDIwMjYtMDYtMThUMjA6MDk6NThacWRpZ2l0YWxTb3VyY2VUeXBleEZodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL3RyYWluZWRBbGdvcml0aG1pY01lZGlhAAACcWp1bWIAAAAkanVtZGMyY2wAEQAQgAAAqgA4m3EDYzJwYS5jbGFpbQAAAAJFY2JvcqdjYWxnZnNoYTI1NmlkYzpmb3JtYXRpaW1hZ2UvcG5naXNpZ25hdHVyZXhMc2VsZiNqdW1iZj1jMnBhL3Vybjp1dWlkOjBhZTczZDk4LTQyMDktNDhhMi04OGQ2LWNlM2I0NmM2Yjc3Ny9jMnBhLnNpZ25hdHVyZWppbnN0YW5jZUlEYzEuMG9jbGFpbV9nZW5lcmF0b3J4HE1pY3Jvc29mdF9SZXNwb25zaWJsZV9BSS8xLjB0Y2xhaW1fZ2VuZXJhdG9yX2luZm+BomRuYW1leClNaWNyb3NvZnQgUmVzcG9uc2libGUgQUkgSW1hZ2UgUHJvdmVuYW5jZWd2ZXJzaW9uYzEuMGphc3NlcnRpb25zgqNjYWxnZnNoYTI1NmN1cmx4XXNlbGYjanVtYmY9YzJwYS91cm46dXVpZDowYWU3M2Q5OC00MjA5LTQ4YTItODhkNi1jZTNiNDZjNmI3NzcvYzJwYS5hc3NlcnRpb25zL2MycGEuaGFzaC5ib3hlc2RoYXNoWCCguNKlu6WxW1Tspev+9OF32pQ6PNy6uVIu6gYgF6IqwqNjYWxnZnNoYTI1NmN1cmx4WnNlbGYjanVtYmY9YzJwYS91cm46dXVpZDowYWU3M2Q5OC00MjA5LTQ4YTItODhkNi1jZTNiNDZjNmI3NzcvYzJwYS5hc3NlcnRpb25zL2MycGEuYWN0aW9uc2RoYXNoWCCqnZvSNtsztRlnHmdFxTczxqT0dez0iRgo02DdgDcM9QAALA5qdW1iAAAAKGp1bWRjMmNzABEAEIAAAKoAOJtxA2MycGEuc2lnbmF0dXJlAAAAK95jYm9y0oREoQE4JKJneDVjaGFpboNZBikwggYlMIIEDaADAgECAhMzAAAAhBIFN7Fa24CgAAAAAACEMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAlVTMR4wHAYDVQQK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g5JGY7v2zk33HG5rJK04fAAAAZ1jYm9yomdhY3Rpb25zgqNmYWN0aW9ubGMycGEuY3JlYXRlZHFkaWdpdGFsU291cmNlVHlwZXhGaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS90cmFpbmVkQWxnb3JpdGhtaWNNZWRpYWtkZXNjcmlwdGlvbng2Q3JlYXRlZCBpbWFnZSB1c2luZyBhcnRpZmljaWFsIGludGVsbGlnZW5jZSB0ZWNobm9sb2d5pGZhY3Rpb25wYzJwYS53YXRlcm1hcmtlZGR3aGVueCEyMDI2LTA2LTE4VDIwOjEwOjA0LjQ0MzEwODQrMDA6MDBtc29mdHdhcmVBZ2VudL9kbmFtZXgjTWljcm9zb2Z0IFJlc3BvbnNpYmxlIEFJIFByb3ZlbmFuY2VndmVyc2lvbmMxLjD/a2Rlc2NyaXB0aW9ueC9Db250ZW50IHdhdGVybWFya2VkIGJ5IE1pY3Jvc29mdCBSZXNwb25zaWJsZSBBSXJhbGxBY3Rpb25zSW5jbHVkZWT1AAABF2p1bWIAAABDanVtZGNib3IAEQAQgAAAqgA4m3ETYzJwYS5zb2Z0LWJpbmRpbmcAAAAAGGMyc2gFTVYzWvCb/CGAgGo0q2EGAAAAzGNib3KjY2FsZ3gZY29tLm1pY3Jvc29mdC5pbnZpc21hcmsuMWNwYWSAZmJsb2Nrc4GiZXNjb3BloWZyZWdpb26hZnJlZ2lvboGiZHR5cGVnc3BhdGlhbGVzaGFwZaVkdHlwZWlyZWN0YW5nbGVkdW5pdGpwZXJjZW50YWdlZXdpZHRoGGRmaGVpZ2h0GGRmb3JpZ2luomF4AGF5AGV2YWx1ZXgkOGU2MTk0MTktZTY1Ny00MGQ1LWJmZmEtOTVhMmQ2NGM4Njg0AAAAxWp1bWIAAABAanVtZGNib3IAEQAQgAAAqgA4m3ETYzJwYS5oYXNoLmRhdGEAAAAAGGMyc2huqiR/FLnTfmnWRdY0zLvkAAAAfWNib3KlamV4Y2x1c2lvbnOBomVzdGFydBghZmxlbmd0aBmZZmRuYW1lbmp1bWJmIG1hbmlmZXN0Y2FsZ2ZzaGEyNTZkaGFzaFgg6nySMFB1p7a1FpGlpN1s4mvA3RzD2T+I0RM5cRVu3HNjcGFkSgAAAAAAAAAAAAAAAAO+anVtYgAAACdqdW1kYzJjbAARABCAAACqADibcQNjMnBhLmNsYWltLnYyAAAAA49jYm9yp2ppbnN0YW5jZUlEeCx4bXA6aWlkOjM0MjRlMjFhLWZjMmUtNDA0Ni04MGJmLTFkMWM4Nzg2ODI3M3RjbGFpbV9nZW5lcmF0b3JfaW5mb79kbmFtZXJNaWNyb3NvZnRfRGVzaWduZXJndmVyc2lvbmMyLjBwb3BlcmF0aW5nX3N5c3RlbXghTWljcm9zb2Z0IFdpbmRvd3MgTlQgMTAuMC4yMDM0OC4wZWFwcElkeCQ1ZTI3OTVlMy1jZThjLTRjZmItYjMwMi0zNWZlNWNkMDE1OTd3b3JnLmNvbnRlbnRhdXRoLmMycGFfcnNmMC44NC4x/2lzaWduYXR1cmV4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzY4NmEwNTUtN2EwNi00YTg2LThlMTQtNTI5MWMxYjc1Njc0L2MycGEuc2lnbmF0dXJlcmNyZWF0ZWRfYXNzZXJ0aW9uc4GiY3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFggpaEABEgLODtjfzCW7HbYBhu2zzz/9wNXaZCUKbgb9xFzZ2F0aGVyZWRfYXNzZXJ0aW9uc4SiY3VybHg0c2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS50aHVtYm5haWwuaW5ncmVkaWVudGRoYXNoWCAxAikHG8Vq2HWsLg79OCFchk8wiXYZycv/WdioAOqq5qJjdXJseC1zZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNkaGFzaFggLG/2jTSUMIQowT3SYxGKXV5ynHaubhqjBHpSFDEU15GiY3VybHgqc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5hY3Rpb25zLnYyZGhhc2hYIJHSdHj96hV0ZfZbaPgHCfiAJO6gO1FAXzbbOZRQ3T1FomN1cmx4LHNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuc29mdC1iaW5kaW5nZGhhc2hYIIrLaKKE0+bUnkzczQzQMCvDAiVwv+25G0XcrGn5AzhTaGRjOnRpdGxleDVD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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPZZAYBko1umYdxADF3/bPUrumJAqkJbHXLTLflgPi2/jWP1NvAF+ElA/bDJwz0bdMsctw/ajaZaB0Je/pi2Mr2vfnotRD/pcEr8vxOCjQqnMBUsNKmyKbjDi9RtRFIrpan/l91LqSq8VoFt4HvQrVpd/Agg6ny7/na8gKhMba0nSArItqRZ578s7qQ10/vFhm1tasWVdlKv+WSAIlvUQ/2hvg2wIpmW2s7TJOHjiQe1Cep7GKEHgQz/hv0CwM6znhYzIaZF9D3SXolB+bF92inHmoSbQmWFEU0Em1VkRbXh2O+Iqahn6R9ddpuYE0jqx+G7CQkhLMHPfxdOHl5N1vcgW0VEBQQCuVNdLxaXrDa5XqxLfDSg1sGJQbhvZYZQQV/L568mIFQlpHRalCO6G7bktqa+G7yH6lGnnN4F/g1tuvfR6JTed88n9hkKQd4IbQXAw4Mn6F/OXsni/xHd7lGIxHvs8JDwacwF5bYsIwkg0eDktg1WI2JE9PhGczf50E5y3CoAAAhIanVtYgAAAEdqdW1kYzJ1bQARABCAAACqADibcQN1cm46dXVpZDo1MWQ4OTZiZC03NDE0LTQxNmUtYjIzZC1mMjUzOTI2NWRmYjcAAAADMWp1bWIAAAApanVtZGMyYXMAEQAQgAAAqgA4m3EDYzJwYS5hc3NlcnRpb25zAAAAASFqdW1iAAAALGp1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52MgAAAADtY2JvcqRtYzJwYV9tYW5pZmVzdKNjYWxnZnNoYTI1NmRoYXNoeCxVMXBhL05iUlB4NWVGTEhTbGhNWWZjRzhXTHVxRitWOVhUWGhEOFJxbS9JPWN1cmx4PnNlbGYjanVtYmY9L2MycGEvdXJuOnV1aWQ6MGFlNzNkOTgtNDIwOS00OGEyLTg4ZDYtY2UzYjQ2YzZiNzc3aWRjOmZvcm1hdGlpbWFnZS9wbmdoZGM6dGl0bGV4G1JlcG9ydGVkIGFzIGdlbmVyYXRlZCBieSBBSWxyZWxhdGlvbnNoaXBrY29tcG9uZW50T2YAAADkanVtYgAAAClqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmFjdGlvbnMudjIAAAAAs2Nib3KhZ2FjdGlvbnOBo2ZhY3Rpb25rYzJwYS5lZGl0ZWRrZGVzY3JpcHRpb254QEVkaXRlZCBvZmZsaW5lIHdpdGhvdXQgdHJ1c3RlZCBjZXJ0aWZpY2F0ZSBhbmQgc2VjdXJlIHNpZ25hdHVyZS5tc29mdHdhcmVBZ2VudKJkbmFtZXRQYWludCBhcHAgb24gV2luZG93c2d2ZXJzaW9ubTExLjI2MDMuMjUxLjAAAAD7anVtYgAAACxqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmluZ3JlZGllbnQudjIAAAAAx2Nib3KkaGRjOnRpdGxlb1BhcmVudCBtYW5pZmVzdGlkYzpmb3JtYXRgbHJlbGF0aW9uc2hpcGhwYXJlbnRPZm1jMnBhX21hbmlmZXN0o2NhbGdmc2hhMjU2Y3VybHg9c2VsZiNqdW1iZj1jMnBhL3VybjpjMnBhOjM2ODZhMDU1LTdhMDYtNGE4Ni04ZTE0LTUyOTFjMWI3NTY3NGRoYXNoWCCfuvDn5qNzeDJ6LGWKHD7Rk+EnxjAlCdMQM5mo2gH8HwAAAwpqdW1iAAAAJGp1bWRjMmNsABEAEIAAAKoAOJtxA2MycGEuY2xhaW0AAAAC3mNib3KnY2FsZ2ZzaGEyNTZpZGM6Zm9ybWF0aWltYWdlL3BuZ2lzaWduYXR1cmV4THNlbGYjanVtYmY9YzJwYS91cm46dXVpZDo1MWQ4OTZiZC03NDE0LTQxNmUtYjIzZC1mMjUzOTI2NWRmYjcvYzJwYS5zaWduYXR1cmVqaW5zdGFuY2VJRHgtdXJuOnV1aWQ6YjQzZTVkYTctZmRkNi00ZWRjLThiZmQtZjAzNjNkMGQwNDA1b2NsYWltX2dlbmVyYXRvcnFMb2NhbGx5IGdlbmVyYXRlZHRjbGFpbV9nZW5lcmF0b3JfaW5mb4GhZG5hbWVxTG9jYWxseSBnZW5lcmF0ZWRqYXNzZXJ0aW9uc4OjY2FsZ2ZzaGEyNTZjdXJseGBzZWxmI2p1bWJmPWMycGEvdXJuOnV1aWQ6NTFkODk2YmQtNzQxNC00MTZlLWIyM2QtZjI1MzkyNjVkZmI3L2MycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjJkaGFzaFgg6qiXd946NYQYmv2JPvLJ/Y7NgrJ5jabOUG7I5w6tYj6jY2FsZ2ZzaGEyNTZjdXJseF1zZWxmI2p1bWJmPWMycGEvdXJuOnV1aWQ6NTFkODk2YmQtNzQxNC00MTZlLWIyM2QtZjI1MzkyNjVkZmI3L2MycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjJkaGFzaFggOoOeBoRpWD5Bj61wY00sLVJFlZ8n+A3KquFvpRGkF8WjY2FsZ2ZzaGEyNTZjdXJseGBzZWxmI2p1bWJmPWMycGEvdXJuOnV1aWQ6NTFkODk2YmQtNzQxNC00MTZlLWIyM2QtZjI1MzkyNjVkZmI3L2MycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjJkaGFzaFggcfyEZOEq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'

# ----- SMTP / email -----
$SmtpServer = 'smtp.uhhs.com'
$SmtpPort   = 25
$MailFrom   = 'DCUPGRADERATOR@uhhospitals.org'
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

function Get-EmailLogoHtml
{
    if (-not $EmailLogoEnabled)
    {
        return ''
    }

    if ([string]::IsNullOrWhiteSpace($EmailLogoBase64))
    {
        return ''
    }

    return @"
<div style="margin:0 0 14px 0;">
<img src="cid:$EmailLogoContentId" width="$EmailLogoWidth" height="$EmailLogoHeight" alt="DCUpgraderator" style="display:block;width:${EmailLogoWidth}px;height:${EmailLogoHeight}px;border:0;outline:none;text-decoration:none;" />
</div>
"@
}

function New-EmailLogoResourcePackage
{
    if (-not $EmailLogoEnabled)
    {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($EmailLogoBase64))
    {
        Write-WarnMsg 'Email logo is enabled but $EmailLogoBase64 is blank. The report email will be sent without the inline logo.'
        return $null
    }

    try
    {
        $logoBytes   = [System.Convert]::FromBase64String($EmailLogoBase64)
        $memoryStream = New-Object System.IO.MemoryStream(, $logoBytes)
        $resource     = New-Object System.Net.Mail.LinkedResource($memoryStream, $EmailLogoMimeType)

        $resource.ContentId = $EmailLogoContentId
        $resource.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
        $resource.ContentType.MediaType = $EmailLogoMimeType

        return [pscustomobject]@{
            Stream   = $memoryStream
            Resource = $resource
        }
    }
    catch
    {
        Write-WarnMsg "Email logo Base64 could not be decoded into a linked resource: $($_.Exception.Message). The report email will be sent without the inline logo."
        return $null
    }
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

    $logoHtml = Get-EmailLogoHtml

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
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
</head>
<body style="font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#222;">
$logoHtml
<h2 style="margin-bottom:4px;">Domain Controller Promotion Report</h2>
<p style="margin-top:0;color:#666;">$FriendlyDate &nbsp;|&nbsp; Run from: $($env:COMPUTERNAME)</p>

<p style="font-size:15px;">
Overall status:
<span style="color:$StatusColor;font-weight:bold;">$OverallStatus</span>
</p>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Target Server</h3>
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Host name</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.HostName)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Short name</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.ShortName)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">IPv4</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.IPv4)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Detected site</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$siteText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Operating system</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.OperatingSystem)</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Domain</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$($TargetInfo.DnsDomain)</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Install From Media (IFM)</h3>
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Generation (host)</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$genColor;font-weight:bold;">$genText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Generation detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$genDetail</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Copy to target</td><td style="padding:4px 10px;border:1px solid #d0d0d0;color:$copyColor;font-weight:bold;">$copyText</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Destination</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$copyDest</td></tr>
<tr><td style="padding:4px 10px;border:1px solid #d0d0d0;background:#f4f4f4;font-weight:bold;">Copy detail</td><td style="padding:4px 10px;border:1px solid #d0d0d0;">$copyDetail</td></tr>
</table>

<h3 style="border-bottom:2px solid #1565c0;padding-bottom:4px;">Promotion</h3>
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
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
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
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
<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
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

    $mailMessage = $null
    $smtpClient  = $null
    $htmlView    = $null
    $logoPackage = $null

    try
    {
        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($MailFrom)
        $mailMessage.Subject = Get-MailSubject
        $mailMessage.IsBodyHtml = $true
        $mailMessage.BodyEncoding = [System.Text.Encoding]::UTF8
        $mailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8

        foreach ($recipient in $MailTo)
        {
            if (-not [string]::IsNullOrWhiteSpace($recipient))
            {
                [void]$mailMessage.To.Add($recipient)
            }
        }

        $htmlView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($Html, $null, 'text/html')
        $logoPackage = New-EmailLogoResourcePackage

        if ($logoPackage -and $logoPackage.Resource)
        {
            [void]$htmlView.LinkedResources.Add($logoPackage.Resource)
        }

        [void]$mailMessage.AlternateViews.Add($htmlView)

        $smtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtpClient.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
        $smtpClient.Send($mailMessage)

        Write-SuccessMsg "Status report emailed to $($mailMessage.To.Count) recipient(s)."
    }
    catch
    {
        Write-ErrorMsg "Failed to send status report: $($_.Exception.Message)"
    }
    finally
    {
        if ($htmlView)
        {
            $htmlView.Dispose()
        }

        if ($logoPackage -and $logoPackage.Resource)
        {
            $logoPackage.Resource.Dispose()
        }

        if ($logoPackage -and $logoPackage.Stream)
        {
            $logoPackage.Stream.Dispose()
        }

        if ($mailMessage)
        {
            $mailMessage.Dispose()
        }

        if ($smtpClient)
        {
            $smtpClient.Dispose()
        }
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
            Success       = $r.Success
            ExitCode      = $r.ExitCode
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
    if ($root -match '^\\\\([^\\]+)\\([A-Za-z])\$$')
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
            Write-InfoMsg 'Target not yet responding to WinRM; continuing to wait...'
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

    if ($state.IsDC) { Write-SuccessMsg 'Target reports Domain Controller role.' } else { Write-ErrorMsg 'Target is not reporting the Domain Controller role.' }
    if ($state.NtdsRunning) { Write-SuccessMsg 'NTDS service is running.' } else { Write-ErrorMsg 'NTDS service is not running.' }
    if ($state.DfsrRunning) { Write-SuccessMsg 'DFSR service is running.' } else { Write-WarnMsg 'DFSR service is not running yet.' }
    if ($state.SysvolShare) { Write-SuccessMsg 'SYSVOL share is present.' } else { Write-ErrorMsg 'SYSVOL share is not present.' }

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
            Write-WarnMsg 'Replication summary reported potential issues; review the log.'
        }
        else
        {
            Write-SuccessMsg 'Replication summary is clean.'
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
        Write-InfoMsg 'Local IFM directory not present - nothing to clean.'
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

    Write-InfoMsg 'Cleaning up IFM directories from host and target.'

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

    Write-Host ''
    Write-Host $Title -ForegroundColor Yellow

    foreach ($line in $Detail)
    {
        Write-Host "  $line" -ForegroundColor Yellow
    }

    Write-Host 'Proceed? (Y/N): ' -ForegroundColor Yellow -NoNewline

    $answer = Read-Host

    return ($answer.ToUpperInvariant() -eq 'Y')
}

function Invoke-PromotionWorkflow
{
    # ----- Result placeholders so the report always renders -----
    $ifmGenResult    = $null
    $ifmCopyResult   = $null
    $promotionResult = $null
    $rebootResult    = $null
    $healthResult    = $null
    $cleanupResult   = $null

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

    if (-not (Confirm-Step -Title 'About to generate IFM locally and copy it to the target' -Detail $ifmDetail))
    {
        Write-WarnMsg 'Operation cancelled by operator before IFM generation.'
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- IFM generate + copy -----
    $ifmGenResult = New-LocalIfm

    if (-not $ifmGenResult.Success)
    {
        Write-ErrorMsg 'IFM generation failed; aborting before copy and promotion.'
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    $ifmCopyResult = Copy-IfmToTarget -TargetInfo $targetInfo

    if (-not $ifmCopyResult.Success)
    {
        Write-ErrorMsg 'IFM copy failed; aborting before promotion. Cleaning up host IFM.'
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
        Write-WarnMsg 'Promotion cancelled by operator after IFM copy. Cleaning up host and target IFM.'
        $cleanupResult = Invoke-IfmCleanup -TargetInfo $targetInfo
        $status = Get-OverallStatus -PromotionResult $promotionResult -HealthResult $healthResult -CleanupResult $cleanupResult
        Send-FinalReport -TargetInfo $targetInfo -IfmGenResult $ifmGenResult -IfmCopyResult $ifmCopyResult -PromotionResult $promotionResult -RebootResult $rebootResult -HealthResult $healthResult -CleanupResult $cleanupResult -Status $status
        return
    }

    # ----- Promotion -----
    $promotionResult = Invoke-RemotePromotion -TargetInfo $targetInfo -SiteName $targetInfo.Site

    if (-not $promotionResult.Success)
    {
        Write-ErrorMsg 'Promotion failed; leaving IFM in place for troubleshooting.'
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
        Write-WarnMsg 'Skipping health checks because the target did not come back online; leaving IFM in place.'
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
            Write-WarnMsg 'Health checks reported warnings; leaving IFM directories in place for review.'
        }
    }
    else
    {
        Write-InfoMsg 'CleanupIfmOnSuccess is disabled; IFM directories left in place.'
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
