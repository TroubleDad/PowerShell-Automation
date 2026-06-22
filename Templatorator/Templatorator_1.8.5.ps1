# =====================================================================
# Script      : Templatorator.ps1
# Author      : Alan W. Phillips
# Date        : 06-20-2026
# Version     : 1.8.5
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
#               Operates against more than one Active Directory forest: a
#               $DomainConfigs registry defines each forest (DNS name, label,
#               and issuing-CA list) and the operator switches the active
#               forest from the menu (option D). Every LDAP bind and PSPKI
#               call is server-qualified to the selected forest, so the same
#               session can author templates in uhhs.com or uhtd.local. The
#               active forest's CA list drives publication; when a forest
#               defines several issuing CAs the operator is prompted to pick
#               one, and delete can sweep every configured CA in the forest.
#               Selecting a forest the running account does not belong to
#               relaunches the script as an account in that forest (a new
#               window) so every operation runs under the correct token. All
#               CA, template, ACL and principal operations use direct LDAP, so
#               PSPKI is not required and the tool works on a machine that is
#               not joined to the target forest. At startup the script detects
#               which configured forest the running account belongs to and
#               makes that the active forest automatically - so run natively
#               inside UHTD it starts on UHTD with no relaunch or prompt.
#
# Requirements: PowerShell 5.1; PSPKI module (auto-installed from PSGallery);
#               System.DirectoryServices (built into .NET); Enterprise
#               Admin (or delegated) rights on the Configuration partition
#               to author templates; for -DelegatePublishRights, WRITE_DAC
#               on the CA Enrollment Services object (Enterprise Admin);
#               LDAP access to a DC in each targeted forest (uhhs.com and,
#               for the uhtd.local option, the uhtd.local DCs and issuing
#               CAs - reachable by name, with credentials valid in that
#               forest), and network access to smtp.uhhs.com:25. Selecting a
#               forest the running account does not belong to relaunches the
#               script with runas /netonly as an account in that forest, so
#               that account's credentials are used for all network logon
#               (LDAP, RPC to the CAs). The account does NOT need local logon
#               rights on this workstation - only a correct password and a
#               reachable target forest. runas prompts for the password on the
#               console; /netonly defers credential validation to first network
#               use, so a wrong password surfaces in the relaunched window. The
#               relaunch is performed by writing a small .cmd launcher next to
#               the script and opening it in its own console (cmd.exe), which
#               runs runas reliably; the relaunched session is detected by its
#               -DomainKey argument and does not relaunch again.
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
#   1.3.7 - 2026-06-20 - Replaced the placeholder logo with the approved
#                        TemplatoratorSwampLogo image (360 x 240 JPEG, 73,929
#                        bytes / 98,572 Base64 chars). Embedded value verified
#                        to decode to the exact source JPEG. Dimensions and
#                        MIME type are unchanged; only the Base64 payload and
#                        its descriptive comments were updated.
#   1.3.8 - 2026-06-20 - The base-template picker now pages long lists instead
#                        of dumping every template at once. Added a reusable
#                        Read-PagedMenuChoice helper and a $MenuPageSize
#                        setting (default 20): each page shows up to 20 rows
#                        with a 'Showing X-Y of Z' header, and the operator
#                        presses Enter or N for the next 20 (P for the
#                        previous 20) or types any listed number to select.
#                        Numbers are global, so a selection on any page maps
#                        to the correct template. The short EKU/subject-source
#                        menus continue to use the single-page Read-MenuChoice.
#   1.3.9 - 2026-06-20 - Fixed a strict-mode crash ('The property Count cannot
#                        be found on this object') that occurred after a Create
#                        when no enrollment grants were entered. Read-Enrollment
#                        Grants returned $grants.ToArray(); an empty array sent
#                        through return unrolls to nothing, so the caller got
#                        $null and Definition.Grants.Count then threw. The same
#                        latent defect existed in Get-PublishingCANames (the
#                        Delete DryRun all-CAs preview when a template is not
#                        published anywhere). Both now return ,$list.ToArray()
#                        so an empty result stays an empty array.
#   1.3.10 - 2026-06-20 - Changed the $DryRun parameter default from $false to
#                        $true so the script is safe by default and makes no
#                        changes unless explicitly run live. Pass -DryRun $false
#                        to perform real operations.
#   1.4.0 - 2026-06-20 - Multi-forest support. Replaced the single $CAConfig
#                        with a $DomainConfigs registry keyed by forest, each
#                        carrying the forest DNS name, a friendly label, and
#                        its issuing-CA list. uhhs.com (default) keeps its one
#                        sub CA; uhtd.local was added with its two issuing sub
#                        CAs (TDPKI-SUBCA01-2025, TDPKI-SUBCA02-2025). A new
#                        menu option D (Select Domain) switches the active
#                        forest, shown with the current selection and set off
#                        by a blank line above options 1/2/3. New helpers
#                        (Get-ActiveDomain, Get-LdapServerPrefix, Get-LdapPath,
#                        Get-RootDsePath, Get-DomainCAConfigs, Resolve-Active
#                        CAConfig, Set-ActiveDomain, Select-Domain) route every
#                        RootDSE and DN bind through a server-qualified LDAP
#                        path so all directory access targets the selected
#                        forest instead of the machine's joined domain. When a
#                        forest defines more than one CA the operator is
#                        prompted once and the choice is cached per forest;
#                        Get-PublishingCANames and Remove-TemplateFromAllCAs
#                        now iterate the active forest's configured CA list via
#                        Connect-CertificationAuthority rather than an ambient
#                        Get-CertificationAuthority enumeration, keeping the
#                        sweep deterministic and forest-scoped. The base-
#                        template / OID / Enrollment Services lookups, the
#                        publish, unpublish, and delegate paths, and every
#                        prompt and report line that named the CA were updated
#                        accordingly. Switching forests resets the cached CA.
#   1.4.1 - 2026-06-20 - Template pick-list paging raised from 20 to 25 rows
#                        per page ($MenuPageSize). The pager navigation hint
#                        now reflects $MenuPageSize rather than a hardcoded 20,
#                        and the active forest is surfaced in the startup INFO
#                        line and the email report summary.
#   1.4.2 - 2026-06-20 - Added an explicit startup INFO line naming the log
#                        directory and full log file path so the operator can
#                        see where logs are written ($LogDir / $LogFile under
#                        %ProgramData%\UH\Logs); the first log write also forces
#                        directory creation. Commented out the Jeffrey.Altomari
#                        recipient in $MailTo (per request) so the report now
#                        goes only to Alan.Phillips; the address is retained as
#                        a comment to re-enable later.
#   1.4.3 - 2026-06-20 - Logs are now written to a 'Logs' folder beneath the
#                        script's own directory instead of %ProgramData%\UH\
#                        Logs. Added a $ScriptRoot resolver ($PSScriptRoot,
#                        falling back to $PSCommandPath's parent, then the
#                        current location) and based $LogDir on it. The startup
#                        INFO line continues to report the resolved directory
#                        and file path.
#   1.5.0 - 2026-06-20 - Cross-forest credentials. When a forest other than the
#                        script account's own is selected (e.g. uhtd.local from
#                        a uhhs.com account), the operator is prompted once for
#                        credentials valid in the target forest and they are
#                        cached per forest ($Script:DomainCredentials) and
#                        applied to every LDAP bind. Added Test-DomainCredential
#                        Needed (compares $env:USERDNSDOMAIN / $env:USERDOMAIN
#                        to the target's DnsName / NetbiosName), Get-Domain
#                        Credential (prompt + cache), Get-ActiveDomainCredential,
#                        and a New-DomainDirectoryEntry factory that builds every
#                        DirectoryEntry with the credential when present; all 13
#                        binds now route through it. Set-ActiveDomain captures
#                        the credential on switch, and a new -DomainKey parameter
#                        lets the non-interactive -DelegatePublishRights mode
#                        target a forest (Invoke-Main switches up front). Because
#                        PSPKI (Connect-CertificationAuthority, *-CATemplate, the
#                        Read + Enroll grant) and NTAccount SID translation
#                        authenticate with the process token and cannot take a
#                        PSCredential, publishing to CAs, enrollment-rights
#                        grants, and the all-CAs unpublish sweep now detect a
#                        foreign active forest (Test-ActiveForestIsForeign) and
#                        defer with a clear WARN (Get-ForeignForestDeferralMessage)
#                        ledgered as 'Publish deferred' instead of failing under
#                        the wrong identity. The DirectoryServices-based
#                        -DelegatePublishRights DACL write remains credential-
#                        capable. Added NetbiosName to each $DomainConfigs entry.
#   1.5.1 - 2026-06-20 - Fixed 'Cannot index into a null array' when switching
#                        to a cross-forest domain and listing templates. RootDSE
#                        binds via DirectoryEntry are lazy, so a credentialed
#                        cross-forest bind that did not connect surfaced only on
#                        first property access as the null-array error. Added
#                        Get-RootDseAttribute, which binds RootDSE, forces the
#                        connection with RefreshCache (RootDSE operational
#                        attributes are not returned by default), validates the
#                        value, and throws a clear error naming the forest, path,
#                        and attribute on failure. Get-ConfigNamingContext and
#                        Get-AttributeSchemaGuid now read through it. New-Domain
#                        DirectoryEntry sets AuthenticationType Secure -bor
#                        Sealing on credentialed binds so the cross-forest bind
#                        is signed and deterministic rather than silently empty.
#   1.6.0 - 2026-06-20 - Reworked cross-forest handling from in-process
#                        credentialed LDAP binds (which could not carry the token
#                        to PSPKI and failed authentication in practice) to a
#                        relaunch model. Selecting a forest the running account
#                        is not part of now prompts for that forest's credentials
#                        and relaunches the whole script as that account via
#                        Start-Process -Credential, in a new -NoExit window, with
#                        the forest preselected by -DomainKey and the current
#                        -DryRun posture preserved (passed through -Command so the
#                        boolean binds correctly). The originating session then
#                        ends. Added Restart-UnderDomainCredential, Get-ScriptHost
#                        Path, and Get-ScriptFilePath; Set-ActiveDomain, Select-
#                        Domain, the menu D handler, and Invoke-Main now return /
#                        honor a 'Relaunched' status and exit cleanly. New-Domain
#                        DirectoryEntry reverts to a native token bind (the
#                        relaunched process is already the right identity), and
#                        the orphaned in-process Get-DomainCredential / Get-Active
#                        DomainCredential helpers were removed. The token-bound
#                        deferral guards remain as a safety net but no longer fire
#                        in the normal flow because nothing is foreign after the
#                        relaunch. Relaunch requires a saved .ps1 on disk.
#   1.6.1 - 2026-06-20 - Switched the cross-forest relaunch from Start-Process
#                        -Credential to runas /netonly. Start-Process -Credential
#                        performs an INTERACTIVE logon, which requires the foreign
#                        account to hold 'Allow log on locally' on this
#                        workstation; it does not, so the launch failed with a
#                        misleading 'The user name or password is incorrect'
#                        (ERROR_LOGON_FAILURE) even with a verified-correct
#                        password. runas /netonly uses LOGON32_LOGON_NEW_
#                        CREDENTIALS: the local session is unchanged and the
#                        supplied credentials are used only for network auth
#                        (LDAP / RPC to the CAs), needing just the right password
#                        and a reachable forest. The relaunch now prompts for the
#                        DOMAIN\user (defaulting to the forest NetBIOS name),
#                        builds the inner relaunch command, passes it as
#                        -EncodedCommand (Base64 / UTF-16LE) to avoid nested-
#                        quoting issues across the runas boundary, and invokes
#                        runas.exe /netonly /user:... ; runas prompts for the
#                        password on the console (it cannot take a captured
#                        PSCredential). Because /netonly defers validation to
#                        first network use, a wrong password now surfaces as the
#                        clear RootDSE bind error in the relaunched window rather
#                        than at launch.
#   1.6.2 - 2026-06-20 - Fixed the runas relaunch exiting 1 instantly without
#                        ever prompting for the password. runas was being started
#                        through Start-Process -NoNewWindow, which detaches the
#                        console runas needs to show its secure prompt, so it
#                        failed immediately. runas.exe is now invoked directly via
#                        the call operator so it inherits the live console and
#                        prompts normally; $LASTEXITCODE carries its result. Also
#                        made the command passed to runas quote-free by using the
#                        bare host exe name (powershell.exe / pwsh.exe, resolved
#                        via PATH) instead of a quoted full path, since embedded
#                        quotes inside the single runas program argument were
#                        being mangled; combined with the space-free Base64
#                        -EncodedCommand the whole argument now needs no inner
#                        quoting.
#   1.7.0 - 2026-06-20 - Reworked the cross-forest relaunch to a .cmd launcher.
#                        Driving runas live from the PowerShell host was
#                        unreliable every way it was tried (Start-Process
#                        -Credential needed local logon rights; runas via Start-
#                        Process exited 1 with no prompt; runas called directly
#                        hung without prompting). The script now writes a small
#                        batch launcher (ScriptName_Relaunch_<NETBIOS>.cmd) next
#                        to itself and opens it in its own console via cmd.exe
#                        (launching cmd is reliable where launching runas is
#                        not). The .cmd runs runas /netonly /user:<acct> with the
#                        host exe and the Base64 -EncodedCommand, prompts for the
#                        password in that window, and starts Templatorator as the
#                        target-forest network identity; it PAUSEs on a runas
#                        error so the message is readable. Added a relaunch
#                        marker: when started with an explicit -DomainKey the
#                        session knows it IS the relaunched window (runas /netonly
#                        leaves the LOCAL token unchanged, so env-based detection
#                        would otherwise loop and would wrongly defer token-bound
#                        ops). Invoke-Main now sets the active forest directly
#                        from -DomainKey and sets ForestPresetViaRelaunch, which
#                        makes Test-ActiveForestIsForeign return false so publish,
#                        grants, and the all-CAs sweep run for real under the
#                        /netonly network credentials. The launcher is written
#                        ASCII/CRLF (a BOM can break a .cmd first line) without
#                        backticks per the script standard.
#   1.7.1 - 2026-06-20 - Fixed the relaunch failing with 'There is no option
#                        with the following name: NoExit' when launched from the
#                        PowerShell ISE. Get-ScriptHostPath was resolving the host
#                        from the current process path, which under the ISE is
#                        powershell_ise.exe - and the ISE accepts only -File /
#                        -MTA / -NoProfile, rejecting the -NoExit / -EncodedCommand
#                        the relaunch needs and being unable to host the menu. The
#                        host is now chosen by edition ($PSVersionTable.PSEdition):
#                        Core -> pwsh.exe, Desktop -> powershell.exe, never the
#                        ISE, with a System32 v1.0 fallback for Windows PowerShell.
#   1.7.2 - 2026-06-20 - The relaunch .cmd launcher now deletes itself after
#                        launching so it never lingers next to the script. Its
#                        final line is (GOTO) 2>NUL & DEL "%~f0": runas /netonly
#                        has already handed off to the child PowerShell by then
#                        (it does not wait), so the file is no longer in use; the
#                        (GOTO) pops the batch call stack to release the handle
#                        and DEL removes the launcher's own file. This runs on
#                        both the success path and the post-PAUSE error path.
#   1.7.3 - 2026-06-20 - Cross-forest RootDSE bind in the relaunched session was
#                        failing ('user name or password is incorrect') on the
#                        domain-name form LDAP://uhtd.local/RootDSE. Under runas
#                        /netonly the DC locator runs in the local machine context
#                        and can fail to find a DC in the target forest. Added a
#                        DcName field to each $DomainConfigs entry (uhtd.local set
#                        to tddc01.uhtd.local) and made Get-LdapServerPrefix prefer
#                        it over the forest DNS name, so binds now target a named
#                        DC (LDAP://tddc01.uhtd.local/...), which is reliable
#                        under /netonly. DcName is blank for the home forest. The
#                        RootDSE error now explains the /netonly causes (name
#                        resolution, reachability, TCP 389, Kerberos time skew)
#                        and points at DcName.
#   1.8.0 - 2026-06-20 - Removed the runtime dependency on PSPKI cmdlets, which
#                        enforce 'AD DS Domain Membership' and refuse to run on a
#                        machine not joined to the target forest - the reason the
#                        cross-forest create failed at Get-CertificateTemplate
#                        even though LDAP worked. Every CA / template / ACL /
#                        principal operation now uses direct LDAP (the same
#                        DcName-qualified binds that already worked): existence
#                        checks and post-create verification via Test-Template
#                        ExistsLdap; publish/unpublish by editing the issuing CA's
#                        Enrollment Services certificateTemplates attribute
#                        (Publish-TemplateToCA, Remove-TemplateFromCALdap, Remove-
#                        TemplateFromCA, Remove-TemplateFromAllCAs, and the
#                        Get-PublishingCANames preview); enrollment-rights grant
#                        by writing Read + Enroll (+ optional Autoenroll, via the
#                        well-known control-access-right GUIDs) directly onto the
#                        template DACL in Grant-TemplateEnrollmentRights; and
#                        principal validation by an LDAP search of the forest
#                        (Resolve-AdPrincipal) instead of token-bound NTAccount.
#                        Translate, which could not resolve uhtd accounts from a
#                        uhhs token. Because nothing is token-bound anymore, the
#                        foreign-forest deferral guards no longer trigger in the
#                        relaunched session and publish / grants run for real.
#                        Initialize-PSPKI is now best-effort and non-fatal (the
#                        module is imported when present, silencing its 'not
#                        joined' warning, but is no longer required), and the
#                        report Engine label reads 'Direct LDAP (Configuration
#                        partition)'.
#   1.8.1 - 2026-06-20 - Fixed a DryRun safety gap in the create flow: template
#                        creation and the enrollment-rights grant ran regardless
#                        of DryRun (only publish was guarded), so a 'DryRun' run
#                        could have written a real template and DACL. Both are now
#                        previewed under DryRun (Write-DryRunMsg + ledger 'DryRun')
#                        and only executed when DryRun is off. Added main-menu
#                        option T (Toggle DryRun), shown after a blank line below
#                        option 3 with the current state; it flips $script:DryRun
#                        live for the rest of the session. Pressing Q at the base-
#                        template picker (create) or the template picker (modify /
#                        delete) now returns to the main menu instead of forcing a
#                        choice (Read-MenuChoice / Read-PagedMenuChoice gained an
#                        -AllowQuit switch; the pickers return null and the
#                        orchestrators return 'Returned to menu'). The summary
#                        report now captures every choice for all actions: Modify
#                        and Delete build a full $Script:RunContext summary (each
#                        changed attribute and its new value, grants, publish
#                        target, unpublish scope, OID handling, DryRun state, run-
#                        by) to match what Create already recorded, and Create's
#                        summary gained the DryRun state.
#   1.8.2 - 2026-06-20 - The active forest is now auto-detected at startup: if
#                        the running account belongs to one of the configured
#                        forests (matched on $env:USERDNSDOMAIN / $env:USERDOMAIN
#                        against each entry's DnsName / NetbiosName), that forest
#                        becomes active automatically. Running the script natively
#                        inside UHTD therefore starts on UHTD with no relaunch and
#                        no credential prompt; inside UHHS it starts on UHHS. An
#                        explicit -DomainKey (the relaunched /netonly session)
#                        still wins, and an account in no configured forest keeps
#                        the default. Added Get-CurrentForestKey as the single
#                        source of truth for 'which forest am I in' and refactored
#                        Test-DomainCredentialNeeded to use it. The startup line
#                        notes when a forest was auto-selected from the native
#                        session.
#   1.8.3 - 2026-06-20 - Replaced the hardcoded per-forest DC with dynamic domain-
#                        controller resolution. Added Resolve-ActiveDomainControl-
#                        ler, which Get-LdapServerPrefix uses to pick the LDAP
#                        server: (1) a cached DC for the forest; (2) when the
#                        session is NATIVE to the active forest, $env:LOGONSERVER -
#                        the DC that actually authenticated the logon - qualified
#                        to an FQDN; (3) dynamic discovery via nltest /dsgetdc
#                        against the forest DNS name; (4) the configured DcName
#                        fallback; (5) the forest DNS name. In a relaunched runas
#                        /netonly session LOGONSERVER still points at the home
#                        forest, so it is used only when native. The chosen DC is
#                        cached per forest ($Script:ResolvedDomainControllers) and
#                        cleared for a forest on an interactive switch so a downed
#                        DC is re-resolved. DcName is now a last-resort fallback
#                        rather than the primary mechanism.
#   1.8.4 - 2026-06-20 - Set the UHHS fallback DcName to ldaps.uhhs.com, the
#                        local load-balanced pool of UHHS DCs (plain LDAP on 389;
#                        the name is cosmetic, no LDAPS implied). It is used only
#                        as the post-discovery fallback (after $env:LOGONSERVER
#                        when native and nltest discovery), so normal native and
#                        relaunch paths still bind to a specific live DC. Note the
#                        pool resolves at local sites only, not remote locations.
#   1.8.5 - 2026-06-20 - Re-enabled the Jeffrey.Altomari recipient in $MailTo;
#                        reports now go to Alan.Phillips and Jeffrey.Altomari
#                        again (reverses the 1.4.2 comment-out).
# =====================================================================

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [switch]$DelegatePublishRights,

    [Parameter(Mandatory = $false)]
    [string]$DelegateToPrincipal,

    [Parameter(Mandatory = $false)]
    [string]$DomainKey,

    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

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

# --- Script location -------------------------------------------------
#     Resolve the directory the script is executing from so logs live
#     beneath it. $PSScriptRoot is populated when the .ps1 is run normally;
#     $PSCommandPath is a fallback, and the current location is the last
#     resort for unusual hosts (e.g. dot-sourced into a bare console). ---
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot))
{
    $ScriptRoot = $PSScriptRoot
}
elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath))
{
    $ScriptRoot = Split-Path -Path $PSCommandPath -Parent
}
else
{
    $ScriptRoot = (Get-Location).Path
}

# --- Logging paths. A 'Logs' folder beneath the script's own directory,
#     created on first write by Write-Log. ---
$LogDir  = Join-Path -Path $ScriptRoot -ChildPath 'Logs'
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
# the linked resource. The byte content is JPEG, so the MIME type is
# image/jpeg - Outlook keys off the LinkedResource content type, not a
# filename. The embedded value below is the TemplatoratorSwampLogo image
# (360 x 240, 73,929 bytes / 98,572 Base64 chars). If it is ever cleared
# back to a placeholder ending in '...', or fails to decode, the report is
# sent without the inline logo (a single WARN) instead of a broken image.
$EmailLogoEnabled   = $true
$EmailLogoContentId = 'templatoratorlogo'
$EmailLogoWidth     = 360
$EmailLogoHeight    = 240
$EmailLogoMimeType  = 'image/jpeg'
$EmailLogoBase64    = '/9j/61SASlAKAAAAAAEAAFR2anVtYgAAAB5qdW1kYzJwYQARABCAAACqADibcQNjMnBhAAAASf1qdW1iAAAAR2p1bWRjMm1hABEAEIAAAKoAOJtxA3VybjpjMnBhOjkzOTUxZmE1LTBiZmUtNGQ0MS04Y2MzLWQyZTA4NzM5NzMwOAAAAAQWanVtYgAAAClqdW1kYzJhcwARABCAAACqADibcQNjMnBhLmFzc2VydGlvbnMAAAACC2p1bWIAAABBanVtZGNib3IAEQAQgAAAqgA4m3ETYzJwYS5hY3Rpb25zLnYyAAAAABhjMnNocX1cv71yR1c25VFqoPyW5AAAAcJjYm9yomdhY3Rpb25zgqVmYWN0aW9ubGMycGEuY3JlYXRlZGR3aGVueBkyMDI2LTA2LTIwVDAyOjU1OjUwKzAwOjAwbXNvZnR3YXJlQWdlbnS/ZG5hbWV1QXp1cmUgT3BlbkFJIEltYWdlR2Vu/3FkaWdpdGFsU291cmNlVHlwZXhGaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS90cmFpbmVkQWxnb3JpdGhtaWNNZWRpYWtkZXNjcmlwdGlvbnFHZW5lcmF0ZWQgd2l0aCBBSaRmYWN0aW9ucGMycGEud2F0ZXJtYXJrZWRkd2hlbnghMjAyNi0wNi0yMFQwMjo1NTo1MC40NDQyOTg5KzAwOjAwbXNvZnR3YXJlQWdlbnS/ZG5hbWV4I01pY3Jvc29mdCBSZXNwb25zaWJsZSBBSSBQcm92ZW5hbmNlZ3ZlcnNpb25jMS4w/2tkZXNjcmlwdGlvbngvQ29udGVudCB3YXRlcm1hcmtlZCBieSBNaWNyb3NvZnQgUmVzcG9uc2libGUgQUlyYWxsQWN0aW9uc0luY2x1ZGVk9QAAARdqdW1iAAAAQ2p1bWRjYm9yABEAEIAAAKoAOJtxE2MycGEuc29mdC1iaW5kaW5nAAAAABhjMnNoq1DmhsbIlRN5jec0mtnFVQAAAMxjYm9yo2NhbGd4GWNvbS5taWNyb3NvZnQuaW52aXNtYXJrLjFjcGFkgGZibG9ja3OBomVzY29wZaFmcmVnaW9uoWZyZWdpb26BomR0eXBlZ3NwYXRpYWxlc2hhcGWlZHR5cGVpcmVjdGFuZ2xlZHVuaXRqcGVyY2VudGFnZWV3aWR0aBhkZmhlaWdodBhkZm9yaWdpbqJheABheQBldmFsdWV4JDg0YTA0ZjMzLTdjODYtNDA5ZS04M2ZiLWVmYzI5ZGJkZDFkYwAAAMNqdW1iAAAAQGp1bWRjYm9yABEAEIAAAKoAOJtxE2MycGEuaGFzaC5kYXRhAAAAABhjMnNovfpVkjscKLeoQtrCmBR71wAAAHtjYm9ypWpleGNsdXNpb25zgaJlc3RhcnQYIWZsZW5ndGgZSi9kbmFtZW5qdW1iZiBtYW5pZmVzdGNhbGdmc2hhMjU2ZGhhc2hYIKX8P0OtqSJZ8CueRjV09ql4pLdsUFol0stgxBjDnJ2hY3BhZEgAAAAAAAAAAAAAAnNqdW1iAAAAJ2p1bWRjMmNsABEAEIAAAKoAOJtxA2MycGEuY2xhaW0udjIAAAACRGNib3Kmamluc3RhbmNlSUR4LHhtcDppaWQ6N2U3OGRmZTUtMTU5My00NTJhLWEzOGQtOTc1YjE0ODk5OTI3dGNsYWltX2dlbmVyYXRvcl9pbmZvv2RuYW1leCNNaWNyb3NvZnQgUmVzcG9uc2libGUgQUkgUHJvdmVuYW5jZWd2ZXJzaW9uYzEuMHdvcmcuY29udGVudGF1dGguYzJwYV9yc2YwLjg0LjH/aXNpZ25hdHVyZXhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTo5Mzk1MWZhNS0wYmZlLTRkNDEtOGNjMy1kMmUwODczOTczMDgvYzJwYS5zaWduYXR1cmVyY3JlYXRlZF9hc3NlcnRpb25zgaJjdXJseClzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmhhc2guZGF0YWRoYXNoWCAh1JJtLXRZlFeT5CEwR8h/smwjk5L6FfeELIqx9dCeWHNnYXRoZXJlZF9hc3NlcnRpb25zgqJjdXJseCpzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjJkaGFzaFggZqKXvPWfvzzAn5Ey5jl4TeOs9DKAHXPj2OtDOqUeVheiY3VybHgsc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5zb2Z0LWJpbmRpbmdkaGFzaFgg5GW6zNyzHr8t7KKJkD6zbSctFOVfilRPYq/+xTNWAbhjYWxnZnNo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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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c2hYIDg2Z21ssqU1n31crGQ86kClBrVDExqE4z32waB3s8rDY3BhZECjZW5hbWVzgWNFT0lkaGFzaFggzeZueOVBnep033z0PZqodrjGadQAZ5kucZzvkKxfP+BjcGFkQAAAASFqdW1iAAAALGp1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52MgAAAADtY2JvcqRtYzJwYV9tYW5pZmVzdKNjYWxnZnNoYTI1NmRoYXNoeCx0cHZqamRoUEltRmhmbUczUExSMGtzREVCRGttR2hrd0tka0ZNcWd3bElRPWN1cmx4PnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6OTM5NTFmYTUtMGJmZS00ZDQxLThjYzMtZDJlMDg3Mzk3MzA4aWRjOmZvcm1hdGlpbWFnZS9wbmdoZGM6dGl0bGV4G1JlcG9ydGVkIGFzIGdlbmVyYXRlZCBieSBBSWxyZWxhdGlvbnNoaXBrY29tcG9uZW50T2YAAADkanVtYgAAAClqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmFjdGlvbnMudjIAAAAAs2Nib3KhZ2FjdGlvbnOBo2ZhY3Rpb25rYzJwYS5lZGl0ZWRrZGVzY3JpcHRpb254QEVkaXRlZCBvZmZsaW5lIHdpdGhvdXQgdHJ1c3RlZCBjZXJ0aWZpY2F0ZSBhbmQgc2VjdXJlIHNpZ25hdHVyZS5tc29mdHdhcmVBZ2VudKJkbmFtZXRQYWludCBhcHAgb24gV2luZG93c2d2ZXJzaW9ubTExLjI2MDMuMjUxLjAAAAMIanVtYgAAACRqdW1kYzJjbAARABCAAACqADibcQNjMnBhLmNsYWltAAAAAtxjYm9yp2NhbGdmc2hhMjU2aWRjOmZvcm1hdGppbWFnZS9qcGVnaXNpZ25hdHVyZXhMc2VsZiNqdW1iZj1jMnBhL3Vybjp1dWlkOmZlZGIzMDRjLWNkNDQtNDdjNi1iYzExLTEzNzViY2QzZjdhMi9jMnBhLnNpZ25hdHVyZWppbnN0YW5jZUlEeC11cm46dXVpZDpkMzg3MzA0MC02NDk0LTQ0NTQtYWI2OS1iMmI2MTg4NTE4ZTRvY2xhaW1fZ2VuZXJhdG9ycUxvY2FsbHkgZ2VuZXJhdGVkdGNsYWltX2dlbmVyYXRvcl9pbmZv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'

# --- Multi-domain configuration ---------------------------------------
#     Templatorator can target more than one Active Directory forest. Each
#     entry is keyed by a short label and carries the forest DNS name (used
#     as the LDAP server component so every bind and PSPKI call is directed
#     at that forest rather than the machine's joined domain), a friendly
#     label for prompts and the report, and the issuing CA list. A CA entry
#     is 'CAHostName\CA Common Name' exactly as Connect-CertificationAuthority
#     and the Enrollment Services object expect it. uhhs.com is the default;
#     uhtd.local carries its two issuing sub CAs. The operator switches the
#     active forest from the main menu (option D). ---
$DomainConfigs = @{
    'uhhs.com' = [pscustomobject]@{
        Key         = 'uhhs.com'
        Label       = 'UHHS (uhhs.com)'
        DnsName     = 'uhhs.com'
        NetbiosName = 'UHHS'
        # DcName: a LAST-RESORT fallback server. Resolve-ActiveDomainController
        # normally finds a live DC dynamically (the authenticating DC when
        # native, else nltest discovery), so this is only used if discovery
        # returns nothing. ldaps.uhhs.com is a local load-balanced pool of UHHS
        # DCs that answers plain LDAP on 389 (the name is cosmetic - no LDAPS is
        # implied); note it resolves only at local sites, not remote locations.
        DcName      = 'ldaps.uhhs.com'
        CAConfigs  = @(
            'uhpkisub03\University Hospitals Sub CA 3'
        )
    }
    'uhtd.local' = [pscustomobject]@{
        Key         = 'uhtd.local'
        Label       = 'UHTD (uhtd.local)'
        DnsName     = 'uhtd.local'
        NetbiosName = 'UHTD'
        DcName      = 'tddc01.uhtd.local'
        CAConfigs  = @(
            'tdpkisubca01.uhtd.local\TDPKI-SUBCA01-2025'
            'tdpkisubca02.uhtd.local\TDPKI-SUBCA02-2025'
        )
    }
}

# --- Default and active forest. $Script:ActiveDomainKey is the currently
#     selected forest; it starts on the default and is changed by Select-Domain
#     (menu option D). All LDAP binds and CA operations resolve through the
#     active forest's $DomainConfigs entry - nothing is hardcoded per call. ---
$DefaultDomainKey       = 'uhhs.com'
$Script:ActiveDomainKey = $DefaultDomainKey

# --- Active issuing CA within the selected forest. uhhs.com has a single CA
#     so it is fixed; uhtd.local has two, so the operator is prompted to pick
#     one (or all) at publish/unpublish time. $Script:ActiveCAConfig caches the
#     last single-CA selection for the current forest and is reset whenever the
#     forest changes. A $null value means 'ask on next use'. ---
$Script:ActiveCAConfig  = $null

# --- Cross-forest credentials. When a forest other than the one the script
#     account belongs to is selected, AD object operations need credentials
#     valid in the target forest. $Script:DomainCredentials caches one
#     PSCredential per forest key (captured once, reused for the session).
#     The credential is applied to every DirectoryEntry LDAP bind. Note: the
#     PSPKI cmdlets (Connect-CertificationAuthority, *-CATemplate, the Read +
#     Enroll grant) and NTAccount SID translation authenticate with the
#     process token and cannot consume a PSCredential, so publish, enrollment
#     grants, and principal resolution are deferred with a clear WARN when run
#     cross-forest - perform those from a shell running as the target-forest
#     account (or via -DelegatePublishRights once, as that account). ---
$Script:DomainCredentials = @{}

# --- Relaunch marker. Set true when the script is started with an explicit
#     -DomainKey, i.e. this IS the session relaunched by runas /netonly with the
#     target forest's NETWORK credentials. The local token is still the original
#     account, so env-based forest detection would wrongly see the forest as
#     foreign; this flag tells the token-bound paths that network access already
#     uses the right identity and must NOT defer or relaunch again. ---
$Script:ForestPresetViaRelaunch = $false

# --- Resolved domain-controller cache. Get-LdapServerPrefix resolves a live DC
#     for the active forest once and caches the FQDN here, keyed by forest, so
#     repeated binds in a session do not re-run discovery. Cleared for a forest
#     when it is (re)selected. ---
$Script:ResolvedDomainControllers = @{}

# --- Module dependency ---
$PSPKIModuleName = 'PSPKI'

# --- Policy guardrails for interactive input ---
$MinimumKeySize     = 2048                  # RSA minimum key-size floor enforced at the prompt
$TemplateNamePattern = '^[A-Za-z0-9_\-]+$'  # CN must be letters, numbers, underscore, hyphen (no spaces)

# --- Interactive menu paging ---
$MenuPageSize = 25  # Long pick-lists (e.g. the base-template picker) show this many rows per page

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

function Get-ActiveDomain
{
    [CmdletBinding()]
    param()

    # Returns the $DomainConfigs entry for the currently selected forest. The
    # active key is validated against the registry so a bad value fails loudly
    # rather than producing serverless binds against the wrong forest.
    if (-not $DomainConfigs.ContainsKey($Script:ActiveDomainKey))
    {
        throw ('Active domain key [{0}] is not present in $DomainConfigs.' -f $Script:ActiveDomainKey)
    }

    return $DomainConfigs[$Script:ActiveDomainKey]
}

function Get-CurrentForestKey
{
    [CmdletBinding()]
    param()

    # Returns the $DomainConfigs key for the forest the running account belongs
    # to, by matching the logged-on domain ($env:USERDNSDOMAIN FQDN, with
    # $env:USERDOMAIN NetBIOS as a fallback) against each entry's DnsName /
    # NetbiosName, case-insensitively. Returns $null when the account is not in
    # any configured forest (e.g. a machine joined to neither). This is the
    # single source of truth for 'which forest am I natively in'.
    $currentDns     = [string]$env:USERDNSDOMAIN
    $currentNetbios = [string]$env:USERDOMAIN

    foreach ($key in $DomainConfigs.Keys)
    {
        $entry = $DomainConfigs[$key]

        if (-not [string]::IsNullOrWhiteSpace($currentDns) -and
            ($currentDns -ieq $entry.DnsName))
        {
            return $key
        }

        if (-not [string]::IsNullOrWhiteSpace($currentNetbios) -and
            ($currentNetbios -ieq $entry.NetbiosName))
        {
            return $key
        }
    }

    return $null
}

function Test-DomainCredentialNeeded
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainKey
    )

    # Credentials (and a relaunch) are needed when the target forest differs from
    # the forest the running account belongs to. Delegates the 'which forest am I
    # in' decision to Get-CurrentForestKey so detection lives in one place. When
    # the account is in no configured forest, the target is treated as foreign.
    $currentKey = Get-CurrentForestKey

    if ([string]::IsNullOrWhiteSpace($currentKey))
    {
        return $true
    }

    return ($currentKey -ne $DomainKey)
}

function Get-ScriptHostPath
{
    [CmdletBinding()]
    param()

    # The console host used for the relaunch. This must be an INTERACTIVE console
    # host, never the ISE: powershell_ise.exe rejects -NoExit / -EncodedCommand
    # (it accepts only -File / -MTA / -NoProfile) and cannot host the menu. So the
    # host is chosen by edition, not by the current process path - running from
    # the ISE would otherwise yield powershell_ise.exe. PowerShell 7 (Core) uses
    # pwsh.exe; Windows PowerShell 5.1 uses powershell.exe. The PSHOME path is
    # used when present (handles non-standard installs), with the bare name as a
    # PATH-resolved fallback.
    $edition = 'Desktop'

    if (($null -ne $PSVersionTable) -and $PSVersionTable.ContainsKey('PSEdition'))
    {
        $edition = [string]$PSVersionTable.PSEdition
    }

    if ($edition -eq 'Core')
    {
        $exeName = 'pwsh.exe'
    }
    else
    {
        $exeName = 'powershell.exe'
    }

    $candidate = Join-Path -Path $PSHOME -ChildPath $exeName

    if (Test-Path -LiteralPath $candidate)
    {
        return $candidate
    }

    # PSHOME points at the ISE folder only for the exe that launched it; the
    # console host lives in the same System32 / PowerShell 7 directory, so for
    # Desktop fall back to the well-known System32 location, else the bare name.
    if ($exeName -eq 'powershell.exe')
    {
        $system32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

        if (Test-Path -LiteralPath $system32)
        {
            return $system32
        }
    }

    return $exeName
}

function Get-ScriptFilePath
{
    [CmdletBinding()]
    param()

    # Full path to this .ps1 on disk, needed to relaunch it. $PSCommandPath is
    # the running script file; fall back to ScriptRoot + the known name.
    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath))
    {
        return $PSCommandPath
    }

    return (Join-Path -Path $ScriptRoot -ChildPath ('{0}.ps1' -f $ScriptName))
}

function Restart-UnderDomainCredential
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainKey
    )

    # Relaunches the script as an account in the target forest so every operation
    # - LDAP binds, the PSPKI publish/grant cmdlets, and NTAccount SID translation
    # - runs with that forest's credentials for network access. The mechanism is
    # runas /netonly (LOGON32_LOGON_NEW_CREDENTIALS): the local session is
    # unchanged, only network auth (LDAP / RPC to the CAs) uses the supplied
    # account, which needs just a correct password and a reachable forest - NOT
    # local logon rights on this workstation.
    #
    # Driving runas live from inside this PowerShell host proved unreliable (it
    # needs a clean attached console for its secure password prompt and otherwise
    # exits without prompting or hangs). Instead we WRITE a small .cmd launcher
    # next to the script and open it in its own fresh console via cmd.exe. runas
    # prompts for the password in that window and then starts Templatorator as the
    # target-forest network identity. Launching cmd.exe is reliable where
    # launching runas.exe directly is not.
    $target   = $DomainConfigs[$DomainKey]
    $hostPath = Get-ScriptHostPath
    $filePath = Get-ScriptFilePath

    if (-not (Test-Path -LiteralPath $filePath))
    {
        throw ('Cannot relaunch: the script file [{0}] was not found on disk. Run Templatorator from a saved .ps1 (not pasted into the console) to switch forests by relaunch.' -f $filePath)
    }

    # The account to authenticate as on the network, in DOMAIN\user form.
    $defaultUser = '{0}\' -f $target.NetbiosName
    $userName    = Read-Host -Prompt ('Enter the {0} account for network logon (DOMAIN\sAMAccountName) [{1}]' -f $target.Label, $defaultUser)

    if ([string]::IsNullOrWhiteSpace($userName))
    {
        Write-WarnMsg -Message ('Forest switch to [{0}] cancelled - no account supplied.' -f $target.Label)
        return $false
    }

    # Build the inner PowerShell command the relaunched session runs. -DomainKey
    # preselects the forest and -DryRun preserves the current posture. It is passed
    # as -EncodedCommand (Base64 / UTF-16LE) so neither the .cmd file nor the runas
    # argument has to quote it.
    $dryRunToken = if ($DryRun) { '$true' } else { '$false' }

    $safeFile   = $filePath -replace "'", "''"
    $safeDomain = $DomainKey -replace "'", "''"

    $innerCommand = "& '{0}' -DomainKey '{1}' -DryRun {2}" -f $safeFile, $safeDomain, $dryRunToken

    if ($DelegatePublishRights)
    {
        $innerCommand += ' -DelegatePublishRights'

        if (-not [string]::IsNullOrWhiteSpace($DelegateToPrincipal))
        {
            $safePrincipal = $DelegateToPrincipal -replace "'", "''"
            $innerCommand += " -DelegateToPrincipal '{0}'" -f $safePrincipal
        }
    }

    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($innerCommand))
    $hostExe = Split-Path -Path $hostPath -Leaf

    # Compose the launcher .cmd. The runas line uses the bare host exe name (on
    # PATH, no spaces) and the space-free encoded command, so no quoting is needed
    # around the program runas starts. ECHO lines orient the operator; PAUSE keeps
    # the window open if runas reports an error so the message can be read.
    $launcherName = '{0}_Relaunch_{1}.cmd' -f $ScriptName, $target.NetbiosName
    $launcherPath = Join-Path -Path $ScriptRoot -ChildPath $launcherName

    $cmdLines = New-Object System.Collections.Generic.List[string]
    $cmdLines.Add('@ECHO OFF')
    $cmdLines.Add('TITLE ' + $ScriptName + ' - relaunch as ' + $userName)
    $cmdLines.Add('ECHO.')
    $cmdLines.Add('ECHO  Starting ' + $ScriptName + ' as ' + $userName + ' for forest ' + $target.Label + '.')
    $cmdLines.Add('ECHO  Enter the password for ' + $userName + ' when prompted.')
    $cmdLines.Add('ECHO.')
    $cmdLines.Add('runas /netonly /user:' + $userName + ' "' + $hostExe + ' -NoExit -ExecutionPolicy Bypass -EncodedCommand ' + $encoded + '"')
    $cmdLines.Add('IF ERRORLEVEL 1 (')
    $cmdLines.Add('  ECHO.')
    $cmdLines.Add('  ECHO  runas reported an error. The password prompt may have been cancelled,')
    $cmdLines.Add('  ECHO  or the account may be locked, disabled, or mistyped.')
    $cmdLines.Add('  PAUSE')
    $cmdLines.Add(')')
    # Self-delete: by the time control reaches here, runas has already handed off
    # to the child PowerShell (runas /netonly does not wait for it), so this .cmd
    # is no longer in use. (GOTO) with no label pops the batch call stack, which
    # releases the file handle, and the chained DEL then removes the launcher's own
    # file (%~f0 = this script's full path). This runs on both the success and the
    # post-PAUSE error path so the launcher never lingers next to the script.
    $cmdLines.Add('(GOTO) 2>NUL & DEL "%~f0"')

    # Write the launcher as ANSI/ASCII with CRLF - the safest, most portable form
    # for a .cmd batch file (a UTF-8 BOM can break the first line of a batch file).
    try
    {
        $crlf    = [string][char]13 + [string][char]10
        $cmdText = ($cmdLines -join $crlf) + $crlf
        [System.IO.File]::WriteAllText($launcherPath, $cmdText, [System.Text.Encoding]::ASCII)
    }
    catch
    {
        throw ('Failed to write the relaunch launcher [{0}]: {1}.' -f $launcherPath, $_.Exception.Message)
    }

    Write-SuccessMsg -Message ('Wrote relaunch launcher [{0}] (it deletes itself after launching).' -f $launcherPath)
    Write-InfoMsg -Message ('Opening a new window to relaunch {0} as [{1}] in forest [{2}].' -f $ScriptName, $userName, $target.Label)
    Write-Host ''
    Write-Host ('  A new window will open and prompt for the password for [{0}].' -f $userName) -ForegroundColor Yellow
    Write-Host ('  If it does not appear, double-click: {0}' -f $launcherPath) -ForegroundColor Yellow
    Write-Host ''

    # Open the launcher in its own console. Launching cmd.exe (unlike runas.exe)
    # is reliable from inside the host; cmd then runs runas in that clean window.
    try
    {
        Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', ('"{0}"' -f $launcherPath)) -WorkingDirectory $ScriptRoot | Out-Null
    }
    catch
    {
        Write-WarnMsg -Message ('Could not auto-open the launcher: {0}. Run it manually: {1}' -f $_.Exception.Message, $launcherPath)
        return $false
    }

    Write-SuccessMsg -Message ('Launcher started for forest [{0}]. This window will now close.' -f $target.Label)

    return $true
}

function New-DomainDirectoryEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Single factory for every LDAP bind. Templatorator works one forest at a
    # time, and a forest the running account does not belong to is reached by
    # relaunching the whole script as a target-forest account (see Restart-
    # UnderDomainCredential) rather than by passing credentials to individual
    # binds - that is the only way the PSPKI publish/grant cmdlets and SID
    # translation also run under the correct token. By the time any bind runs,
    # the process identity is already native to the active forest, so a plain
    # token-based bind is correct. A cached credential is honored only if one
    # exists (kept for diagnostics / unusual hosts) and never prompts here.
    if ($Script:DomainCredentials.ContainsKey($Script:ActiveDomainKey) -and
        ($null -ne $Script:DomainCredentials[$Script:ActiveDomainKey]))
    {
        $cred        = $Script:DomainCredentials[$Script:ActiveDomainKey]
        $networkCred = $cred.GetNetworkCredential()

        $entry = New-Object System.DirectoryServices.DirectoryEntry ($Path, $cred.UserName, $networkCred.Password)
        $entry.AuthenticationType = ([System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Sealing)

        return $entry
    }

    return (New-Object System.DirectoryServices.DirectoryEntry ($Path))
}

function Get-RootDseAttribute
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$AttributeName
    )

    # Reads a single RootDSE attribute (e.g. configurationNamingContext,
    # schemaNamingContext) from the active forest. DirectoryEntry binds lazily,
    # so a bad server/credential surfaces only on first property touch and as
    # the unhelpful 'Cannot index into a null array'. Binding RootDSE explicitly
    # and reading through .Properties[..].Value inside a guarded block lets us
    # throw a clear, actionable error naming the forest and attribute instead.
    $domain  = Get-ActiveDomain
    $rootDse = New-DomainDirectoryEntry -Path (Get-RootDsePath)

    try
    {
        # RefreshCache forces the bind now and pulls the named operational
        # attribute (RootDSE attributes are not returned by default).
        $rootDse.RefreshCache(@($AttributeName))
        $value = [string]$rootDse.Properties[$AttributeName].Value
    }
    catch
    {
        throw ('Unable to bind RootDSE for forest [{0}] at [{1}] and read [{2}]: {3}. If this says the user name or password is incorrect under a relaunched (runas /netonly) session, the password is usually fine - the bind to the target forest failed. Check that the DC FQDN in the forest''s DcName resolves and is reachable from this machine (ping / nslookup {4}), that TCP 389 is open to it, and that time is in sync (Kerberos). Setting DcName to a specific reachable DC often fixes a domain-name bind that the DC locator could not satisfy cross-forest.' -f $domain.Label, (Get-RootDsePath), $AttributeName, $_.Exception.Message, $domain.DnsName)
    }

    if ([string]::IsNullOrWhiteSpace($value))
    {
        throw ('RootDSE for forest [{0}] returned no value for [{1}]. The bind may have failed silently - check forest reachability and credentials.' -f $domain.Label, $AttributeName)
    }

    return $value
}

function Test-ActiveForestIsForeign
{
    [CmdletBinding()]
    param()

    # True when the active forest is not reachable under the right identity.
    # Token-bound operations (PSPKI publish/unpublish, the Read + Enroll grant,
    # NTAccount SID translation) use this to defer with a clear WARN instead of
    # running under the wrong identity. When the session was relaunched via runas
    # /netonly for this forest (ForestPresetViaRelaunch), network access already
    # uses the correct credentials even though the local token is unchanged, so
    # it is NOT foreign for these purposes.
    if ($Script:ForestPresetViaRelaunch)
    {
        return $false
    }

    return (Test-DomainCredentialNeeded -DomainKey $Script:ActiveDomainKey)
}

function Get-ForeignForestDeferralMessage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Operation
    )

    $domain = Get-ActiveDomain

    return ('{0} cannot run from this account against forest [{1}] - the PSPKI / SID-translation layer authenticates with the process token, not the supplied credentials. Run this step from a shell started as a {2} account (or use -DelegatePublishRights once as that account).' -f $Operation, $domain.Label, $domain.NetbiosName)
}

function Resolve-ActiveDomainController
{
    [CmdletBinding()]
    param()

    # Resolve a specific, live domain controller FQDN for the active forest to use
    # as the LDAP server component. Binding to a named DC is far more reliable than
    # a domain-name bind, especially under runas /netonly where the DC locator runs
    # in the local machine context. Resolution order (first that yields a value):
    #
    #   1. Cached result for this forest (resolved earlier this session).
    #   2. NATIVE session only: $env:LOGONSERVER - the DC that actually
    #      authenticated this logon. Valid only when the running account belongs to
    #      the active forest; in a relaunched /netonly session LOGONSERVER still
    #      points at the ORIGINAL (home) forest's DC, so it is skipped there.
    #   3. Dynamic discovery via nltest /dsgetdc against the forest DNS name.
    #   4. The configured DcName fallback (if set).
    #   5. $null - caller then uses the forest DNS name directly.
    #
    # The chosen DC is cached per forest. Returns a bare FQDN (no scheme/slash) or
    # $null.
    $domain = Get-ActiveDomain
    $key    = $domain.Key

    if ($Script:ResolvedDomainControllers.ContainsKey($key) -and
        (-not [string]::IsNullOrWhiteSpace($Script:ResolvedDomainControllers[$key])))
    {
        return $Script:ResolvedDomainControllers[$key]
    }

    $resolved = $null

    # Step 2: the authenticating DC, but only when this session is native to the
    # active forest (not a relaunched /netonly session, where LOGONSERVER is the
    # home forest's DC).
    $isNative = (-not $Script:ForestPresetViaRelaunch) -and ((Get-CurrentForestKey) -eq $key)

    if ($isNative -and (-not [string]::IsNullOrWhiteSpace($env:LOGONSERVER)))
    {
        # LOGONSERVER is a NetBIOS UNC like \TDDC02. Strip the leading backslashes
        # and qualify with the forest DNS suffix to get an FQDN the binder can use.
        $logon = $env:LOGONSERVER.TrimStart('\')

        if (-not [string]::IsNullOrWhiteSpace($logon))
        {
            if ($logon -like '*.*')
            {
                $resolved = $logon
            }
            else
            {
                $resolved = '{0}.{1}' -f $logon, $domain.DnsName
            }

            Write-InfoMsg -Message ('Using the authenticating domain controller [{0}] for forest [{1}].' -f $resolved, $domain.Label)
        }
    }

    # Step 3: dynamic discovery for the target forest (works cross-forest when DNS
    # resolves the forest). nltest is part of Windows; failures are non-fatal.
    if ([string]::IsNullOrWhiteSpace($resolved))
    {
        try
        {
            $nltestOutput = & nltest.exe ('/dsgetdc:{0}' -f $domain.DnsName) 2>$null

            if ($LASTEXITCODE -eq 0)
            {
                foreach ($line in $nltestOutput)
                {
                    $trimmed = $line.Trim()

                    # The DC name line looks like: 'DC: \TDDC01.uhtd.local'
                    if ($trimmed -match '^DC:\s*\\\\(.+)$')
                    {
                        $candidate = $matches[1].Trim()

                        # Qualify a short name with the forest DNS suffix; leave an
                        # already-qualified FQDN as-is.
                        if ($candidate -like '*.*')
                        {
                            $resolved = $candidate
                        }
                        else
                        {
                            $resolved = '{0}.{1}' -f $candidate, $domain.DnsName
                        }

                        Write-InfoMsg -Message ('Discovered domain controller [{0}] for forest [{1}] via nltest.' -f $resolved, $domain.Label)
                        break
                    }
                }
            }
        }
        catch
        {
            # nltest unavailable or failed - fall through to the configured fallback.
            $resolved = $null
        }
    }

    # Step 4: configured DcName fallback.
    if ([string]::IsNullOrWhiteSpace($resolved) -and
        ($null -ne $domain.PSObject.Properties['DcName']) -and
        (-not [string]::IsNullOrWhiteSpace($domain.DcName)))
    {
        $resolved = $domain.DcName
        Write-InfoMsg -Message ('Using the configured fallback domain controller [{0}] for forest [{1}].' -f $resolved, $domain.Label)
    }

    if (-not [string]::IsNullOrWhiteSpace($resolved))
    {
        $Script:ResolvedDomainControllers[$key] = $resolved
    }

    return $resolved
}

function Get-LdapServerPrefix
{    [CmdletBinding()]
    param()

    # The LDAP server component placed in front of every distinguished name so
    # the bind is directed at the selected forest instead of the machine's joined
    # domain. A specific DC FQDN is preferred because, under runas /netonly,
    # binding to a named server is reliable where a domain-name bind can fail in
    # the DC locator. Resolve-ActiveDomainController finds a live DC dynamically
    # (authenticating DC when native, else nltest discovery, else the configured
    # DcName); only if all of those come back empty do we fall back to the forest
    # DNS name. Returns the server with a trailing slash, ready to prepend to a DN.
    $domain = Get-ActiveDomain
    $server = Resolve-ActiveDomainController

    if ([string]::IsNullOrWhiteSpace($server))
    {
        $server = $domain.DnsName
    }

    return ('{0}/' -f $server)
}

function Get-LdapPath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    # Builds a server-qualified LDAP path for a distinguished name against the
    # active forest. Every DirectoryEntry/DirectorySearcher bind in the script
    # routes through here so a single forest switch redirects all of them.
    return ('LDAP://{0}{1}' -f (Get-LdapServerPrefix), $DistinguishedName)
}

function Get-RootDsePath
{
    [CmdletBinding()]
    param()

    # Server-qualified RootDSE path for the active forest. Reading RootDSE from
    # the selected server yields that forest's configuration / schema naming
    # contexts, which in turn anchor every PKI container DN.
    return ('LDAP://{0}RootDSE' -f (Get-LdapServerPrefix))
}

function Get-DomainCAConfigs
{
    [CmdletBinding()]
    param()

    # The configured issuing-CA list for the active forest, normalized to an
    # array so callers can rely on .Count and indexing under Set-StrictMode.
    $domain = Get-ActiveDomain

    return @($domain.CAConfigs)
}

function Resolve-ActiveCAConfig
{
    [CmdletBinding()]
    param()

    # Returns the single issuing-CA config string to act on for the active
    # forest. When the forest defines exactly one CA it is used directly. When
    # it defines several (uhtd.local has two), the operator is prompted once and
    # the choice is cached on $Script:ActiveCAConfig for the rest of the session
    # (until the forest is switched, which clears the cache). The cached value is
    # re-validated against the current list so a stale selection is never reused.
    $configs = Get-DomainCAConfigs

    if ($configs.Count -eq 0)
    {
        throw ('No issuing CAs are configured for forest [{0}].' -f $Script:ActiveDomainKey)
    }

    if ($configs.Count -eq 1)
    {
        $Script:ActiveCAConfig = $configs[0]
        return $Script:ActiveCAConfig
    }

    if (($null -ne $Script:ActiveCAConfig) -and ($configs -contains $Script:ActiveCAConfig))
    {
        return $Script:ActiveCAConfig
    }

    $choice = Read-MenuChoice -Title ('Select the issuing CA for forest [{0}]:' -f $Script:ActiveDomainKey) -Items $configs
    $Script:ActiveCAConfig = $configs[$choice - 1]

    Write-InfoMsg -Message ('Active issuing CA set to [{0}].' -f $Script:ActiveCAConfig)

    return $Script:ActiveCAConfig
}

function Set-ActiveDomain
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainKey
    )

    # Switches the active forest and clears the cached CA selection so the next
    # publish/unpublish in a multi-CA forest prompts fresh.
    if (-not $DomainConfigs.ContainsKey($DomainKey))
    {
        throw ('Domain key [{0}] is not present in $DomainConfigs.' -f $DomainKey)
    }

    # When the target forest is not the one this process's account belongs to,
    # switching cannot be done in-process: the PSPKI publish/grant cmdlets and
    # SID translation authenticate with the process token, which credentials on
    # an LDAP bind cannot change. Instead we relaunch the whole script as an
    # account in the target forest. On a successful relaunch this returns the
    # 'Relaunched' status so the caller can exit and hand control to the new
    # window; the active key is intentionally NOT changed in this process.
    if (Test-DomainCredentialNeeded -DomainKey $DomainKey)
    {
        $domain = $DomainConfigs[$DomainKey]
        Write-InfoMsg -Message ('Forest [{0}] is in a different directory than this session''s account; a relaunch as a {1} account is required.' -f $domain.Label, $domain.NetbiosName)

        if (Restart-UnderDomainCredential -DomainKey $DomainKey)
        {
            return 'Relaunched'
        }

        # Relaunch was cancelled or declined - stay on the current forest.
        Write-WarnMsg -Message ('Remaining on forest [{0}].' -f (Get-ActiveDomain).Label)
        return 'Unchanged'
    }

    # Same-forest (or no-credential) switch: apply in-process.
    $Script:ActiveDomainKey = $DomainKey
    $Script:ActiveCAConfig  = $null

    # Drop any cached DC for this forest so the next bind re-resolves a live one
    # (useful if a previously chosen DC has since gone offline).
    if ($Script:ResolvedDomainControllers.ContainsKey($DomainKey))
    {
        [void]$Script:ResolvedDomainControllers.Remove($DomainKey)
    }

    $domain = Get-ActiveDomain
    Write-SuccessMsg -Message ('Active forest set to [{0}] ({1}).' -f $domain.Label, $domain.DnsName)

    return 'Switched'
}

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

    # PSPKI is no longer a hard dependency: every CA / template / ACL operation is
    # done with direct LDAP so the tool works cross-forest on a machine that is not
    # joined to the target forest (PSPKI's cmdlets enforce AD DS domain membership
    # and refuse to run there). The module is still imported when present - it does
    # no harm and keeps the environment familiar - but a missing module or import
    # warning is non-fatal. The import is silenced because, off a joined machine,
    # PSPKI emits a 'not joined to AD DS forest' warning that is irrelevant here.
    if (Get-Module -Name $PSPKIModuleName)
    {
        return
    }

    $available = Get-Module -ListAvailable -Name $PSPKIModuleName |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (($null -eq $available) -and $AutoInstallModules)
    {
        try
        {
            Install-PSPKIModule

            $available = Get-Module -ListAvailable -Name $PSPKIModuleName |
                Sort-Object Version -Descending |
                Select-Object -First 1
        }
        catch
        {
            Write-WarnMsg -Message ('Optional module [{0}] could not be installed: {1}. Continuing - it is not required.' -f $PSPKIModuleName, $_.Exception.Message)
            return
        }
    }

    if ($null -eq $available)
    {
        Write-InfoMsg -Message ('Optional module [{0}] is not installed. Continuing - all operations use direct LDAP and do not require it.' -f $PSPKIModuleName)
        return
    }

    try
    {
        Import-Module $PSPKIModuleName -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        Write-SuccessMsg -Message ('Loaded optional module [{0}] version [{1}].' -f $available.Name, $available.Version)
    }
    catch
    {
        Write-WarnMsg -Message ('Optional module [{0}] failed to import: {1}. Continuing - it is not required.' -f $PSPKIModuleName, $_.Exception.Message)
    }
}

# ============================================================
# REGION: LDAP CLONE ENGINE
# ============================================================

function Get-ConfigNamingContext
{
    [CmdletBinding()]
    param()

    return (Get-RootDseAttribute -AttributeName 'configurationNamingContext')
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
    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $TemplatesDN)

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
    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $TemplatesDN)

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

        $checkRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $OidDN)

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

    $container = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $OidDN)
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
    $container = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $containers.TemplatesDN)
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

    # Allow replication a moment, then verify via direct LDAP (not PSPKI, which
    # cannot run cross-forest on a non-joined machine).
    Start-Sleep -Seconds 3
    $verifiedCn = Test-TemplateExistsLdap -Cn $ShortName

    if ([string]::IsNullOrWhiteSpace($verifiedCn))
    {
        Start-Sleep -Seconds 5
        $verifiedCn = Test-TemplateExistsLdap -Cn $ShortName
    }

    if ([string]::IsNullOrWhiteSpace($verifiedCn))
    {
        throw ('Template [{0}] was not found in AD DS after creation.' -f $ShortName)
    }

    Write-SuccessMsg -Message 'Verified the new template is present in AD DS.'
    return $verifiedCn
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

    # Grant Read + Enroll (optionally Autoenroll) on the template by editing the
    # template object's DACL directly over LDAP, instead of PSPKI's Get/Add/Set-
    # CertificateTemplateAcl (which cannot run on a machine not joined to the
    # target forest). Read is the GenericRead-style allow ACE; Enroll and
    # Autoenroll are extended-right ACEs identified by their well-known control-
    # access-right GUIDs. The principal is resolved to a SID first (also via LDAP).
    $resolved = Resolve-AdPrincipal -Name $Principal

    if ($null -eq $resolved)
    {
        throw ('Principal [{0}] could not be resolved in forest [{1}].' -f $Principal, (Get-ActiveDomain).Label)
    }

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc
    $templateDn = 'CN={0},{1}' -f $ShortName, $containers.TemplatesDN

    $entry = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $templateDn)

    # Limit the read/write to the DACL so CommitChanges does not touch the owner
    # or SACL (which would need extra privileges). Set before reading ObjectSecurity.
    $entry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
    [void]$entry.RefreshCache(@('ntSecurityDescriptor'))

    $sid = New-Object System.Security.Principal.SecurityIdentifier ($resolved.Sid)

    # Well-known control-access-right GUIDs for certificate enrollment.
    $enrollGuid     = New-Object System.Guid ('0e10c968-78fb-11d2-90d4-00c04f79dc55')
    $autoEnrollGuid = New-Object System.Guid ('a05b8cc2-17bc-4802-a710-e7c15ab866a2')

    $allow      = [System.Security.AccessControl.AccessControlType]::Allow
    $extRight   = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    $genRead    = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
    $noneType   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

    $rules = New-Object System.Collections.Generic.List[System.DirectoryServices.ActiveDirectoryAccessRule]

    # Read (allows the principal to see the template).
    $rules.Add((New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, $genRead, $allow, $noneType)))

    # Enroll extended right.
    $rules.Add((New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, $extRight, $allow, $enrollGuid, $noneType)))

    if ($AddAutoEnroll)
    {
        $rules.Add((New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, $extRight, $allow, $autoEnrollGuid, $noneType)))
    }

    $sd = $entry.ObjectSecurity

    foreach ($rule in $rules)
    {
        $sd.AddAccessRule($rule)
    }

    $entry.CommitChanges()
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

    if (Test-ActiveForestIsForeign)
    {
        Write-WarnMsg -Message (Get-ForeignForestDeferralMessage -Operation 'Granting enrollment rights')
        Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'Publish deferred' -Detail ('{0} - cross-forest token limitation' -f $Principal)
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

    if (Test-ActiveForestIsForeign)
    {
        Write-WarnMsg -Message (Get-ForeignForestDeferralMessage -Operation 'Publishing to a CA')
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Publish deferred' -Detail ('{0} - cross-forest token limitation' -f $ShortName)
        return
    }

    # Publish by writing the template CN onto the issuing CA's Enrollment Services
    # object (its multi-valued certificateTemplates attribute) via direct LDAP.
    # This replaces PSPKI's Connect-CertificationAuthority / Add-CATemplate /
    # Set-CATemplate, which require the machine to be joined to the CA's forest and
    # so cannot run in the cross-forest case. Adding the CN here is exactly what
    # Add-CATemplate does under the hood. The write lands on the Enrollment
    # Services CA object, so a delegated author may lack rights there; that is
    # deferred, not failed.
    $caConfig     = Resolve-ActiveCAConfig
    $caCommonName = ($caConfig -split '\\')[1]

    Write-InfoMsg -Message ('Publishing template [{0}] to CA [{1}] via LDAP.' -f $ShortName, $caCommonName)

    try
    {
        $esEntry = Get-EnrollmentServiceEntry -CaCommonName $caCommonName
    }
    catch
    {
        Write-WarnMsg -Message ('Could not locate the Enrollment Services object for CA [{0}]: {1}. Publish skipped.' -f $caCommonName, $_.Exception.Message)
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Skipped' -Detail ('{0} - CA object not found' -f $ShortName)
        return
    }

    # Current assignment list (may be absent on a CA with no published templates).
    $assigned = @()

    if ($esEntry.Properties.Contains('certificateTemplates'))
    {
        $assigned = @($esEntry.Properties['certificateTemplates'])
    }

    if ($assigned -contains $ShortName)
    {
        Write-SuccessMsg -Message ('Template [{0}] is already published on [{1}].' -f $ShortName, $caCommonName)
        Add-LedgerEntry -Action 'Publish to CA' -Result 'Already published' -Detail $ShortName
        return
    }

    try
    {
        [void]$esEntry.Properties['certificateTemplates'].Add($ShortName)
        $esEntry.CommitChanges()
    }
    catch
    {
        if (Test-InsufficientRights -ErrorRecord $_)
        {
            Write-WarnMsg -Message ('Template [{0}] was created and secured, but publishing it to [{1}] needs write access to the CA''s Enrollment Services object. Publish deferred.' -f $ShortName, $caCommonName)
            Add-LedgerEntry -Action 'Publish to CA' -Result 'Publish deferred' -Detail ('{0} - current account lacks publish rights' -f $ShortName)
            return
        }

        throw
    }

    Write-SuccessMsg -Message ('Published template [{0}] to [{1}].' -f $ShortName, $caCommonName)
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
        [string[]]$Items,

        [Parameter(Mandatory = $false)]
        [switch]$AllowQuit
    )

    # When -AllowQuit is set, entering Q returns 0 so the caller can treat it as
    # 'go back to the main menu' rather than forcing a selection.
    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan

    for ($i = 0; $i -lt $Items.Count; $i++)
    {
        Write-Host ('  {0,3}. {1}' -f ($i + 1), $Items[$i])
    }

    Write-Host ''

    $promptText = 'Select a number'

    if ($AllowQuit)
    {
        $promptText = '{0} (Q to return to the main menu)' -f $promptText
    }

    while ($true)
    {
        $entry  = Read-Host -Prompt $promptText
        $number = 0

        if ([int]::TryParse($entry, [ref]$number) -and $number -ge 1 -and $number -le $Items.Count)
        {
            return $number
        }

        if ($AllowQuit -and ($entry.Trim().ToUpperInvariant() -eq 'Q'))
        {
            return 0
        }

        Write-Host '  Enter a number from the list.' -ForegroundColor Yellow
    }
}

function Read-PagedMenuChoice
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string[]]$Items,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = $MenuPageSize,

        [Parameter(Mandatory = $false)]
        [switch]$AllowQuit
    )

    # When -AllowQuit is set, entering Q returns 0 so the caller can treat it as
    # 'go back to the main menu'.
    $total     = $Items.Count
    $pageCount = [int][System.Math]::Ceiling($total / [double]$PageSize)
    $page      = 0

    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan

    while ($true)
    {
        $start = $page * $PageSize
        $end   = [System.Math]::Min($start + $PageSize, $total)

        Write-Host ''
        Write-Host ('  Showing {0}-{1} of {2}  (page {3} of {4})' -f ($start + 1), $end, $total, ($page + 1), $pageCount) -ForegroundColor DarkGray

        for ($i = $start; $i -lt $end; $i++)
        {
            Write-Host ('  {0,3}. {1}' -f ($i + 1), $Items[$i])
        }

        Write-Host ''

        $hasNext = $page -lt ($pageCount - 1)
        $hasPrev = $page -gt 0

        $navParts = New-Object System.Collections.Generic.List[string]

        if ($hasNext)
        {
            $navParts.Add(('Enter or N for the next {0}' -f $PageSize))
        }

        if ($hasPrev)
        {
            $navParts.Add(('P for the previous {0}' -f $PageSize))
        }

        if ($AllowQuit)
        {
            $navParts.Add('Q to return to the main menu')
        }

        $promptText = 'Select a number'

        if ($navParts.Count -gt 0)
        {
            $promptText = '{0} ({1})' -f $promptText, ($navParts -join ', ')
        }

        $entry  = Read-Host -Prompt $promptText
        $number = 0

        if ([int]::TryParse($entry, [ref]$number) -and $number -ge 1 -and $number -le $total)
        {
            return $number
        }

        $token = $entry.Trim().ToUpperInvariant()

        if (($token -eq 'N' -or $token -eq '') -and $hasNext)
        {
            $page++
            continue
        }

        if ($token -eq 'P' -and $hasPrev)
        {
            $page--
            continue
        }

        if ($AllowQuit -and ($token -eq 'Q'))
        {
            return 0
        }

        Write-Host '  Enter a listed number, N / P to page, or Q to return to the main menu.' -ForegroundColor Yellow
    }
}

function Select-BaseTemplate
{
    [CmdletBinding()]
    param()

    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc

    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $containers.TemplatesDN)

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

    $choice = Read-PagedMenuChoice -Title 'Select the base template to clone from:' -Items $labels -AllowQuit

    if ($choice -eq 0)
    {
        # Q - operator wants to abandon the selection and return to the menu.
        return $null
    }

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

    # Validate a user/group and return its canonical DOMAIN\name and SID by
    # searching the ACTIVE FOREST directly over LDAP. The old approach used
    # NTAccount.Translate, which authenticates with the local process token and
    # therefore cannot resolve principals in a forest this machine is not joined
    # to (the cross-forest case). A DirectorySearcher against the forest's default
    # naming context works under the runas /netonly network credentials, the same
    # way the template binds do. Accepts 'DOMAIN\name', 'name', or a UPN and
    # matches sAMAccountName (or userPrincipalName); returns $null if not found.
    try
    {
        $rootDn = Get-RootDseAttribute -AttributeName 'defaultNamingContext'
    }
    catch
    {
        return $null
    }

    # Strip a domain prefix or UPN suffix down to the bare logon name for the
    # sAMAccountName match; keep the original for a UPN match as well.
    $bare = $Name

    if ($bare.Contains('\'))
    {
        $bare = ($bare -split '\\', 2)[1]
    }

    $upn = ''

    if ($Name.Contains('@'))
    {
        $upn  = $Name
        $bare = ($Name -split '@', 2)[0]
    }

    # Escape LDAP filter metacharacters in the user-supplied value.
    $escBare = $bare -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
    $escUpn  = $upn  -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'

    if (-not [string]::IsNullOrWhiteSpace($escUpn))
    {
        $filter = '(|(sAMAccountName={0})(userPrincipalName={1}))' -f $escBare, $escUpn
    }
    else
    {
        $filter = '(sAMAccountName={0})' -f $escBare
    }

    try
    {
        $searcher              = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot   = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $rootDn)
        $searcher.SearchScope  = 'Subtree'
        $searcher.Filter       = '(&(|(objectClass=user)(objectClass=group)){0})' -f $filter
        $searcher.PageSize     = 100
        [void]$searcher.PropertiesToLoad.Add('objectSid')
        [void]$searcher.PropertiesToLoad.Add('sAMAccountName')
        [void]$searcher.PropertiesToLoad.Add('msDS-PrincipalName')

        $result = $searcher.FindOne()
    }
    catch
    {
        return $null
    }

    if ($null -eq $result)
    {
        return $null
    }

    $sidBytes = $result.Properties['objectsid'][0]
    $sid      = New-Object System.Security.Principal.SecurityIdentifier ($sidBytes, 0)

    # msDS-PrincipalName is the canonical DOMAIN\name when available; otherwise
    # build it from the active forest's NetBIOS name and the sAMAccountName.
    $canonical = ''

    if ($result.Properties.Contains('msds-principalname') -and
        (-not [string]::IsNullOrWhiteSpace([string]$result.Properties['msds-principalname'][0])))
    {
        $canonical = [string]$result.Properties['msds-principalname'][0]
    }
    else
    {
        $sam       = [string]$result.Properties['samaccountname'][0]
        $canonical = '{0}\{1}' -f (Get-ActiveDomain).NetbiosName, $sam
    }

    return [pscustomobject]@{
        Name = $canonical
        Sid  = $sid.Value
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

    # Unary comma keeps an empty result an empty array; a bare return of an
    # empty array unrolls to nothing and the caller would receive $null.
    return ,$grants.ToArray()
}

function Read-TemplateDefinition
{
    [CmdletBinding()]
    param()

    $baseName = Select-BaseTemplate

    if ($null -eq $baseName)
    {
        # Operator pressed Q at the base-template picker; abandon the definition.
        return $null
    }

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
    $publishCA = Resolve-ActiveCAConfig
    $publish   = Read-YesNo -Prompt ('Publish to issuing CA [{0}]?' -f $publishCA) -Default $false

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
        $publishText = Resolve-ActiveCAConfig
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

    $schemaNc = Get-RootDseAttribute -AttributeName 'schemaNamingContext'

    $searcher             = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $schemaNc)
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

    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $esContainer)

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

    $caConfig     = Resolve-ActiveCAConfig
    $caCommonName = ($caConfig -split '\\')[1]
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

    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $containers.TemplatesDN)

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

function Test-TemplateExistsLdap
{
    [CmdletBinding()]
    param
    (
        [string]$Cn,
        [string]$DisplayName
    )

    # Existence check by direct LDAP against the active forest's Certificate
    # Templates container, replacing PSPKI's Get-CertificateTemplate (which has an
    # 'AD DS Domain Membership' requirement and refuses to run on a machine not
    # joined to the target forest - the cross-forest case). Returns the matching
    # CN string, or $null when neither the CN nor the display name is present.
    $configNc   = Get-ConfigNamingContext
    $containers = Get-PkiContainerDNs -ConfigNc $configNc

    $clauses = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($Cn))
    {
        $escCn = $Cn -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
        $clauses.Add(('(cn={0})' -f $escCn))
    }

    if (-not [string]::IsNullOrWhiteSpace($DisplayName))
    {
        $escDn = $DisplayName -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
        $clauses.Add(('(displayName={0})' -f $escDn))
    }

    if ($clauses.Count -eq 0)
    {
        return $null
    }

    $orFilter = if ($clauses.Count -eq 1) { $clauses[0] } else { '(|{0})' -f ($clauses -join '') }
    $filter   = '(&(objectClass=pKICertificateTemplate){0})' -f $orFilter

    $searcher              = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot   = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $containers.TemplatesDN)
    $searcher.SearchScope  = 'OneLevel'
    $searcher.Filter       = $filter
    [void]$searcher.PropertiesToLoad.Add('cn')

    $result = $searcher.FindOne()

    if ($null -eq $result)
    {
        return $null
    }

    return [string]$result.Properties['cn'][0]
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

    $choice = Read-MenuChoice -Title ('Select the template to {0}:' -f $ActionLabel) -Items $labels -AllowQuit

    if ($choice -eq 0)
    {
        # Q - operator wants to return to the main menu without choosing.
        return $null
    }

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

    return (New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $dn))
}

function Remove-TemplateFromCALdap
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$CaConfig,
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    # Remove the template CN from one issuing CA's Enrollment Services object via
    # direct LDAP (the inverse of Publish-TemplateToCA). Returns one of: 'Removed',
    # 'NotPublished', 'Deferred' (insufficient rights), or 'NotFound' (CA object
    # missing). PSPKI is intentionally not used so this works cross-forest.
    $caCommonName = ($CaConfig -split '\\')[1]

    try
    {
        $esEntry = Get-EnrollmentServiceEntry -CaCommonName $caCommonName
    }
    catch
    {
        return 'NotFound'
    }

    $assigned = @()

    if ($esEntry.Properties.Contains('certificateTemplates'))
    {
        $assigned = @($esEntry.Properties['certificateTemplates'])
    }

    if (-not ($assigned -contains $ShortName))
    {
        return 'NotPublished'
    }

    try
    {
        $esEntry.Properties['certificateTemplates'].Remove($ShortName)
        $esEntry.CommitChanges()
    }
    catch
    {
        if (Test-InsufficientRights -ErrorRecord $_)
        {
            return 'Deferred'
        }

        throw
    }

    return 'Removed'
}

function Remove-TemplateFromCA
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    if (Test-ActiveForestIsForeign)
    {
        Write-WarnMsg -Message (Get-ForeignForestDeferralMessage -Operation 'Unpublishing from a CA')
        Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail ('{0} - cross-forest token limitation' -f $ShortName)
        return
    }

    $caConfig     = Resolve-ActiveCAConfig
    $caCommonName = ($caConfig -split '\\')[1]

    $status = Remove-TemplateFromCALdap -CaConfig $caConfig -ShortName $ShortName

    switch ($status)
    {
        'Removed' {
            Write-SuccessMsg -Message ('Unpublished [{0}] from [{1}].' -f $ShortName, $caCommonName)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Created' -Detail $ShortName
        }
        'NotPublished' {
            Write-InfoMsg -Message ('Template [{0}] is not published on [{1}]; nothing to unpublish.' -f $ShortName, $caCommonName)
        }
        'Deferred' {
            Write-WarnMsg -Message ('Could not unpublish [{0}] - the current account lacks write access on [{1}]''s Enrollment Services object. Unpublish deferred.' -f $ShortName, $caCommonName)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail $ShortName
        }
        'NotFound' {
            Write-WarnMsg -Message ('Enrollment Services object for CA [{0}] was not found; unpublish skipped.' -f $caCommonName)
            Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Skipped' -Detail ('{0} - CA object not found' -f $ShortName)
        }
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

    # Read-only: returns the config string of every CA configured for the active
    # forest whose Enrollment Services object lists the template. Reads the ES
    # objects directly over LDAP (not PSPKI), so the preview is correct across a
    # forest boundary and on a non-joined machine. Any CA that cannot be read is
    # skipped.
    $names     = New-Object System.Collections.Generic.List[string]
    $caConfigs = Get-DomainCAConfigs

    foreach ($caConfig in $caConfigs)
    {
        $caCommonName = ($caConfig -split '\\')[1]

        try
        {
            $esEntry  = Get-EnrollmentServiceEntry -CaCommonName $caCommonName
            $assigned = @()

            if ($esEntry.Properties.Contains('certificateTemplates'))
            {
                $assigned = @($esEntry.Properties['certificateTemplates'])
            }

            if ($assigned -contains $ShortName)
            {
                $names.Add($caConfig)
            }
        }
        catch
        {
            # Unreadable / unreachable CA - skip it in the read-only preview.
            continue
        }
    }

    # Unary comma keeps an empty result an empty array; a bare return of an
    # empty array unrolls to nothing and the caller would receive $null.
    return ,$names.ToArray()
}

function Remove-TemplateFromAllCAs
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ShortName
    )

    if (Test-ActiveForestIsForeign)
    {
        Write-WarnMsg -Message (Get-ForeignForestDeferralMessage -Operation 'Unpublishing from CAs')
        Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail ('{0} - cross-forest token limitation' -f $ShortName)
        return
    }

    $caConfigs = Get-DomainCAConfigs

    if ($caConfigs.Count -eq 0)
    {
        Write-WarnMsg -Message ('No issuing CAs are configured for forest [{0}].' -f $Script:ActiveDomainKey)
        return
    }

    $found = $false

    foreach ($caConfig in $caConfigs)
    {
        $caName = $caConfig
        $status = Remove-TemplateFromCALdap -CaConfig $caConfig -ShortName $ShortName

        switch ($status)
        {
            'Removed' {
                $found = $true
                Write-SuccessMsg -Message ('Unpublished [{0}] from [{1}].' -f $ShortName, $caName)
                Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Created' -Detail ('{0} on {1}' -f $ShortName, $caName)
            }
            'Deferred' {
                $found = $true
                Write-WarnMsg -Message ('Could not unpublish [{0}] from [{1}] - the current account lacks write access on its Enrollment Services object. Unpublish deferred.' -f $ShortName, $caName)
                Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Publish deferred' -Detail ('{0} on {1}' -f $ShortName, $caName)
            }
            'NotFound' {
                Write-WarnMsg -Message ('Enrollment Services object for CA [{0}] was not found; skipped.' -f $caName)
                Add-LedgerEntry -Action 'Unpublish from CA' -Result 'Skipped' -Detail ('{0} on {1} - CA object not found' -f $ShortName, $caName)
            }
            'NotPublished' {
                continue
            }
        }
    }

    if (-not $found)
    {
        Write-InfoMsg -Message ('Template [{0}] was not published on any configured CA; nothing to unpublish.' -f $ShortName)
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

    $searchRoot = New-DomainDirectoryEntry -Path (Get-LdapPath -DistinguishedName $containers.OidDN)

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

    if ($null -eq $record)
    {
        Write-InfoMsg -Message 'Returned to the main menu.'
        return 'Returned to menu'
    }

    $entry = Get-TemplateEntryByCn -Cn $record.Cn

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
                Write-Host ('  Will publish to [{0}] on apply.' -f (Resolve-ActiveCAConfig)) -ForegroundColor Green
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

    # Build the full summary of every modification for the console review and the
    # email report, so the record reflects exactly what the operator changed.
    $modSummary = New-Object System.Collections.Generic.List[object]
    $modSummary.Add(@('Template (CN)', $record.Cn))
    $modSummary.Add(@('Display Name', $record.DisplayName))
    $modSummary.Add(@('Forest', (Get-ActiveDomain).Label))

    if ($changes.ContainsKey('displayName'))
    {
        $modSummary.Add(@('New Display Name', [string]$changes['displayName']))
    }

    if ($changes.ContainsKey('eku'))
    {
        $modSummary.Add(@('New EKU', (@($changes['eku']) -join ', ')))
    }

    if ($changes.ContainsKey('keySize'))
    {
        $modSummary.Add(@('New Minimum Key Size', [string]$changes['keySize']))
    }

    if ($changes.ContainsKey('nameFlag'))
    {
        $modSummary.Add(@('New Subject Name Flag', [string]$changes['nameFlag']))
    }

    if ($grants.Count -gt 0)
    {
        foreach ($g in $grants)
        {
            $rights = 'Read + Enroll'

            if ($g.AutoEnroll)
            {
                $rights = '{0} + Autoenroll' -f $rights
            }

            $modSummary.Add(@('Grant', ('{0} ({1})' -f $g.Principal, $rights)))
        }
    }

    if ($publish)
    {
        $modSummary.Add(@('Publish To', (Resolve-ActiveCAConfig)))
    }

    if ($changes.Count -gt 0)
    {
        $modSummary.Add(@('Minor Revision', 'Incremented'))
    }

    $modSummary.Add(@('DryRun', $(if ($DryRun) { 'ON (previewed only)' } else { 'OFF (applied)' })))
    $modSummary.Add(@('Run By', ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)))

    $Script:RunContext = [pscustomobject]@{
        Heading = 'Modify Certificate Template'
        Summary = $modSummary.ToArray()
    }

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
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $record.Cn, (Resolve-ActiveCAConfig))
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

    if ($null -eq $record)
    {
        Write-InfoMsg -Message 'Returned to the main menu.'
        return 'Returned to menu'
    }

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

    $allCAs    = Read-YesNo -Prompt ('Unpublish from ALL configured CAs in this forest? (No = only [{0}])' -f (Resolve-ActiveCAConfig)) -Default $true
    $deleteOid = Read-YesNo -Prompt 'Also delete the associated template OID object?' -Default $true

    $entry    = Get-TemplateEntryByCn -Cn $record.Cn
    $oidValue = ''

    if ($entry.Properties.Contains('msPKI-Cert-Template-OID'))
    {
        $oidValue = [string]$entry.Properties['msPKI-Cert-Template-OID'][0]
    }

    # Full summary of the delete choices for the console review and email report.
    $delSummary = New-Object System.Collections.Generic.List[object]
    $delSummary.Add(@('Template (CN)', $record.Cn))
    $delSummary.Add(@('Display Name', $record.DisplayName))
    $delSummary.Add(@('Forest', (Get-ActiveDomain).Label))
    $delSummary.Add(@('Unpublish Scope', $(if ($allCAs) { 'All configured CAs in this forest' } else { ('Active CA only ({0})' -f (Resolve-ActiveCAConfig)) })))
    $delSummary.Add(@('Delete OID Object', $(if ($deleteOid) { 'Yes' } else { 'No' })))

    if (-not [string]::IsNullOrWhiteSpace($oidValue))
    {
        $delSummary.Add(@('Template OID', $oidValue))
    }

    $delSummary.Add(@('DryRun', $(if ($DryRun) { 'ON (previewed only)' } else { 'OFF (applied)' })))
    $delSummary.Add(@('Run By', ('{0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)))

    $Script:RunContext = [pscustomobject]@{
        Heading = 'Delete Certificate Template'
        Summary = $delSummary.ToArray()
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
            Write-DryRunMsg -Message ('Would unpublish [{0}] from CA [{1}].' -f $record.Cn, (Resolve-ActiveCAConfig))
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

    if ($null -eq $def)
    {
        Write-InfoMsg -Message 'Returned to the main menu.'
        return 'Returned to menu'
    }
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
        $publishText = Resolve-ActiveCAConfig
    }
    else
    {
        $publishText = 'No'
    }

    $summary = New-Object System.Collections.Generic.List[object]
    $summary.Add(@('CN', $def.ShortName))
    $summary.Add(@('Forest', (Get-ActiveDomain).Label))
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
    $summary.Add(@('DryRun', $(if ($DryRun) { 'ON (previewed only)' } else { 'OFF (applied)' })))
    $summary.Add(@('Engine', 'Direct LDAP (Configuration partition)'))
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
    $existing = Test-TemplateExistsLdap -Cn $def.ShortName -DisplayName $def.DisplayName

    if ($existing)
    {
        Write-WarnMsg -Message ('A template named [{0}] (or display name [{1}]) already exists; skipping creation.' -f $def.ShortName, $def.DisplayName)
        Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'Skipped' -Detail 'Already exists'
        $shortForGrant = $existing
    }
    elseif ($DryRun)
    {
        # DryRun: preview creation only - do NOT write the template object.
        Write-DryRunMsg -Message ('Would create template [{0}] (display [{1}]) cloned from [{2}].' -f $def.ShortName, $def.DisplayName, $def.BaseName)
        Add-LedgerEntry -Action 'Create template (LDAP)' -Result 'DryRun' -Detail ('{0} from {1}' -f $def.ShortName, $def.BaseName)
        $shortForGrant = $def.ShortName
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
            if ($DryRun)
            {
                # DryRun: preview the grant; do NOT write the template DACL. In a
                # real run the template might not exist yet (only previewed above),
                # so the grant is shown rather than attempted.
                $autoText = ''

                if ($grant.AutoEnroll)
                {
                    $autoText = ' + Autoenroll'
                }

                Write-DryRunMsg -Message ('Would grant Read + Enroll{0} on [{1}] to [{2}].' -f $autoText, $shortForGrant, $grant.Principal)
                Add-LedgerEntry -Action 'Grant enrollment rights' -Result 'DryRun' -Detail $grant.Principal
            }
            else
            {
                Invoke-EnrollmentGrant -ShortName $shortForGrant -Principal $grant.Principal -AddAutoEnroll $grant.AutoEnroll
            }
        }
    }

    if ($def.Publish)
    {
        if ($DryRun)
        {
            Write-DryRunMsg -Message ('Would publish template [{0}] to CA [{1}].' -f $shortForGrant, (Resolve-ActiveCAConfig))
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

    $caConfig     = Resolve-ActiveCAConfig
    $caCommonName = ($caConfig -split '\\')[1]

    Write-Host ''
    Write-Host '==== Delegate publish rights ====' -ForegroundColor Cyan
    Write-Host ('  Principal     : {0}' -f $principal)
    Write-Host ('  Issuing CA    : {0}' -f $caCommonName)
    Write-Host  '  Permission    : Write certificateTemplates on the Enrollment Services object'
    Write-Host ''

    $delegateSummary = New-Object System.Collections.Generic.List[object]
    $delegateSummary.Add(@('Mode', 'Delegate publish rights'))
    $delegateSummary.Add(@('Forest', (Get-ActiveDomain).Label))
    $delegateSummary.Add(@('Principal', $principal))
    $delegateSummary.Add(@('Issuing CA', $caConfig))
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

function Select-Domain
{
    [CmdletBinding()]
    param()

    # Presents the configured forests and switches the active one. The current
    # forest is shown so the operator can confirm before changing it. Keys are
    # ordered with the default first, then the remainder alphabetically, so the
    # numbering is stable run to run.
    $current = Get-ActiveDomain

    $orderedKeys = New-Object System.Collections.Generic.List[string]
    $orderedKeys.Add($DefaultDomainKey)

    foreach ($key in ($DomainConfigs.Keys | Sort-Object))
    {
        if ($key -ne $DefaultDomainKey)
        {
            $orderedKeys.Add($key)
        }
    }

    $keys   = $orderedKeys.ToArray()
    $labels = @($keys | ForEach-Object { $DomainConfigs[$_].Label })

    Write-Host ''
    Write-Host ('  Current forest: {0} ({1})' -f $current.Label, $current.DnsName) -ForegroundColor DarkGray

    $choice   = Read-MenuChoice -Title 'Select the Active Directory forest to work in:' -Items $labels
    $selected = $keys[$choice - 1]

    if ($selected -eq $Script:ActiveDomainKey)
    {
        Write-InfoMsg -Message ('Forest unchanged ([{0}]).' -f $current.Label)
        return 'Unchanged'
    }

    # Returns the Set-ActiveDomain status. 'Relaunched' means a new window has
    # opened as a target-forest account and this session should end.
    return (Set-ActiveDomain -DomainKey $selected)
}

function Invoke-MainMenu
{
    [CmdletBinding()]
    param()

    $opCount = 0

    while ($true)
    {
        $dryRunState = if ($DryRun) { 'ON (no changes will be made)' } else { 'OFF (changes WILL be made)' }

        Write-Host ''
        Write-Host '  ====== ' -ForegroundColor Cyan -NoNewline
        Write-Host 'TEMPLATORATOR MENU' -ForegroundColor Yellow -NoNewline
        Write-Host ' ======' -ForegroundColor Cyan
        Write-Host ('  D. Select Domain  (current: {0})' -f (Get-ActiveDomain).Label) -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  1. Create a certificate template' -ForegroundColor Green
        Write-Host '  2. Modify a certificate template' -ForegroundColor White
        Write-Host '  3. DELETE a certificate template' -ForegroundColor Red
        Write-Host ''
        Write-Host ('  T. Toggle DryRun  (currently: {0})' -f $dryRunState) -ForegroundColor Magenta
        Write-Host '  Q. Exit' -ForegroundColor White
        Write-Host '  ================================' -ForegroundColor Cyan
        Write-Host ''
        $choice = Read-Host -Prompt 'Select an option'

        switch ($choice.Trim().ToUpper())
        {
            'D' {
                $domainResult = Select-Domain

                if ($domainResult -eq 'Relaunched')
                {
                    # A new window has opened as the target-forest account.
                    # End this session so control passes to it cleanly.
                    return ('Relaunched into another forest as a different account')
                }
            }
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
            'T' {
                # Toggle the script-scoped DryRun flag. All functions read this
                # same script variable, so flipping it here changes the posture
                # for every subsequent operation in this session.
                $script:DryRun = -not $DryRun

                if ($DryRun)
                {
                    Write-SuccessMsg -Message 'DryRun is now ON - operations will be previewed only; no changes will be made.'
                }
                else
                {
                    Write-WarnMsg -Message 'DryRun is now OFF - operations WILL make real changes.'
                }
            }
            'Q' {
                $exitSummary = New-Object System.Collections.Generic.List[object]
                $exitSummary.Add(@('Operations', [string]$opCount))
                $exitSummary.Add(@('Forest', (Get-ActiveDomain).Label))
                $exitSummary.Add(@('DryRun at exit', $(if ($DryRun) { 'ON' } else { 'OFF' })))
                $exitSummary.Add(@('Engine', 'Direct LDAP (Configuration partition)'))
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
                Write-Host '  Please choose D, 1, 2, 3, T, or Q.' -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-Main
{
    [CmdletBinding()]
    param()

    # Resolve the starting forest before announcing it. Precedence:
    #  1. An explicit -DomainKey means this process IS the relaunched session
    #     (started by runas /netonly with the target forest's network creds).
    #     Under /netonly the LOCAL identity is unchanged, so the env-based check
    #     would still see the forest as foreign and Set-ActiveDomain would try to
    #     relaunch AGAIN - an endless loop. Trust the flag, set it directly, and
    #     mark ForestPresetViaRelaunch so token-bound ops do not defer.
    #  2. Otherwise auto-detect: if the running account is natively in one of the
    #     configured forests, make THAT the active forest. So running the script
    #     inside UHTD starts on UHTD with no relaunch and no prompt; running it
    #     inside UHHS starts on UHHS. An account in neither keeps the default.
    if (-not [string]::IsNullOrWhiteSpace($DomainKey))
    {
        if (-not $DomainConfigs.ContainsKey($DomainKey))
        {
            throw ('Domain key [{0}] is not present in $DomainConfigs.' -f $DomainKey)
        }

        $Script:ActiveDomainKey         = $DomainKey
        $Script:ActiveCAConfig          = $null
        $Script:ForestPresetViaRelaunch = $true
    }
    else
    {
        $detectedKey = Get-CurrentForestKey

        if ((-not [string]::IsNullOrWhiteSpace($detectedKey)) -and
            ($detectedKey -ne $Script:ActiveDomainKey))
        {
            $Script:ActiveDomainKey = $detectedKey
            $Script:ActiveCAConfig  = $null
        }
    }

    $startupDomain = Get-ActiveDomain
    Write-InfoMsg -Message ('{0} starting (DryRun = {1}, forest = {2}).' -f $ScriptName, $DryRun, $startupDomain.Label)
    Write-InfoMsg -Message ('Logging to directory [{0}], file [{1}].' -f $LogDir, $LogFile)

    if ($Script:ForestPresetViaRelaunch)
    {
        Write-InfoMsg -Message ('Forest preset to [{0}] ({1}) from -DomainKey; using the network credentials this session was started with.' -f $startupDomain.Label, $startupDomain.DnsName)
    }
    elseif ((Get-CurrentForestKey) -eq $Script:ActiveDomainKey)
    {
        Write-InfoMsg -Message ('Detected this session is running natively in [{0}]; selected it as the active forest.' -f $startupDomain.Label)
    }

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
