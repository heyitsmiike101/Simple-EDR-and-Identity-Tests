#Requires -Version 5.1
<#
.SYNOPSIS
    SentinelOne Identity Detection & Response (IDR) Test Suite

.DESCRIPTION
    Interactive menu to run IDR validation tests. Run from a domain-joined Windows workstation
    with the SentinelOne Unified Agent installed (v24.1.5.277+).

    ALL TESTS ARE SAFE - they run standard Windows/AD queries that a real attacker would use
    for reconnaissance. No credential dumping, no exploitation, no changes to AD objects.

    Tests are organized by IDR capability:
      Module 1 - AD Enumeration Detection (IDR deception triggers)
      Module 2 - Decoy Verification (confirm fake objects appear in output)
      Module 3 - ISIDP Attack Rules (SAMR/LDAP detection on DC)
      Module 4 - ISIDP Trigger Rules (RDP / Remote PowerShell interception)
      Module 5 - Credential Recon (SPN scanning, Kerberoasting target discovery)

    A timestamped log file is written to .\Logs\ automatically.

.PARAMETER Domain
    AD domain FQDN. Defaults to $env:USERDNSDOMAIN.

.PARAMETER DC
    Domain Controller FQDN. Auto-detected if not specified.

.PARAMETER LogPath
    Override the log file path. Default: .\Logs\S1IDR-<timestamp>.log

.PARAMETER RunAll
    Skip the menu and run all non-interactive modules (1, 2, 5) automatically.

.NOTES
    Run as a standard domain user unless otherwise indicated.
    RSAT AD tools required for Module 1 PowerShell cmdlet tests (optional).

    ALERT VISIBILITY by agent version:
      Agent <= 25.2.2 : Alerts > Identity, filter by Detection Engine = ADSecure-EP
      Agent >= 25.2.3 : No traditional alerts for deception; check Event Search instead
                        Query: event.type = 'Behavioral Indicators'  (XDR view)

    Sources: IDR.md, ISIDP.md from SentinelOne Community KB (extracted May 2026)
#>

[CmdletBinding()]
param(
    [string]$Domain  = $env:USERDNSDOMAIN,
    [string]$DC      = "",
    [string]$LogPath = "",
    [switch]$RunAll
)

$ErrorActionPreference = "Continue"

#region -- Logging ---------------------------------------------------------------

$script:LogFile   = ""
$script:PassCount = 0
$script:FailCount = 0
$script:SkipCount = 0
$script:TestCount = 0

function Start-Log {
    param([string]$OverridePath = "")

    if ($OverridePath) {
        $script:LogFile = $OverridePath
    } else {
        $logDir = Join-Path $PSScriptRoot "Logs"
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -ErrorAction SilentlyContinue | Out-Null
        }
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $script:LogFile = Join-Path $logDir "S1IDR-$ts.log"
    }

    $header = @"
================================================================================
  SentinelOne IDR Test Suite - Run Log
  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host     : $env:COMPUTERNAME
  User     : $env:USERDOMAIN\$env:USERNAME
  Domain   : $($Domain)
  Script   : $PSCommandPath
================================================================================

"@
    $header | Out-File -FilePath $script:LogFile -Encoding UTF8 -Force
    Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    if (-not $script:LogFile) { return }
    $ts = Get-Date -Format "HH:mm:ss.fff"
    "[$ts] [$($Level.PadRight(5))] $Message" |
        Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

function Write-LogOutput {
    # Writes raw command output to log (full, untruncated)
    param([object[]]$Lines)
    if (-not $script:LogFile -or -not $Lines) { return }
    $Lines | ForEach-Object {
        Write-Log "          $_" "OUT"
    }
}

#endregion

#region -- Helpers ---------------------------------------------------------------

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    $line = "=" * 70
    Write-Host ""
    Write-Host $line -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
    Write-Host ""
    Write-Log "" "---"
    Write-Log $Text "MOD"
    Write-Log "" "---"
}

function Write-TestHeader {
    param(
        [string]$TestName,
        [string]$ExpectedAlert,
        [string]$AlertLocation
    )
    $script:TestCount++
    Write-Host ""
    Write-Host ("-" * 65) -ForegroundColor DarkGray
    Write-Host "  [TEST]     $TestName" -ForegroundColor Yellow
    Write-Host "  [ALERT]    $ExpectedAlert" -ForegroundColor Magenta
    Write-Host "  [WHERE]    $AlertLocation" -ForegroundColor DarkCyan
    Write-Host ("-" * 65) -ForegroundColor DarkGray

    Write-Log "" "---"
    Write-Log "TEST     : $TestName" "TEST"
    Write-Log "ALERT    : $ExpectedAlert" "TEST"
    Write-Log "WHERE    : $AlertLocation" "TEST"
}

function Write-Status {
    param([string]$Msg, [string]$Level = "INFO")

    $colorMap  = @{ INFO="Gray"; OK="Green"; WARN="Yellow"; FAIL="Red"; NOTE="DarkCyan" }
    $prefixMap = @{ INFO="[i]";  OK="[+]";   WARN="[~]";   FAIL="[!]"; NOTE="[>]" }

    # Safe defaults for unknown levels
    $color  = if ($colorMap.ContainsKey($Level))  { $colorMap[$Level]  } else { "Gray" }
    $prefix = if ($prefixMap.ContainsKey($Level)) { $prefixMap[$Level] } else { "[?]"  }

    Write-Host "  $prefix $Msg" -ForegroundColor $color
    Write-Log "$prefix $Msg" $Level

    if ($Level -eq "OK")   { $script:PassCount++ }
    if ($Level -eq "FAIL") { $script:FailCount++ }
}

function Invoke-TestCommand {
    param([string]$Label, [scriptblock]$Command)

    Write-Host "  Running: $Label" -ForegroundColor DarkGray
    Write-Log "CMD : $Label" "CMD"

    try {
        # Capture output; 2>&1 redirects stderr into the success stream
        [string[]]$output = & $Command 2>&1 | ForEach-Object { "$_" }

        # Console: show first 25 lines
        if ($output) {
            $output | Select-Object -First 25 |
                ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            if ($output.Count -gt 25) {
                Write-Host "    ... ($($output.Count - 25) more lines in log)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    (no output)" -ForegroundColor DarkGray
        }

        # Log: full output
        Write-LogOutput $output
        Write-Log "CMD completed ($($output.Count) lines)" "OK"

    } catch {
        Write-Status "Command error: $_" FAIL
        Write-Log "Exception: $_" "FAIL"
    }
}

function Pause-Between {
    param([int]$Seconds = 4)
    Write-Host ""
    Write-Status "Pausing $Seconds s before next test (reduces throttling overlap)..." INFO
    Start-Sleep -Seconds $Seconds
}

function Write-Summary {
    $elapsed = if ($script:StartTime) {
        $span = (Get-Date) - $script:StartTime
        "$([int]$span.TotalMinutes)m $($span.Seconds)s"
    } else { "n/a" }

    $summary = @"

================================================================================
  Run Summary
  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Elapsed  : $elapsed
  Tests    : $($script:TestCount)
  Pass     : $($script:PassCount)
  Fail     : $($script:FailCount)
  Skipped  : $($script:SkipCount)
  Log file : $($script:LogFile)
================================================================================
"@
    Write-Host $summary -ForegroundColor Cyan
    if ($script:LogFile) {
        $summary | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
}

#endregion

#region -- Prerequisites Check --------------------------------------------------

function Confirm-Prerequisites {
    Write-Banner "Prerequisites Check" "White"

    # Domain membership
    if ($Domain) {
        Write-Status "Domain: $Domain" OK
    } else {
        Write-Status "Endpoint does not appear domain-joined. Tests will fail." FAIL
    }

    # S1 Agent service
    $svc = Get-Service -Name SentinelAgent -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Status "SentinelOne Agent service: Running" OK
    } else {
        Write-Status "SentinelOne Agent: NOT running (install/start before testing)" FAIL
    }

    # IDR engine status via SentinelCtl
    $s1ctl = Get-ChildItem "C:\Program Files\SentinelOne\*\SentinelCtl.exe" -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($s1ctl) {
        try {
            $idrCfg = & $s1ctl.FullName config idr 2>&1
            $idrOutput = ($idrCfg | ForEach-Object { "$_" }) -join " "
            Write-Log "SentinelCtl config idr output: $idrOutput" INFO

            if ($idrOutput -match '"idrEnabled":true') {
                Write-Status "IDR Engine: ENABLED (confirmed via SentinelCtl)" OK
            } else {
                Write-Status "IDR Engine may not be enabled. Output: $idrOutput" WARN
                Write-Status "Enable: Policies > Policy > Detection Engines > Identity Detection & Response" NOTE
            }
            # Detect agent version from folder path
            if ($s1ctl.FullName -match "(\d+\.\d+\.\d+)") {
                $script:AgentVersion = $Matches[1]
                Write-Status "Agent version detected: $($script:AgentVersion)" INFO
            }
        } catch {
            Write-Status "Could not query SentinelCtl: $_" WARN
        }
    } else {
        Write-Status "SentinelCtl not found at default path - verify IDR manually in S1 Console" WARN
    }

    # RSAT
    $rsat = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Installed" }
    if ($rsat) {
        Write-Status "RSAT AD Tools: Installed (PowerShell cmdlet tests enabled)" OK
        $script:RSATInstalled = $true
    } else {
        Write-Status "RSAT AD Tools: Not installed (cmdlet tests will be skipped)" WARN
        Write-Status "Install: Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'" NOTE
        $script:RSATInstalled = $false
    }

    # DC discovery
    if (-not $script:DC) {
        try {
            $script:DC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
            Write-Status "Domain Controller: $($script:DC)" OK
        } catch {
            Write-Status "Could not auto-detect DC - specify with -DC parameter" WARN
            Write-Log "DC auto-detect error: $_" WARN
        }
    } else {
        Write-Status "Domain Controller: $($script:DC)" OK
    }

    Write-Host ""
    Write-Status "ALERT VISIBILITY REMINDER:" NOTE
    Write-Host "    Agent <= 25.2.2  -->  Alerts > Identity, Detection Engine = ADSecure-EP" -ForegroundColor DarkCyan
    Write-Host "    Agent >= 25.2.3  -->  Event Search (XDR): event.type = 'Behavioral Indicators'" -ForegroundColor DarkCyan
    Write-Log "Alert visibility: <= 25.2.2 = Alerts tab; >= 25.2.3 = Event Search Behavioral Indicators" NOTE
}

#endregion

#region -- Module 1: AD Enumeration Detection -----------------------------------

function Test-ADEnumeration {
    Write-Banner "Module 1: AD Enumeration Detection (IDR Deception)"
    Write-Status "Runs standard AD recon commands - each should trigger an IDR alert." INFO
    Write-Status "Decoy objects may appear in output if Hide/Add Decoys rules are active." WARN
    Write-Host ""

    # 1.1 Domain Admins (SAMR)
    Write-TestHeader `
        -TestName     "Privileged Group Enumeration - Domain Admins (SAMR)" `
        -ExpectedAlert "AD Privilege Group Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net group `"Domain Admins`" /domain" { net group "Domain Admins" /domain }
    Pause-Between

    # 1.2 Enterprise Admins
    Write-TestHeader `
        -TestName     "Privileged Group Enumeration - Enterprise Admins (SAMR)" `
        -ExpectedAlert "AD Privilege Group Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net group `"Enterprise Admins`" /domain" { net group "Enterprise Admins" /domain }
    Pause-Between

    # 1.3 Domain Computers
    Write-TestHeader `
        -TestName     "Domain Computer Enumeration" `
        -ExpectedAlert "AD Domain Computer Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net group `"Domain Computers`" /domain" { net group "Domain Computers" /domain }
    Pause-Between

    # 1.4 Domain Users
    Write-TestHeader `
        -TestName     "Domain Users Enumeration" `
        -ExpectedAlert "Domain Users Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net user /domain" { net user /domain }
    Pause-Between

    # 1.5 Domain Controllers group
    Write-TestHeader `
        -TestName     "Domain Controller Discovery (group query)" `
        -ExpectedAlert "Domain Controller Discovery Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net group `"Domain Controllers`" /domain" { net group "Domain Controllers" /domain }
    Pause-Between

    # 1.6 nltest domain trusts
    Write-TestHeader `
        -TestName     "Domain Trust Discovery (nltest /domain_trusts)" `
        -ExpectedAlert "Domain Trust Discovery Detected | Nltest Command Usage Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "nltest /domain_trusts" { nltest /domain_trusts }
    Pause-Between

    # 1.7 nltest DC list - $Domain is script-scoped and accessible from the scriptblock
    Write-TestHeader `
        -TestName     "Domain Controller Discovery (nltest /dclist)" `
        -ExpectedAlert "Domain Controller Discovery Detected | Nltest Command Usage Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    $localDomain = $Domain
    Invoke-TestCommand "nltest /dclist:$localDomain" { nltest /dclist:$localDomain }
    Pause-Between

    # 1.8 klist
    Write-TestHeader `
        -TestName     "Kerberos Ticket Cache Enumeration (klist)" `
        -ExpectedAlert "Kerberos Ticket Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "klist" { klist }
    Pause-Between

    # 1.9 Local admins
    Write-TestHeader `
        -TestName     "Local Administrator Group Enumeration" `
        -ExpectedAlert "Local Administrator user Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net localgroup Administrators" { net localgroup Administrators }
    Pause-Between

    # 1.10 WMI domain info
    Write-TestHeader `
        -TestName     "Domain Information Discovery (WMI Win32_NTDomain)" `
        -ExpectedAlert "Domain Information Discovery Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "Get-WmiObject Win32_NTDomain" {
        Get-WmiObject -Class Win32_NTDomain | Select-Object DomainName, DnsForestName, DomainControllerName
    }
    Pause-Between

    # 1.11 net session
    Write-TestHeader `
        -TestName     "Network Session Enumeration (net session)" `
        -ExpectedAlert "AD Session Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "net session" { net session }
    Pause-Between

    # 1.12 SPN scan
    Write-TestHeader `
        -TestName     "SPN Scanning via setspn (Kerberoasting recon)" `
        -ExpectedAlert "SPN Scanning Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "setspn -Q */*" { setspn -Q "*/*" | Select-Object -First 30 }
    Pause-Between

    # 1.13 LDAP - admincount=1
    Write-TestHeader `
        -TestName     "LDAP Query - admincount=1 (critical objects)" `
        -ExpectedAlert "Critical AD Objects Queried | LDAP Search Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "DirectorySearcher: (admincount=1)" {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.Filter   = "(admincount=1)"
        $s.SizeLimit = 10
        $r = $s.FindAll()
        "Found $($r.Count) objects with admincount=1"
        $r | ForEach-Object { "  $($_.Properties['samaccountname'])" }
    }
    Pause-Between

    # 1.14 dsquery (if available)
    # BUG FIX: use string join before -notmatch, not array-level -notmatch
    Write-TestHeader `
        -TestName     "LDAP Query - dsquery (admincount=1)" `
        -ExpectedAlert "Critical AD Objects Queried | Suspicious LDAP Queries Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP  |  ISIDP Event Search"

    Write-Host "  Running: dsquery * -filter `"(admincount=1)`" -limit 10" -ForegroundColor DarkGray
    Write-Log "CMD : dsquery * -filter `"(admincount=1)`" -limit 10" CMD
    [string[]]$dqResult = dsquery * -filter "(admincount=1)" -limit 10 2>&1 | ForEach-Object { "$_" }
    $dqJoined = $dqResult -join "`n"
    Write-LogOutput $dqResult

    if ($dqResult -and ($dqJoined -notmatch "not recognized") -and ($dqJoined -notmatch "is not recognized")) {
        $dqResult | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    } else {
        Write-Status "dsquery not available on this endpoint - skipping" WARN
        $script:SkipCount++
    }
    Pause-Between

    # 1.15-1.18 RSAT cmdlets (optional)
    if ($script:RSATInstalled) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        Write-TestHeader `
            -TestName     "AD PowerShell Cmdlet - Get-ADUser -Filter * (RSAT)" `
            -ExpectedAlert "Active Directory Powershell Cmdlets Usage Detected | AD WebServices Usage Detected" `
            -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
        Invoke-TestCommand "Get-ADUser -Filter * -ResultSetSize 5" {
            Get-ADUser -Filter * -ResultSetSize 5 | Select-Object Name, SamAccountName
        }
        Pause-Between

        Write-TestHeader `
            -TestName     "AD PowerShell Cmdlet - Get-ADDomainController (RSAT)" `
            -ExpectedAlert "Domain Controller Discovery Detected | Active Directory Powershell Cmdlets Usage Detected" `
            -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
        Invoke-TestCommand "Get-ADDomainController -Filter *" {
            Get-ADDomainController -Filter * | Select-Object Name, IPv4Address
        }
        Pause-Between

        Write-TestHeader `
            -TestName     "AD PowerShell Cmdlet - Get-ADGroup -Filter * (RSAT)" `
            -ExpectedAlert "AD Group Enumeration Detected" `
            -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
        Invoke-TestCommand "Get-ADGroup -Filter * -ResultSetSize 10" {
            Get-ADGroup -Filter * -ResultSetSize 10 | Select-Object Name
        }
        Pause-Between

        Write-TestHeader `
            -TestName     "AD PowerShell Cmdlet - Get-ADComputer -Filter * (RSAT)" `
            -ExpectedAlert "AD Domain Computer Enumeration Detected" `
            -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
        Invoke-TestCommand "Get-ADComputer -Filter * -ResultSetSize 10" {
            Get-ADComputer -Filter * -ResultSetSize 10 | Select-Object Name, DNSHostName
        }
        Pause-Between
    } else {
        Write-Status "RSAT not installed - skipping PowerShell cmdlet tests (1.15-1.18)" WARN
        $script:SkipCount += 4
    }

    Write-Host ""
    Write-Status "Module 1 complete. Verify in S1 Console:" OK
    Write-Host "    <= 25.2.2: Alerts > Identity (filter: ADSecure-EP, Today)" -ForegroundColor Cyan
    Write-Host "    >= 25.2.3: Visibility Enhanced > XDR > event.type = 'Behavioral Indicators'" -ForegroundColor Cyan
    Write-Log "Module 1 complete" OK
}

#endregion

#region -- Module 2: Decoy Verification -----------------------------------------

function Test-DeceptionVerify {
    Write-Banner "Module 2: Decoy Object Verification"
    Write-Status "Purpose: Confirm that the IDR deception layer is active and serving fake objects." INFO
    Write-Host ""
    Write-Host "  How to interpret results:" -ForegroundColor White
    Write-Host "    1. Note the names/IPs in each command output below." -ForegroundColor Gray
    Write-Host "    2. In S1 Console: Identity > Identity Policies > [active policy] > Decoys tab." -ForegroundColor Gray
    Write-Host "    3. Decoy names shown in the tab should appear in command output." -ForegroundColor Gray
    Write-Host "    4. Real admin names should be ABSENT (if 'Hide Real Objects' is on)." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Policy recommendation for first deployment:" -ForegroundColor White
    Write-Host "    Alert: ON  |  Add Decoys: ON  |  Hide Real Objects: OFF (safer to start)" -ForegroundColor Gray
    Write-Host ""

    $checks = @(
        @{
            Label   = "Domain Admins group - look for fake usernames"
            Command = { net group "Domain Admins" /domain }
            Hint    = "Compare to: Identity Policy > Decoys > Privileged Administrators"
        },
        @{
            Label   = "Domain Controllers - look for fake DC names/IPs"
            Command = { nltest /dclist:$script:DC.Split(".")[0] }
            Hint    = "Compare to: Identity Policy > Decoys > Domain Controllers"
        },
        @{
            Label   = "SPN list - look for decoy service account SPNs"
            Command = { setspn -Q "*/*" | Select-Object -First 30 }
            Hint    = "Decoy SPNs use your configured SPN prefix. Compare to: Decoys > Service Accounts"
        },
        @{
            Label   = "Schema Admins - look for fake group members"
            Command = { net group "Schema Admins" /domain }
            Hint    = "Compare to: Identity Policy > Decoys > Privileged Administrators"
        }
    )

    foreach ($check in $checks) {
        Write-Host ("-" * 65) -ForegroundColor DarkGray
        Write-Host "  [DECOY CHECK] $($check.Label)" -ForegroundColor Yellow
        Write-Host ("-" * 65) -ForegroundColor DarkGray
        Write-Log "DECOY CHECK: $($check.Label)" "TEST"

        try {
            [string[]]$out = & $check.Command 2>&1 | ForEach-Object { "$_" }
            $out | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            Write-LogOutput $out
        } catch {
            Write-Status "Command error: $_" FAIL
        }

        Write-Host ""
        Write-Status $check.Hint NOTE
        Pause-Between 5
    }

    Write-Host ""
    Write-Status "Module 2 complete." OK
    Write-Status "If NO decoys appear: verify policy is Active and rules have 'Add Decoys' checked." WARN
    Write-Status "Console path: Identity > Identity Policies > [policy name] > Decoys tab" NOTE
    Write-Log "Module 2 complete" OK
}

#endregion

#region -- Module 3: ISIDP Attack Rules -----------------------------------------

function Test-AttackRules {
    Write-Banner "Module 3: ISIDP Attack Rule Detection (SAMR / LDAP)"
    Write-Status "Tests detection of privileged enumeration at the Domain Controller level." INFO
    Write-Status "Detection engine: ADSecure-DC-SAMR (SAMR) and ADSecure-DC-LDAP (LDAP)" INFO
    Write-Host ""
    Write-Host "  REQUIRED before running:" -ForegroundColor White
    Write-Host "    - Identity Provider Policy ACTIVE" -ForegroundColor Gray
    Write-Host "    - Learning Mode = DISABLED" -ForegroundColor Gray
    Write-Host "    - Authentication event logs = Aggressive" -ForegroundColor Gray
    Write-Host "    - Conditional Access policy with attack rules (SAMR + LDAP selected)" -ForegroundColor Gray
    Write-Host "    - Response Action = Audit (safe) or Block (to test blocking)" -ForegroundColor Gray
    Write-Host ""

    $ok = Read-Host "  Prerequisites met? (Y to continue, N to skip)"
    if ($ok -notmatch "^[Yy]") {
        Write-Status "Skipping Module 3. Configure prerequisites in S1 Console first." WARN
        $script:SkipCount += 4
        Write-Log "Module 3 skipped by user" WARN
        return
    }

    # 3.1 SAMR - net group Domain Admins
    Write-TestHeader `
        -TestName     "SAMR - AD Privileged User Enumeration (net group)" `
        -ExpectedAlert "SAMR AD Privileged User Enumeration (ISIDP event)" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-DC-SAMR  |  Event Search: api.service.name='SAMR'"
    Invoke-TestCommand "net group `"Domain Admins`" /domain" { net group "Domain Admins" /domain }
    Pause-Between 8

    # 3.2 LDAP - dsquery admincount=1
    # BUG FIX: join to string before -notmatch to avoid array-level filter
    Write-TestHeader `
        -TestName     "LDAP - AD Privileged User Enumeration (admincount=1)" `
        -ExpectedAlert "LDAP AD Privileged User Enumeration (ISIDP event)" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-DC-LDAP  |  Event Search: api.service.name='LDAP'"

    Write-Host "  Running: dsquery * -filter `"(admincount=1)`" -limit 10" -ForegroundColor DarkGray
    Write-Log "CMD : dsquery * -filter `"(admincount=1)`" -limit 10" CMD
    [string[]]$dq1 = dsquery * -filter "(admincount=1)" -limit 10 2>&1 | ForEach-Object { "$_" }
    $dq1Joined = $dq1 -join "`n"
    Write-LogOutput $dq1

    if ($dq1 -and ($dq1Joined -notmatch "not recognized")) {
        Write-Status "dsquery output:" INFO
        $dq1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    } else {
        Write-Status "dsquery unavailable - using DirectorySearcher fallback" WARN
        Invoke-TestCommand "DirectorySearcher: (admincount=1)" {
            $s = New-Object System.DirectoryServices.DirectorySearcher
            $s.Filter   = "(admincount=1)"
            $s.SizeLimit = 10
            $r = $s.FindAll()
            "Found $($r.Count) objects with admincount=1"
        }
    }
    Pause-Between 8

    # 3.3 LDAP - domain admins group name query
    # BUG FIX: same array -notmatch fix
    Write-TestHeader `
        -TestName     "LDAP - Domain Admins group name query" `
        -ExpectedAlert "LDAP AD Privileged User Enumeration (ISIDP event)" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-DC-LDAP"

    Write-Host "  Running: dsquery * -filter `"(name=domain admins)`" -limit 10" -ForegroundColor DarkGray
    Write-Log "CMD : dsquery * -filter `"(name=domain admins)`" -limit 10" CMD
    [string[]]$dq2 = dsquery * -filter "(name=domain admins)" -limit 10 2>&1 | ForEach-Object { "$_" }
    $dq2Joined = $dq2 -join "`n"
    Write-LogOutput $dq2

    if ($dq2 -and ($dq2Joined -notmatch "not recognized")) {
        $dq2 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    } else {
        Invoke-TestCommand "DirectorySearcher: (name=Domain Admins)" {
            $s = New-Object System.DirectoryServices.DirectorySearcher
            $s.Filter = "(name=Domain Admins)"
            $r = $s.FindAll()
            "Found $($r.Count) objects"
        }
    }
    Pause-Between 8

    # 3.4 LSARPC via RSAT (if available)
    if ($script:RSATInstalled) {
        Write-TestHeader `
            -TestName     "LSARPC - Privileged User Enumeration (RSAT Get-ADUser)" `
            -ExpectedAlert "LSARPC AD Privileged User Enumeration" `
            -AlertLocation "Alerts > Identity | Engine: ADSecure-DC-LSARPC  |  Event Search: api.operation='LsarEnumerateAccountsWithUserRight'"
        Invoke-TestCommand "Get-ADUser -LDAPFilter (admincount=1)" {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Get-ADUser -LDAPFilter "(admincount=1)" -Properties admincount |
                Select-Object Name, SamAccountName | Select-Object -First 10
        }
    } else {
        Write-Status "RSAT not available - skipping LSARPC test" WARN
        $script:SkipCount++
    }

    Write-Host ""
    Write-Status "Module 3 complete." OK
    Write-Host "    Event Search query (Visibility Enhanced > All Data):" -ForegroundColor Cyan
    Write-Host "    api.service.name='LDAP' or api.service.name='SAMR' or api.operation='SamrLookupIdsInDomain' or api.service.name='LSARPC'" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Status "If Learning Mode was recently disabled, wait for the learning period to expire first." NOTE
    Write-Status "First occurrence generates alert; Block is enforced from the second occurrence onward." NOTE
    Write-Log "Module 3 complete" OK
}

#endregion

#region -- Module 4: ISIDP Trigger Rules ----------------------------------------

function Test-TriggerRules {
    Write-Banner "Module 4: ISIDP Trigger Rules (RDP / Remote PowerShell)"
    Write-Status "Tests that ISIDP intercepts Kerberos auth for RDP and PS Remoting." INFO
    Write-Host ""
    Write-Host "  REQUIRED before running:" -ForegroundColor White
    Write-Host "    - Identity Provider Policy ACTIVE" -ForegroundColor Gray
    Write-Host "    - Trigger rules for RDP AND Remote PowerShell configured" -ForegroundColor Gray
    Write-Host "    - Response Action = Audit (events only) or Block (to test blocking)" -ForegroundColor Gray
    Write-Host "    - NTLM outbound restricted - forces Kerberos which ISIDP can intercept" -ForegroundColor Gray
    Write-Host "      Local Security Policy > Network security > Restrict NTLM: Outgoing = Deny all" -ForegroundColor Gray
    Write-Host "    - Two domain-joined endpoints available" -ForegroundColor Gray
    Write-Host ""

    $targetFQDN = Read-Host "  Enter target endpoint FQDN (or press Enter to skip Module 4)"
    if (-not $targetFQDN) {
        Write-Status "No target specified - skipping Module 4." WARN
        $script:SkipCount += 2
        Write-Log "Module 4 skipped - no target FQDN provided" WARN
        return
    }
    Write-Log "Module 4 target: $targetFQDN" INFO

    # Verify WinRM before attempting PS Remoting
    Write-Status "Testing WinRM connectivity to $targetFQDN..." INFO
    $wsTest = Test-WSMan -ComputerName $targetFQDN -ErrorAction SilentlyContinue
    if ($wsTest) {
        Write-Status "WinRM is reachable on $targetFQDN" OK
        Write-Log "WinRM reachable on $targetFQDN" OK
    } else {
        Write-Status "WinRM not reachable on $targetFQDN. PS Remoting test may fail." WARN
        Write-Log "WinRM not reachable on $targetFQDN" WARN
        Write-Status "On target: Enable-PSRemoting -Force; Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP'" NOTE
    }

    # 4.1 Remote PowerShell
    Write-TestHeader `
        -TestName     "Remote PowerShell Session" `
        -ExpectedAlert "Unauthorized Access Attempt detected (Remote PowerShell)" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-CA  |  Event Search: service.name='Remote Powershell'"
    Write-Host ""
    Write-Status "You will be prompted for domain credentials." INFO
    Write-Status "Use FQDN (not IP) - IP forces NTLM which ISIDP cannot intercept." NOTE

    try {
        $cred = Get-Credential -Message "Domain credentials for remote PS session to $targetFQDN"
        $sb   = { Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -First 5 -Property Name, Status }
        $res  = Invoke-Command -ComputerName $targetFQDN -Credential $cred -ScriptBlock $sb -ErrorAction Stop
        Write-Status "Remote PS session succeeded - check S1 for ISIDP trigger event." OK
        Write-Log "Remote PS to $targetFQDN succeeded" OK
        $res | Format-Table | Out-String | Write-Host -ForegroundColor Gray
    } catch {
        Write-Status "Remote PS error: $_" FAIL
        Write-Log "Remote PS error: $_" FAIL
        Write-Status "If Kerberos auth was intercepted (Block mode), this failure is expected." NOTE
    }
    Pause-Between 5

    # 4.2 RDP
    Write-TestHeader `
        -TestName     "RDP Connection" `
        -ExpectedAlert "Unauthorized Access Attempt detected (Remote Desktop)" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-CA  |  Event Search: service.name='RDP'"
    Write-Host ""
    Write-Status "Connect via RDP using FQDN (not IP) to trigger Kerberos interception." NOTE
    Write-Host "    Command: mstsc /v:$targetFQDN" -ForegroundColor DarkGray
    Write-Host ""
    $launch = Read-Host "  Launch RDP to $targetFQDN now? (Y/N)"
    if ($launch -match "^[Yy]") {
        Start-Process mstsc -ArgumentList "/v:$targetFQDN"
        Write-Status "RDP launched. Authenticate, then check S1 Console for the trigger event." OK
        Write-Log "RDP launched to $targetFQDN" OK
    } else {
        Write-Status "RDP launch skipped." WARN
        $script:SkipCount++
    }

    Write-Host ""
    Write-Status "Module 4 complete." OK
    Write-Host "    Event Search query:" -ForegroundColor Cyan
    Write-Host "    category_name='Identity & Access Management' and (service.name='Remote Powershell' or service.name='RDP')" -ForegroundColor DarkCyan
    Write-Status "Block mode: first attempt generates alert; access blocked from the second attempt onward." NOTE
    Write-Log "Module 4 complete" OK
}

#endregion

#region -- Module 5: Credential Recon -------------------------------------------

function Test-CredentialRecon {
    Write-Banner "Module 5: Credential Recon (SPN / Kerberoasting / ACL Recon)"
    Write-Status "Safe recon commands used in real attacks to find Kerberoasting targets." INFO
    Write-Status "No tickets are requested, no credentials are extracted." INFO
    Write-Host ""

    # 5.1 SPN enumeration
    Write-TestHeader `
        -TestName     "SPN Scan - setspn -Q */* (Kerberoasting target discovery)" `
        -ExpectedAlert "SPN Scanning Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "setspn -Q */*" { setspn -Q "*/*" | Select-Object -First 30 }
    Pause-Between

    # 5.2 User accounts with SPNs (LDAP)
    Write-TestHeader `
        -TestName     "LDAP - User accounts with SPNs (Kerberoasting targets)" `
        -ExpectedAlert "AD Service Account Enumeration Detected | SPN Scanning Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "DirectorySearcher: (&(objectCategory=user)(servicePrincipalName=*))" {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
        $s.PropertiesToLoad.AddRange([string[]]@("samaccountname", "servicePrincipalName"))
        $r = $s.FindAll()
        "Found $($r.Count) user accounts with SPNs (potential Kerberoasting targets)"
        $r | Select-Object -First 10 | ForEach-Object {
            "  User: $($_.Properties['samaccountname'])  SPN: $($_.Properties['serviceprincipalname'][0])"
        }
    }
    Pause-Between

    # 5.3 AS-REP Roastable accounts
    Write-TestHeader `
        -TestName     "LDAP - Accounts without Kerberos pre-auth (AS-REP Roasting targets)" `
        -ExpectedAlert "Suspicious LDAP Queries Detected | Critical AD Objects Queried" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "DirectorySearcher: userAccountControl DONT_REQ_PREAUTH (0x400000)" {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            "WARNING: $($r.Count) account(s) do NOT require Kerberos pre-authentication (AS-REP Roastable):"
            $r | ForEach-Object { "  - $($_.Properties['samaccountname'])" }
        } else {
            "Good: No AS-REP Roastable accounts found."
        }
    }
    Pause-Between

    # 5.4 ACL enumeration on Domain Admins
    Write-TestHeader `
        -TestName     "ACL Enumeration - Domain Admins group permissions" `
        -ExpectedAlert "AD ACL Enumeration | AD Object Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "ADSI ACL query on CN=Domain Admins" {
        $domDN = ([adsi]"").distinguishedName
        $path  = "LDAP://CN=Domain Admins,CN=Users,$domDN"
        $obj   = [adsi]$path
        $acl   = $obj.ObjectSecurity
        "Domain Admins ACL: $($acl.Access.Count) access control entries"
        $acl.Access | Select-Object -First 5 | ForEach-Object {
            "  $($_.IdentityReference) - $($_.ActiveDirectoryRights)"
        }
    }
    Pause-Between

    # 5.5 DCSync-capable accounts (replication rights on domain object)
    Write-TestHeader `
        -TestName     "LDAP - Accounts with Replication Permissions (DCSync potential)" `
        -ExpectedAlert "Critical AD Objects Queried | AD ACL Enumeration" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP  (also check ISPM Exposures > DCSync)"
    Invoke-TestCommand "ADSI ACL: DS-Replication-Get-Changes on domain object" {
        $domDN = ([adsi]"").distinguishedName
        $dom   = [adsi]"LDAP://$domDN"
        $acl   = $dom.ObjectSecurity
        # GUIDs for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
        $replGuids = @(
            [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            [guid]"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
        )
        $replRights = $acl.Access | Where-Object { $_.ObjectType -in $replGuids }
        if ($replRights) {
            "Accounts with replication permissions (potential DCSync):"
            $replRights | ForEach-Object { "  $($_.IdentityReference)" }
        } else {
            "No non-standard replication permissions found on domain object."
        }
    }
    Pause-Between

    # 5.6 System Information Discovery
    Write-TestHeader `
        -TestName     "System Information Discovery (systeminfo)" `
        -ExpectedAlert "System Information Discovery" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Invoke-TestCommand "systeminfo (abbreviated)" {
        systeminfo 2>&1 | Select-String "OS Name|Domain|System Type" | Select-Object -First 5
    }
    Pause-Between

    # 5.7 BloodHound-style LDAP queries
    Write-TestHeader `
        -TestName     "LDAP - BloodHound-style privileged group enumeration" `
        -ExpectedAlert "BloodHound Usage Detected | AD Privilege Group Enumeration Detected" `
        -AlertLocation "Alerts > Identity | Engine: ADSecure-EP"
    Write-Status "Running LDAP queries mimicking SharpHound collection patterns..." INFO
    Invoke-TestCommand "DirectorySearcher: (&(objectClass=group)(admincount=1))" {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.Filter = "(&(objectClass=group)(admincount=1))"
        $s.PropertiesToLoad.Add("name") | Out-Null
        $r = $s.FindAll()
        "Found $($r.Count) privileged groups (admincount=1)"
        $r | ForEach-Object { "  $($_.Properties['name'])" }
    }
    Pause-Between

    Invoke-TestCommand "DirectorySearcher: (&(objectCategory=computer)(operatingSystem=*Server*))" {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.Filter = "(&(objectCategory=computer)(operatingSystem=*Server*))"
        $s.PropertiesToLoad.AddRange([string[]]@("name", "operatingSystem"))
        $s.SizeLimit = 20
        $r = $s.FindAll()
        "Found $($r.Count) Windows Server objects"
        $r | Select-Object -First 10 | ForEach-Object {
            "  $($_.Properties['name'])  --  $($_.Properties['operatingsystem'])"
        }
    }

    Write-Host ""
    Write-Status "Module 5 complete." OK
    Write-Host "    Check Alerts > Identity (filter: ADSecure-EP)" -ForegroundColor Cyan
    Write-Host "    Also check ISPM > Exposures for DCSync and service account findings" -ForegroundColor Cyan
    Write-Log "Module 5 complete" OK
}

#endregion

#region -- Main Menu -------------------------------------------------------------

function Show-Menu {
    Write-Banner "SentinelOne IDR Test Suite  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" "Green"
    Write-Host "  Domain : $Domain" -ForegroundColor Gray
    if ($script:DC) { Write-Host "  DC     : $($script:DC)" -ForegroundColor Gray }
    Write-Host "  Log    : $($script:LogFile)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1]  Module 1  - AD Enumeration Detection (IDR deception triggers)" -ForegroundColor White
    Write-Host "  [2]  Module 2  - Decoy Object Verification" -ForegroundColor White
    Write-Host "  [3]  Module 3  - ISIDP Attack Rules (SAMR / LDAP at DC)" -ForegroundColor White
    Write-Host "  [4]  Module 4  - ISIDP Trigger Rules (RDP / Remote PowerShell)" -ForegroundColor White
    Write-Host "  [5]  Module 5  - Credential Recon (SPN scan / Kerberoasting targets)" -ForegroundColor White
    Write-Host ""
    Write-Host "  [A]  Run All non-interactive modules (1, 2, 5)" -ForegroundColor Cyan
    Write-Host "  [C]  Check prerequisites" -ForegroundColor DarkGray
    Write-Host "  [Q]  Quit" -ForegroundColor DarkGray
    Write-Host ""
}

# -- Entry point --------------------------------------------------------------

$script:DC            = $DC
$script:RSATInstalled = $false
$script:AgentVersion  = "unknown"
$script:StartTime     = Get-Date

Start-Log -OverridePath $LogPath

if ($RunAll) {
    Confirm-Prerequisites
    Test-ADEnumeration
    Test-DeceptionVerify
    Test-CredentialRecon
    Write-Summary
    exit 0
}

Confirm-Prerequisites

while ($true) {
    Show-Menu
    $choice = (Read-Host "  Select option").Trim().ToUpper()
    Write-Log "Menu choice: $choice" INFO

    switch ($choice) {
        "1" { Test-ADEnumeration }
        "2" { Test-DeceptionVerify }
        "3" { Test-AttackRules }
        "4" { Test-TriggerRules }
        "5" { Test-CredentialRecon }
        "A" {
            Test-ADEnumeration
            Test-DeceptionVerify
            Test-CredentialRecon
        }
        "C" { Confirm-Prerequisites }
        "Q" {
            Write-Summary
            Write-Host "Exiting. Log saved to: $($script:LogFile)" -ForegroundColor DarkGray
            exit 0
        }
        default { Write-Status "Unknown option: $choice" FAIL }
    }
    Write-Host ""
    Read-Host "  Press Enter to return to menu"
}

#endregion
