#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    ISPM Threat Detection simulation tests.

.DESCRIPTION
    Triggers ISPM (Identity Security Posture Management) real-time threat detections
    by performing monitored AD object changes:

      T1 - Suspicious password change (from unusual host → Event 4724)
      T2 - Reactivation of a disabled privileged account (Event 4722)
      T3 - Brute-force / mass account lockout simulation (Event 4625)
      T4 - Built-in Administrator account exposure check
      T5 - SID History inspection (detect existing tampering)

    IMPORTANT: These tests MODIFY AD objects. Run ONLY in a lab/test environment
    where you have full Domain Admin rights and can undo all changes.

    Each test creates a dedicated account named s1test_<module> and cleans up
    on completion. Real production accounts are never touched.

    A timestamped log is written to .\Logs\ automatically.

.PARAMETER Domain
    AD domain FQDN. Defaults to $env:USERDNSDOMAIN.

.PARAMETER OUPath
    OU distinguished name for test accounts, e.g. "OU=TestUsers,DC=lab,DC=local".
    Defaults to the built-in CN=Users container.

.PARAMETER SkipCleanup
    Leave test accounts in AD after running (for manual inspection).
    Remove with: Get-ADUser -Filter "Name -like 's1test_*'" | Remove-ADUser -Confirm:$false

.PARAMETER LogPath
    Override the log file path. Default: .\Logs\ISPMThreats-<timestamp>.log
#>

[CmdletBinding()]
param(
    [string]$Domain      = $env:USERDNSDOMAIN,
    [string]$OUPath      = "",
    [switch]$SkipCleanup,
    [string]$LogPath     = ""
)

$ErrorActionPreference = "Continue"
Import-Module ActiveDirectory -ErrorAction Stop

#region -- Logging ---------------------------------------------------------------

$script:LogFile   = ""
$script:PassCount = 0
$script:FailCount = 0
$script:SkipCount = 0

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
        $script:LogFile = Join-Path $logDir "ISPMThreats-$ts.log"
    }

    @"
================================================================================
  ISPM Threat Detection Simulation Log
  Started    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host       : $env:COMPUTERNAME
  User       : $env:USERDOMAIN\$env:USERNAME
  Domain     : $Domain
  SkipCleanup: $SkipCleanup
  Script     : $PSCommandPath
================================================================================

"@ | Out-File -FilePath $script:LogFile -Encoding UTF8 -Force
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    if (-not $script:LogFile) { return }
    $ts = Get-Date -Format "HH:mm:ss.fff"
    "[$ts] [$($Level.PadRight(5))] $Message" |
        Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

#endregion

#region -- Helpers ---------------------------------------------------------------

function Write-TestHeader {
    param([string]$TestName, [string]$ExpectedThreat, [string]$AlertLocation)
    Write-Host ""
    Write-Host ("-" * 65) -ForegroundColor DarkGray
    Write-Host "  [TEST]    $TestName" -ForegroundColor Yellow
    Write-Host "  [THREAT]  $ExpectedThreat" -ForegroundColor Magenta
    Write-Host "  [WHERE]   $AlertLocation" -ForegroundColor DarkCyan
    Write-Host ("-" * 65) -ForegroundColor DarkGray
    Write-Host ""
    Write-Log "" "---"
    Write-Log "TEST  : $TestName" TEST
    Write-Log "THREAT: $ExpectedThreat" TEST
    Write-Log "WHERE : $AlertLocation" TEST
}

function Write-Status {
    param([string]$Msg, [string]$Level = "INFO")
    $colorMap  = @{ INFO="Gray"; OK="Green"; WARN="Yellow"; FAIL="Red"; NOTE="DarkCyan" }
    $prefixMap = @{ INFO="[i]";  OK="[+]";   WARN="[~]";   FAIL="[!]"; NOTE="[>]" }
    $color  = if ($colorMap.ContainsKey($Level))  { $colorMap[$Level]  } else { "Gray" }
    $prefix = if ($prefixMap.ContainsKey($Level)) { $prefixMap[$Level] } else { "[?]"  }
    Write-Host "  $prefix $Msg" -ForegroundColor $color
    Write-Log "$prefix $Msg" $Level
    if ($Level -eq "OK")   { $script:PassCount++ }
    if ($Level -eq "FAIL") { $script:FailCount++ }
}

function Get-TargetOU {
    if ($OUPath) { return $OUPath }
    $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    return "CN=Users,$domainDN"
}

function New-TestUser {
    param([string]$Name, [string]$OU)
    # Strip non-alphanumeric chars to produce a valid sAMAccountName
    $sam  = $Name -replace "[^a-zA-Z0-9]", ""
    $pass = ConvertTo-SecureString "S1TestPass@2026!" -AsPlainText -Force
    try {
        # Remove any pre-existing test account with this name
        $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-ADUser -Identity $sam -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Removed pre-existing test user: $sam" INFO
        }
        $user = New-ADUser -Name $Name -SamAccountName $sam -AccountPassword $pass `
                           -Enabled $true -Path $OU -PassThru -ErrorAction Stop
        Write-Status "Created test user: $sam (DN: $($user.DistinguishedName))" OK
        Write-Log "New-ADUser: $sam in $OU" OK
        return $sam
    } catch {
        Write-Status "Could not create test user '$sam': $_" FAIL
        Write-Log "New-ADUser exception for $sam : $_" FAIL
        return $null
    }
}

function Remove-TestUser {
    param([string]$Sam)
    try {
        Remove-ADUser -Identity $Sam -Confirm:$false -ErrorAction Stop
        Write-Status "Cleaned up test user: $Sam" OK
        Write-Log "Removed test user: $Sam" OK
    } catch {
        Write-Status "Cleanup error for '$Sam': $_" WARN
        Write-Log "Remove-ADUser exception for $Sam : $_" WARN
    }
}

#endregion

# -- Entry point ---------------------------------------------------------------

Start-Log -OverridePath $LogPath

Write-Host ""
Write-Host "  ==========================================================" -ForegroundColor Magenta
Write-Host "    ISPM Threat Detection - Simulation Tests" -ForegroundColor Magenta
Write-Host "    CAUTION: This script MODIFIES AD objects. Lab use only." -ForegroundColor Red
Write-Host "    Log: $($script:LogFile)" -ForegroundColor DarkGray
Write-Host "  ==========================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Prerequisites:" -ForegroundColor White
Write-Host "    - Domain Admin credentials" -ForegroundColor Gray
Write-Host "    - ISPM configured with Threat Detection ENABLED" -ForegroundColor Gray
Write-Host "    - AD Sync ENABLED in ISPM AD configuration" -ForegroundColor Gray
Write-Host ""

$confirm = Read-Host "  Type 'CONFIRM' to proceed (lab environment only)"
if ($confirm -ne "CONFIRM") {
    Write-Host "  Aborted." -ForegroundColor Yellow
    Write-Log "Script aborted at confirmation prompt." WARN
    exit 0
}
Write-Log "User confirmed execution" INFO

try {
    $ou = Get-TargetOU
} catch {
    Write-Status "Could not determine target OU: $_" FAIL
    Write-Log "Get-TargetOU failed: $_" FAIL
    exit 1
}
Write-Status "Using OU: $ou" INFO
Write-Host ""

#region Test T1: Suspicious Password Change

Write-TestHeader `
    -TestName     "T1 - Suspicious Password Change" `
    -ExpectedThreat "Suspicious password change detected" `
    -AlertLocation "ISPM > Threat Detection > Threats  |  Alerts > Identity"

$t1sam = New-TestUser -Name "s1test_pwchange" -OU $ou
if ($t1sam) {
    Start-Sleep -Seconds 2

    $newPass = ConvertTo-SecureString "S1TestNewPass@2026!" -AsPlainText -Force
    try {
        Set-ADAccountPassword -Identity $t1sam -NewPassword $newPass -Reset -ErrorAction Stop
        Write-Status "Password reset on '$t1sam' - ISPM should detect Event 4724 on the DC" OK
        Write-Status "Source host: $env:COMPUTERNAME  |  Subject: $env:USERDOMAIN\$env:USERNAME" INFO
        Write-Log "Set-ADAccountPassword succeeded for $t1sam" OK
    } catch {
        Write-Status "Password change error: $_" FAIL
        Write-Log "Set-ADAccountPassword exception: $_" FAIL
    }

    Write-Host ""
    Write-Host "  Verify in DC Security Event Log:" -ForegroundColor Cyan
    Write-Host "    Event ID 4724 - An attempt was made to reset an account's password" -ForegroundColor Gray
    Write-Host "    Subject: $env:USERDOMAIN\$env:USERNAME  |  Target account: $t1sam" -ForegroundColor Gray
    Write-Host "  ISPM alerts when the source host is unexpected (non-DC, remote session)." -ForegroundColor Gray

    if (-not $SkipCleanup) {
        Start-Sleep -Seconds 10
        Remove-TestUser -Sam $t1sam
    }
}

#endregion

#region Test T2: Reactivation of Disabled Privileged Account

Write-TestHeader `
    -TestName     "T2 - Reactivation of Disabled Privileged Account" `
    -ExpectedThreat "Reactivation of disabled privileged accounts" `
    -AlertLocation "ISPM > Threat Detection > Threats  |  Alerts > Identity"

$t2sam = New-TestUser -Name "s1test_reactivate" -OU $ou
if ($t2sam) {
    # Add to Domain Admins so ISPM classifies the account as privileged
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members $t2sam -ErrorAction Stop
        Write-Status "Added '$t2sam' to Domain Admins (classifies as privileged)" OK
        Write-Log "Added $t2sam to Domain Admins" OK
    } catch {
        Write-Status "Could not add to Domain Admins: $_ (test may still generate event)" WARN
        Write-Log "Add-ADGroupMember exception: $_" WARN
    }

    # Disable - simulates a dormant privileged account
    try {
        Disable-ADAccount -Identity $t2sam -ErrorAction Stop
        Write-Status "Disabled '$t2sam' (simulating dormant privileged account)" OK
        Write-Log "Disabled $t2sam" OK
    } catch {
        Write-Status "Disable-ADAccount error: $_" FAIL
        Write-Log "Disable-ADAccount exception: $_" FAIL
    }

    Start-Sleep -Seconds 5

    # Re-enable - this is the suspicious action ISPM detects
    try {
        Enable-ADAccount -Identity $t2sam -ErrorAction Stop
        Write-Status "Re-ENABLED '$t2sam' - ISPM should detect privileged account reactivation" OK
        Write-Log "Enabled $t2sam (reactivation)" OK
    } catch {
        Write-Status "Enable-ADAccount error: $_" FAIL
        Write-Log "Enable-ADAccount exception: $_" FAIL
    }

    Write-Host ""
    Write-Host "  Verify in DC Security Event Log:" -ForegroundColor Cyan
    Write-Host "    Event ID 4722 - A user account was enabled" -ForegroundColor Gray
    Write-Host "    Subject: $env:USERDOMAIN\$env:USERNAME  |  Target account: $t2sam" -ForegroundColor Gray

    if (-not $SkipCleanup) {
        Start-Sleep -Seconds 10
        try {
            Remove-ADGroupMember -Identity "Domain Admins" -Members $t2sam -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Removed $t2sam from Domain Admins" INFO
        } catch {
            Write-Log "Remove-ADGroupMember error: $_" WARN
        }
        Remove-TestUser -Sam $t2sam
    }
}

#endregion

#region Test T3: Brute-Force / Mass Account Lockout Simulation

Write-TestHeader `
    -TestName     "T3 - Brute-Force / Mass Account Lockout Simulation" `
    -ExpectedThreat "Brute-force attack - Mass account lockout" `
    -AlertLocation "ISPM > Threat Detection > Threats  |  Alerts > Identity"

Write-Host "  Generates multiple failed authentication events via LDAP bad-credential binds." -ForegroundColor Gray
Write-Host "  ISPM detects the pattern when multiple accounts lock out in a short window." -ForegroundColor Gray
Write-Host "  This test shows the per-account pattern; repeat for multiple accounts for full detection." -ForegroundColor Gray
Write-Host ""

$t3sam = New-TestUser -Name "s1test_lockout" -OU $ou
if ($t3sam) {
    Write-Status "Generating failed logon attempts for '$t3sam'..." INFO
    Write-Log "Starting bad-credential LDAP binds against $t3sam" INFO

    $failCount = 0
    1..6 | ForEach-Object {
        try {
            # DirectoryEntry with wrong password forces an LDAP bind that generates Event 4625
            $entry = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$Domain",
                "$Domain\$t3sam",
                "WrongPassword_$_!"
            )
            # Accessing NativeObject forces the actual bind attempt; assign to $null to discard result
            $null = $entry.NativeObject
        } catch {
            $failCount++
        }
    }

    Write-Status "Generated $failCount failed authentication attempts (Event ID 4625 on DC)" OK
    Write-Log "Bad-credential binds completed: $failCount failures" OK
    Write-Host ""
    Write-Host "  Verify in DC Security Event Log:" -ForegroundColor Cyan
    Write-Host "    Event ID 4625 - An account failed to log on (repeated)" -ForegroundColor Gray
    Write-Host "    Source: $env:COMPUTERNAME  |  Target account: $t3sam" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: For 'Mass account lockout' ISPM detection, repeat this pattern" -ForegroundColor Yellow
    Write-Host "  against several accounts simultaneously (crackmapexec/kerbrute behaviour)." -ForegroundColor Yellow

    if (-not $SkipCleanup) {
        Start-Sleep -Seconds 5
        # Unlock in case account was locked out by the bad-credential attempts
        try {
            Unlock-ADAccount -Identity $t3sam -ErrorAction SilentlyContinue
            Write-Log "Unlocked $t3sam" INFO
        } catch { }
        Remove-TestUser -Sam $t3sam
    }
}

#endregion

#region Test T4: Default Administrator Account Exposure Check

Write-TestHeader `
    -TestName     "T4 - Default Administrator Account Exposure Check" `
    -ExpectedThreat "Default Admin Account usage" `
    -AlertLocation "ISPM > Threat Detection > Threats  |  ISPM > Exposures > Weak default Administrator Account"

Write-Host "  Checks whether the built-in Administrator account is enabled." -ForegroundColor Gray
Write-Host "  Authentication with this account triggers 'Default Admin Account usage' threat." -ForegroundColor Gray
Write-Host "  No AD changes are made in this test." -ForegroundColor Gray
Write-Host ""

try {
    $builtinAdmin = Get-ADUser -Filter "SamAccountName -eq 'Administrator'" `
                               -Properties Enabled, LastLogonDate, PasswordLastSet `
                               -ErrorAction Stop
    if ($builtinAdmin) {
        $enabled = $builtinAdmin.Enabled
        Write-Host "  Built-in Administrator account:" -ForegroundColor White
        Write-Host "    Enabled        : $enabled" -ForegroundColor $(if ($enabled) { "Yellow" } else { "Green" })
        Write-Host "    Last logon     : $($builtinAdmin.LastLogonDate)" -ForegroundColor Gray
        Write-Host "    Password set   : $($builtinAdmin.PasswordLastSet)" -ForegroundColor Gray

        Write-Log "Built-in Administrator: Enabled=$enabled LastLogon=$($builtinAdmin.LastLogonDate)" INFO

        if ($enabled) {
            Write-Host ""
            Write-Status "EXPOSURE: Built-in Administrator is enabled." WARN
            Write-Status "ISPM flags this as 'Weak default Administrator Account'." WARN
            Write-Status "Any authentication with Administrator triggers 'Default Admin Account usage'." INFO
        } else {
            Write-Status "Built-in Administrator is disabled (good security posture)." OK
        }
    } else {
        Write-Status "Could not find the built-in Administrator account." WARN
    }
} catch {
    Write-Status "Administrator account query error: $_" FAIL
    Write-Log "Get-ADUser Administrator exception: $_" FAIL
}

#endregion

#region Test T5: SID History Inspection

Write-TestHeader `
    -TestName     "T5 - SID History Inspection" `
    -ExpectedThreat "SID history tampering detected" `
    -AlertLocation "ISPM > Threat Detection > Threats  |  ISPM > Exposures"

Write-Host "  Queries for user accounts with non-empty SIDHistory attribute." -ForegroundColor Gray
Write-Host "  SIDHistory should be empty unless migrated from another domain." -ForegroundColor Gray
Write-Host "  No AD changes are made in this test." -ForegroundColor Gray
Write-Host ""
Write-Log "Querying for SIDHistory using LDAP filter (sidhistory=*)" INFO

try {
    # BUG FIX: use LDAPFilter to avoid loading every user object
    # (sidhistory=*) matches only accounts with a non-empty SIDHistory attribute
    $usersWithSIDHistory = Get-ADUser -LDAPFilter "(sidhistory=*)" `
                                      -Properties SIDHistory `
                                      -ErrorAction Stop

    # Materialise to array so .Count is reliable
    [array]$sidUsers = @($usersWithSIDHistory)

    if ($sidUsers.Count -gt 0) {
        Write-Status "Found $($sidUsers.Count) user(s) with non-empty SIDHistory:" WARN
        $sidUsers | Select-Object -First 10 | ForEach-Object {
            $sidList = ($_.SIDHistory | ForEach-Object { $_.ToString() }) -join ", "
            Write-Host "    - $($_.SamAccountName)  SIDHistory: $sidList" -ForegroundColor Gray
            Write-Log "SIDHistory: $($_.SamAccountName) = $sidList" WARN
        }
        Write-Host ""
        Write-Status "Review these accounts in ISPM - unexpected SIDHistory is an exposure." WARN
        Write-Status "Legitimate SIDHistory exists for accounts migrated from another domain." INFO
    } else {
        Write-Status "No users with SIDHistory entries found (expected in a clean domain)." OK
        Write-Log "No SIDHistory entries found" OK
    }
} catch {
    Write-Status "SID History query error: $_" FAIL
    Write-Log "Get-ADUser SIDHistory exception: $_" FAIL
}

#endregion

# -- Summary ------------------------------------------------------------------

$summary = @"

================================================================================
  ISPM Threat Tests - Summary
  Finished     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  PASS/OK      : $($script:PassCount)
  FAIL         : $($script:FailCount)
  Log file     : $($script:LogFile)
================================================================================

  Verify threats at:
    S1 Console > Identity > ISPM > Threat Detection > Threats

  Key DC Security Event IDs to correlate:
    4724 - Password reset attempt          (T1)
    4722 - User account enabled            (T2)
    4625 - Failed logon attempt            (T3)
    4725 - User account disabled           (T2 setup)
    4738 - User account changed            (general)
"@

Write-Host $summary -ForegroundColor Cyan
if ($script:LogFile) { $summary | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 }

if ($SkipCleanup) {
    Write-Host ""
    Write-Status "SkipCleanup is set. Remove test users when done:" WARN
    Write-Host "    Get-ADUser -Filter `"Name -like 's1test_*'`" | Remove-ADUser -Confirm:`$false" -ForegroundColor DarkGray
    Write-Log "SkipCleanup=true - test users left in AD" WARN
}
Write-Host ""
