#Requires -Version 5.1
<#
.SYNOPSIS
    Quick health-check for SentinelOne IDR configuration.

.DESCRIPTION
    Validates that the local endpoint is properly configured for IDR testing:
      - S1 Agent running and IDR engine enabled
      - Domain-joined
      - DC reachable on required ports (389, 88, 445, 9389, 5985)
      - RSAT installed
      - Live LDAP query succeeds
      - Kerberos TGT present
      - S1 Identity API reachable on HTTPS 443

    Run this BEFORE running Invoke-S1IDRTests.ps1 to catch config issues early.
    A timestamped log file is written to .\Logs\ automatically.

.PARAMETER DC
    Domain Controller FQDN. Auto-detected from current domain if not provided.

.PARAMETER LogPath
    Override the log file path. Default: .\Logs\IDRConfig-<timestamp>.log
#>

[CmdletBinding()]
param(
    [string]$DC      = "",
    [string]$LogPath = ""
)

$ErrorActionPreference = "Continue"

#region -- Logging ---------------------------------------------------------------

$script:LogFile  = ""
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

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
        $script:LogFile = Join-Path $logDir "IDRConfig-$ts.log"
    }

    @"
================================================================================
  SentinelOne IDR Config Health Check Log
  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host     : $env:COMPUTERNAME
  User     : $env:USERDOMAIN\$env:USERNAME
  Domain   : $env:USERDNSDOMAIN
  Script   : $PSCommandPath
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

function Write-Check {
    param(
        [string]$Label,
        [bool]$Pass,
        [string]$Detail = ""
    )
    $status = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    $color  = if ($Pass) { "Green"  } else { "Red"   }
    Write-Host ("  {0,-8} {1}" -f $status, $Label) -ForegroundColor $color
    if ($Detail) {
        Write-Host ("           {0}" -f $Detail) -ForegroundColor DarkGray
    }

    Write-Log "$status $Label" $(if ($Pass) { "OK" } else { "FAIL" })
    if ($Detail) { Write-Log "         Detail: $Detail" INFO }

    if ($Pass) { $script:PassCount++ } else { $script:FailCount++ }
}

function Write-CheckWarn {
    # Like Write-Check but a failure is a warning, not a hard fail
    param([string]$Label, [bool]$Pass, [string]$Detail = "")
    $status = if ($Pass) { "[PASS]" } else { "[WARN]" }
    $color  = if ($Pass) { "Green"  } else { "Yellow" }
    Write-Host ("  {0,-8} {1}" -f $status, $Label) -ForegroundColor $color
    if ($Detail) {
        Write-Host ("           {0}" -f $Detail) -ForegroundColor DarkGray
    }
    Write-Log "$status $Label" $(if ($Pass) { "OK" } else { "WARN" })
    if ($Detail) { Write-Log "         Detail: $Detail" INFO }
    if ($Pass) { $script:PassCount++ } else { $script:WarnCount++ }
}

function Write-Info {
    param([string]$Label, [string]$Value)
    Write-Host ("  [INFO]   {0}: {1}" -f $Label, $Value) -ForegroundColor Cyan
    Write-Log "INFO  $Label : $Value" INFO
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  -- $Title --" -ForegroundColor Yellow
    Write-Log "" "---"
    Write-Log "SECTION: $Title" INFO
}

#endregion

# -- Start --------------------------------------------------------------------

Start-Log -OverridePath $LogPath

Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Cyan
Write-Host "    SentinelOne IDR Configuration Health Check" -ForegroundColor Cyan
Write-Host "    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "    Log: $($script:LogFile)" -ForegroundColor DarkGray
Write-Host "  ======================================================" -ForegroundColor Cyan
Write-Host ""

#region Section 1: Endpoint Identity

Write-Section "Endpoint Identity"

$osCaption = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
Write-Info "Hostname"  $env:COMPUTERNAME
Write-Info "Username"  "$env:USERDOMAIN\$env:USERNAME"
Write-Info "Domain"    $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "(not domain-joined)" })
Write-Info "OS"        $(if ($osCaption) { $osCaption } else { "Unknown" })

$domainJoined = [bool]$env:USERDNSDOMAIN
Write-Check "Domain-joined endpoint" $domainJoined `
    $(if (-not $domainJoined) { "Join this endpoint to the domain before running IDR tests." })

#endregion

#region Section 2: SentinelOne Agent

Write-Section "SentinelOne Agent"

$svc = Get-Service -Name SentinelAgent -ErrorAction SilentlyContinue
Write-Check "SentinelAgent service exists"  ($null -ne $svc)
Write-Check "SentinelAgent service running" ($null -ne $svc -and $svc.Status -eq "Running") `
    $(if ($null -ne $svc -and $svc.Status -ne "Running") { "Start-Service SentinelAgent" })

# Agent install folder and version
[array]$s1dirs = Get-ChildItem "C:\Program Files\SentinelOne\" -ErrorAction SilentlyContinue
if ($s1dirs -and $s1dirs.Count -gt 0) {
    $s1dir = $s1dirs[0]
    Write-Info "Install folder" $s1dir.FullName

    if ($s1dir.Name -match "(\d+\.\d+\.\d+)") {
        $agentVer = $Matches[1]
        Write-Info "Agent version (from folder)" $agentVer

        $parts = $agentVer.Split(".")
        $isNewAlertModel = ([int]$parts[0] -gt 25) -or
                           ([int]$parts[0] -eq 25 -and [int]$parts[1] -gt 2) -or
                           ([int]$parts[0] -eq 25 -and [int]$parts[1] -eq 2 -and [int]$parts[2] -ge 3)

        if ($isNewAlertModel) {
            Write-Host "  [NOTE]   Agent >= 25.2.3: Deception alerts show in Event Search (Behavioral Indicators), NOT Alerts tab." -ForegroundColor Yellow
            Write-Log "NOTE: Agent >= 25.2.3 - alert model uses Event Search" INFO
        } else {
            Write-Host "  [NOTE]   Agent <= 25.2.2: IDR alerts appear in Alerts > Identity, filter Engine = ADSecure-EP." -ForegroundColor Yellow
            Write-Log "NOTE: Agent <= 25.2.2 - alert model uses Alerts tab" INFO
        }
    }
} else {
    Write-CheckWarn "SentinelOne install folder found" $false "Expected: C:\Program Files\SentinelOne\<version>\"
}

# IDR engine via SentinelCtl
$s1ctl = Get-ChildItem "C:\Program Files\SentinelOne\*\SentinelCtl.exe" -ErrorAction SilentlyContinue |
         Select-Object -First 1
if ($s1ctl) {
    try {
        [string[]]$idrRaw = & $s1ctl.FullName config idr 2>&1 | ForEach-Object { "$_" }
        $idrOutput  = $idrRaw -join " "
        $idrEnabled = $idrOutput -match '"idrEnabled":true'

        Write-Check "IDR engine enabled (SentinelCtl config idr)" $idrEnabled `
            $(if (-not $idrEnabled) {
                "Enable in S1 Console: Policies > Policy > Detection Engines > Identity Detection & Response = ON.`n" +
                "           Then verify here: expected output {`"dynamicHooks`":true,`"idrEnabled`":true}"
            })
        Write-Info "SentinelCtl output" $idrOutput
    } catch {
        Write-Check "SentinelCtl query" $false "Exception: $_"
        Write-Log "SentinelCtl exception: $_" FAIL
    }
} else {
    Write-CheckWarn "SentinelCtl found" $false "Path not found. Verify IDR status manually in S1 Console."
}

#endregion

#region Section 3: Domain Connectivity

Write-Section "Domain Connectivity"

# Resolve DC - use param or auto-detect
$dcFQDN = $DC
if (-not $dcFQDN) {
    try {
        $dcFQDN = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
        Write-Log "DC auto-detected: $dcFQDN" INFO
    } catch {
        Write-Log "DC auto-detect error: $_" WARN
    }
}

if ($dcFQDN) {
    Write-Info "Domain Controller" $dcFQDN

    # Ping
    $pingOk = Test-Connection -ComputerName $dcFQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
    Write-Check "DC reachable (ping)" ([bool]$pingOk)

    # Helper: safe TCP test that returns false on null/error instead of throwing
    function Test-Port {
        param([string]$Host, [int]$Port)
        try {
            $conn = Test-NetConnection -ComputerName $Host -Port $Port `
                        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            # Guard: $conn could be null if DNS resolution failed entirely
            if ($conn) { return [bool]$conn.TcpTestSucceeded } else { return $false }
        } catch {
            Write-Log "Test-Port $Host`:$Port exception: $_" WARN
            return $false
        }
    }

    Write-Check "LDAP port 389 open"                                  (Test-Port $dcFQDN 389)
    Write-Check "Kerberos port 88 open"                               (Test-Port $dcFQDN 88)
    Write-Check "SMB port 445 open"                                   (Test-Port $dcFQDN 445)
    Write-CheckWarn "AD Web Services port 9389 open (RSAT cmdlets)"   (Test-Port $dcFQDN 9389) `
        "Required for Get-ADUser etc. - check DC firewall if FAIL."
    Write-CheckWarn "WinRM port 5985 open to DC (ISPM assessment)"    (Test-Port $dcFQDN 5985) `
        "Required for ISPM WinRM-based assessment. Enable WinRM on DC: Enable-PSRemoting -Force"
} else {
    Write-Check "Domain Controller detected" $false "Could not locate DC. Use -DC <FQDN> parameter."
}

#endregion

#region Section 4: RSAT Tools

Write-Section "RSAT Active Directory Tools"

$rsatCap      = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq "Installed" }
$rsatInstalled = $null -ne $rsatCap

Write-CheckWarn "RSAT AD Tools installed" $rsatInstalled `
    $(if (-not $rsatInstalled) {
        "Install: Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
    })

if ($rsatInstalled) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Check "ActiveDirectory PowerShell module importable" $true
    } catch {
        Write-Check "ActiveDirectory PowerShell module importable" $false "Import-Module error: $_"
        Write-Log "ActiveDirectory module import error: $_" FAIL
    }
}

#endregion

#region Section 5: AD Connectivity (live LDAP query)

Write-Section "AD Connectivity (live LDAP query)"

try {
    $searcher          = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter   = "(objectClass=domain)"
    $searcher.SizeLimit = 1
    $result            = $searcher.FindOne()
    if ($result) {
        $domainDN = $result.Properties["distinguishedname"][0]
        Write-Check "LDAP query to AD succeeded" $true
        Write-Info  "Domain DN" $domainDN
    } else {
        Write-Check "LDAP query returned a result" $false "FindOne() returned null - check domain binding."
    }
} catch {
    Write-Check "LDAP query to AD succeeded" $false "Exception: $_"
    Write-Log "LDAP query exception: $_" FAIL
}

# Kerberos TGT check using klist
try {
    [string[]]$klistOut = klist 2>&1 | ForEach-Object { "$_" }
    # -match on an array returns matching elements; cast to bool for truthiness
    $tgtLines = $klistOut | Where-Object { $_ -match "#0" }
    $hasTGT   = $tgtLines.Count -gt 0
    Write-Check "Kerberos TGT present (klist #0)" $hasTGT `
        $(if (-not $hasTGT) { "Log off and on, or run 'klist get krbtgt' to obtain a TGT." })
    Write-Log "klist lines: $($klistOut.Count); TGT found: $hasTGT" INFO
} catch {
    Write-CheckWarn "klist available" $false "Exception: $_"
    Write-Log "klist exception: $_" WARN
}

#endregion

#region Section 6: S1 Identity API Reachability

Write-Section "SentinelOne Identity API Reachability (HTTPS 443)"

Write-Host "  Testing connectivity to Identity API endpoints (one should succeed for your region):" -ForegroundColor DarkGray

$regions = [ordered]@{
    "US East 1"        = "usea1-identity.sentinelone.net"
    "EU Central 1"     = "euce1-identity.sentinelone.net"
    "Canada Central 1" = "cace1-identity.sentinelone.net"
    "AP SE 1"          = "apse1-identity.sentinelone.net"
    "AP SE 2"          = "apse2-identity.sentinelone.net"
}

foreach ($region in $regions.GetEnumerator()) {
    try {
        $conn       = Test-NetConnection -ComputerName $region.Value -Port 443 `
                          -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        # BUG FIX: guard against null $conn when DNS resolution fails entirely
        $connResult = if ($conn) { [bool]$conn.TcpTestSucceeded } else { $false }
        Write-CheckWarn "$($region.Key) ($($region.Value):443)" $connResult `
            $(if (-not $connResult) { "Check firewall/proxy allows TCP 443 to $($region.Value)" })
    } catch {
        Write-CheckWarn "$($region.Key) - connection test error" $false "Exception: $_"
        Write-Log "Region $($region.Key) test exception: $_" WARN
    }
}

#endregion

#region Section 7: Manual Console Checklist

Write-Section "Manual Verification Checklist (complete in S1 Console)"

$checks = @(
    "Sentinels > Policy > Detection Engines > Identity Detection & Response = ON (purple)"
    "Identity > Identity Policies - at least one policy is ACTIVE (green dot)"
    "Sentinels > Identity Policy > AD Connector status = Connected (green)"
    "Active policy > Decoys tab - decoy objects are listed (usernames, computers, DCs)"
    "Identity > Identity Policies > [policy] > Rules - at least one rule with Alert checked"
    "If ISIDP: Identity Provider Policy ACTIVE, Learning Mode = DISABLED for attack rule testing"
    "If ISPM: AD Sync enabled, Threat Detection enabled in AD configuration"
)

Write-Host ""
for ($i = 0; $i -lt $checks.Count; $i++) {
    Write-Host ("  [ ]  {0}. {1}" -f ($i + 1), $checks[$i]) -ForegroundColor Gray
    Write-Log "Console checklist $($i+1): $($checks[$i])" INFO
}

#endregion

# -- Summary ------------------------------------------------------------------

$summary = @"

================================================================================
  Health Check Summary
  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  PASS     : $($script:PassCount)
  FAIL     : $($script:FailCount)
  WARN     : $($script:WarnCount)
  Log file : $($script:LogFile)
================================================================================
"@

Write-Host $summary -ForegroundColor Cyan
if ($script:LogFile) { $summary | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 }

if ($script:FailCount -gt 0) {
    Write-Host "  Fix all [FAIL] items before running Invoke-S1IDRTests.ps1" -ForegroundColor Red
} elseif ($script:WarnCount -gt 0) {
    Write-Host "  Review [WARN] items - tests may succeed but some features could be limited." -ForegroundColor Yellow
} else {
    Write-Host "  All checks passed. Run: .\Invoke-S1IDRTests.ps1" -ForegroundColor Green
}
Write-Host ""
