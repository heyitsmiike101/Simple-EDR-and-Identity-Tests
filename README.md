# Simple EDR and Identity Tests

**Version:** 1.1.0

A menu-driven PowerShell tool that fires common attacker-style behaviors so you
can watch SentinelOne (or any EDR/Identity product) detect them and validate your
alert-correlation logic. (The in-tool banner still reads "EDR Lab Rat".)

> **SANDBOX / NON-PRODUCTION USE ONLY.** This is for **authorized** detection
> testing (your own lab, a pentest engagement, or security research). It
> intentionally generates malicious-looking telemetry and makes real changes to
> the host (shadow copies, VSS, registry, scheduled tasks) and, via the bundled
> Identity scripts, to Active Directory. Run it only on a disposable,
> snapshot-restorable VM / lab domain that you are authorized to test.

---

## Files

| File | Purpose |
|------|---------|
| `EDR-Test-Menu.ps1`      | The interactive menu harness (start here). |
| `Invoke-S1IDRTests.ps1`  | S1 IDR AD-enumeration / Identity attack tests (launched by option 9). |
| `Verify-IDRConfig.ps1`   | Read-only IDR configuration health check (option 10). |
| `Test-ISPMThreats.ps1`   | ISPM threat simulation — **modifies AD**, lab only (option 11). |

All four scripts live in the repo root. Options 9–11 launch the three bundled
scripts from that same folder. A `Logs\` folder is created at runtime for session
logs and per-run result transcripts; it is **git-ignored** (see [Logging](#command-visibility--logging)).

---

## Design: process isolation

The menu loop is the **parent** process. Every numbered action is decoded in the
parent, then launched in a **separate child process / window** via `Start-Process`
(no `-Wait`) using `-EncodedCommand` — the payload is handed to the child
**in-memory** (base64 UTF-16LE), so **no plaintext `.ps1` is written to disk**. So
when SentinelOne terminates or quarantines the child that performed an action, the
menu **keeps running** — you just pick the next test without restarting the tool.
The menu loops until you type `q`.

---

## Running it

From a PowerShell prompt in the project folder:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File ".\EDR-Test-Menu.ps1"
```

- **Recommended: run this from an elevated (Administrator) PowerShell.** Several
  actions require elevation, and running the menu as admin lets them run without a
  separate UAC prompt each time.

### AV / EDR exclusion for the harness itself

On a machine with active AV/S1, an un-obfuscated version of this harness gets
**flagged and quarantined before it can run** (the shadow-delete, credential-dump,
and persistence patterns match signatures). This was observed during development —
the local AV blocked the plaintext script on load.

To reduce that, **all action payloads are stored obfuscated** (see below), so the
`.ps1` at rest no longer contains the plaintext commands or tool-name literals.
That hardens the file *at rest*; it does **not** hide the behavior *at execution*
(that is intentional — you still want S1 to detect the real actions).

With the payloads obfuscated, the launcher often runs without any exclusion (it
has on at least one test setup). If it still gets quarantined in your environment,
**you may need to add a static file exclusion** for `EDR-Test-Menu.ps1` in your
sandbox AV / S1 policy before running.

---

## Payload obfuscation

Every detection-generating command in the harness (options 1–8, `enableshadow`,
and the `cleanup` logic) is **not stored in plaintext**. Each payload is encoded
and only reconstructed in memory the instant before it runs. This keeps the
launcher file from matching at-rest signatures so the menu survives to fire tests.

### Scheme

Encoding (how it is stored in the file):

```
command  ->  UTF-8 bytes  ->  base64  ->  reverse the string
```

So each payload appears in the file as an opaque, backwards base64 blob, e.g.
`$DeleteShadowBody = '==gCuFWeD...'`.

Decoding (how it is restored at run time) is the exact inverse:

```
stored string  ->  reverse  ->  base64-decode  ->  original command text
```

This is done by the `Restore-Payload` function:

```powershell
function Restore-Payload {
    param([Parameter(Mandatory)] [string] $Obf)
    $chars = $Obf.ToCharArray()
    [System.Array]::Reverse($chars)
    $b64 = -join $chars
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
}
```

Wiring:

- **Options 1–8 and `enableshadow`** — `Start-DetachedAction` calls
  `$Body = Restore-Payload $Body` in the parent, then delivers the plaintext to the
  child via `powershell -EncodedCommand` (base64 UTF-16LE). The decode happens in
  the **parent, before the child is created**, and nothing is written to disk — the
  child decodes the `-EncodedCommand` blob in memory and runs it.
- **`cleanup`** — `Invoke-Cleanup` runs `Invoke-Expression (Restore-Payload $CleanupBody)`.
- **EICAR (option 1)** is doubly protected: the outer payload is reverse-base64,
  and *inside* it the EICAR string itself is stored **triple-base64** and decoded
  three times at write-time, so the EICAR signature never appears in the file.
- Tool-name literals that remained in code comments (e.g. the VSS CLI, the
  signed-DLL memory-dump technique) were **neutralized to generic wording** in the
  script; the full technique detail lives here in the README instead.

### De-obfuscating a payload manually (for auditing)

To inspect what any stored blob actually runs, reverse the string and base64-decode
it — for example in PowerShell:

```powershell
# Paste a stored payload blob between the quotes:
$blob = '==gCuFWeD...'
$chars = $blob.ToCharArray(); [Array]::Reverse($chars)
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(-join $chars))
```

> Running the line above will materialize the plaintext command in memory, which
> local AMSI/AV may flag — that is expected. Do it only in your sandbox.

### Scope / limitations

- Obfuscation covers the **payloads**, not the harness scaffolding (menu loop,
  `Write-Host`, `Start-Process`, the decoder) — those must stay executable and are
  benign.
- This is at-rest hardening only. When a payload runs, **AMSI scans the decoded
  script block in the child process**, so SentinelOne still sees and detects the
  real behavior. That is the point of the tool.

---

## Menu options

| Input          | Action                                   | MITRE ATT&CK        | Elevated |
|----------------|------------------------------------------|---------------------|----------|
| `1`            | Download EICAR and write to disk         | T1105               | no       |
| `2`            | Delete shadow copies                     | T1490               | yes      |
| `3`            | Disable shadow copy / VSS                | T1490               | yes      |
| `4`            | List shadow copy / VSS state (read-only) | —                   | yes¹     |
| `5`            | AD / privileged-group enumeration        | T1069.002 / T1087.002 | no     |
| `6`            | Local host discovery / recon             | T1082 / T1033 / T1016 / T1057 | no |
| `7`            | LSASS credential-dump test               | T1003.001           | yes      |
| `8`            | Persistence: Run key + scheduled task    | T1547.001 / T1053.005 | no     |
| `9`            | Launch `Invoke-S1IDRTests.ps1` (AD enum / IDR) | T1069 / T1087 / T1558 | no |
| `10`           | Launch `Verify-IDRConfig.ps1` (read-only health check) | —      | no |
| `11`           | Launch `Test-ISPMThreats.ps1` — **MODIFIES AD** | T1098 / T1078 | yes |
| `enableshadow` | Re-enable shadow copy / VSS (undo #3)    | —                   | yes      |
| `cleanup`      | Remove persistence + delete artifacts    | —                   | no       |
| `q`            | Quit                                     | —                   | —        |

¹ `vssadmin list` requires admin, so option 4 elevates even though it only reads state.

Options **9–11** are thin launchers: they start the corresponding script (in the
same folder as `EDR-Test-Menu.ps1`) in its own window (`-NoExit`), so those scripts
run with their own menus, prompts, and logging. Option **11** creates/modifies AD
objects and requires Domain Admin — run it only in a lab, and let its own
confirmation prompt gate execution.

### Notes per option

- **1 — EICAR:** Tries the live download from `secure.eicar.org` first; if blocked,
  falls back to a triple-base64-encoded copy decoded at write-time. Writes
  `eicar_<timestamp>.com` to `%TEMP%\EDRTest\`. The file is byte-identical standard
  EICAR, so S1 detects it normally.
- **2 / 3 — Shadow copies:** These make **real, non-reversible-by-cleanup** changes.
  Use `enableshadow` to restore VSS state.
- **4 — State check:** Run before and after 2/3/`enableshadow` to visually confirm
  the effect and correlate against the S1 alert timeline.
- **5 — AD enum:** Works domain-joined; the `/domain` queries error out gracefully
  in a workgroup and fall back to local groups + `whoami /groups`.
- **7 — LSASS dump:** Often produces **no** dump on a modern box (Credential Guard /
  S1 blocks the read) — the **attempt** is what fires the detection, not a
  successful dump. No exfiltration; the dump (if any) stays local.
- **8 — Persistence:** Leaves an HKCU Run value and a scheduled task behind. The
  child window prints the exact removal commands; `cleanup` also removes both.
- **9–11 — Bundled test scripts:** Launch the existing scripts kept alongside the harness.
  Option 9 (`Invoke-S1IDRTests.ps1`) already covers the deeper Identity attacks —
  AD enumeration, Kerberoasting / AS-REP / DCSync recon, and BloodHound-style LDAP
  — so those are exercised from that maintained script rather than duplicated here.

---

## Command visibility & logging

Every option **shows what it will do**, then **captures the results of what ran**.
Everything lands under `.\Logs\` (created next to the script at first run).

**1. Commands shown + recorded (what it does).**
On selection, the harness prints a `Commands that will run for '<name>':` block to
the console — the decoded command text for options 1–8/`cleanup`, or the launch
line for options 9–11 — **before** anything executes. The same is written to the
per-session log `.\Logs\EDR-Test-Menu-<timestamp>.log`, which records the start
banner, every menu selection (`MENU`), and each action's full command block between
`----- commands begin/end -----` markers (`RUN` / `CMD`).

**2. Results captured per run (what happened).**
Each launched action's **full output** is captured to its own per-run transcript
at `.\Logs\run-<Name>-<timestamp>.log` via `Start-Transcript`:

- Options **1–8** and **`enableshadow`** — the child process is wrapped so its
  entire session (results, errors, S1 reactions it prints) is transcribed. The
  console shows `Results will be captured to: ...\run-<Name>-<timestamp>.log`.
- Options **9–11** — the bundled script is run inside a transcript the same way, so
  the whole test run (including its own menus/output) is captured. Those scripts
  *also* keep their own internal logs.
- **`cleanup`** runs inline in the parent process, so its results are written
  straight into the session log (`RESULT` block) rather than a separate transcript.

Together this gives you, per action: a timestamped record of the exact commands
**and** a transcript of their results — ready to line up against the SentinelOne
alert timeline when validating correlation.

> Logs contain the plaintext commands (including tool names) and host/user/domain
> details, so `.\Logs\` is **git-ignored** and should stay inside the sandbox.

---

## Cleanup

Type `cleanup` at the menu to:

1. Remove the HKCU Run value `EDRTestPersist` (from option 8)
2. Delete the scheduled task `EDRTestTask` (from option 8)
3. Delete artifact files in `%TEMP%\EDRTest\` — `eicar_*.com`, `lsass_*.dmp`, and
   any leftover `*.ps1` (payloads now run via `-EncodedCommand`, so child scripts
   are no longer written; the `*.ps1` sweep remains for older artifacts)

`cleanup` runs inline in the parent process and is idempotent (safe to run when
nothing is present). It does **not** revert shadow-copy deletion/disabling — use
`enableshadow` for that.

---

## Artifacts location

Generated artifacts (EICAR downloads, LSASS dumps) live under the path below.
Payloads run via `-EncodedCommand`, so child scripts are **not** written here.

```
%TEMP%\EDRTest\
```

Removed by the `cleanup` command, or reset by restoring your VM snapshot.
