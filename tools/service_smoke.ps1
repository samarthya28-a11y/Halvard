# Live test of the Halvard Guard Windows service. MUST be run from an elevated (Administrator) PowerShell.
# Steps: install -> start -> fake attacker touches the decoy and is frozen -> kill the service and check it restarts itself -> stop -> uninstall.
# Result is printed and also saved to $Out (default: your profile folder).
param([string]$Out = "$env:USERPROFILE\halvard-service-smoke.txt")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root "native\halvard-svc\target\release\halvard-svc.exe"
if (-not (Test-Path $exe)) { throw "build first: cd native\halvard-svc; cargo build --release" }
$log = New-Object System.Collections.Generic.List[string]
$fail = 0
# Native stderr must not abort the script under -ErrorAction Stop (Windows PowerShell 5.1 turns it into an exception): run the exe with errors relaxed and return its text.
function Svc { $q = ($args | ForEach-Object { '"' + $_ + '"' }) -join ' '; $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"; try { (cmd /c "`"$exe`" $q 2>&1" | Out-String).Trim() } finally { $ErrorActionPreference = $old } }
function Say($m) { $log.Add($m); Write-Host $m }
function Check($ok, $pass, $failmsg) { if ($ok) { Say "PASS: $pass" } else { Say "FAIL: $failmsg"; $script:fail++ } }
$a = $null
try {
  $d = Join-Path $env:USERPROFILE "halvard-svc-smoke"; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $d | Out-Null
  $trap = Join-Path $d "!000-budget.xlsx"; Set-Content $trap "decoy"
  $tick = Join-Path $d "ticks.txt"
  $guardLog = "$env:ProgramData\Halvard\guard.log"; Remove-Item $guardLog -ErrorAction SilentlyContinue

  Svc service uninstall | Out-Null   # clean slate if an old install exists
  Say (Svc service install --tripwire $trap)
  $cfg = sc.exe qc HalvardGuard | Out-String
  Check ($cfg -match "AUTO_START" -and $cfg -match "LocalSystem") "service is auto-start, LocalSystem" "unexpected service config: $cfg"
  $fa = sc.exe qfailure HalvardGuard | Out-String
  Check ($fa -match "RESTART") "failure actions include RESTART" "failure actions missing: $fa"
  Check (Test-Path "$env:ProgramFiles\Halvard\halvard-svc.exe") "binary copied to Program Files" "binary not in Program Files"

  Say ("start: " + (Svc service start))
  Start-Sleep 2
  Check ((Svc service status) -match "Running") "service reports Running" "service not running"

  $script = "`$i=0; while(`$true){ Add-Content '$tick' 1; `$i++; if(`$i -eq 75){ Set-Content '$trap' (New-Guid) }; Start-Sleep -Milliseconds 20 }"
  $a = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $script -PassThru -WindowStyle Hidden
  Start-Sleep 6
  $s1 = (Get-Item $tick).Length; Start-Sleep 1; $s2 = (Get-Item $tick).Length
  $alerts = if (Test-Path $guardLog) { Get-Content $guardLog -Raw } else { "" }
  Check ($s1 -eq $s2 -and $alerts -match '"frozen":true') "service froze the attacker (ticks stopped at $s1 bytes) and logged it" "attacker not frozen or no alert in $guardLog. log: $alerts"

  $before = (Get-CimInstance Win32_Service -Filter "Name='HalvardGuard'").ProcessId
  Stop-Process -Id $before -Force
  Say "killed service process $before; waiting for the service manager to restart it"
  $new = 0
  for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; $new = (Get-CimInstance Win32_Service -Filter "Name='HalvardGuard'").ProcessId; if ($new -ne 0 -and $new -ne $before) { break } }
  Check ($new -ne 0 -and $new -ne $before) "service restarted itself (new pid $new)" "service did not restart after being killed"

  Say ("stop: " + (Svc service stop))
  Check ((Svc service status) -match "Stopped") "service stops cleanly" "service did not stop"
  Say (Svc service uninstall)
  Start-Sleep 1
  $gone = (sc.exe query HalvardGuard 2>&1 | Out-String) -match "1060"
  Check $gone "service removed" "service still present"
  Check (-not (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object DisplayName -like "*Halvard*")) "no firewall or other system settings were changed" "unexpected firewall rule"
  Say ("RESULT: " + $(if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILED" }))
} catch {
  Say "ERROR: $($_.Exception.Message)"
} finally {
  if ($a) { try { Stop-Process -Id $a.Id -Force -ErrorAction SilentlyContinue } catch {} }
  try { Svc service uninstall | Out-Null } catch {}
  $log | Set-Content $Out -Encoding utf8
  Write-Host "saved to $Out"
}
