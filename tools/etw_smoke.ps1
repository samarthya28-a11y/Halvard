# Live test of the ETW guard. MUST be run from an elevated (Administrator) PowerShell.
# Starts the guard on a decoy file, starts a fake attacker that overwrites it, and checks the attacker is frozen. Result is also written to $Out.
param([string]$Out = "$env:TEMP\halvard_etw_smoke.txt")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root "native\halvard-svc\target\release\halvard-svc.exe"
if (-not (Test-Path $exe)) { throw "build first: cd native\halvard-svc; cargo build --release" }
$log = New-Object System.Collections.Generic.List[string]
function Say($m) { $log.Add($m); Write-Host $m }
try {
  $d = Join-Path $env:USERPROFILE "halvard-etw-smoke"; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $d | Out-Null
  $trap = Join-Path $d "!000-budget.xlsx"; Set-Content $trap "decoy"
  $tick = Join-Path $d "attacker_ticks.txt"
  & $exe stop | Out-Null
  $g = Start-Process $exe -ArgumentList "guard", "`"$trap`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$d\guard_out.txt" -RedirectStandardError "$d\guard_err.txt"
  Start-Sleep 2
  if ($g.HasExited) { Say "FAIL: guard exited: $(Get-Content "$d\guard_err.txt" -Raw)"; throw "guard did not start" }
  # fake attacker: ticks to a file every 20 ms; after 1.5 s it overwrites the tripwire, then keeps ticking if it is still alive
  $script = "`$i=0; while(`$true){ Add-Content '$tick' 1; `$i++; if(`$i -eq 75){ Set-Content '$trap' (New-Guid) }; Start-Sleep -Milliseconds 20 }"
  $a = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $script -PassThru -WindowStyle Hidden
  Start-Sleep 6
  $size1 = (Get-Item $tick).Length; Start-Sleep 1; $size2 = (Get-Item $tick).Length
  Say ("attacker pid {0}; tick file {1} -> {2} bytes over 1 s" -f $a.Id, $size1, $size2)
  $alert = Get-Content "$d\guard_out.txt" -Raw
  Say "guard output: $alert"
  if ($size1 -eq $size2 -and $alert -match '"frozen":true') { Say "PASS: tripwire touched, attacker frozen (it stopped ticking)" } else { Say "FAIL: attacker still running or no freeze alert" }
} finally {
  Get-Process | Where-Object { $_.Id -eq $a.Id } | ForEach-Object { try { $_.Kill() } catch {} }
  if ($g -and -not $g.HasExited) { & $exe stop | Out-Null; Start-Sleep 1; if (-not $g.HasExited) { $g.Kill() } }
  $log | Set-Content $Out -Encoding utf8
}
