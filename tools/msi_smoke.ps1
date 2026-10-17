# Live test of the Halvard Guard MSI. MUST be run from an elevated (Administrator) PowerShell.
# Installs silently with decoys in a throw-away folder (your real Documents folders are NOT touched), checks the service and decoys,
# lets a fake attacker touch a decoy (must be frozen), upgrades over itself, uninstalls, and checks everything was removed and a real file was left alone.
# Result is printed and saved to $Out.
param([string]$Out = "$env:USERPROFILE\halvard-msi-smoke.txt")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$msi = Get-ChildItem (Join-Path $root "dist\halvard-*-x64.msi") | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $msi) { throw "build first: powershell -File tools\build_msi.ps1" }
$log = New-Object System.Collections.Generic.List[string]; $fail = 0
function Say($m) { $log.Add($m); Write-Host $m }
function Check($ok, $pass, $failmsg) { if ($ok) { Say "PASS: $pass" } else { Say "FAIL: $failmsg"; $script:fail++ } }
function Msi($args) { $p = Start-Process msiexec -ArgumentList $args -Wait -PassThru; $p.ExitCode }
$a = $null
try {
  Say "package: $($msi.Name)"
  $d = Join-Path $env:USERPROFILE "halvard-msi-smoke"; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $d | Out-Null
  Set-Content (Join-Path $d "my-real-report.docx") "real work"
  $trap = Join-Path $d "!000-budget-draft.xlsx"; $tick = Join-Path $d "ticks.txt"
  $ilog = Join-Path $env:USERPROFILE "halvard-msi-install.log"

  $code = Msi "/i `"$($msi.FullName)`" /qn /l*v `"$ilog`" TRIPWIREDIRS=`"$d`""
  Check ($code -eq 0) "silent install exit code 0" "install exit code $code (see $ilog)"
  $qc = sc.exe qc HalvardGuard | Out-String
  Check ($qc -match "AUTO_START" -and $qc -match "DELAYED" -and $qc -match "LocalSystem") "service auto-start (delayed), LocalSystem" "service config: $qc"
  Check ((sc.exe qfailure HalvardGuard | Out-String) -match "RESTART") "restart-on-failure actions present" "no failure actions"
  Check ((sc.exe query HalvardGuard | Out-String) -match "RUNNING") "service is running right after install" "service not running"
  Check (Test-Path "$env:ProgramFiles\Halvard\halvard-svc.exe") "binary in Program Files" "binary missing"
  Check ((Test-Path $trap) -and ((Get-Content (Join-Path $d "my-real-report.docx") -Raw).Trim() -eq "real work")) "decoys placed, real file untouched" "decoy missing or real file changed"

  $script = "`$i=0; while(`$true){ Add-Content '$tick' 1; `$i++; if(`$i -eq 75){ Set-Content '$trap' (New-Guid) }; Start-Sleep -Milliseconds 20 }"
  $a = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $script -PassThru -WindowStyle Hidden
  Start-Sleep 6
  $s1 = (Get-Item $tick).Length; Start-Sleep 1; $s2 = (Get-Item $tick).Length
  $alerts = if (Test-Path "$env:ProgramData\Halvard\guard.log") { Get-Content "$env:ProgramData\Halvard\guard.log" -Raw } else { "" }
  Check ($s1 -eq $s2 -and $alerts -match '"frozen":true') "attacker frozen and logged" "attacker not frozen (ticks $s1 -> $s2)"
  Stop-Process -Id $a.Id -Force -ErrorAction SilentlyContinue; $a = $null

  $code = Msi "/i `"$($msi.FullName)`" /qn /l*v `"$env:USERPROFILE\halvard-msi-upgrade.log`" TRIPWIREDIRS=`"$d`""
  Check ($code -eq 0 -and (sc.exe query HalvardGuard | Out-String) -match "RUNNING") "re-install over itself works, service still running" "re-install exit $code"

  $code = Msi "/x `"$($msi.FullName)`" /qn /l*v `"$env:USERPROFILE\halvard-msi-uninstall.log`""
  Check ($code -eq 0) "silent uninstall exit code 0" "uninstall exit code $code"
  Start-Sleep 2
  Check ((sc.exe query HalvardGuard 2>&1 | Out-String) -match "1060") "service removed" "service still present"
  Check (-not (Test-Path "$env:ProgramFiles\Halvard\halvard-svc.exe")) "binary removed" "binary still there"
  Check (-not (Test-Path (Join-Path $d "!000-budget-draft.xlsx")) -or ((Get-Content $trap -Raw) -notmatch "Reference")) "decoy removed (or it had been changed by the attacker, so it was kept as 'not ours')" "decoy still there unchanged"
  Check ((Get-Content (Join-Path $d "my-real-report.docx") -Raw).Trim() -eq "real work") "real file still untouched after uninstall" "real file damaged"
  Check (-not (Test-Path "$env:ProgramData\Halvard\service.json")) "config removed" "config left behind"
  Say ("RESULT: " + $(if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILED" }))
} catch {
  Say "ERROR: $($_.Exception.Message)"
} finally {
  if ($a) { try { Stop-Process -Id $a.Id -Force -ErrorAction SilentlyContinue } catch {} }
  if ((sc.exe query HalvardGuard 2>&1 | Out-String) -notmatch "1060") { Say "cleanup: removing the package"; Start-Process msiexec -ArgumentList "/x `"$($msi.FullName)`" /qn" -Wait | Out-Null }
  $log | Set-Content $Out -Encoding utf8
  Write-Host "saved to $Out"
}
