# Live test of the ETW guard. MUST be run from an elevated (Administrator) PowerShell.
# Four fake attackers. Three each touch their OWN decoy file (overwrite, delete, rename). The fourth is a ransomware-style burst on ordinary documents
# with NO decoy involved: it overwrites 16 documents with random bytes and must be frozen by the behavioral detector before it finishes.
# Each must be frozen. The guard runs with --debug so the real contents of delete/rename events are saved for review.
param([string]$Out = "$env:USERPROFILE\halvard-etw-smoke.txt")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root "native\halvard-svc\target\release\halvard-svc.exe"
if (-not (Test-Path $exe)) { throw "build first: cd native\halvard-svc; cargo build --release" }
$log = New-Object System.Collections.Generic.List[string]; $fail = 0
function Say($m) { $log.Add($m); Write-Host $m }
function Check($ok, $pass, $failmsg) { if ($ok) { Say "PASS: $pass" } else { Say "FAIL: $failmsg"; $script:fail++ } }
$procs = @(); $g = $null
try {
  $d = Join-Path $env:USERPROFILE "halvard-etw-smoke"; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $d | Out-Null
  $cases = @(
    @{ Name = "write";  Trap = "$d\!000-write.xlsx";  Act = "Set-Content '$d\!000-write.xlsx' (New-Guid)" },
    @{ Name = "delete"; Trap = "$d\!000-delete.xlsx"; Act = "Remove-Item '$d\!000-delete.xlsx' -Force" },
    @{ Name = "rename"; Trap = "$d\!000-rename.xlsx"; Act = "Rename-Item '$d\!000-rename.xlsx' '!000-rename.locked'" }
  )
  foreach ($c in $cases) { Set-Content $c.Trap "decoy"; $c.Tick = "$d\ticks-$($c.Name).txt" }
  # documents for the burst test: created BEFORE the guard starts, so it can remember what they looked like
  $docs = Join-Path $d "burst-docs"; New-Item -ItemType Directory $docs | Out-Null
  1..16 | ForEach-Object { Set-Content (Join-Path $docs ("report{0:D2}.txt" -f $_)) ("Meeting notes $_. " * 300) }
  & $exe stop | Out-Null
  $tw = ($cases | ForEach-Object { "`"$($_.Trap)`"" }) -join " "
  $g = Start-Process $exe -ArgumentList (@("guard") + ($cases | ForEach-Object { "`"$($_.Trap)`"" }) + @("--debug")) -PassThru -WindowStyle Hidden -RedirectStandardOutput "$d\guard_out.txt" -RedirectStandardError "$d\guard_err.txt"
  Start-Sleep 2
  if ($g.HasExited) { throw "guard did not start: $(Get-Content "$d\guard_err.txt" -Raw)" }
  foreach ($c in $cases) {
    $script = "`$i=0; while(`$true){ Add-Content '$($c.Tick)' 1; `$i++; if(`$i -eq 75){ $($c.Act) }; Start-Sleep -Milliseconds 20 }"
    $c.Proc = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $script -PassThru -WindowStyle Hidden
    $procs += $c.Proc
  }
  # the burst: overwrite each document with random bytes, 150 ms apart (about 2.4 s in all), no decoy involved. ETW delivers events up to about a
# second late, so a few files are lost before the freeze; the check is that the burst is frozen BEFORE it finishes.
  $burst = "`$r = New-Object Random 7; foreach(`$f in (Get-ChildItem '$docs' -Filter *.txt | Sort-Object Name)){ `$b = New-Object byte[] 4000; `$r.NextBytes(`$b); [IO.File]::WriteAllBytes(`$f.FullName, `$b); Start-Sleep -Milliseconds 150 }; Start-Sleep 30"
  $bp = Start-Process powershell -ArgumentList "-NoProfile", "-Command", $burst -PassThru -WindowStyle Hidden
  $procs += $bp
  Start-Sleep 7
  $out = Get-Content "$d\guard_out.txt" -Raw
  foreach ($c in $cases) {
    $s1 = (Get-Item $c.Tick).Length; Start-Sleep -Milliseconds 800; $s2 = (Get-Item $c.Tick).Length
    $hit = $out -match ('"pid":' + $c.Proc.Id + ',"process":"powershell.exe"[^}]*"frozen":true')
    Check ($s1 -eq $s2 -and $hit) "$($c.Name): attacker pid $($c.Proc.Id) frozen and logged (ticks stopped at $s1 bytes)" "$($c.Name): ticks $s1 -> $s2, alert for this pid: $hit"
  }
  $changed = @(Get-ChildItem $docs -Filter *.txt | Where-Object { -not ((Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -like "Meeting notes*") }).Count
  $bhit = $out -match ('"alert":"bulk_encryption","pid":' + $bp.Id + ',"process":"powershell.exe"[^}]*"frozen":true')
  Check ($bhit -and $changed -lt 16) "burst: ransomware-style attacker pid $($bp.Id) frozen by the behavioral detector after $changed of 16 documents were overwritten" "burst: alert for this pid: $bhit; documents overwritten: $changed of 16 (a Stage A limit applies, see docs/25)"
  Say "---- guard output (alerts and --debug dump of delete/rename/new-file events) ----"
  ($out -split "`n" | Select-Object -First 60) | ForEach-Object { Say $_ }
  Say ("RESULT: " + $(if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILED (send me this file)" }))
} catch {
  Say "ERROR: $($_.Exception.Message)"
} finally {
  foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
  if ($g -and -not $g.HasExited) { & $exe stop | Out-Null; Start-Sleep 1; if (-not $g.HasExited) { $g.Kill() } }
  $log | Set-Content $Out -Encoding utf8
  Write-Host "saved to $Out"
}
