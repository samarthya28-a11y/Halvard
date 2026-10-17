# Build dist\halvard-<version>-x64.msi. Needs: dotnet tool install --global wix --version 5.0.2 ; wix extension add -g WixToolset.Util.wixext/5.0.2
# Optional signing: -PfxPath cert.pfx -PfxPassword (env HALVARD_PFX_PASSWORD) uses signtool (Windows SDK). An unsigned MSI works but shows "Unknown publisher".
param([string]$PfxPath = "", [string]$TimestampUrl = "http://timestamp.digicert.com")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$env:Path += ";$env:USERPROFILE\.dotnet\tools;$env:USERPROFILE\.cargo\bin"
Set-Location $root
$ver = (python -c "import sys; sys.path.insert(0,'src'); import halvard; print(halvard.__version__)").Trim()
if ($ver -notmatch '^\d+\.\d+\.\d+$') { throw "version '$ver' is not a.b.c" }
Push-Location native\halvard-svc; cargo build --release; if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }; Pop-Location
$exe = Join-Path $root "native\halvard-svc\target\release\halvard-svc.exe"
New-Item -ItemType Directory -Force dist | Out-Null
$msi = Join-Path $root "dist\halvard-$ver-x64.msi"
wix build -arch x64 -ext WixToolset.Util.wixext -d Version=$ver -d ExePath=$exe native\installer\halvard.wxs -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
if ($PfxPath) {
  $st = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName | Select-Object -Last 1
  if (-not $st) { throw "signtool not found (install the Windows SDK)" }
  & $st.FullName sign /fd sha256 /tr $TimestampUrl /td sha256 /f $PfxPath /p $env:HALVARD_PFX_PASSWORD $msi
  if ($LASTEXITCODE -ne 0) { throw "signing failed" }
}
Get-Item $msi | Select-Object Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 2) } }
