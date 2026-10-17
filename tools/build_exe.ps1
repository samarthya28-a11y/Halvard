# Build a single-file halvard.exe. Needs: py -m pip install pyinstaller (build machine only; the exe itself needs nothing).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$ver = (python -c "import sys; sys.path.insert(0,'src'); import halvard; print(halvard.__version__)")
python -m PyInstaller --noconfirm --clean --onefile --name halvard --paths src --paths tests `
  --hidden-import helpers --collect-submodules halvard `
  --exclude-module tkinter --exclude-module unittest.mock --exclude-module pydoc --exclude-module test `
  --add-data "$root\policy;policy" --add-data "$root\src\halvard\graph;halvard\graph" --distpath dist --workpath build\pyi --specpath build `
  src\halvard\launcher.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Copy-Item dist\halvard.exe "dist\halvard-$ver.exe"
Get-Item dist\halvard*.exe | Select-Object Name, @{n="MB";e={[math]::Round($_.Length/1MB,1)}}
