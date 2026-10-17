# Builds the installer artwork from assets/logo/halvard-mark-v2.svg: native\installer\art\halvard.ico, banner.bmp (493x58), dialog.bmp (493x312).
# Uses Microsoft Edge (headless) to rasterize the SVG and System.Drawing to compose the images. Nothing is downloaded.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
$root = Split-Path $PSScriptRoot -Parent
$art = Join-Path $root "native\installer\art"; New-Item -ItemType Directory -Force $art | Out-Null
$edge = (Get-Command msedge.exe -ErrorAction SilentlyContinue).Source
if (-not $edge) { $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" }
if (-not (Test-Path $edge)) { throw "Microsoft Edge not found (needed to rasterize the SVG)" }
$svg = (Get-Content (Join-Path $root "assets\logo\halvard-mark-v2.svg") -Raw) -replace '<\?xml[^>]*\?>', ''
$html = Join-Path $art "mark.html"
Set-Content $html "<!doctype html><html><body style='margin:0;background:#0b0b0e;width:512px;height:512px;overflow:hidden'><div style='width:512px;height:512px'>$svg</div></body></html>" -Encoding utf8
$png = Join-Path $art "mark512.png"; Remove-Item $png -ErrorAction SilentlyContinue
# Edge prints harmless "LoadEnclaveImageW failed" noise on stderr; Start-Process keeps it out of PowerShell's error stream
$args = @("--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1", "--window-size=512,512", "--screenshot=`"$png`"", "`"file:///$($html -replace '\\', '/')`"")
Start-Process $edge -ArgumentList $args -Wait -WindowStyle Hidden -RedirectStandardError (Join-Path $art "edge.err.txt") | Out-Null
for ($i = 0; $i -lt 40 -and -not (Test-Path $png); $i++) { Start-Sleep -Milliseconds 250 }
if (-not (Test-Path $png)) { throw "could not rasterize the logo" }
$mark = [System.Drawing.Image]::FromFile($png)

function Resize($img, $w, $h) {
  $b = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($b); $g.InterpolationMode = "HighQualityBicubic"; $g.SmoothingMode = "HighQuality"; $g.PixelOffsetMode = "HighQuality"
  $g.DrawImage($img, 0, 0, $w, $h); $g.Dispose(); $b
}

# ---- halvard.ico: PNG-compressed entries (supported since Windows Vista) ----
$sizes = 256, 64, 48, 32, 24, 16
$pngs = foreach ($s in $sizes) { $b = Resize $mark $s $s; $ms = New-Object System.IO.MemoryStream; $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $b.Dispose(); ,$ms.ToArray() }
$out = New-Object System.IO.MemoryStream; $w = New-Object System.IO.BinaryWriter $out
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $dim = if ($s -ge 256) { 0 } else { $s }
  $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0); $w.Write([uint16]1); $w.Write([uint16]32)
  $w.Write([uint32]$pngs[$i].Length); $w.Write([uint32]$offset); $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
[System.IO.File]::WriteAllBytes((Join-Path $art "halvard.ico"), $out.ToArray())

$gold = [System.Drawing.Color]::FromArgb(255, 201, 38); $dark = [System.Drawing.Color]::FromArgb(11, 11, 14); $white = [System.Drawing.Color]::White
function Canvas($w, $h) { $b = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb); $g = [System.Drawing.Graphics]::FromImage($b); $g.TextRenderingHint = "AntiAlias"; $g.SmoothingMode = "HighQuality"; $g.InterpolationMode = "HighQualityBicubic"; ,@($b, $g) }

# ---- banner.bmp 493x58 (top strip of the wizard pages) ----
$bg = Canvas 493 58; $b = $bg[0]; $g = $bg[1]
$g.Clear($dark)
$g.DrawImage($mark, 428, 4, 50, 50)
$f1 = New-Object System.Drawing.Font "Segoe UI", 16, ([System.Drawing.FontStyle]::Bold); $f2 = New-Object System.Drawing.Font "Segoe UI", 8.5
$g.DrawString("HALVARD GUARD", $f1, (New-Object System.Drawing.SolidBrush $gold), 12, 8)
$g.DrawString("Hold the line.", $f2, (New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(230, 200, 120))), 14, 34)
$g.Dispose(); $b.Save((Join-Path $art "banner.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp); $b.Dispose()

# ---- dialog.bmp 493x312 (welcome page: artwork on the left 164 px, white elsewhere) ----
$bg = Canvas 493 312; $b = $bg[0]; $g = $bg[1]
$g.Clear($white)
$g.FillRectangle((New-Object System.Drawing.SolidBrush $dark), 0, 0, 164, 312)
$g.DrawImage($mark, 7, 40, 150, 150)
$f3 = New-Object System.Drawing.Font "Segoe UI", 15, ([System.Drawing.FontStyle]::Bold); $f4 = New-Object System.Drawing.Font "Segoe UI", 8.5
$fmt = New-Object System.Drawing.StringFormat; $fmt.Alignment = "Center"
$g.DrawString("HALVARD", $f3, (New-Object System.Drawing.SolidBrush $gold), (New-Object System.Drawing.RectangleF 0, 200, 164, 30), $fmt)
$g.DrawString("Corporate Assurance Fabric", $f4, (New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(230, 200, 120))), (New-Object System.Drawing.RectangleF 0, 230, 164, 20), $fmt)
$g.Dispose(); $b.Save((Join-Path $art "dialog.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp); $b.Dispose()
$mark.Dispose()
Get-ChildItem $art | Where-Object { $_.Extension -in ".ico", ".bmp" } | Select-Object Name, Length
