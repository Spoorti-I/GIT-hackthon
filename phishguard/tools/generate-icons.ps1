# PhishGuard Icon Generator
# Generates PNG icons at 16x32x48x128 sizes using .NET Graphics
# Run from the phishguard directory

Add-Type -AssemblyName System.Drawing

$sizes = @(16, 32, 48, 128)
$iconsDir = "$PSScriptRoot\assets\icons"

if (-not (Test-Path $iconsDir)) {
    New-Item -ItemType Directory -Path $iconsDir -Force | Out-Null
}

foreach ($size in $sizes) {
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $gfx    = [System.Drawing.Graphics]::FromImage($bitmap)
    $gfx.SmoothingMode    = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $gfx.CompositingMode  = [System.Drawing.Drawing2D.CompositingMode]::SourceOver

    # Transparent background
    $gfx.Clear([System.Drawing.Color]::Transparent)

    $f    = $size / 128.0
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath

    # Shield points (scaled from 128px base)
    $pts = @(
        [System.Drawing.PointF]::new(64 * $f, 8  * $f),
        [System.Drawing.PointF]::new(16 * $f, 28 * $f),
        [System.Drawing.PointF]::new(16 * $f, 64 * $f),
        [System.Drawing.PointF]::new(64 * $f, 120* $f),
        [System.Drawing.PointF]::new(112* $f, 64 * $f),
        [System.Drawing.PointF]::new(112* $f, 28 * $f)
    )
    $path.AddPolygon($pts)

    # Gradient fill
    $gradBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        [System.Drawing.PointF]::new(0, 0),
        [System.Drawing.PointF]::new($size, $size),
        [System.Drawing.Color]::FromArgb(255, 99, 102, 241),    # indigo
        [System.Drawing.Color]::FromArgb(255, 139, 92, 246)     # purple
    )
    $gfx.FillPath($gradBrush, $path)

    # Checkmark
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [float]([Math]::Max(2, $size / 16)))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round

    $checkPts = @(
        [System.Drawing.PointF]::new(42 * $f, 64 * $f),
        [System.Drawing.PointF]::new(58 * $f, 80 * $f),
        [System.Drawing.PointF]::new(86 * $f, 50 * $f)
    )
    $gfx.DrawLines($pen, $checkPts)

    # Save
    $outPath = "$iconsDir\icon${size}.png"
    $bitmap.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host "Generated: $outPath"

    $gfx.Dispose()
    $bitmap.Dispose()
    $gradBrush.Dispose()
    $pen.Dispose()
    $path.Dispose()
}

Write-Host "`nAll icons generated successfully in: $iconsDir" -ForegroundColor Green
