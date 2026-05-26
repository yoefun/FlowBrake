param(
    [string]$Configuration = "release",
    [string]$PackageRoot = "dist",
    [string]$Version = "",
    [string]$PackageName = "FlowBrake-windows-x64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$targetDir = Join-Path $repoRoot "target\$Configuration"
$binaryPath = Join-Path $targetDir "flowbrake-ui.exe"

if (-not (Test-Path -LiteralPath $binaryPath)) {
    throw "Missing release binary: $binaryPath. Run cargo build -p flowbrake-ui --release first."
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $metadata = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
    $uiPackage = $metadata.packages | Where-Object { $_.name -eq "flowbrake-ui" } | Select-Object -First 1
    if ($null -eq $uiPackage) {
        throw "Unable to find flowbrake-ui in cargo metadata."
    }
    $Version = $uiPackage.version
}

$distRoot = Join-Path $repoRoot $PackageRoot
$stageDir = Join-Path $distRoot $PackageName
$archivePath = Join-Path $distRoot "$PackageName-v$Version.zip"
$checksumPath = "$archivePath.sha256"

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
if (Test-Path -LiteralPath $stageDir) {
    Remove-Item -LiteralPath $stageDir -Recurse -Force
}
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
if (Test-Path -LiteralPath $checksumPath) {
    Remove-Item -LiteralPath $checksumPath -Force
}
New-Item -ItemType Directory -Path $stageDir | Out-Null

$files = @(
    @{ Source = $binaryPath; Destination = "FlowBrake.exe" },
    @{ Source = (Join-Path $targetDir "WinDivert.dll"); Destination = "WinDivert.dll" },
    @{ Source = (Join-Path $targetDir "WinDivert64.sys"); Destination = "WinDivert64.sys" },
    @{ Source = (Join-Path $repoRoot "README.md"); Destination = "README.md" },
    @{ Source = (Join-Path $repoRoot "LICENSE"); Destination = "LICENSE" }
)

foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file.Source)) {
        throw "Missing package input: $($file.Source)"
    }
    Copy-Item -LiteralPath $file.Source -Destination (Join-Path $stageDir $file.Destination)
}

Compress-Archive -LiteralPath $stageDir -DestinationPath $archivePath -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $(Split-Path -Leaf $archivePath)" | Set-Content -LiteralPath $checksumPath -Encoding ascii

Write-Host "Created $archivePath"
Write-Host "Created $checksumPath"

if ($env:GITHUB_OUTPUT) {
    $archiveOutput = Join-Path $PackageRoot "$PackageName-v$Version.zip"
    $checksumOutput = "$archiveOutput.sha256"
    "archive_path=$archiveOutput" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "checksum_path=$checksumOutput" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "version=$Version" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
