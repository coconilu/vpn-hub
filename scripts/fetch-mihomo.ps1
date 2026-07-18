[CmdletBinding()]
param(
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $repoRoot '.tools\mihomo'
}

$lockPath = Join-Path $repoRoot 'tools\mihomo.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
$versionDirectory = Join-Path $Destination $lock.version
$archivePath = Join-Path $Destination $lock.asset
$expectedHash = $lock.sha256.ToLowerInvariant()

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
New-Item -ItemType Directory -Path $versionDirectory -Force | Out-Null

$needsDownload = -not (Test-Path -LiteralPath $archivePath)
if (-not $needsDownload) {
    $existingHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $needsDownload = $existingHash -ne $expectedHash
}

if ($needsDownload) {
    Invoke-WebRequest -Uri $lock.url -OutFile $archivePath
}

$archive = Get-Item -LiteralPath $archivePath
if ($archive.Length -ne [long]$lock.size) {
    throw "Mihomo archive size mismatch. Expected $($lock.size), got $($archive.Length)."
}
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Mihomo SHA-256 mismatch. Expected $expectedHash, got $actualHash."
}

$existingExecutable = Get-ChildItem -LiteralPath $versionDirectory -Filter 'mihomo*.exe' -File -ErrorAction SilentlyContinue
if (@($existingExecutable).Count -eq 0) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $versionDirectory -Force
    $existingExecutable = Get-ChildItem -LiteralPath $versionDirectory -Filter 'mihomo*.exe' -File
}
if (@($existingExecutable).Count -ne 1) {
    throw "Expected exactly one Mihomo executable in $versionDirectory."
}

$result = [pscustomobject]@{
    Version = $lock.version
    Executable = $existingExecutable[0].FullName
    Sha256 = $actualHash
}
$result
