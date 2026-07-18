[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot 'config\mihomo\development.yaml'
$runtimePath = Join-Path $repoRoot '.tools\mihomo\runtime'

$protectedListener = Get-NetTCPConnection -State Listen -LocalPort 6666 -ErrorAction Stop |
    Select-Object -First 1
$protectedOwnerBefore = $protectedListener.OwningProcess
if (Get-NetTCPConnection -State Listen -LocalPort 36666 -ErrorAction SilentlyContinue) {
    throw 'Development port 36666 is already occupied.'
}

$info = & (Join-Path $PSScriptRoot 'fetch-mihomo.ps1')
New-Item -ItemType Directory -Path $runtimePath -Force | Out-Null
& $info.Executable -t -d $runtimePath -f $configPath
if ($LASTEXITCODE -ne 0) {
    throw 'Mihomo configuration validation failed.'
}

Write-Output "Starting Mihomo $($info.Version) on development port 36666. Press Ctrl+C to stop."
try {
    & $info.Executable -d $runtimePath -f $configPath
}
finally {
    $protectedOwnerAfter = (Get-NetTCPConnection -State Listen -LocalPort 6666 -ErrorAction Stop |
        Select-Object -First 1).OwningProcess
    if ($protectedOwnerAfter -ne $protectedOwnerBefore) {
        throw 'Protected port 6666 changed owner while the development core was running.'
    }
}
