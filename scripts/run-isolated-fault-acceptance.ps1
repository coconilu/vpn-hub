[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# The fetch helper verifies the repository lock before returning the executable.
# It downloads only when the pinned archive is absent or has the wrong hash.
& (Join-Path $PSScriptRoot 'fetch-mihomo.ps1') | Out-Null

Push-Location $repoRoot
try {
    cargo test -p vpn-hub-core --test dynamic_fault_acceptance isolated_dynamic_fault_runtime -- --ignored --exact --nocapture
    if ($LASTEXITCODE -ne 0) {
        throw "Isolated dynamic fault acceptance failed."
    }
}
finally {
    Pop-Location
}
