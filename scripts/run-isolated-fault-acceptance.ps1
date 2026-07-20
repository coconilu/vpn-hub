[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# The fetch helper verifies the repository lock before returning the executable.
# It downloads only when the pinned archive is absent or has the wrong hash.
& (Join-Path $PSScriptRoot 'fetch-mihomo.ps1') | Out-Null

Push-Location $repoRoot
try {
    cargo test -p vpn-hub-core --test dynamic_fault_acceptance -- --ignored --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) {
        throw "One or more isolated fault acceptance scenarios failed."
    }
}
finally {
    Pop-Location
}
