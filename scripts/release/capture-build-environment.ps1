param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"
$source = (Resolve-Path -LiteralPath $SourceRoot).Path

function Invoke-Version([string]$Command, [string[]]$Arguments) {
    $output = & $Command @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "failed to capture version from $Command" }
    return $output.Trim()
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw "vswhere.exe is unavailable" }
$vsRoot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if ([string]::IsNullOrWhiteSpace($vsRoot)) { throw "MSVC x64 tools are unavailable" }
$vcVersion = (Get-Content -Raw -LiteralPath (Join-Path $vsRoot "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt")).Trim()
$vcBin = Join-Path $vsRoot "VC\Tools\MSVC\$vcVersion\bin\Hostx64\x64"
$cl = Join-Path $vcBin "cl.exe"
$link = Join-Path $vcBin "link.exe"
if (-not (Test-Path -LiteralPath $cl -PathType Leaf) -or -not (Test-Path -LiteralPath $link -PathType Leaf)) {
    throw "MSVC cl.exe/link.exe are unavailable"
}

$kitsRoot = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots").KitsRoot10
$sdkVersion = Get-ChildItem -LiteralPath (Join-Path $kitsRoot "Include") -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "um\Windows.h") -PathType Leaf } |
    Sort-Object { [version]$_.Name.TrimEnd("\") } -Descending |
    Select-Object -First 1 -ExpandProperty Name
if ([string]::IsNullOrWhiteSpace($sdkVersion)) { throw "Windows SDK is unavailable" }
$rc = Join-Path $kitsRoot "bin\$sdkVersion\x64\rc.exe"
if (-not (Test-Path -LiteralPath $rc -PathType Leaf)) { throw "Windows SDK rc.exe is unavailable" }

$makensisCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} "NSIS\makensis.exe"),
    (Join-Path $env:ProgramFiles "NSIS\makensis.exe")
)
foreach ($root in @((Join-Path $env:LOCALAPPDATA "tauri"), (Join-Path $env:USERPROFILE ".cache\tauri"))) {
    if (Test-Path -LiteralPath $root -PathType Container) {
        $makensisCandidates += Get-ChildItem -LiteralPath $root -Filter makensis.exe -File -Recurse |
            Select-Object -ExpandProperty FullName
    }
}
$makensis = $makensisCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($makensis)) { throw "makensis.exe is unavailable after the NSIS build" }

$tauri = Join-Path $source "apps\desktop\node_modules\.bin\tauri.cmd"
if (-not (Test-Path -LiteralPath $tauri -PathType Leaf)) { throw "the pinned local Tauri CLI is unavailable" }

$evidence = [ordered]@{
    schema_version = 1
    runner = [ordered]@{
        image_os = $env:ImageOS
        image_version = $env:ImageVersion
    }
    msvc = [ordered]@{
        tools_version = $vcVersion
        cl_product_version = (Get-Item -LiteralPath $cl).VersionInfo.ProductVersion
        link_product_version = (Get-Item -LiteralPath $link).VersionInfo.ProductVersion
    }
    windows_sdk = [ordered]@{
        version = $sdkVersion
        rc_product_version = (Get-Item -LiteralPath $rc).VersionInfo.ProductVersion
    }
    nsis = [ordered]@{
        version = Invoke-Version $makensis @("/VERSION")
    }
    rust = Invoke-Version "rustc" @("--version", "--verbose")
    cargo = Invoke-Version "cargo" @("--version", "--verbose")
    node = Invoke-Version "node" @("--version")
    npm = Invoke-Version "npm" @("--version")
    tauri = Invoke-Version $tauri @("--version")
}

$parent = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
$json = $evidence | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false))
