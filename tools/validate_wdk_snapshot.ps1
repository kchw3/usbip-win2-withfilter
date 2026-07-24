param(
    [string] $Configuration = 'Release',
    [string] $Platform = 'x64',
    [switch] $StaticOnly
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DeviceCpp = Join-Path $RepoRoot 'drivers\ude\device.cpp'
$FilterCpp = Join-Path $RepoRoot 'drivers\ude\device_filter.cpp'
$PackageProject = Join-Path $RepoRoot 'drivers\package\package.vcxproj'

function Assert-Text {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Pattern,
        [Parameter(Mandatory)] [string] $Message
    )
    $text = Get-Content -Raw -LiteralPath $Path
    if ($text -notmatch $Pattern) {
        throw $Message
    }
}

Write-Host '[wdk-snapshot] checking descriptor snapshot source contract'
Assert-Text $DeviceCpp 'UdecxUsbDeviceInitAddDescriptor\s*\(' `
    'device.cpp must register the accepted device descriptor snapshot'
Assert-Text $DeviceCpp 'UdecxUsbDeviceInitAddDescriptorWithIndex\s*\(' `
    'device.cpp must register indexed configuration descriptor snapshots'
Assert-Text $DeviceCpp 'add_snapshot_descriptors\s*\(\s*init\.ptr,\s*ext\.descriptors\s*\)' `
    'device.cpp must add snapshot descriptors before UdecxUsbDeviceCreate'
Assert-Text $FilterCpp 'snapshot\.ready\s*=\s*true' `
    'device_filter.cpp must publish descriptor snapshots only after validation'

$deviceText = Get-Content -Raw -LiteralPath $DeviceCpp
$addIndex = $deviceText.IndexOf('add_snapshot_descriptors(init.ptr, ext.descriptors)')
$createIndex = $deviceText.IndexOf('UdecxUsbDeviceCreate(&init.ptr')
if ($addIndex -lt 0 -or $createIndex -lt 0 -or $addIndex -gt $createIndex) {
    throw 'descriptor snapshot registration must occur before UdecxUsbDeviceCreate'
}

if ($StaticOnly) {
    Write-Host '[wdk-snapshot] static checks passed'
    exit 0
}

function Find-MSBuild {
    $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $install = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($install) {
            $candidate = Join-Path $install 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }
    return $null
}

$msbuild = Find-MSBuild
if (!$msbuild) {
    throw 'MSBuild was not found. Run this on a Visual Studio/WDK build host.'
}

Write-Host "[wdk-snapshot] building package project with /WX via $msbuild"
& $msbuild $PackageProject `
    /m `
    /restore `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /p:TreatWarningsAsErrors=true `
    /p:WarningsAsErrors=true `
    /p:RunCodeAnalysis=true `
    /warnaserror

if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

Write-Host '[wdk-snapshot] WDK /WX build passed'
