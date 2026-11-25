param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$PreviousCore
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:RUNNER_TEMP ('netverge-package-' + [guid]::NewGuid().ToString('N'))
$candidate = Join-Path $root 'candidate'
$previous = Join-Path $root 'previous'
$coreRelative = 'service/netverge-mihomo-service.exe'
$installed = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "clash-verge-service-dev/cores/netverge-mihomo-service.exe"
$developmentService = 'clash_verge_service_dev'

if ((Get-Service -Name $developmentService -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installed)) {
    throw 'The package test requires a clean development service installation.'
}

function Get-Digest([string]$File) {
    return (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
}

function Assert-Installed([string]$Digest) {
    if ((Get-Service -Name $developmentService).Status -ne 'Running' -or (Get-Digest $installed) -ne $Digest) {
        throw 'The running development service has the wrong approved core.'
    }
}

Expand-Archive -LiteralPath $Archive -DestinationPath $candidate
$candidateLauncher = Join-Path $candidate 'NetVerge-MITM.ps1'
$previousLauncher = Join-Path $previous 'NetVerge-MITM.ps1'
$candidateCore = Join-Path $candidate $coreRelative
$candidateDigest = Get-Digest $candidateCore
$previousDigest = Get-Digest $PreviousCore
if ($candidateDigest -eq $previousDigest) {
    throw 'Upgrade and rollback require two distinct core digests.'
}
$null = New-Item -ItemType Directory -Path $previous
Copy-Item (Join-Path $candidate 'service') $previous -Recurse
Copy-Item $candidateLauncher $previous
Copy-Item (Join-Path $candidate 'verge-mihomo.exe') $previous
Copy-Item -LiteralPath $PreviousCore -Destination (Join-Path $previous $coreRelative) -Force
$priorManifest = Get-Content (Join-Path $candidate 'manifest.json') -Raw | ConvertFrom-Json
$priorManifest.sha256."$coreRelative" = $previousDigest
ConvertTo-Json -InputObject $priorManifest -Depth 5 | Set-Content (Join-Path $previous 'manifest.json')

try {
    & $previousLauncher -Action Install
    Assert-Installed $previousDigest
    & $candidateLauncher -Action Install
    Assert-Installed $candidateDigest
    Write-Host 'PASS: extracted Windows package upgraded and verified the approved core'

    Copy-Item -LiteralPath $PreviousCore -Destination $candidateCore -Force
    try {
        & $candidateLauncher -Action Install
        throw 'Expected rejection of a mismatched archive payload.'
    } catch {
        if ($_.Exception.Message -notlike 'Package digest mismatch for *') { throw }
    }
    Assert-Installed $candidateDigest

    & $previousLauncher -Action Install
    Assert-Installed $previousDigest
    Write-Host 'PASS: digest mismatch preserved the upgrade and reinstalling the saved payload rolled back'
} finally {
    try {
        & $candidateLauncher -Action Uninstall
        if ((Get-Service -Name $developmentService -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installed)) {
            throw 'The package uninstaller left the development service or approved core behind.'
        }
        Write-Host 'PASS: extracted Windows package uninstalled the development service and approved core'
    } finally {
        Remove-Item -LiteralPath $root -Force -Recurse
    }
}
