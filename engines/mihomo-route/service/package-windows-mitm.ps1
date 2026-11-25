param(
    [Parameter(Mandatory)][string]$Components,
    [Parameter(Mandatory)][string]$Desktop,
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$Archive
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$staging = Join-Path $env:RUNNER_TEMP ('netverge-payload-' + [guid]::NewGuid().ToString('N'))
$worker = Join-Path $staging 'worker'
$service = Join-Path $staging 'service'
$null = New-Item -ItemType Directory -Path $worker, $service

try {
    Copy-Item -LiteralPath $Desktop -Destination (Join-Path $staging 'NetVerge-MITM.exe')
    Copy-Item (Join-Path $Components 'verge-mihomo.exe') $staging
    Copy-Item (Join-Path $SourceRoot 'src-tauri/sidecar/verge-mihomo-alpha-x86_64-pc-windows-msvc.exe') (Join-Path $staging 'verge-mihomo-alpha.exe')
    Copy-Item (Join-Path $SourceRoot 'src-tauri/resources') $staging -Recurse
    Get-ChildItem (Join-Path $staging 'resources') -Filter 'clash-verge-service*' | Remove-Item -Force -Recurse
    foreach ($name in @('clash-verge-service.exe', 'clash-verge-service-install.exe', 'clash-verge-service-uninstall.exe', 'netverge-mihomo-service.exe')) {
        Copy-Item (Join-Path $Components $name) $service
    }
    Copy-Item (Join-Path $SourceRoot 'LICENSE') $staging
    Copy-Item (Join-Path $PSScriptRoot 'NetVerge-MITM.ps1') $staging
    Copy-Item (Join-Path $PSScriptRoot 'windows-test-package.md') (Join-Path $staging 'README.md')

    $node = (Get-Command node).Source
    Copy-Item -LiteralPath $node -Destination (Join-Path $worker 'node.exe')
    Copy-Item (Join-Path (Split-Path $node) 'LICENSE') (Join-Path $worker 'NODE-LICENSE')
    foreach ($name in @('route-worker.cjs', 'ca-integrity.cjs', 'package.json')) {
        Copy-Item (Join-Path $SourceRoot "engines/whistle/$name") $worker
    }
    Push-Location $worker
    try {
        npm install --omit=dev --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "Whistle package installation failed with exit code $LASTEXITCODE." }
        node -e "if(require('whistle/package.json').version!=='2.10.15')process.exit(1)"
        if ($LASTEXITCODE -ne 0) { throw 'The packaged Whistle version does not match the tested worker.' }
    } finally {
        Pop-Location
    }

    $digests = [ordered]@{}
    foreach ($name in @(
        'NetVerge-MITM.exe', 'verge-mihomo.exe', 'verge-mihomo-alpha.exe',
        'service/clash-verge-service.exe', 'service/clash-verge-service-install.exe',
        'service/clash-verge-service-uninstall.exe', 'service/netverge-mihomo-service.exe',
        'worker/node.exe', 'worker/route-worker.cjs', 'worker/ca-integrity.cjs'
    )) {
        $digests[$name] = (Get-FileHash -LiteralPath (Join-Path $staging $name) -Algorithm SHA256).Hash
    }
    @{ revision = $env:GITHUB_SHA; sha256 = $digests } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $staging 'manifest.json')
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $Archive
} finally {
    Remove-Item -LiteralPath $staging -Force -Recurse
}
