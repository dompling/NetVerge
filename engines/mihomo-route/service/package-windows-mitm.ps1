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
$scripts = Join-Path $staging 'script-runner'
$null = New-Item -ItemType Directory -Path $worker, $service, $scripts

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
    foreach ($name in @('route-worker.cjs', 'rewrite-rules.cjs', 'url-regex.cjs', 'body-rewrite.cjs', 'local-response.cjs', 'ca-integrity.cjs', 'package.json')) {
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

    # Package only the trusted runner and runtime dependencies; no tests or
    # unreviewed workspace scripts. The runner is still not a live traffic hook.
    $runnerSource = Join-Path $SourceRoot 'engines/script-runner'
    foreach ($name in @('runner.cjs', 'package.json')) {
        Copy-Item -LiteralPath (Join-Path $runnerSource $name) -Destination $scripts
    }
    Copy-Item -LiteralPath (Join-Path $runnerSource 'windows-job/target/release/netverge-script-job.exe') -Destination $scripts
    Push-Location $scripts
    try {
        npm install --omit=dev --ignore-scripts --no-audit --no-fund --package-lock=false
        if ($LASTEXITCODE -ne 0) { throw 'QuickJS runtime dependency installation failed.' }
        $quickjs = Get-Content -LiteralPath 'node_modules/quickjs-emscripten/package.json' -Raw | ConvertFrom-Json
        if ($quickjs.version -ne '0.31.0') { throw 'Unexpected packaged QuickJS version.' }
    } finally {
        Pop-Location
    }

    $digests = [ordered]@{}
    foreach ($name in @(
        'NetVerge-MITM.exe', 'verge-mihomo.exe', 'verge-mihomo-alpha.exe',
        'service/clash-verge-service.exe', 'service/clash-verge-service-install.exe',
        'service/clash-verge-service-uninstall.exe', 'service/netverge-mihomo-service.exe',
        'worker/node.exe', 'worker/route-worker.cjs', 'worker/rewrite-rules.cjs', 'worker/url-regex.cjs', 'worker/body-rewrite.cjs', 'worker/local-response.cjs', 'worker/ca-integrity.cjs'
    )) {
        $digests[$name] = (Get-FileHash -LiteralPath (Join-Path $staging $name) -Algorithm SHA256).Hash
    }
    # Cover every packaged runner dependency, including WASM and JS loaders.
    foreach ($entry in Get-ChildItem -LiteralPath $scripts -Recurse -Force) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected runner reparse point.' }
        if ($entry.PSIsContainer) { continue }
        $relative = $entry.FullName.Substring($staging.Length + 1).Replace('\', '/')
        $digests[$relative] = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash
    }
    @{ revision = $env:GITHUB_SHA; sha256 = $digests } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $staging 'manifest.json')
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $Archive
} finally {
    Remove-Item -LiteralPath $staging -Force -Recurse
}
