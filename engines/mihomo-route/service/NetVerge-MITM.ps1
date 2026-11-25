param(
    [ValidateSet('Install', 'Run', 'Uninstall')][string]$Action = 'Run',
    [string]$Bootstrap
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$serviceDirectory = Join-Path $PSScriptRoot 'service'
$manifest = Get-Content (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
$coreName = 'netverge-mihomo-service.exe'

function Get-VerifiedFile([string]$RelativePath) {
    $expected = $manifest.sha256."$RelativePath"
    if ($expected -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Missing package digest for $RelativePath"
    }
    $file = Join-Path $PSScriptRoot $RelativePath
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected) {
        throw "Package digest mismatch for $RelativePath"
    }
    return $file
}

switch ($Action) {
    'Install' {
        if (Get-Process -Name 'netverge-mihomo-service' -ErrorAction SilentlyContinue) {
            throw 'Close NetVerge or stop its MITM service core before changing the installed version.'
        }
        $installer = Get-VerifiedFile 'service/clash-verge-service-install.exe'
        $null = Get-VerifiedFile 'service/clash-verge-service.exe'
        $core = Get-VerifiedFile "service/$coreName"
        $sidecar = Get-VerifiedFile 'verge-mihomo.exe'
        & $installer --prepare-install --ensure --core verge-mihomo.exe $sidecar --core $coreName $core
        if ($LASTEXITCODE -ne 0) {
            throw "The development service installer returned exit code $LASTEXITCODE."
        }
    }
    'Run' {
        $desktop = Get-VerifiedFile 'NetVerge-MITM.exe'
        $env:CLASH_VERGE_DEV_SERVICE_DIR = $serviceDirectory
        if ($Bootstrap) {
            $null = Get-VerifiedFile "service/$coreName"
            $node = Get-VerifiedFile 'worker/node.exe'
            $worker = Get-VerifiedFile 'worker/route-worker.cjs'
            $null = Get-VerifiedFile 'worker/ca-integrity.cjs'
            $configPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Bootstrap)
            if (!(Test-Path -LiteralPath $configPath)) {
                $config = @{ node = $node; worker = $worker; hosts = @() }
                New-Item -ItemType File -Path $configPath -Value (ConvertTo-Json -InputObject $config) | Out-Null
            }
            $env:NETVERGE_MITM_ROUTE_DEV_CONFIG = $configPath
            $env:NETVERGE_MITM_SERVICE_CORE_SHA256 = $manifest.sha256."service/$coreName"
        }
        Start-Process -FilePath $desktop -WorkingDirectory $PSScriptRoot
    }
    'Uninstall' {
        $uninstaller = Get-VerifiedFile 'service/clash-verge-service-uninstall.exe'
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            & $uninstaller
            $exitCode = $LASTEXITCODE
        } else {
            $exitCode = (Start-Process -FilePath $uninstaller -Verb RunAs -Wait -PassThru).ExitCode
        }
        if ($exitCode -ne 0) {
            throw "The development service uninstaller returned exit code $exitCode."
        }
    }
}
