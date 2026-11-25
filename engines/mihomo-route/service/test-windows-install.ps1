param(
    [Parameter(Mandatory)][string]$BuildDirectory,
    [Parameter(Mandatory)][string]$GuardedCore,
    [Parameter(Mandatory)][string]$Worker
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$serviceName = 'clash_verge_service_dev'
$stateRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'clash-verge-service-dev'
$coreDirectory = Join-Path $stateRoot 'cores'
$coreName = 'netverge-mihomo-service.exe'
$installedCore = Join-Path $coreDirectory $coreName
$installer = Join-Path $BuildDirectory 'clash-verge-service-install.exe'
$uninstaller = Join-Path $BuildDirectory 'clash-verge-service-uninstall.exe'
$corePath = (Resolve-Path -LiteralPath $GuardedCore).Path

if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $stateRoot)) {
    throw 'The isolated development service or its state directory already exists'
}

$expectedDigest = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash
$fixtureDirectory = Join-Path $env:RUNNER_TEMP ('netverge-install-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixtureDirectory
$rejectedCore = Join-Path $fixtureDirectory $coreName
$installAttempted = $false
try {
    # The installer reports success only after IPC verifies the LocalSystem
    # service digest and the SHA-256 of the protected approved core.
    $installAttempted = $true
    & $installer --prepare-install --core $coreName $corePath
    if ($LASTEXITCODE -ne 0) {
        throw "Development service installation or inspection failed with exit code $LASTEXITCODE"
    }
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        throw 'The Windows development service is not running'
    }
    if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash -ne $expectedDigest) {
        throw 'The installed guarded core differs from the CI build'
    }
    foreach ($name in @('verge-mihomo.exe', 'verge-mihomo-alpha.exe')) {
        if (Test-Path -LiteralPath (Join-Path $coreDirectory $name)) {
            throw "Dedicated installation wrote to the standard core slot $name"
        }
    }
    Write-Host 'PASS: installed Windows development service verified its dedicated guarded core and service digest'

    Set-Content -LiteralPath $rejectedCore -Value 'Intentionally different fixture bytes'
    $output = (& $installer --install-core $rejectedCore --sha256 $expectedDigest 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0 -or $output -notmatch 'does not match the attested sha256') {
        throw "The installer did not report the expected SHA-256 refusal: $output"
    }
    if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash -ne $expectedDigest) {
        throw 'Rejected core bytes changed the approved copy'
    }
    Write-Host 'PASS: a digest mismatch leaves the approved guarded core intact'

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerRoot = Join-Path $fixtureDirectory 'owner'
    $null = New-Item -ItemType Directory -Path $ownerRoot
    $directoryAcl = Get-Acl -LiteralPath $ownerRoot
    $directoryAcl.SetOwner($identity)
    Set-Acl -LiteralPath $ownerRoot -AclObject $directoryAcl
    $tokenPath = Join-Path $ownerRoot '.clash-verge-service-owner-token'
    $token = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    [IO.File]::WriteAllBytes($tokenPath, $token)
    $tokenAcl = [Security.AccessControl.FileSecurity]::new()
    $tokenAcl.SetOwner($identity)
    $tokenAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $principal = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($principal, 'FullControl', 'Allow')
        $tokenAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $tokenPath -AclObject $tokenAcl

    $manifest = Join-Path $PSScriptRoot 'rust-lab/Cargo.toml'
    cargo run --locked --manifest-path $manifest --no-default-features --features installed-service -- $installedCore $Worker $identity.Value $ownerRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Installed service recovery scenario failed with exit code $LASTEXITCODE"
    }
} finally {
    try {
        if ($installAttempted) {
            & $uninstaller
            if ($LASTEXITCODE -ne 0) {
                throw "Development service uninstaller failed with exit code $LASTEXITCODE"
            }
            if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installedCore)) {
                throw 'The development service or its approved guarded core survived uninstall'
            }
            Write-Host 'PASS: Windows development service and approved guarded core removed'
        }
    } finally {
        Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
    }
}
