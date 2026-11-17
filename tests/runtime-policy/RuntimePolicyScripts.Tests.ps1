#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$temporaryRoot = Join-Path $env:TEMP ('UtoAegis.RuntimePolicy.ScriptTests.' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $guardBuild = Join-Path $repositoryRoot 'src/UtoAegis.Guard/bin/Release/net10.0'
    $guardInstall = Join-Path $temporaryRoot 'guard-install'
    Copy-Item -LiteralPath $guardBuild -Destination $guardInstall -Recurse
    $guard = Join-Path $guardInstall 'utoaegis-guard.exe'
    if (-not (Test-Path -LiteralPath $guard -PathType Leaf)) {
        throw 'The Release guard executable must be built before this integration test.'
    }

    $keyDirectory = Join-Path $temporaryRoot 'keys'
    [IO.Directory]::CreateDirectory($keyDirectory) | Out-Null
    $privateKeyPath = Join-Path $keyDirectory 'policy-private.pem'
    $publicKeyPath = Join-Path $keyDirectory 'policy-public.pem'
    $curve = [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
    $key = [Security.Cryptography.ECDsa]::Create($curve)
    try {
        [IO.File]::WriteAllText(
            $privateKeyPath,
            $key.ExportPkcs8PrivateKeyPem(),
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            $publicKeyPath,
            $key.ExportSubjectPublicKeyInfoPem(),
            [Text.UTF8Encoding]::new($false))
    } finally {
        $key.Dispose()
    }

    $now = [DateTimeOffset]::UtcNow
    $definition = [ordered]@{
        schemaVersion = 1
        algorithm = 'ecdsa-p256-sha256'
        sequence = 3
        policyId = 'integration-policy'
        keyId = 'policy-key-1'
        issuedUtc = $now.AddMinutes(-1).ToString('O')
        expiresUtc = $now.AddDays(1).ToString('O')
        response = [ordered]@{
            mode = 'ObserveOnly'
            allowlistedPathPrefixes = @()
            allowlistedSha256 = @()
            maxActionsPerWindow = 3
            rateLimitWindowSeconds = 300
        }
        integrity = [ordered]@{
            auditIntervalSeconds = 300
            maximumRecoveriesPerWindow = 2
            recoveryWindowSeconds = 3600
            services = @([ordered]@{
                name = 'UtoAegis'
                executablePath = Join-Path $temporaryRoot 'utoaegis-service.exe'
                executableSha256 = ('a' * 64 -join '')
                account = 'NT SERVICE\UtoAegis'
                startMode = 'DelayedAutomatic'
                recover = $true
            })
            paths = @()
        }
    }
    $definitionPath = Join-Path $temporaryRoot 'policy-definition.json'
    [IO.File]::WriteAllText(
        $definitionPath,
        ($definition | ConvertTo-Json -Depth 8 -Compress),
        [Text.UTF8Encoding]::new($false))
    $policyBundle = Join-Path $temporaryRoot 'policy'
    & (Join-Path $repositoryRoot 'scripts/windows/Protect-UtoAegisRuntimePolicy.ps1') `
        -DefinitionPath $definitionPath `
        -PrivateKeyPath $privateKeyPath `
        -OutputDirectory $policyBundle

    $settings = [ordered]@{
        UtoAegisGuard = [ordered]@{
            PolicyBundlePath = $policyBundle
            PolicyStatePath = Join-Path $temporaryRoot 'state/policy-state.json'
            TrustedSigningKeys = @([ordered]@{
                KeyId = 'policy-key-1'
                PublicKeyPath = $publicKeyPath
            })
            RecoveryStatePath = Join-Path $temporaryRoot 'state/recovery-state.json'
            SecurityTelemetrySpoolPath = Join-Path $temporaryRoot 'telemetry'
            DeploymentId = 'integration-endpoint'
            TelemetryMaximumRecords = 32
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $guardInstall 'appsettings.json'),
        ($settings | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false))

    & $guard --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'The signed runtime policy failed guard validation.'
    }

    $policyPath = Join-Path $policyBundle 'policy.json'
    $policyText = [IO.File]::ReadAllText($policyPath)
    [IO.File]::WriteAllText(
        $policyPath,
        $policyText.Replace('ObserveOnly', 'DryRunQuarantine'),
        [Text.UTF8Encoding]::new($false))
    & $guard --validate-config 2>$null
    if ($LASTEXITCODE -eq 0) {
        throw 'The integrity guard accepted a tampered runtime policy.'
    }

    Write-Host 'Runtime policy script integration tests passed.'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        $resolved = (Resolve-Path -LiteralPath $temporaryRoot).Path
        $temporaryPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            (Resolve-Path -LiteralPath $env:TEMP).Path) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a runtime policy test directory outside the system temporary directory.'
        }

        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
