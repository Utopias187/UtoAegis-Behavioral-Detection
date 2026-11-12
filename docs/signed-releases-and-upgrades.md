# Signed Releases and Transactional Upgrades

Milestone 13 adds a release boundary around the UtoAegis monitor, updater,
telemetry forwarder, and operator CLI. A production bundle is built from locked
NuGet graphs for `win-x64` and `win-arm64`, inventories every file, includes a
CycloneDX 1.7 SBOM, Authenticode-signs UtoAegis binaries, signs the complete
inventory with detached CMS, and verifies all evidence before packaging.

The tooling supports unsigned development candidates only when the operator
passes an explicit switch. An unsigned candidate is not a production release
and the production verifier rejects it by default.

## Release contents

```text
UtoAegis-<version>-<runtime>\
  services\
    monitor\
    updater\
    telemetry\
  tools\
    guard\
  deployment\
    windows\
    Install-UtoAegisRelease.ps1
    Restore-UtoAegisRelease.ps1
    Test-UtoAegisRelease.ps1
    Test-UtoAegisServiceRecovery.ps1
  sbom.cdx.json
  release-manifest.json
  release-manifest.p7s
  LICENSE
  THIRD-PARTY-NOTICES.md
  README.md
```

The adjacent ZIP checksum file binds the transport archive. Inside the archive,
`release-manifest.json` binds every relative path, byte length, and SHA-256
digest. The detached `release-manifest.p7s` signature authenticates that exact
manifest, including the hashes of configuration templates, deployment scripts,
the SBOM, third-party assemblies, and UtoAegis binaries.

UtoAegis-owned `.exe` and `.dll` files additionally carry embedded Authenticode
signatures. Third-party assemblies retain their publishers' original bytes and
are authenticated through the signed release manifest instead of being
re-signed as UtoAegis code.

## Reproducible metadata and SBOM

The build timestamp is derived from the release commit, the ZIP entry order and
timestamps are fixed, and the manifest inventory is sorted. .NET deterministic
and continuous-integration build properties are enabled. The result is stable
release metadata and archive construction for the same source, SDK, and build
environment; this is not a claim that arbitrary operating systems or SDK
versions will produce bit-for-bit identical PE files.

`sbom.cdx.json` follows the current
[CycloneDX 1.7 JSON schema](https://cyclonedx.org/schema/bom-1.7.schema.json).
It is derived from the committed production `packages.lock.json` files, rejects
inconsistent versions or package hashes, records direct versus transitive use,
and associates each component with the production projects that consume it.

## Local production signing

Prerequisites:

- .NET 10 and the Windows SDK, including `SignTool.exe`;
- a currently valid code-signing certificate with an accessible private key;
- the certificate installed in exactly one Current User or Local Machine
  personal certificate store; and
- an HTTPS RFC 3161 timestamp service operated or recommended by the issuing CA.

Use a hardware-backed or managed signing key for commercial releases when
available. A software-exportable PFX increases key-exfiltration risk.

From a clean checkout, run:

```powershell
pwsh ./scripts/release/New-UtoAegisRelease.ps1 `
  -Version '1.0.0' `
  -RuntimeIdentifier win-x64 `
  -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -TimestampServer 'https://timestamp.example.com' `
  -OutputDirectory './output/releases'
```

Repeat for `win-arm64`. The script performs locked restore and all tests before
publishing, signs only UtoAegis-owned binaries, uses SHA-256 and RFC 3161
timestamps, creates the manifest after binary signing, creates and timestamps a
detached CMS signature, verifies the complete release, builds a deterministic
ZIP, and writes the ZIP SHA-256 file.

Microsoft recommends SHA-256 file digests and RFC 3161 timestamps with an
explicit SHA-256 timestamp digest; the scripts use those
[SignTool settings](https://learn.microsoft.com/windows/win32/seccrypto/signtool).

## Development candidate

CI and local integration tests can create an unmistakably unsigned candidate:

```powershell
pwsh ./scripts/release/New-UtoAegisRelease.ps1 `
  -Version '1.0.0-dev.1' `
  -RuntimeIdentifier win-x64 `
  -UnsignedDevelopment `
  -OutputDirectory './output/development'
```

The manifest records `UnsignedDevelopment`. Verification requires the explicit
`-AllowUnsignedDevelopment` switch. The signed-release workflow never uses this
mode, and an unsigned candidate must not be deployed as a production release.

## Verification before deployment

Verify the ZIP against its adjacent checksum before extraction. Then verify the
extracted production package using a thumbprint provisioned through an
independent administrator-controlled channel:

```powershell
pwsh ./deployment/Test-UtoAegisRelease.ps1 `
  -RootPath '.' `
  -AllowedSignerThumbprint '0123456789ABCDEF0123456789ABCDEF01234567'
```

Verification rejects missing or extra files, modified lengths or hashes, path
traversal, rooted or duplicate paths, reparse-point directories, invalid SBOM
identity, missing or invalid CMS, an unapproved signer, invalid Authenticode, and
unsigned development content without its explicit override.

## Upgrade planning and installation

The upgrade tool is for already installed services. Existing first-time
installation scripts remain responsible for creating virtual service accounts,
Event Log sources, and least-privilege ACLs.

Create a no-change plan:

```powershell
pwsh ./deployment/Install-UtoAegisRelease.ps1 `
  -ReleaseRoot '.' `
  -InstallationRoot 'C:\Program Files\UtoAegis' `
  -AllowedSignerThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -PlanOnly
```

Review the JSON service paths and target version. Then run the same command
without `-PlanOnly` in an elevated PowerShell 7 session. The installer:

1. verifies the untouched release before creating installation files;
2. copies it to an isolated versioned staging directory;
3. copies current operator configuration into the staged service payloads;
4. validates every staged service configuration;
5. stops only services that were running;
6. switches all SCM binary paths to the new version;
7. restores prior paths and running states if any switch or restart fails;
8. commits deployment state only after every required service starts; and
9. protects current and rollback versions while pruning only older managed
   semantic-version directories to the configured bound.

The installed version is a deployment derivative because its `appsettings.json`
files contain operator configuration rather than the signed templates. Preserve
the original ZIP, checksum, manifest, and signature as release evidence.

## Rollback

The immediate prior paths and running states are stored in
`deployment-state.json`. To restore them:

```powershell
pwsh ./deployment/Restore-UtoAegisRelease.ps1 `
  -InstallationRoot 'C:\Program Files\UtoAegis'
```

The command verifies that rollback binaries and configurations exist, stops the
current services, restores prior SCM paths, restarts services that were running,
and swaps the deployment-state pointers. If rollback fails, it attempts to
restore the current version instead of deleting either set of binaries.

Rollback changes executables only. It does not lower threat-content anti-rollback
floors, rewrite databases, restore quarantined files, or remove telemetry
checkpoints.

## Controlled recovery test

After a maintenance-window deployment, an administrator can prove that service
processes stop and restart within a bound:

```powershell
pwsh ./deployment/Test-UtoAegisServiceRecovery.ps1 -Execute
```

All selected services must already be running. The test records old and new
process IDs and fails if a service does not restart in a distinct process within
the timeout. This is intentionally disruptive and is never run automatically by
CI or the release workflow.

## Protected GitHub release workflow

`.github/workflows/signed-release.yml` is manual-only and references the
`release-signing` environment. Configure these environment secrets:

- `UTOAEGIS_SIGNING_CERTIFICATE_BASE64` — base64 of the PFX bytes;
- `UTOAEGIS_SIGNING_CERTIFICATE_PASSWORD` — the PFX password; and
- `UTOAEGIS_SIGNING_CERTIFICATE_THUMBPRINT` — the independently verified
  certificate thumbprint.

The workflow imports the certificate without making the key exportable, builds
and verifies both Windows architectures, uploads evidence, creates a draft
rather than published release, and removes the certificate from the runner.
Configure the strongest environment and branch controls available on the
repository's GitHub plan. Missing signing secrets make the workflow fail closed.

GitHub artifact attestations are not required because private-repository support
currently depends on GitHub Enterprise Cloud. They can be an additional layer
when supported; they do not replace Authenticode, the signed manifest, or
operator thumbprint verification.

## Current limitations

- A trusted production certificate must be acquired before the first commercial
  artifact can be signed.
- The repository does not yet build MSI or MSIX packages or register with a
  Windows package-management channel.
- The workflow's PFX option is practical but weaker than an HSM or managed
  signing service. Local tooling supports Windows-store hardware-backed keys.
- Automated tests cover metadata integrity, tampering, archive verification,
  locked dual-architecture publishing, and side-effect-free upgrade planning.
  Live SCM switching and recovery testing require a controlled Windows host.
