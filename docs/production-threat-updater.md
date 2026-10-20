# Production Threat-Intelligence Updater

Milestone 10 adds `UtoAegis.Updater`, a separately privileged .NET 10 worker
that retrieves signed threat content, invokes the Milestone 9 activation core,
and bounds retry, disk retention, and operational telemetry. It does not move
network or content-store write privileges into the endpoint monitoring service.

## Security model

The channel is an absolute HTTPS directory URI containing the same four fixed
files as an offline bundle:

```text
https://updates.example.com/utoaegis/pilot/manifest.json
https://updates.example.com/utoaegis/pilot/manifest.sig
https://updates.example.com/utoaegis/pilot/indicators.jsonl
https://updates.example.com/utoaegis/pilot/signatures.jsonl
```

The production HTTP client uses the operating system certificate trust and
revocation checks. Redirects, cookies, and automatic content decompression are
disabled. Every response must report the exact requested HTTPS URI, HTTP 200,
and a positive bounded `Content-Length`. The updater downloads only
`manifest.json` and `manifest.sig` first, verifies the exact manifest bytes with
an endpoint-trusted ECDSA key, applies time and sequence policy, and only then
requests the two payloads at their signed lengths. The existing activation path
rehashes and reparses every payload before changing `state.json`.

HTTPS authenticates the configured server and encrypts transport. The detached
signature remains the authority for content. A compromised mirror cannot sign
new content, and a valid TLS connection does not bypass signature, expiration,
schema, or anti-rollback checks.

The updater intentionally has no bearer token, embedded secret, or private
signing key. Environments that require proxy authentication or mutual TLS need
an organization-managed transport adapter in front of the fixed HTTPS channel.

## Configuration

Publish the updater, edit its `appsettings.json`, provision the public keys and
directories, then install it. A representative configuration is:

```json
{
  "UtoAegisUpdater": {
    "ChannelBaseUri": "https://updates.example.com/utoaegis/pilot/",
    "ContentStorePath": "C:\\ProgramData\\UtoAegis\\Content",
    "DownloadPath": "C:\\ProgramData\\UtoAegisUpdater\\Downloads",
    "TelemetryPath": "C:\\ProgramData\\UtoAegisUpdater\\Telemetry\\updates.jsonl",
    "DeploymentId": "endpoint-001",
    "RolloutRing": "pilot",
    "PollIntervalSeconds": 3600,
    "RequestTimeoutSeconds": 120,
    "MaximumRetainedVersions": 3,
    "Retry": {
      "MaximumAttempts": 4,
      "InitialDelaySeconds": 5,
      "MaximumDelaySeconds": 300
    },
    "SigningKeys": [
      {
        "KeyId": "production-2026",
        "PublicKeyPath": "C:\\ProgramData\\UtoAegis\\Policy\\production-2026.public.pem",
        "Status": "Trusted"
      },
      {
        "KeyId": "production-2025",
        "PublicKeyPath": "C:\\ProgramData\\UtoAegis\\Policy\\production-2025.public.pem",
        "Status": "Revoked"
      }
    ]
  }
}
```

`DeploymentId`, `RolloutRing`, and key IDs accept 1–64 ASCII letters, digits,
dots, dashes, or underscores and must begin and end with a letter or digit.
Writable directories must be existing, distinct, non-nested, non-reparse-point
directories outside the installation. Public keys must be regular files outside
every updater-writable directory.

| Setting | Accepted range |
| --- | ---: |
| `PollIntervalSeconds` | 60–86,400 |
| `RequestTimeoutSeconds` | 5–600 |
| `MaximumRetainedVersions` | 2–64 |
| `Retry:MaximumAttempts` | 1–10 |
| `Retry:InitialDelaySeconds` | 1–300 |
| `Retry:MaximumDelaySeconds` | initial delay–3,600 |

Only HTTP 408, HTTP 429, server errors, transport failures, and request timeouts
receive an in-cycle retry. The delay doubles after each failed attempt and is
capped by `MaximumDelaySeconds`. Bad signatures, expired content, unsafe
responses, schema failures, and rollback attempts fail the cycle immediately.
The next scheduled poll starts a new bounded cycle.

## Publish and install

From the repository:

```powershell
pwsh ./scripts/windows/Publish-UtoAegisUpdater.ps1 `
  -OutputDirectory 'C:\Program Files\UtoAegisUpdater'
```

After editing configuration and provisioning keys, install from an elevated
PowerShell session:

```powershell
pwsh ./scripts/windows/Install-UtoAegisUpdater.ps1 `
  -PublishDirectory 'C:\Program Files\UtoAegisUpdater' `
  -Start
```

The installer creates the passwordless virtual account identity
`NT SERVICE\UtoAegisUpdater` through Service Control Manager. It grants that
identity read/execute access to the published program, read access to configured
public keys, and modify access only to the content, download, and telemetry
directories. It does not grant write access to the monitor installation,
monitored files, scan history, or quarantine vault.

Validate or run one bounded cycle without registering a service:

```powershell
& 'C:\Program Files\UtoAegisUpdater\utoaegis-updater.exe' --validate-config
& 'C:\Program Files\UtoAegisUpdater\utoaegis-updater.exe' --once
```

Inspect or remove the registration with:

```powershell
pwsh ./scripts/windows/Get-UtoAegisUpdaterStatus.ps1
pwsh ./scripts/windows/Remove-UtoAegisUpdater.ps1
```

Removal preserves content, downloads, telemetry, published files, and ACLs for
recovery. Review and remove those separately under the organization's retention
policy.

## Staged rollout telemetry

Each cycle appends bounded JSON Lines records to `TelemetryPath`. Records include
UTC time, one run ID, deployment ID, rollout ring, attempt number, sequence,
candidate version, event, and a non-secret message. Events distinguish checks,
scheduled retries, current content, activation, rejection, transport failure,
retention failure, and retention deferred by an in-flight scanner lease.

Telemetry is local and is not uploaded by UtoAegis. Forward the file with the
organization's existing log collector. Use a different fixed channel URI per
rollout ring, promote the same signed sequence from pilot to broader rings, and
compare activation/rejection rates before promotion. Do not put access tokens,
user names, or host secrets in deployment or ring identifiers.

## Retention and recovery

After successful activation the updater prunes old immutable version
directories to `MaximumRetainedVersions`. The currently active and immediate
rollback versions are always protected. Additional slots retain the newest
unreferenced versions by sequence. A generation still used by an in-flight
monitor scan is pinned and reported rather than deleted, even when retention
temporarily exceeds the target. A later cycle can prune it after the scan
drains. A reparse point, file, noncanonical directory, missing state target, or
unrelated deletion failure stops pruning and emits a retention failure without
undoing the already committed activation.

The anti-rollback sequence floor is never pruned. A manual rollback still
requires the Milestone 9 CLI and trusted key set. The updater will then accept
only a sequence higher than the greatest sequence ever activated.

## Key rotation and revocation

For planned rotation:

1. Provision the new public key through the trusted host-configuration channel.
2. Configure old and new keys as `Trusted` in the updater and monitor.
3. Publish a higher sequence signed by the new key to the pilot channel.
4. Confirm pilot activation and monitor reload telemetry, then promote the
   identical signed bundle through the remaining rollout rings.
5. Mark the old updater key `Revoked`, remove it from the monitor's trusted-key
   list, and restart monitors during a controlled window.

A `Revoked` updater entry is retained for explicit audit but is excluded from
the runtime trust store. Its public-key file must remain present while the entry
is configured. Removing the entry and file also removes trust, but loses that
local status record.

For suspected compromise, provision a replacement key through a channel that
does not depend on the compromised signer, mark the old key `Revoked`, and
publish a higher sequence. Existing last-known-good content remains active until
replacement content is available; revocation does not delete the active files.
The monitoring service has an independent key list and must be updated as part
of the same incident procedure.

## Current limitations

- Monitor trust-key changes still require a controlled restart even though
  content generations now reload without one.
- Rollout telemetry is local JSON Lines, not a remote delivery service or SLA.
- Key status is protected by host configuration controls, not a remotely signed
  root-metadata format.
- The updater supports system-trusted server certificates but not built-in
  certificate pinning, mutual TLS, proxy credentials, or bearer tokens.
- Content-store anti-rollback state remains inside the local-administrator trust
  boundary.
