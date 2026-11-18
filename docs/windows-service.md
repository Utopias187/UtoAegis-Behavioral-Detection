# Windows Service Deployment

UtoAegis can run its bounded file-monitoring pipeline as a .NET 10 Windows
Service. The service is intentionally observe-only until an administrator
selects another response mode. Use the harmless fixtures in `samples` while
validating a deployment; do not introduce live malware.

## Protected layout

Use separate directories for executable code, read-only detection policy, and
writable operational state. A suitable local layout is:

```text
C:\Program Files\UtoAegis\
  utoaegis-service.exe
  appsettings.json
  runtime files...

C:\ProgramData\UtoAegis\Policy\
  production-2026.public.pem

C:\ProgramData\UtoAegis\State\
  history.db
  quarantine\

C:\ProgramData\UtoAegis\SecurityTelemetry\
  state.json
  records\

C:\ProgramData\UtoAegis\Content\
  state.json
  versions\
  staging\
```

The installer gives `NT SERVICE\UtoAegis` read/execute access to the program
and monitored directories, read access to managed content and public keys, and
modify access only to configured operational state directories. Quarantine mode
additionally receives
`Delete child` on the monitored tree so the verified handle-removal operation
can complete. It does not receive general write access to monitored content.

Configuration validation rejects these layouts:

- the service installation directory inside the monitored tree;
- the database, history database, or vault inside the monitored tree;
- a signature file inside a service-writable state directory;
- a content store inside the monitored or installation tree;
- a trusted public key inside the content store or writable state;
- a writable state directory that is a filesystem root or contains the service
  installation directory;
- the same path assigned to two operational roles; or
- a reparse point used as the monitoring root.

## Configuration

Edit the published `appsettings.json` before installation. Environment-variable
tokens such as `%ProgramData%` are expanded. Relative paths, including path
allowlist entries, are resolved from the service installation directory.

```json
{
  "UtoAegis": {
    "MonitorRoot": "C:\\Users\\Public\\Downloads",
    "Recursive": true,
    "RunInitialScan": true,
    "ContentStorePath": "C:\\ProgramData\\UtoAegis\\Content",
    "TrustedSigningKeys": [
      {
        "KeyId": "production-2026",
        "PublicKeyPath": "C:\\ProgramData\\UtoAegis\\Policy\\production-2026.public.pem"
      }
    ],
    "HistoryPath": "C:\\ProgramData\\UtoAegis\\State\\history.db",
    "VaultPath": "C:\\ProgramData\\UtoAegis\\State\\quarantine",
    "MaximumConcurrency": 4,
    "QueueCapacity": 4096,
    "WatcherBufferSize": 16384,
    "DebounceMilliseconds": 500,
    "HealthIntervalSeconds": 60,
    "ContentReloadIntervalSeconds": 30,
    "SecurityTelemetrySpoolPath": "C:\\ProgramData\\UtoAegis\\SecurityTelemetry",
    "DeploymentId": "endpoint-001",
    "TelemetryMaximumRecords": 10000,
    "Behavior": {
      "Enabled": false,
      "Source": "KernelEtw",
      "HistoryPath": "C:\\ProgramData\\UtoAegis\\behavior-history.db",
      "QueueCapacity": 1024,
      "PollIntervalMilliseconds": 1000
    },
    "Response": {
      "Mode": "ObserveOnly",
      "AllowlistedPathPrefixes": [
        "C:\\Users\\Public\\Downloads\\approved"
      ],
      "AllowlistedSha256": [],
      "MaxActionsPerWindow": 3,
      "RateLimitWindowSeconds": 300
    }
  }
}
```

`ContentStorePath` with at least one `TrustedSigningKeys` entry is the preferred
detection source. It cannot be combined with `DatabasePath` or `SignaturePath`.
The direct paths remain available for manual or development deployments; at
least one direct path is required when no managed store is configured. All
detection content is verified at startup and then checked for authenticated
generation changes. Activation or rollback is adopted without a restart after
candidate reverification succeeds. Direct-path deployments remain startup-only.

The optional `UtoAegisUpdater` companion runs under its own virtual service
account. It receives modify access to the content store plus its isolated
download and telemetry directories, while `NT SERVICE\UtoAegis` retains only
read access to managed content. The two services do not share an executable or
private credentials. Installation and rotation procedures are documented in the
[production updater guide](production-threat-updater.md).

`SecurityTelemetrySpoolPath` is optional. When configured, `DeploymentId` is
required and the service writes health, detection, response, and content-reload
events to a local SHA-256 hash chain. The monitor has no collector credential and
does not upload telemetry. The separate `UtoAegisTelemetry` service receives
read-only access to the spool and owns remote delivery. See the
[security telemetry guide](security-telemetry.md).

Build and activate the initial signed content before validating or installing
the service. The complete workflow and bundle schema are in the
[authenticated update guide](authenticated-threat-updates.md).

Production binary releases, preflight verification, transactional upgrades,
rollback, and controlled restart testing are documented in the
[signed release guide](signed-releases-and-upgrades.md).

Authenticated response policy, SCM and ACL drift auditing, Guard telemetry, and
bounded recovery are documented in the
[runtime integrity guide](authenticated-runtime-policy-and-integrity-guard.md).

The principal bounds are:

| Setting | Accepted range |
| --- | ---: |
| `MaximumConcurrency` | 1–32 |
| `QueueCapacity` | 1–65,536 |
| `WatcherBufferSize` | 4,096–65,536 bytes |
| `DebounceMilliseconds` | 0–60,000 |
| `HealthIntervalSeconds` | 10–86,400 |
| `ContentReloadIntervalSeconds` | 5–3,600 |
| `TelemetryMaximumRecords` | 1–1,000,000 |
| `Behavior:QueueCapacity` | 2–8,192 |
| `Behavior:PollIntervalMilliseconds` | 250–60,000 |
| `Response:MaxActionsPerWindow` | 1–100 |
| `Response:RateLimitWindowSeconds` | 1–86,400 |

The policy accepts at most 1,024 path prefixes and 10,000 SHA-256 allowlist
entries. Hashes must contain exactly 64 hexadecimal characters.

Behavioral collection is opt-in. `KernelEtw` provides the approved process,
image, file, registry, and TCP connection coverage; Windows must authorize the
service account to start a kernel trace session. `ProcessSnapshot` is a reduced
process-only diagnostic source. The full privacy, failure, and recovery
contract is in the
[behavioral telemetry guide](behavioral-telemetry-and-detection.md).

## Response modes

The engine considers a response only for a completed detection. It then checks
the hash allowlist followed by the path-prefix allowlist before applying the
selected mode:

- `ObserveOnly` emits the detection and decision without changing the file.
- `DryRunQuarantine` emits that the file would be quarantined, but performs no
  mutation.
- `Quarantine` reserves one action in the sliding rate window and invokes the
  same exact-handle identity recheck and durable vault used by the CLI.

Failed quarantine attempts remain counted in the current rate window. This
prevents a persistent failure or attacker-controlled file from creating an
unbounded retry loop. A service restart resets the in-memory rate window.

## Publish and install

The service is framework-dependent and requires the .NET 10 runtime. From the
repository, publish it to an administrator-protected directory:

```powershell
pwsh ./scripts/windows/Publish-UtoAegisService.ps1 `
  -OutputDirectory 'C:\Program Files\UtoAegis'
```

Place the trusted public key in its read-only policy directory, activate an
initial signed bundle, edit the published `appsettings.json`, and validate it
without starting monitoring:

```powershell
& 'C:\Program Files\UtoAegis\utoaegis-service.exe' --validate-config
```

In an elevated PowerShell 7 session, install and start in observe-only or
dry-run mode:

```powershell
pwsh ./scripts/windows/Install-UtoAegisService.ps1 `
  -PublishDirectory 'C:\Program Files\UtoAegis' `
  -Start
```

An initial installation whose configuration already selects `Quarantine` is
refused unless the administrator also supplies `-AllowQuarantineResponse`.
Operate in observe-only and then dry-run mode long enough to review false
positives and allowlists before enabling file removal.

## Observe and recover

Inspect service identity, state, start mode, executable path, and recent
Application log events with:

```powershell
pwsh ./scripts/windows/Get-UtoAegisServiceStatus.ps1
```

Event IDs are grouped by purpose: `100`–`106` cover lifecycle, health,
authenticated content loading, reload, and content health; `200`–`201` cover
file and recovery scans; `108` records behavioral-source startup and `202`
records bounded behavioral assessments; `300`–`301` cover detections and monitor
issues; `302` warns about expired last-known-good content; `303` reports a
rejected reload; and `400` reports history persistence failure. Event data can
include file paths and must follow the host's access and retention policy.

To recover a quarantined file, stop the service, inspect the vault with
`quarantine list` and `quarantine show`, then use the CLI `quarantine restore`
command. Restore revalidates payload integrity and refuses overwrite. Restart
the service only after adding a justified path or hash allowlist entry when the
detection was a false positive.

Remove only the Windows service registration with:

```powershell
pwsh ./scripts/windows/Remove-UtoAegisService.ps1
```

Published files, state databases, quarantine payloads, and ACL entries are
preserved deliberately so removal does not destroy recovery evidence.

## Current limitations

- The filesystem watcher is a best-effort change signal, not a kernel minifilter
  or a transactional audit source. Overflow triggers a recovery scan.
- Managed content reload uses bounded polling rather than a push notification.
- Trust keys, direct content paths, and response policy are loaded at startup.
- Rate-limit state is in memory and resets when the service restarts.
- Event Log messages are operational notifications, not a remote alerting or
  incident-management integration.
- Service installation and ACL behavior are Windows-specific. The service host
  is not a substitute for kernel-mode on-access blocking.
- Removal preserves data and ACLs; operators must review and remove them
  separately after their retention and recovery requirements have ended.
