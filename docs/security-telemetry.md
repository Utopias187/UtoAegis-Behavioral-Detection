# Security Telemetry

Milestone 12 adds bounded, tamper-evident telemetry without giving the endpoint
monitor or threat-content updater a collector credential. Each producer writes
only to its own local spool. A separately privileged .NET 10 Windows service
verifies those chains and forwards bounded batches over authenticated HTTPS.

This design makes deletion, modification, reordering, stale checkpoints, and
retention gaps visible. It does not make a Windows host tamper-proof against a
local administrator. Fleet-side retention of the latest accepted sequence and
hash is what lets the collector detect an endpoint attempting to present an
older chain.

## Trust and privilege boundaries

```text
NT SERVICE\UtoAegis                 NT SERVICE\UtoAegisUpdater
  monitor + response policy           content download + activation
  modify monitor spool only           modify updater spool only
           |                                      |
           +---------- read-only spools ----------+
                              |
                  NT SERVICE\UtoAegisTelemetry
                    read producer spools
                    read collector HMAC key
                    modify checkpoint state only
                    HTTPS egress to one collector URI
                              |
                     authenticated collector
                     durable accepted anchors
```

Use a different spool directory for every producer. Do not place a collector
key in a producer directory, and do not grant the forwarder write access to a
producer spool. The telemetry service installer enforces read-only spool grants,
read access to the key, and modify access only to its checkpoint directory.

## Producer configuration

The monitor accepts these optional `UtoAegis` settings:

```json
{
  "SecurityTelemetrySpoolPath": "C:\\ProgramData\\UtoAegis\\SecurityTelemetry",
  "DeploymentId": "endpoint-001",
  "TelemetryMaximumRecords": 10000
}
```

The updater accepts the same fields under `UtoAegisUpdater`, using a separate
path such as `C:\ProgramData\UtoAegisUpdater\SecurityTelemetry`. The maximum is
1 through 1,000,000 records and defaults to 10,000. A serialized record is
limited to 16 KiB. Omitting `SecurityTelemetrySpoolPath` disables this channel;
when the path is present, `DeploymentId` is required.

The monitor records lifecycle, periodic health, detections, response decisions,
content-reload results, and content health. Detection and response records share
the scan correlation identifier. The updater mirrors its check, retry,
activation, rejection, transport, and retention events while preserving its
existing local JSON Lines operations log.

## Record and retention model

Each spool stores one canonical JSON envelope per record:

```json
{
  "schemaVersion": 1,
  "sequence": 42,
  "timestampUtc": "2026-11-11T18:30:00+00:00",
  "source": "monitor",
  "eventType": "detection.response",
  "deploymentId": "endpoint-001",
  "correlationId": "scan-id",
  "payload": {},
  "previousHash": "64 lowercase hexadecimal characters",
  "hash": "64 lowercase hexadecimal characters"
}
```

`hash` is SHA-256 over the canonical envelope material excluding `hash` itself.
It binds the schema, sequence, timestamp, identity fields, payload, and prior
hash. State and record updates use same-directory atomic replacement. Startup
revalidates every retained record and the state anchor before delivery.

When the configured count is exceeded, the producer first atomically advances a
pruning anchor and then removes the oldest files. A record left behind by an
interruption after that commit is ignored because it is already covered by the
anchor. Records at or after the retained anchor must remain complete and valid.
If a collector checkpoint falls behind the pruning anchor, delivery stops with
an explicit gap instead of silently skipping data.

## Forwarder configuration

Publish the forwarder, create its state directory, provision a random base64
key, and edit the published `appsettings.json`:

```json
{
  "UtoAegisTelemetry": {
    "CollectorUri": "https://telemetry.example.com/v1/records",
    "AuthenticationKeyId": "endpoint-001-2026-01",
    "AuthenticationKeyPath": "C:\\ProgramData\\UtoAegisTelemetry\\Policy\\collector.key",
    "StatePath": "C:\\ProgramData\\UtoAegisTelemetry\\State",
    "BatchSize": 128,
    "PollIntervalSeconds": 30,
    "RequestTimeoutSeconds": 30,
    "Sources": [
      {
        "Name": "monitor",
        "SpoolPath": "C:\\ProgramData\\UtoAegis\\SecurityTelemetry"
      },
      {
        "Name": "updater",
        "SpoolPath": "C:\\ProgramData\\UtoAegisUpdater\\SecurityTelemetry"
      }
    ]
  }
}
```

Generate a 32-byte key in an administrator-controlled session and store only
its base64 text in the configured file. Transfer the same key and key ID to the
collector through the organization's secret-provisioning channel.

```powershell
$bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
[Convert]::ToBase64String($bytes) | Set-Content `
  'C:\ProgramData\UtoAegisTelemetry\Policy\collector.key' -NoNewline
[Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
```

The decoded key must be 32 through 64 bytes. Configuration allows 1 through 32
unique sources, batches of 1 through 1,000 records, polling from 5 through 3,600
seconds, and request timeouts from 5 through 120 seconds. The key, state, source
spools, and installation directory must remain separate according to validation
rules. Paths cannot be reparse points.

## Collector protocol

The forwarder sends an `application/json` POST whose body is:

```json
{
  "schemaVersion": 1,
  "source": "monitor",
  "records": []
}
```

Every request includes:

- `X-UtoAegis-Key-Id`: the configured key ID;
- `X-UtoAegis-Timestamp`: current Unix time in seconds;
- `X-UtoAegis-Nonce`: 16 random bytes encoded as lowercase hexadecimal; and
- `X-UtoAegis-Signature`: a base64 HMAC-SHA256 value.

The signed UTF-8 input is exactly:

```text
POST
/escaped/path?query
unix-timestamp
lowercase-hex-nonce
lowercase-sha256-of-exact-body
```

The collector should select the secret by key ID, reject timestamps outside a
small policy window, atomically reject reused nonces within that window, hash
the exact body bytes, and compare the HMAC in constant time before parsing JSON.
It should validate the source-to-key authorization, schema, sequence continuity,
previous hash, and every record hash. The latest accepted sequence and hash must
be durably stored before success is returned.

After committing the entire batch, return HTTP 2xx with no more than 16 KiB:

```json
{
  "acceptedSequence": 42,
  "acceptedHash": "the exact hash of record 42"
}
```

The forwarder advances its atomic per-source checkpoint only when both values
exactly match the final record sent. An error, partial acceptance, malformed
response, mismatched acknowledgement, or interrupted checkpoint write causes
the same batch to be retried. The collector therefore needs idempotent handling
of an already accepted sequence and hash.

HTTPS is mandatory. Redirects, cookies, and transparent response decompression
are disabled, certificate revocation checks are enabled, and system certificate
trust authenticates the collector. HMAC authenticates the endpoint request; it
does not replace TLS.

## Publish, install, and operate

From the repository:

```powershell
pwsh ./scripts/windows/Publish-UtoAegisTelemetry.ps1 `
  -OutputDirectory 'C:\Program Files\UtoAegisTelemetry'

& 'C:\Program Files\UtoAegisTelemetry\utoaegis-telemetry.exe' --validate-config

pwsh ./scripts/windows/Install-UtoAegisTelemetry.ps1 `
  -PublishDirectory 'C:\Program Files\UtoAegisTelemetry' `
  -Start
```

Inspect or remove the registration with:

```powershell
pwsh ./scripts/windows/Get-UtoAegisTelemetryStatus.ps1
pwsh ./scripts/windows/Remove-UtoAegisTelemetry.ps1
```

Removal preserves checkpoints, spools, keys, published files, and ACLs for
recovery. Review and remove those separately under the organization's retention
and secret-destruction policies.

## Operational response

- Treat a chain verification failure as possible corruption or tampering; copy
  the spool and checkpoint state for investigation before repair.
- Treat a checkpoint-behind-pruning error as a confirmed delivery gap. Record
  the missing interval centrally, establish a new operator-approved anchor, and
  investigate collector reachability and capacity.
- Alert on repeated authentication, TLS, or acknowledgement failures. Never
  advance a local checkpoint manually merely to clear an alert.
- Rotate HMAC keys by provisioning a new key file and key ID to endpoint and
  collector, then restarting the forwarder in a controlled window. Dynamic
  multi-key overlap is not implemented in this milestone.
- Size each producer spool for the maximum expected collector outage. The bound
  protects endpoint disk usage, so delivery is not an unlimited-retention SLA.

Local administrator compromise remains inside the endpoint trust boundary. A
local administrator can stop services, delete data, or replace producer state;
the fleet collector's previously accepted anchor provides detection, not
prevention. For stronger assurance, protect keys with an OS or hardware-backed
secret store and combine collector records with independent host attestation.
