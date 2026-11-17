# Endpoint enrollment and policy distribution

Milestone 15 gives each installed endpoint a cryptographic identity and a
bounded management channel for receiving already signed runtime policy. It also
adds durable acknowledgements so operators can distinguish an assigned policy
from one that a device has actually verified and applied.

## Security goals

- Generate the device private key on the endpoint and never transmit it.
- Bind enrollment records to the exact public-key fingerprint and device ID.
- Use a one-time bootstrap credential only for initial enrollment.
- Authenticate every post-enrollment request with a fresh signed request
  envelope that cannot be replayed at another method, path, or body.
- Keep runtime-policy signing keys offline. The management channel distributes
  signed policy bundles but cannot manufacture or modify them.
- Enforce the enrolled rollout ring locally as well as in the control plane.
- Reject revoked, expired, rolled-back, or equivocating enrollment and policy
  state.
- Persist policy acknowledgements before reporting success to the control
  plane, then retry them safely until the server confirms the exact record.
- Report a small, bounded health document rather than arbitrary endpoint data.

## Trust boundaries

The management channel has three distinct forms of authority:

1. The bootstrap authority may admit a new device once. Its credential is not a
   general API credential and must be removed after enrollment.
2. The online management service may authenticate devices, assign a device to a
   rollout ring, revoke enrollment, and choose among policy bundles already
   approved for that ring.
3. The offline policy signer alone may authorize response and integrity
   behavior. A compromised management service can withhold or replay available
   content, but endpoint anti-rollback state prevents it from lowering policy
   sequence or changing content at an accepted sequence.

TLS authenticates and protects the network connection. Device request
signatures add application-level identity and replay binding; they do not
replace normal certificate validation. Local administrator or kernel compromise
remains outside the endpoint trust boundary.

## Device identity

The production endpoint identity is an ECDSA P-256 key created in the Windows
machine key store as non-exportable key material. The stable device ID is a
random 128-bit value, not a hostname, user name, MAC address, or other reusable
personal identifier. The enrollment record stores:

- device ID;
- SHA-256 fingerprint of the SubjectPublicKeyInfo bytes;
- server-issued enrollment ID;
- assigned rollout ring;
- credential sequence and validity window;
- revocation generation observed by the endpoint; and
- the management service origin.

The state file contains no private key. Its directory receives a restricted ACL
during installation, and every replacement is atomic and fail closed.

Lifecycle operations distinguish creation from repair. Repair only validates an
existing state/key pair and will not create a replacement if either side is
missing. Rotation and removal require the exact current device ID and archive
the validated state atomically on the same volume before deleting the old CNG
key. A rotation creates a new random device ID and non-exportable key and
therefore requires new enrollment; archived state is recovery evidence, not an
active credential.

### Windows lifecycle commands

Run these commands from an elevated PowerShell 7 session. `AssemblyDirectory`
is the published directory containing `UtoAegis.Core.dll` and
`UtoAegis.Infrastructure.dll`. The default state root is
`C:\ProgramData\UtoAegis\Management`.

```powershell
pwsh ./scripts/windows/Install-UtoAegisEnrollment.ps1 `
  -AssemblyDirectory 'C:\Program Files\UtoAegis'

pwsh ./scripts/windows/Repair-UtoAegisEnrollment.ps1 `
  -AssemblyDirectory 'C:\Program Files\UtoAegis'

pwsh ./scripts/windows/Rotate-UtoAegisEnrollment.ps1 `
  -AssemblyDirectory 'C:\Program Files\UtoAegis' `
  -ExpectedDeviceId '<current-32-character-device-id>'

pwsh ./scripts/windows/Remove-UtoAegisEnrollment.ps1 `
  -AssemblyDirectory 'C:\Program Files\UtoAegis' `
  -ExpectedDeviceId '<current-32-character-device-id>'
```

All commands support `-WhatIf` and require administrator elevation. The state
root rejects filesystem roots and reparse points, disables inherited ACLs, and
grants full control only to Local System and Administrators by default. A
separate `-StateConsumerIdentity` may receive modify access when a dedicated
management host requires it. Archives must remain beneath the state root.

Installation is idempotent only for the exact existing state/key pair. Repair
fails rather than creating missing identity. Rotation and removal emit the
archive path and set `reEnrollmentRequired` in their result. Do not delete an
archive until the old server enrollment has been revoked and incident or audit
retention requirements have been satisfied.

## Signed request envelope

Every enrolled request signs canonical UTF-8 bytes containing:

- schema version;
- device and enrollment IDs;
- credential sequence;
- UTC request timestamp;
- a 128-bit random nonce;
- uppercase HTTP method;
- absolute request path and query; and
- lowercase SHA-256 digest of the exact request body.

The signature uses ECDSA P-256 with SHA-256 in IEEE P1363 format. The server
checks the stored public key, bounded clock skew, one-time nonce, exact method,
path, body digest, credential status, and revocation generation before handling
the request.

All post-enrollment handlers use one admission coordinator. It loads the
enrollment record by ID, requires the exact device and current credential
sequence, active status, and unexpired validity, verifies the stored public-key
fingerprint and signature against the exact method, target, and body, then
reserves the nonce durably. Invalid signatures never consume a nonce, while a
successfully authenticated nonce remains unavailable for the complete request
validity window.

## Policy distribution flow

```text
endpoint creates non-exportable key + random device ID
        |
        | bootstrap token + public key + proof of private-key possession
        v
management enrollment endpoint
        |-> consumes bootstrap token exactly once
        |-> assigns enrollment ID and rollout ring
        |-> returns bounded enrollment credential
        v
endpoint stores credential atomically
        |
        | signed poll request + current policy sequence/hash
        v
management policy endpoint
        |-> authenticates device and ring
        |-> returns no-change, revocation, or an offline-signed policy bundle
        v
endpoint verifies policy signature, expiry, ring, and anti-rollback state
        |-> publishes policy atomically
        |-> persists pending acknowledgement
        v
signed acknowledgement + bounded health snapshot
        |-> server confirms exact acknowledgement ID
        |-> endpoint marks acknowledgement delivered
```

Policy download and acknowledgement are separate operations. A lost network
response therefore cannot make an unpersisted application look successful or
make a successfully applied policy disappear from fleet health.

After policy activation, the endpoint atomically records a pending
acknowledgement containing a random acknowledgement ID and the exact device,
enrollment, policy ID, sequence, manifest SHA-256, and application time. A retry
reuses the same canonical acknowledgement. The record remains pending until
the server confirms that exact acknowledgement ID; a different policy cannot
replace it while delivery is pending, and a different confirmation cannot mark
it delivered.

## Staged rollout

Rollout rings use short validated identifiers such as `canary`, `pilot`, and
`stable`. Enrollment assigns exactly one ring. An offline-signed policy release
lists the rings for which it is valid. Both the management service and endpoint
must enforce that list. Promotion means publishing the same signed policy to a
broader authorized ring or signing a new higher-sequence policy; it never means
editing signed bytes.

The distribution package has one regular `policy` directory containing the
existing `policy.json` and `policy.sig` files, plus regular
`authorization.json` and `authorization.sig` files. No other entries or
reparse points are accepted. The signed authorization binds its own sequence,
the exact runtime-policy ID and sequence, the SHA-256 digest of the
exact policy manifest bytes, the allowed rollout rings, a bounded validity
window, and the offline policy-authority key ID.

The endpoint verifies the authorization signature and time window, requires a
currently active and unexpired enrollment in an allowed ring, verifies the
runtime-policy signature and time window, and compares the policy identity,
sequence, and manifest digest in constant time where appropriate. The verified
runtime policy then passes through the existing durable anti-rollback store
before activation. The management service cannot add a ring or substitute a
different policy without invalidating the offline signature.

## Revocation

The management service maintains a monotonic revocation generation. A device
credential may be active, suspended, or revoked. Revoked devices receive no new
policy and their health reports are rejected. Endpoints persist the highest
observed generation and reject lower values. Revocation cannot remotely erase
local policy or telemetry; operators must use incident-response procedures for
containment and re-enrollment.

Credential refresh is a single verify-and-persist operation. An authenticated
suspension or revocation is committed atomically before the operation reports
that the enrollment is inactive. On restart, management and policy operations
load the durable snapshot and require active, unexpired state. Once revoked,
the enrollment cannot become active again through a later credential; recovery
requires an explicit local reset and a new enrollment.

## Bounded fleet health

The health snapshot includes only protocol version, device and enrollment IDs,
agent version, rollout ring, current policy identity/sequence/hash, last policy
verification result, monitor/updater/telemetry/guard status, last successful
contact, and a bounded list of stable error codes. It excludes file paths,
usernames, process command lines, file contents, and arbitrary log text.

The schema permits at most 16 error identifiers of at most 64 safe ASCII
characters each. Component and verification values are closed enums, timestamps
are UTC, error identifiers are normalized and sorted, and the complete document
has deterministic canonical bytes suitable for the signed request envelope.

## Implementation stages

1. Device identity, request canonicalization, signing, strict validation, and
   durable enrollment state.
2. One-time bootstrap enrollment and credential/revocation persistence.
3. Ring-authorized signed-policy distribution with local anti-rollback checks.
4. Durable acknowledgement and bounded fleet-health reporting.
5. Windows installation, ACL, rotation, recovery, and removal workflows.
6. End-to-end integration tests, release packaging, operator documentation, and
   CI verification.

## Non-goals

- This milestone does not build the customer-facing desktop interface.
- It does not move policy, release, or threat-content signing keys online.
- It does not collect general endpoint inventory or user activity.
- It does not claim a local administrator or kernel attacker can be remotely
  contained by endpoint software alone.
- It does not yet provide a multi-tenant commercial cloud control plane; the
  protocol and reference coordinator remain deployable as one bounded service.

