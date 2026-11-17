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

## Staged rollout

Rollout rings use short validated identifiers such as `canary`, `pilot`, and
`stable`. Enrollment assigns exactly one ring. An offline-signed policy release
lists the rings for which it is valid. Both the management service and endpoint
must enforce that list. Promotion means publishing the same signed policy to a
broader authorized ring or signing a new higher-sequence policy; it never means
editing signed bytes.

## Revocation

The management service maintains a monotonic revocation generation. A device
credential may be active, suspended, or revoked. Revoked devices receive no new
policy and their health reports are rejected. Endpoints persist the highest
observed generation and reject lower values. Revocation cannot remotely erase
local policy or telemetry; operators must use incident-response procedures for
containment and re-enrollment.

## Bounded fleet health

The health snapshot includes only protocol version, device and enrollment IDs,
agent version, rollout ring, current policy identity/sequence/hash, last policy
verification result, monitor/updater/telemetry/guard status, last successful
contact, and a bounded list of stable error codes. It excludes file paths,
usernames, process command lines, file contents, and arbitrary log text.

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

