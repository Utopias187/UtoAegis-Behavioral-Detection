# Authenticated Runtime Policy and Integrity Guard

Milestone 14 moves response policy and endpoint integrity expectations out of
locally editable service configuration and into an offline-signed policy bundle.
The monitor verifies that bundle before startup. A separate one-shot Guard audits
Windows service configuration, executable hashes, and selected filesystem
security descriptors without granting the monitor, updater, or telemetry service
additional privileges.

Automatic recovery is deliberately separate from the long-running services. An
administrator can register the Guard as a SYSTEM scheduled task, but both the
signed policy and an explicit installer switch must authorize recovery. Every run
writes to an independent tamper-evident telemetry spool.

## Trust boundaries

```text
offline ECDSA P-256 key
          |
          | signs exact policy.json bytes
          v
policy.json + policy.sig -----> monitor startup verification
          |                       |-> response rules
          |                       |-> sequence/hash anti-rollback state
          |
          +--------------------> SYSTEM scheduled Guard
                                  |-> query SCM configuration
                                  |-> hash protected executables
                                  |-> compare owner/group/DACL
                                  |-> optional bounded exact repair
                                  |-> independent telemetry chain
                                                   |
                                      read-only telemetry forwarder
```

The signing private key must remain off endpoints. Endpoints receive only one or
more P-256 public keys. Policy and threat-content keys may be operationally
separate even though both use the same algorithm.

The Guard runs only when Task Scheduler launches it. Existing UtoAegis services
keep their existing virtual accounts and permissions. The Guard's SYSTEM token is
powerful, so its installation directory, policy bundle, configuration, state,
and scheduled task must remain administrator-controlled.

## Signed bundle

A bundle is a regular directory containing exactly:

```text
policy\
  policy.json
  policy.sig
```

`policy.sig` is a base64 DER ECDSA P-256 signature over the exact bytes of
`policy.json` using SHA-256. The strict JSON reader rejects comments, trailing
commas, duplicate or unknown properties, a UTF-8 byte-order mark, unsupported
schema or algorithms, unsafe paths, duplicate targets, excessive collections,
invalid response rules, and invalid recovery bounds.

The policy binds:

- a monotonic sequence, policy identifier, key identifier, issue time, and
  expiration time;
- the monitor's response mode, allowlisted paths and hashes, and quarantine
  rate limit;
- each protected service's name, executable path and SHA-256, service account,
  start mode, and recovery authorization;
- each protected file or directory's owner, group, DACL SDDL, and recovery
  authorization; and
- the audit interval plus a maximum recovery count and time window.

The monitor and Guard share policy anti-rollback state. A higher sequence is
accepted atomically. The same sequence is accepted only when the manifest hash
is identical, which permits safe restarts. Lower sequences and changed content
at the same sequence fail closed.

## Deployment order

Use a controlled, known-good Windows staging endpoint. Do not capture a baseline
from a machine that may already be compromised.

1. Install and configure the monitor and updater with their normal
   least-privilege identities and telemetry spools.
2. Add the `guard` source to the telemetry forwarder's `Sources` array. The
   repository template already contains it. If the Guard spool does not yet
   exist, install the forwarder with the explicit preparation switch:

   ```powershell
   pwsh ./scripts/windows/Install-UtoAegisTelemetry.ps1 `
     -PublishDirectory 'C:\Program Files\UtoAegisTelemetry' `
     -CreateMissingSourceSpools `
     -Start
   ```

3. Confirm service paths, accounts, start modes, executable hashes, and every
   ACL that will become policy. Export an unsigned definition:

   ```powershell
   pwsh ./scripts/windows/Export-UtoAegisRuntimePolicyDefinition.ps1 `
     -PolicyId 'production-endpoints' `
     -Sequence 1 `
     -KeyId 'runtime-policy-2026' `
     -OutputPath './policy-definition.json' `
     -ProtectedPath 'C:\Program Files\UtoAegis' `
     -ProtectedPath 'C:\ProgramData\UtoAegis' `
     -EnableServiceRecovery `
     -EnableAclRecovery
   ```

   Recovery switches only mark captured entries as recoverable. The signed
   maximum and window still bound attempts. Password-backed service accounts can
   be audited but cannot be marked automatically recoverable because the Guard
   never stores service passwords.

4. Transfer the definition to the offline signing environment and create the
   two-file bundle:

   ```powershell
   pwsh ./scripts/windows/Protect-UtoAegisRuntimePolicy.ps1 `
     -DefinitionPath './policy-definition.json' `
     -PrivateKeyPath './runtime-policy-private.pem' `
     -OutputDirectory './signed-policy'
   ```

5. Transfer only the signed bundle and public key to the endpoint. Configure the
   monitor:

   ```json
   {
     "RuntimePolicy": {
       "BundlePath": "C:\\ProgramData\\UtoAegisGuard\\Policy",
       "StatePath": "C:\\ProgramData\\UtoAegis\\PolicyState\\runtime-policy-state.json",
       "TrustedSigningKeys": [
         {
           "KeyId": "runtime-policy-2026",
           "PublicKeyPath": "C:\\ProgramData\\UtoAegisGuard\\Keys\\runtime-policy-2026.pem"
         }
       ]
     }
   }
   ```

   Validate and restart the monitor. Authenticated response settings replace the
   local `Response` section. Quarantine still requires a configured vault.

6. Publish the Guard, configure its `appsettings.json` with the same policy,
   state, public key, deployment identifier, and independent telemetry spool,
   then install the scheduled task:

   ```powershell
   pwsh ./scripts/windows/Publish-UtoAegisGuard.ps1 `
     -OutputDirectory 'C:\Program Files\UtoAegisGuard'

   pwsh ./scripts/windows/Install-UtoAegisGuard.ps1 `
     -PublishDirectory 'C:\Program Files\UtoAegisGuard' `
     -IntervalMinutes 5 `
     -EnableRecovery `
     -Start
   ```

   Omit `-EnableRecovery` for audit-only deployment. This installer removes
   inherited ACLs from Guard-owned directories, grants SYSTEM and Administrators
   full access, grants the monitor read access to policy and keys plus modify
   access to shared anti-rollback state, and grants the telemetry forwarder
   read-only access to the Guard spool.

7. Inspect Task Scheduler status and the last result:

   ```powershell
   pwsh ./scripts/windows/Get-UtoAegisGuardStatus.ps1
   ```

   Exit `0` means the audited state is healthy or was fully recovered. Exit `3`
   means drift remains. Exit `4` means policy, telemetry, inspection, or recovery
   failed. The scheduled task uses `IgnoreNew`, so overlapping recovery runs are
   not created.

If Guard installation changes an ACL that should itself be monitored, export and
sign a higher-sequence policy after installation. Never replace a bundle with
different content at the same sequence.

## Audit and recovery behavior

Every run checks:

- protected services exist;
- SCM binary paths contain only the expected fully qualified executable and no
  arguments;
- service accounts and automatic, delayed-automatic, manual, or disabled start
  modes match policy;
- executable paths are regular files and their SHA-256 values match; and
- protected paths are regular files or directories whose normalized owner,
  group, and DACL match signed SDDL.

The Guard never reconstructs executables, recreates missing services or paths,
follows reparse points, or invents a desired ACL. Those findings remain visible
for release redeployment or administrator investigation.

When recovery is enabled in both task and policy, the Guard can restore signed
SCM path, account, and start-mode values. A service that was running is stopped,
corrected, restarted, and checked within a 30-second bound; a service that was
stopped remains stopped, and a policy-disabled service is not restarted. The
Guard can also restore the exact signed owner, group, and DACL. Multiple findings
for one service consume one recovery operation.

One persistent reservation covers a Guard run. Attempts outside the signed time
window are pruned, and the maximum count fails closed. A higher authenticated
policy sequence starts a new budget. Corrupted or unsafe recovery state stops
recovery rather than resetting the counter.

## Telemetry

The Guard writes source `guard` records to its own chain. `integrity.audit`
contains policy identity and hash, finding counts, bounded finding details,
recovery intent, whether recovery ran, and whether it was rate-limited.
`integrity.guardFailed` records bounded error type and message when configuration,
policy, SCM, ACL, state, or telemetry work fails.

Initial findings remain in the audit result even when recovery succeeds, so the
collector can distinguish a continuously healthy endpoint from one that drifted
and was repaired. The forwarder has read-only access to this third producer
spool and maintains an independent checkpoint.

## Policy rotation and incident response

- Increase the sequence for every content change, including new release paths,
  hashes, accounts, ACLs, response rules, or recovery bounds.
- Use overlapping public-key trust during a key rotation, sign the new higher
  sequence with the new key, verify fleet acceptance, then remove the old key.
- Treat an unexpected policy rejection, executable-hash change, missing service,
  unsafe reparse point, repeated recovery, or exhausted budget as an incident.
- Preserve the Guard spool and collector anchor before repairing or reimaging an
  endpoint.
- Use the signed release installer to restore missing or modified binaries; the
  Guard intentionally does not copy executable content.

## Trust limits

This design detects and bounds drift relative to an authenticated baseline. It
does not make a Windows endpoint tamper-proof against a local administrator or
kernel compromise. A local administrator can disable Task Scheduler, stop the
forwarder, delete state, or replace the operating system. Collector-retained
telemetry anchors and missing-heartbeat alerts are required to make those
actions visible off endpoint.

The policy private key protects the authority to define executable paths,
service identities, ACLs, and response behavior; compromise of that key is a
high-severity event. The current workflow distributes policy out of band and
requires a monitor restart to adopt response changes. Scheduled-task definition
drift and remote policy rollout are not yet monitored by the Guard.
