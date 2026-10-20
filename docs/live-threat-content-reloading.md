# Live Threat-Intelligence Reloading

Milestone 11 lets the Windows monitoring service consume a newly activated
threat-content generation without restarting. The separately privileged updater
still owns download, validation, activation, and retention writes. The monitor
continues to receive read-only access to content and public signing keys.

## Reload flow

At startup the service fully verifies and leases the active generation. While
monitoring, it reads the small authenticated-content state pointer every
`ContentReloadIntervalSeconds`. If the version and sequence are unchanged, no
payload or database work occurs.

When the pointer changes, the service:

1. Opens a read lease on the candidate reputation database.
2. Rechecks the manifest signature with the startup trust store.
3. Rehashes both signed payloads and strictly parses both feeds.
4. Confirms the derived SQLite database matches the signed indicator feed.
5. Builds a complete reputation and byte-signature scanner off to the side.
6. Atomically publishes that scanner as one new generation.

Each scan captures exactly one generation before its first detection stage. A
reload cannot combine a hash result from one generation with reputation or
signature results from another.

```text
updater -> verify + activate -> atomic state pointer
                                  |
read-only monitor -> detect change -> reverify + build candidate
                                      | success -> atomic generation swap
                                      | failure -> keep last-known-good scanner
in-flight old scan -> generation lease -> finish -> release old content
```

## Configuration

Live reload is enabled automatically when `ContentStorePath` and
`TrustedSigningKeys` configure managed content:

```json
{
  "UtoAegis": {
    "ContentStorePath": "C:\\ProgramData\\UtoAegis\\Content",
    "ContentReloadIntervalSeconds": 30,
    "TrustedSigningKeys": [
      {
        "KeyId": "production-2026",
        "PublicKeyPath": "C:\\ProgramData\\UtoAegis\\Policy\\production-2026.public.pem"
      }
    ]
  }
}
```

The reload interval accepts 5 through 3,600 seconds and defaults to 30. Direct
`DatabasePath` or `SignaturePath` deployments remain startup-only because they
have no authenticated generation pointer.

Signing keys are intentionally loaded at service startup. Changing trust policy
still requires controlled service validation and restart; an untrusted content
bundle cannot introduce its own key.

## Failure and rollback behavior

A malformed state file, unknown key, invalid signature, changed payload,
unreadable database, or invalid signature rule rejects the candidate. The
currently loaded scanner continues handling new and in-flight scans. The first
identical failure emits a warning; repeated polls increase the health failure
counter without repeating the same warning continuously.

An operator rollback changes the active pointer to the reverified previous
generation. The monitor treats that pointer change like any other valid reload,
including a lower active sequence. The store's separate highest-accepted
sequence remains unchanged, so the rollback does not weaken update replay
protection.

## Generation leases and retention

The monitor keeps a read handle on each loaded generation's reputation database.
The updater probes for an exclusive handle before deleting an unreferenced
version. A busy version is reported as pinned and retained beyond the configured
retention target until all scans using it drain. A later updater cycle can prune
it normally.

This coordination uses Windows file-sharing semantics and does not grant the
monitor write access. Active and rollback references remain protected by store
state independently of read leases.

## Event Log visibility

- Event 104 records the startup generation.
- Event 105 records a successful generation change.
- Event 106 reports version, sequence, scanner generation, reload count,
  rejection count, and the last check time.
- Event 302 warns when active last-known-good content is expired.
- Event 303 reports the first occurrence of a repeated reload failure while
  confirming which generation remains active.

Reload and rejection counters are process-local health data. Central collection
and durable delivery are not part of this milestone.

## Operational limitations

- Reload discovery is bounded polling rather than a cross-service notification.
- Trust-key configuration, response policy, and direct detection paths still
  require a service restart.
- The service keeps the last-known-good scanner in memory but does not rewrite a
  bad active pointer or automatically invoke store rollback.
- Event Log data has no built-in remote delivery or delivery SLA.
- Local administrator compromise remains inside the host trust boundary.
