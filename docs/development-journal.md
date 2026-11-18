# UtoAegis Development Journal

This journal records engineering decisions, verification results, and known
limitations for each completed milestone. It is not a replacement for API
documentation or issue tracking.

## 2026-10-02 — Milestone 1: SHA-256 file scanner

### Goal

Create the smallest useful scanning foundation: accept one file path, calculate
its SHA-256 digest without executing or modifying the file, and return a result
that future detection components can consume.

### Decisions

- Use C# for the initial Windows product because the available .NET platform
  provides maintained cryptography and file APIs and leaves a direct path to a
  Windows service or desktop UI.
- Keep scanning logic in `UtoAegis.Core`. The CLI is an adapter and contains no
  hashing logic.
- Expose the scanner through `IFileHashScanner` so later orchestration code does
  not depend on one implementation.
- Stream files asynchronously instead of loading them into memory. The default
  stream buffer is 1 MiB.
- Return explicit statuses for expected file-access failures. Cancellation
  remains an exception because callers commonly compose it through cancellation
  tokens.
- Write scan results to standard output and operational logs to standard error,
  allowing scripts to consume output without discarding diagnostics.
- Do not assign a security verdict. A digest is an identifier; an unknown digest
  is not evidence that a file is safe.

### Security notes

The scanner opens files read-only and requests sequential access. It prevents
new write handles while its read handle is open, then compares size and
last-write metadata before accepting the digest. This detects common mutation
cases but does not eliminate every time-of-check/time-of-use race. Any future
quarantine action must revalidate file identity immediately before acting.

Paths appear in operational logs and may disclose usernames or directory names.
Production log storage will need access controls and a retention policy.

### Verification

- Release build completed with zero warnings.
- Eight automated tests passed, covering known content, an empty file, missing
  files, directories, invalid paths, sharing violations, cancellation, and
  invalid scanner configuration.
- Human-readable and JSON CLI output were exercised successfully.
- Missing-file behavior returned the documented process exit code `3`.
- A synthetic 64 MiB file was streamed in approximately 303 ms on the initial
  development machine (about 211 MiB/s). This is a smoke benchmark, not a
  production performance guarantee.

### Known limitations

- There is no malicious-hash database or verdict engine yet.
- There is no recursive scanning, persistent history, or quarantine.
- Mutation detection is metadata-based and intentionally best effort.
- The project currently targets .NET 8 to match the installed toolchain. It must
  move to a supported long-term release before production distribution.

### Next milestone

Add a versioned local malware-hash database behind an
`IHashReputationStore` interface. Imports must validate SHA-256 values and use a
transaction; lookups must distinguish malicious, unknown, and lookup failure.

## 2026-10-02 — Milestone 2: malware hash database

### Goal

Turn the SHA-256 digest into a useful detection signal by comparing it with a
local, versioned database of malicious indicators. Preserve the distinction
between an absent indicator and a trustworthy clean verdict.

### Decisions

- Keep `IHashReputationStore`, indicator validation, and result types in the
  dependency-free core project. SQLite remains an infrastructure detail.
- Use Microsoft.Data.Sqlite with a strict version-one schema. SHA-256 is the
  primary key, making exact lookup indexed without another index.
- Represent lookup outcomes as `Malicious`, `Unknown`, or `LookupFailed`.
  Operational failure is never collapsed into an unknown result.
- Validate a complete JSON Lines feed before opening the write transaction.
  Conflicting duplicate hashes reject the file; identical duplicates are
  counted and ignored.
- Use parameterized upserts inside one transaction. A repeated identical import
  is idempotent and does not rewrite its update timestamp.
- Limit import size, line length, nesting depth, indicator count, text length,
  and accepted JSON properties to bound resource usage and reduce ambiguity.
- Return exit code `10` for a detection so automation can distinguish a threat
  signal from scanner or database failure.

### Verification

- Release builds complete with zero warnings.
- Twenty-three automated tests pass across the core and infrastructure suites.
- Tests cover normalization, validation, missing and matched hashes, idempotent
  imports, unsupported schema versions, malformed JSON, conflicting duplicates,
  duplicate JSON properties, database corruption, and transaction rollback.
- End-to-end CLI verification imported the harmless sample, returned
  `Malicious` with exit code `10` for the matching file, and returned `Unknown`
  with exit code `0` for an absent digest.
- A 10,001-indicator synthetic feed imported in approximately 2.35 seconds on
  the development machine after preparing the upsert command once. This is a
  smoke benchmark rather than a performance guarantee.

### Security notes

The database materially influences detection results and is therefore trusted
security data. SQLite integrity checks and schema constraints protect against
accidental invalid data, not a local attacker who can replace the database.
Signed feeds, authenticated updates, and locked-down file permissions are
required before remote threat-intelligence updates are accepted.

The current schema stores one source record per digest. A later import can
replace that metadata. Multi-source observations, trust ranking, revocation,
and feed provenance should be added with threat-intelligence integration rather
than improvised inside the scanner.

### Known limitations

- Only exact SHA-256 matches are supported; there are no byte-pattern rules.
- Indicators and databases are not cryptographically signed.
- The store does not yet model indicator expiry, revocation, or several sources
  reporting the same digest.
- The project still targets .NET 8 to match the installed toolchain and must
  move to a supported long-term release before production distribution.

### Next milestone

Add signature-based scanning behind its own interface. Start with a constrained
rule model and harmless byte-pattern fixtures, measure streaming performance,
and evaluate YARA only after the integration boundary and safety behavior are
proven.

## 2026-10-02 — Platform hardening before Milestone 3

### Goal

Move off the near-end-of-support .NET 8 baseline and make dependency and build
verification reproducible before signature-scanning work begins.

### Decisions

- Target .NET 10 across the solution from `Directory.Build.props` rather than
  repeating the target framework in every project.
- Add `global.json` with a .NET 10 minimum and latest-feature roll-forward so
  supported .NET 10 feature bands can build the repository.
- Upgrade Microsoft.Data.Sqlite to 10.0.12 while retaining MSTest 4.4.1, which
  already supports .NET 10.
- Manage direct package versions in `Directory.Packages.props` and commit a lock
  file for every project.
- Audit direct and transitive dependencies during restore, treating NuGet
  vulnerability advisories NU1901 through NU1904 as build errors.
- Run locked restore, release build, tests, and a vulnerability report in GitHub
  Actions. Pin third-party workflow actions to full commit hashes.
- Schedule weekly Dependabot checks for both NuGet packages and workflow actions.

### Verification

- The repository selected .NET SDK 10.0.401 through `global.json`.
- Locked restore completed for all five projects.
- Release build completed with zero warnings and zero errors.
- All 23 automated tests passed on `net10.0`.
- NuGet reported no known vulnerable direct or transitive packages.

### Milestone 3 readiness

The platform upgrade does not change scanner behavior or database schema.
Milestone 3 can add signature scanning behind a new independent interface while
the existing hash and reputation contracts remain stable.

## 2026-10-15 — Milestone 3: signature-based scanner

### Goal

Add a second local detection layer that can identify known byte sequences
without executing or loading an entire scanned file into memory. Keep the
engine replaceable so richer rule technology can be evaluated independently.

### Design and data flow

- `ByteSignatureRule` validates and normalizes bounded rule metadata and exact
  hexadecimal patterns.
- `ISignatureScanner` separates orchestration from the first implementation.
- `FixedByteSignatureScanner` reads a file in 1 MiB chunks and retains only the
  overlap needed to find a pattern crossing a chunk boundary.
- `JsonLinesSignatureRuleReader` treats rule files as untrusted input and fully
  validates them before constructing a scanner.
- The CLI optionally runs hash reputation and signature detection together,
  reports each signal independently, and returns detection exit code `10` if
  either engine matches.

```text
rules.jsonl -> strict reader -> validated rules --|
                                                  |-> fixed-byte scanner -> matches
file path ----------------------------------------|
```

The scanner reports the first offset for every matching rule. It continues to
the end of the file so read errors and file changes cannot be hidden by an
early match. `Detected`, `NoMatch`, and operational failures are distinct.

### Security review

- Files are opened read-only with sequential access and are never executed.
- Rule count, pattern length, line length, nesting depth, and rule-file size are
  bounded to limit memory and CPU abuse.
- Shared byte buffers are cleared before being returned to `ArrayPool`.
- Size and last-write metadata are checked during each read. The CLI also takes
  a metadata snapshot around the combined workflow so hash and signature
  results are discarded if a common mutation is observed between stages.
- Metadata checks remain best effort. A privileged attacker may preserve or
  restore metadata, so future quarantine must reopen and revalidate the target.
- Exact byte signatures can produce false positives. Matches retain rule ID,
  name, source, byte offset, and pattern length so decisions remain auditable.
- Rule files affect verdicts and are trusted security data. Production updates
  will require authentication, signing, rollback protection, and source policy.

### YARA-X evaluation

[YARA-X](https://virustotal.github.io/yara-x/docs/) supports text, hexadecimal,
and regular-expression patterns combined with boolean rule conditions and file
format modules. Its native API separates rule compilation from scanning and
supports timeouts and reusable compiled rules. Those capabilities are useful,
but native distribution, lifecycle management, rule compatibility, resource
limits, and failure isolation need a dedicated integration milestone.

The current engine therefore remains intentionally small rather than
implementing a partial YARA language. A future YARA-X adapter can implement
`ISignatureScanner` while preserving the CLI and result boundary established
here.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 63 automated tests passed: 34 core, 22 infrastructure, and 7 CLI tests.
- Tests cover validation, chunk-boundary matches, stable match ordering,
  duplicate rules, malformed JSON, file and line limits, cancellation, access
  failures, and cross-stage metadata changes.
- A 16 MiB file with 32 nonmatching rules completed within the 30-second smoke
  limit; the complete core test assembly ran in under one second on the
  development machine. This is a regression signal, not a production SLA.
- End-to-end CLI checks returned `10` for the harmless demonstration match, `0`
  for a no-match scan, and `6` for an unavailable rule file. JSON output was
  also verified.

### Known limitations

- Rules support only exact, contiguous byte patterns. There are no wildcards,
  regular expressions, conditions, namespaces, or executable-format modules.
- Matching cost grows with both file size and rule count. A production-scale
  rule corpus will require a multi-pattern algorithm or a vetted YARA-X adapter.
- Only the first match per rule is retained to bound result growth.
- Rule files are local and unsigned, with no update or revocation mechanism.
- Results are emitted to the console but are not yet stored as detection history.

### Definition of done

- [x] Stable signature scanner interface and explicit outcomes exist.
- [x] Streaming matching detects patterns inside and across read buffers.
- [x] Strict rule parsing rejects ambiguous or unbounded input.
- [x] CLI human, JSON, logging, and exit-code behavior is integrated.
- [x] Harmless positive and negative paths are verified.
- [x] Error handling, cancellation, mutation checks, and performance are tested.
- [x] Security decisions, false-positive risk, and limitations are documented.

### Next milestone

Build directory and recursive scanning on top of the existing single-file
engines. Traversal must bound concurrency, avoid directory links by default,
continue after per-file failures, and produce a deterministic summary without
calling any `NoMatch` or `Unknown` file clean.

## 2026-10-15 — Milestone 4: directory and recursive scanner

### Goal

Apply the established hash, reputation, and signature stages to a directory
without turning traversal into an unbounded or misleading operation. Preserve
an explicit outcome for each scanned file and distinguish complete, partial,
failed, and detected runs for both people and automation.

### Design and data flow

- `IFileScanner` and `CompositeFileScanner` compose the existing per-file
  stages and enforce one cross-stage metadata-consistency boundary.
- `IDirectoryScanner` and `DirectoryScanner` discover regular files before
  scanning them with bounded asynchronous concurrency.
- Nonrecursive traversal is the default; recursion requires `--recursive`.
- Default limits are 100,000 files, 50,000 directories, depth 64, and four
  concurrent scans. The corresponding absolute maxima are 1,000,000, 250,000,
  256, and 32.
- A hard discovery-limit failure prevents scanning an incomplete file set.
- Files and issues are sorted with ordinal path ordering so output does not
  depend on filesystem enumeration or task completion order.
- Configured rule and database files are excluded from directory scans. SQLite
  sidecar files are also excluded. Exclusions remain visible as issues and make
  the result partial.

```text
root -> bounded discovery -> sorted regular files -> bounded workers
                                                  -> composite file scanner
                                                  -> per-file results + summary
```

The CLI exposes `scan-directory`, `--recursive`, and `--max-concurrency` while
reusing `--database`, `--signatures`, `--json`, and `--quiet`. Exit code `7`
means the directory scan failed, `8` means partial without a detection, `10`
means detection in a complete scan, and `11` means detection with partial
coverage.

### Security review

- A reparse-point root is rejected and discovered file or directory reparse
  points are skipped. The scanner does not intentionally leave the requested
  tree through junctions or symbolic links.
- Every discovered file is revalidated immediately before its scan. A file
  that disappears, becomes a directory, or becomes a reparse point is skipped
  and reported rather than silently accepted.
- Filesystem checks remain best effort. Entries can change after validation,
  and metadata checks cannot prove stable identity against a capable local
  attacker. A future enforcement action must reopen and revalidate its target.
- Traversal work, concurrency, and retained result counts are bounded. The
  current discovery-first design still uses memory proportional to the number
  of discovered files, up to the configured limit.
- Access-denied, disappeared, excluded, and I/O-affected entries make the run
  partial. The interface never describes `Unknown` or `NoMatch` as clean.
- Paths are included in results and operational logs. Retention, access
  control, and path minimization are requirements for persistent history.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 91 automated tests passed: 54 core, 22 infrastructure, and 15 CLI tests.
- Tests cover recursive and nonrecursive traversal, stable ordering, reparse
  handling, depth and item limits, invalid roots, partial results, cancellation,
  bounded concurrency, CLI parsing, and exit-code precedence.
- A race test removes a file after discovery and confirms it is skipped and
  reported during pre-scan revalidation.
- A real 1,000-file recursive SHA-256 smoke scan completed inside its 30-second
  limit; the complete core test assembly ran in approximately five seconds on
  the development machine. This is a regression signal, not a production SLA.
- End-to-end CLI checks verified complete, partial, detected, failed, human,
  and JSON result paths.

### Known limitations

- Traversal is discovery-first rather than streamed through a bounded channel.
  This simplifies deterministic limits but retains all discovered paths and
  all completed results in memory.
- Reparse-point avoidance and metadata checks do not provide a transactional
  filesystem snapshot.
- There is no ignore-pattern language, incremental scan cache, archive
  expansion, scheduled scanning, or quarantine.
- Results are returned and logged but are not persisted as detection history.

### Definition of done

- [x] Existing per-file engines are composed behind a reusable interface.
- [x] Directory and opt-in recursive discovery have explicit safety limits.
- [x] Link handling, entry changes, partial coverage, and failures are visible.
- [x] File work is parallel but bounded; final results are deterministic.
- [x] CLI human, JSON, logging, and exit-code behavior are integrated.
- [x] Race, cancellation, failure, limit, and performance paths are tested.
- [x] Security assumptions, memory behavior, and limitations are documented.

### Next milestone

Add detection history and structured logging behind an independent persistence
interface. Store scan-level and per-file outcomes, define retention and privacy
policies, and avoid mixing append-only operational history with the trusted
reputation database.

## 2026-10-15 — Milestone 5: detection history and structured logging

### Goal

Make scan outcomes auditable across CLI invocations without coupling the scan
engines to one database. Preserve enough structured evidence to explain a
detection or failure while keeping persistence optional because paths and
hashes are sensitive operational data.

### Design and data flow

- `IScanHistoryStore` defines initialization, immutable append, summary listing,
  full-record retrieval, and retention pruning independently of SQLite.
- `ScanHistoryRecord` projects file and directory results into one stable model
  containing target metadata, timing, outcome, files, signature matches, and
  traversal issues.
- `SqliteScanHistoryStore` uses a database separate from malicious reputation
  data. An application ID and schema version reject unrelated or newer files.
- One transaction inserts a scan header and all child rows. Duplicate scan IDs
  fail, and a failed child insert rolls back the complete record.
- Summary queries are capped at 200 rows. Full records validate stored counts
  against their file, detection, failure, match, and issue details.
- Foreign-key cascades make retention deletion atomic for each scan graph.
- Every scan receives a GUID used by operational JSON Lines logs, persisted
  history, JSON results, and `history show`.

```text
scan result -> history projection -> IScanHistoryStore -> SQLite transaction
     |                                                        |
     +-> correlated JSON Lines logs                           +-> list/show/prune
```

History capture is enabled with `--history <path>`. `history list` returns
recent summaries, `history show` returns one complete record, and `history
prune --older-than-days <days>` deletes records before the calculated UTC
cutoff. A missing database is rejected by management commands rather than
silently created after a path typo.

### Failure and exit-code behavior

- History initialization failure prevents a requested history-enabled scan
  from starting and returns exit code `9`.
- A post-scan write failure returns `9` when there was no detection and `12`
  when there was a detection. Code `12` preserves both facts: security evidence
  was found, and the requested audit record was not stored.
- Operational logs use standard error, result output uses standard output, and
  `--quiet` suppresses logs without suppressing storage failures.
- A history database and its `-wal` and `-shm` sidecars are excluded when they
  fall inside a directory target. The exclusions remain visible as partial
  coverage rather than being silently omitted.

### Security and privacy review

- History contains paths, SHA-256 values, timestamps, malware-family and source
  metadata, signature rule details, offsets, and errors. It is opt-in and needs
  directory permissions, backup controls, and a retention policy appropriate
  for the machine and organization.
- The database is structured and transactionally consistent but is not
  encrypted, signed, or tamper-evident. It must not be treated as trustworthy
  forensic evidence after a local attacker gains write access.
- History is operational data and is not joined into the trusted reputation
  database. Compromise or pruning of history therefore does not change scan
  verdicts.
- Parameterized writes prevent scan-controlled values from becoming SQL. Strict
  tables, foreign keys, application identity, schema versioning, and count
  validation catch common corruption or wrong-database mistakes.
- Retention is explicit instead of automatic. This avoids surprising data loss,
  but deployment policy must schedule pruning and monitor database growth.

### Verification

- Locked restore and release build completed on .NET 10 with zero warnings and
  zero errors.
- All 113 automated tests passed: 57 core, 34 infrastructure, and 22 CLI tests.
- Tests cover projection, schema identity, rich-result round trips, immutable
  IDs, transactional rollback, newest-first limits, missing records, retention
  cascades, internal count validation, parser rules, and exit-code precedence.
- A 2,000-file append-and-read smoke test completed inside its 30-second limit;
  the complete infrastructure test assembly ran in approximately three seconds
  on the development machine. This is a regression signal, not a production
  service-level guarantee.
- End-to-end CLI verification captured a real scan, listed it, retrieved the
  same record by scan ID, and exercised retention without deleting the new row.

### Known limitations

- History is local and SQLite-backed; there is no remote collector, forwarding,
  export command, dashboard, or multi-host identity.
- Full-record retrieval materializes every stored file and match in memory.
- Retention is manual and does not compact the SQLite file automatically.
- There are no tamper-evident hashes, signatures, encryption-at-rest controls,
  or operating-system event-log integration.
- Scans are still initiated manually; filesystem changes are not monitored.

### Definition of done

- [x] Storage-neutral contracts preserve scan, file, match, and issue details.
- [x] History data uses an independent, identified, versioned database.
- [x] Complete records are appended atomically and duplicate IDs are rejected.
- [x] Operators can list, inspect, and prune history through the CLI.
- [x] Logs, output, and stored records share one scan correlation ID.
- [x] Privacy, retention, failure precedence, and integrity limits are explicit.
- [x] Rollback, corruption, retention, CLI, and performance paths are tested.

### Next milestone

Add real-time file monitoring behind an independent event-source interface.
Filesystem events should enter a bounded, debounced queue, watcher overflow
must trigger a visible recovery scan, and the monitor should reuse the current
scanner and history contracts. Quarantine and automatic deletion remain out of
scope until identity revalidation and recovery semantics are designed.

## 2026-10-15 — Milestone 6: real-time file monitoring

### Goal

Continuously apply the existing detection pipeline to filesystem changes while
making dropped events, partial coverage, and operational failures visible. Keep
monitoring observational until quarantine identity and recovery guarantees are
designed and tested.

### Design and data flow

- `IFileMonitorEventSource` keeps the orchestration independent of one watcher
  implementation and makes event streams deterministic in tests.
- `FileSystemWatcherEventSource` begins watching during construction, before
  the initial directory recovery scan starts. It publishes created, changed,
  and renamed paths through a bounded channel.
- `FileMonitoringEngine` performs an initial recovery scan, debounces event
  bursts by normalized path, revalidates each changed entry, and invokes the
  existing composite file scanner.
- The default debounce interval is 500 milliseconds. It can be configured from
  zero to 60 seconds with `--debounce-ms`.
- The managed queue defaults to 4,096 events and can be configured from 1 to
  65,536 with `--queue-capacity`. The operating-system watcher buffer defaults
  to 16 KiB and is capped at 64 KiB.
- Overflow from either buffer becomes an explicit event. Pending per-file work
  is cleared and a full recovery scan runs instead of claiming complete event
  coverage.
- Rule, reputation, and history files and SQLite sidecars are excluded by both
  the watcher adapter and scan validation. This prevents monitor-generated
  history writes from feeding back into the scanner.
- Every changed-file or recovery result receives its own scan ID for optional
  history storage. A separate session ID correlates the long-running monitor's
  operational logs and JSON Lines output.

```text
filesystem notifications -> bounded queue -> per-path debounce -> validate
           | overflow ------------------------------------------> recovery scan
                                                               -> file scanner
                                                               -> output/history
```

### Failure and output behavior

- Ctrl+C cancels the event wait and returns exit code `130`.
- Files that disappear before their debounce period ends are reported as
  unavailable rather than scanned or silently ignored.
- Paths outside the root, reparse points, directories, excluded files, source
  failures, and overflow are represented as typed monitor issues.
- Human output summarizes each recovery and changed-file scan. `--json`
  produces a JSON Lines stream because a monitor has many results and no single
  terminal result document.
- Operational JSON Lines logs stay on standard error. `--quiet` suppresses
  those logs, but not result output or errors.
- A requested history write failure is recorded and monitoring continues. If
  the source ends normally, the process preserves the existing history-failure
  and detection exit-code precedence. User cancellation returns `130`.
- Monitor setup or filesystem failures return exit code `13`.

### Security review

- Filesystem notifications are hints, not a complete or ordered audit stream.
  The operating system may coalesce or delay events. Explicit overflow recovery
  closes known event-loss gaps, but cannot create a transactional snapshot.
- Starting the watcher before the initial scan reduces the startup race. Events
  raised during that scan remain queued and are processed afterward.
- Event paths are normalized and checked to remain under the configured root.
  The root, parent segments, and target are checked for reparse points before a
  scan. Files can still change after validation, so enforcement must revalidate
  identity through an opened handle immediately before quarantine.
- Queue, debounce, directory traversal, and recovery-scan concurrency are
  bounded. Changed-file scans are processed sequentially while the watcher
  continues buffering events.
- State files are excluded exactly, including SQLite `-wal` and `-shm`
  sidecars. Placing a history database outside the watched root is still
  recommended because exclusions intentionally make recovery scans partial.
- Monitoring never executes, modifies, quarantines, or deletes a target.

### Verification

- Release build completed on .NET 10 with zero warnings and zero errors.
- All 132 automated tests passed: 64 core, 40 infrastructure, and 28 CLI tests.
- Engine tests cover initial recovery, same-path debounce, overflow recovery,
  source errors, paths outside the root, unavailable and excluded entries, and
  cancellation while idle.
- Infrastructure tests use the real Windows watcher for created-file delivery,
  excluded-file suppression, disposal, and bounded-queue overflow behavior.
- CLI tests cover monitor parsing, bounded option ranges, command-specific
  validation, and the dedicated failure exit code.
- A release-build smoke test started the real CLI monitor against an isolated
  temporary directory, observed the initial recovery result, created a file,
  and received completed changed-file scan events.

### Known limitations

- `FileSystemWatcher` does not guarantee one event per write, stable ordering,
  or delivery when the host or process is unavailable. A single write can emit
  more than one scan if related events arrive outside the debounce window.
- Changed-file scans are sequential. Sustained write rates beyond scan
  throughput can fill the queue and trigger repeated recovery scans.
- The monitor has no durable event journal or resume cursor across restarts.
- Cancellation takes precedence over accumulated detection or history-failure
  exit state because it is an explicit operator stop.
- There is no quarantine, remediation, notification service, background Windows
  service, or desktop interface yet.

### Definition of done

- [x] Monitoring depends on a replaceable event-source interface.
- [x] Startup includes an initial recovery scan while new events are captured.
- [x] Event bursts and memory use are bounded with configurable limits.
- [x] Known event loss produces a visible issue and full recovery scan.
- [x] Existing detection, history, human output, JSON output, and logs are reused.
- [x] Root containment, reparse handling, state-file exclusions, and cancellation are tested.
- [x] Live watcher behavior, failure semantics, and limitations are documented.

### Next milestone

Design safe quarantine and recovery. Quarantine must revalidate identity at the
point of action, move content into a restricted non-executable store, retain
tamper-resistant metadata for restoration, prevent path traversal and overwrite
on recovery, and remain opt-in until rollback behavior is proven.

## 2026-10-16 — Milestone 7: safe quarantine and recovery

### Goal

Add an explicit, reversible response to confirmed local detections without
turning monitoring into automatic deletion. Revalidate the file at the moment
of action, isolate it in a restricted non-executable vault, and make restoration
integrity and overwrite behavior predictable.

### Design and data flow

- `IQuarantineStore` separates response orchestration from the filesystem vault.
- `QuarantineRequest` requires a normalized expected SHA-256, expected length,
  and at least one bounded detection-evidence value.
- `quarantine add` performs the existing complete composite scan first. It
  refuses to act without `--database`, `--signatures`, or both, and it does not
  quarantine an unknown or no-match result.
- On Windows, the vault opens the source with read and delete access while
  denying new write and delete sharing. SHA-256 and length are recomputed from
  that exact handle and compared with the completed scan result.
- The verified handle is rewound and copied into a unique vault entry. The
  payload is flushed to disk, named `payload.uaq`, marked hidden and read-only,
  and accompanied by atomically replaced JSON recovery metadata.
- Only after payload and metadata succeed is the opened source handle marked
  for deletion. A failure before that point preserves the original.
- Vault ACL inheritance is disabled on Windows. The current user, Local System,
  and administrators receive recovery access, while inherited files explicitly
  deny execution to the current user.
- Restore recomputes the payload hash and length, requires an existing ordinary
  destination directory, rejects reparse-point path segments, copies through a
  flushed temporary file, and uses a non-overwriting final move.
- Metadata enters `RestorePending` before the final move. If the process stops
  after the move, a later restore verifies the destination and finalizes the
  `Restored` state rather than overwriting it.

```text
detected scan -> expected identity -> reopen exact handle -> re-hash
                                                       -> flush .uaq payload
                                                       -> atomic metadata
                                                       -> delete opened handle

active entry -> verify payload -> pending metadata -> no-overwrite move
                                                -> restored metadata
```

### CLI and exit behavior

- `quarantine add --vault <path>` scans and conditionally isolates one file.
- `quarantine list` returns newest entries first with a maximum of 200 results.
- `quarantine show` displays identity, evidence, timestamps, and restore state.
- `quarantine restore` uses the original path by default or an explicit
  `--destination`; both must be absent before a new restore begins.
- Human and JSON output are supported. Scan, quarantine, and restore operations
  produce correlated structured logs unless `--quiet` is supplied.
- Exit code `14` means a detection was successfully quarantined. Code `15`
  represents quarantine or vault-management failure. Code `16` means restore
  failed or was safely refused. An already-restored entry is idempotent success.
- Optional scan history is written before quarantine. If quarantine succeeds
  but requested history storage failed, the existing combined code `12` retains
  both the detection and audit failure signal.

### Security and recovery review

- Exact-handle hashing and deletion on Windows prevents a path swap between the
  final identity check and source removal. An already-open incompatible handle
  causes quarantine to fail rather than weakening sharing rules.
- The payload is retained after restoration. This supports evidence and repeated
  integrity checks, but consumes storage and requires a future reviewed purge
  policy.
- Restore never overwrites. A user or attacker placing any destination entry
  first causes a visible refusal. Pending-state reconciliation accepts an
  existing destination only when its complete hash and length match the payload.
- A process stop after committed quarantine metadata but before handle deletion
  can leave both the source and an active vault copy. This is a safe duplicate,
  not data loss, but there is not yet a repair command for that state.
- The JSON manifest is bounded and validated but not signed, chained, or
  encrypted. Payload hashing detects content corruption; it does not prove
  metadata provenance after a privileged attacker changes the vault.
- ACLs restrict ordinary access and deny current-user execution. Administrators
  and Local System necessarily retain control. Host compromise at that level is
  outside the vault's trust boundary.
- Non-Windows fallback behavior exists for development compatibility but cannot
  provide the same Windows handle and ACL guarantees. UtoAegis remains a Windows
  endpoint-security project.
- Quarantine remains manual. Monitor detections do not trigger removal, which
  prevents a false-positive rule from causing unattended disruption.

### Verification

- Release build completed on .NET 10 with zero warnings and zero errors.
- All 153 automated tests passed: 71 core, 47 infrastructure, and 35 CLI tests.
- NuGet reported no known vulnerable direct or transitive packages after adding
  the official filesystem access-control package.
- Contract tests cover hash, path, evidence, and state-transition validation.
- Real vault tests cover protected ACLs, inherited execute denial, exact-handle
  source removal, identity mismatch, payload corruption, overwrite refusal,
  deterministic listing, round-trip restoration, and interrupted-restore
  reconciliation.
- CLI tests cover subcommands, detector and vault requirements, option scope,
  canonical IDs, list limits, and distinct quarantine and restore exit codes.
- An end-to-end harmless-fixture test ran `add`, `list`, `show`, `restore`, and a
  second idempotent restore. It returned code `14`, removed only the copied test
  source, preserved SHA-256 after recovery, and cleaned its isolated test vault.

### Known limitations

- There is no automatic vault size limit, quota, age-based retention, or purge
  command. Listing is bounded, but payload storage must be monitored externally.
- Quarantine evidence stores bounded detector identifiers rather than a complete
  scan record. Use `--history` when the full scan result must be retained.
- Vault metadata and payloads are not encrypted or cryptographically signed.
- An interrupted quarantine can leave an orphan entry directory without metadata
  or a safe duplicate when metadata committed before source removal.
- Restore requires the destination parent directory to already exist and does
  not recreate deleted directory trees or original ACLs.
- Original last-write time is restored; creation time, alternate data streams,
  ownership, detailed ACLs, and other filesystem metadata are not preserved.
- The monitor, background service, policy engine, allowlists, and notifications
  are not connected to quarantine.

### Definition of done

- [x] Quarantine and recovery are behind a storage-neutral contract.
- [x] Only a completed configured detection can authorize quarantine through the CLI.
- [x] Source identity is rechecked through the Windows handle used for removal.
- [x] Payload and metadata are durable before the source is removed.
- [x] The Windows vault restricts access and denies current-user payload execution.
- [x] Restore verifies integrity, rejects links and overwrites, and recovers pending state.
- [x] Human, JSON, logging, history, and exit-code behavior are integrated.
- [x] Failure, corruption, interruption, ACL, and live round-trip paths are tested.

### Next milestone

Build a supervised Windows service and explicit response-policy boundary. The
service should run monitoring with least practical privilege, expose health and
detection notifications, and remain observe-only by default. Any automatic
quarantine policy must add allowlists, rate limits, dry-run behavior, and clear
operator recovery before it can be enabled.

## 2026-10-16 — Milestone 8: supervised Windows monitoring service

### Goal

Move the bounded monitor into a supervised Windows background process without
turning a detection directly into an unbounded destructive action. Keep
observe-only behavior as the default, make every active response decision
auditable, and install the service with only the filesystem rights required by
its configured mode.

### Design and data flow

- `ResponsePolicy` defines `ObserveOnly`, `DryRunQuarantine`, and `Quarantine`
  modes independently of the Windows host.
- `DetectionResponseEngine` requires a completed detection, evaluates SHA-256
  and path-prefix allowlists, and enforces a bounded sliding action window
  before invoking `IQuarantineStore`.
- `UtoAegis.Service` uses the .NET Generic Host and Windows Service lifetime to
  run the existing watcher, recovery scanner, composite detector, optional
  history store, response engine, and quarantine vault.
- Configuration is validated before the host starts. Relative operational and
  allowlist paths are anchored to the installation directory rather than the
  Service Control Manager working directory.
- Health counters and lifecycle, recovery, detection, response, monitor issue,
  and history-failure events flow through `ILogger` to the Windows Application
  event log.
- Publish, install, status, and removal scripts provide a repeatable operator
  workflow. Removal preserves files, state, vault entries, and ACLs.

```text
SCM -> service host -> watcher + recovery scans -> composite detector
                                                  -> history
                                                  -> response policy
detection -> hash allowlist -> path allowlist -> observe / dry run / rate gate
                                                        |-> quarantine vault
service state -> periodic health event + detection/decision event
```

### Response safety

- Observe-only is the constructor and configuration default. It never requires
  a vault and never changes a detected file.
- Dry-run passes through all detection and allowlist checks but does not reserve
  a rate slot or call the quarantine store.
- Quarantine mode cannot be constructed without a store, and service startup
  requires an external vault path.
- The default action limit is three attempts per five minutes. Configuration
  accepts 1–100 attempts and windows from one second through 24 hours.
- Failed attempts remain in the current window to prevent retry storms. Rate
  state is intentionally local to the running process and resets on restart.
- Path-prefix matching is boundary-aware and case-insensitive on Windows, so an
  allowlist for `safe` does not accidentally include a sibling named `safety`.
- Evidence creation moved into the core response boundary so the CLI and service
  use the same bounded detector identifiers.

### Service and privilege boundaries

- The installer uses the passwordless virtual account `NT SERVICE\UtoAegis`
  instead of Local System or an administrator account.
- Program files and the monitored tree receive read/execute access. Quarantine
  mode adds `Delete child` to the monitored tree but not general write access.
- Database, history, and vault locations receive modify access because SQLite
  sidecars and vault payloads require writes. Those locations must remain
  outside the monitored tree.
- Signature policy must remain outside service-writable state, preventing the
  service account from rewriting the byte rules that determine detections.
- Writable state cannot be a filesystem root or contain the installation
  directory. The installation directory cannot be monitored.
- Scanner data files and SQLite sidecars are excluded at both watcher and
  directory-scan boundaries to prevent self-triggering loops.
- The installer refuses a configuration already set to quarantine unless the
  administrator supplies `-AllowQuarantineResponse`.

### Verification

- Locked restore resolved Microsoft.Extensions.Hosting.WindowsServices 10.0.13
  and generated lock files for the service and its tests.
- Release builds completed on .NET 10 with zero warnings and zero errors.
- All 175 automated tests passed: 80 core, 47 infrastructure, 35 CLI, and 13
  service tests.
- Response tests cover defaults, dry-run, both allowlist types, path boundaries,
  verified evidence, rate-window expiry, incomplete scans, and missing stores.
- Service tests cover required detection sources, external state and vault
  placement, policy/state isolation, installation-directory protection,
  response settings, relative allowlist normalization, watcher limits, service
  health accounting, response dispatch, and failed-recovery history fallback.
- The validate-only startup path succeeded with environment-supplied monitor and
  database paths without starting the watcher or creating service state.
- All four PowerShell lifecycle scripts parsed successfully with the PowerShell
  abstract syntax tree parser. Registration and ACL mutations were intentionally
  not executed on the development host.
- NuGet reported no known vulnerable direct or transitive packages.

### Known limitations

- The watcher remains a best-effort user-mode signal and can coalesce, reorder,
  or lose changes. Overflow recovery narrows but does not eliminate that gap.
- This is not a kernel minifilter and does not synchronously block file access or
  execution before a scan finishes.
- Detection policy, reputation databases, and signature files are local and
  unsigned. Administrator compromise remains inside the trust boundary.
- Configuration and signatures load only at startup; there is no authenticated
  update, atomic live reload, or automatic rollback mechanism.
- The rate limit is process-local and resets on service restart.
- Application event logs are local operational notifications. Remote alerting,
  incident workflow, and notification delivery guarantees are not implemented.
- The installer grants inherited access at configured roots. A child with
  protected inheritance can remain inaccessible and will surface as a scan
  issue rather than being silently considered covered.
- Service removal preserves generated files and ACL entries for recovery. Their
  eventual retention and removal remain operator responsibilities.

### Definition of done

- [x] Response policy is independent of the host and defaults to observe-only.
- [x] Hash and path allowlists precede dry-run or active response.
- [x] Automatic quarantine attempts are bounded by a sliding time window.
- [x] The .NET 10 host runs under Windows Service Control Manager.
- [x] Configuration and unsafe path relationships fail before monitoring starts.
- [x] Health, detection, response, recovery, and failure events are visible.
- [x] The virtual service account receives mode-specific filesystem rights.
- [x] Publish, installation, inspection, removal, and recovery are documented.

### Next milestone

Add authenticated threat-intelligence updates. Detection feeds and signature
policy need cryptographic signatures, rollback protection, staged validation,
atomic activation, and last-known-good recovery before UtoAegis accepts remote
or unattended content updates.

## 2026-10-17 — Milestone 9: authenticated threat-intelligence updates

### Goal

Replace manual detection-file replacement with an authenticated update path for
both hash indicators and byte signatures. Reject stale or ambiguous packages,
activate only fully validated content, preserve an explicit last-known-good
version, and keep private signing keys and content-store mutation outside the
monitoring service.

### Design and data flow

- Schema 1 signs the exact UTF-8 `manifest.json` bytes with ECDSA NIST P-256,
  SHA-256, and an RFC 3279 DER signature.
- The manifest binds fixed payload names, lengths, SHA-256 digests, version,
  key ID, publication and expiration times, and a monotonic sequence.
- A public-key-only trust store rejects private PEM material, unknown key IDs,
  non-P-256 keys, oversized files, and reparse points.
- Verification copies signed payloads into a fresh same-volume staging
  directory, then runs the existing strict JSON Lines readers over those copies.
- Activation builds and checks a fresh SQLite reputation database, checkpoints
  it for read-only use, renames the complete staging directory, and atomically
  replaces the small state pointer.
- State retains the active and previous versions plus the highest sequence ever
  accepted. Rollback swaps the pointers after reverification but never reduces
  that sequence floor.
- `updates apply`, `updates status`, and `updates rollback` expose the workflow.
  The separate publisher script creates signed bundles without adding private
  key handling to endpoint runtime code.
- Service startup reads and reverifies the active version without acquiring an
  update lock, creating staging files, or receiving write access to the store.

```text
offline publisher -> exact manifest bytes -> detached signature
                               |-> signed indicator digest + length
                               |-> signed signature digest + length
endpoint CLI -> authenticate -> sequence/time policy -> stage + strict parse
             -> fresh database -> version rename -> atomic state pointer
service restart -> read-only reverification -> scanner inputs
rollback -> reverify previous -> pointer swap -> sequence floor unchanged
```

### Security boundaries

- The default time policy allows five minutes of clock skew and limits a new
  manifest to a 14-day validity period.
- Bundle directories contain exactly four regular files. Filenames are fixed,
  case-sensitive, and never supplied by the manifest, preventing path traversal.
- Version and key IDs use a bounded path-safe ASCII grammar.
- The update lock serializes mutating CLI operations. Corrupt state fails closed
  instead of resetting the anti-rollback floor.
- Active expired content remains available as last-known-good data, with a
  warning event, but an expired bundle cannot be newly activated.
- The installer grants the service read-only content and public-key access.
  Database, history, and quarantine write permissions remain separate.
- Trust configuration and local-administrator compromise remain inside the host
  trust boundary. A compromised signing key can authorize malicious content.

### Verification

- Release builds completed on .NET 10 with zero warnings and zero errors.
- All 216 automated tests passed: 98 core, 63 infrastructure, 39 CLI, and 16
  service tests.
- Core tests cover required payloads, path-safe identifiers, expiration,
  clock-skew boundaries, validity limits, and non-increasing sequences.
- Infrastructure tests cover valid signatures, tampered manifests and payloads,
  unknown keys, strict bundle contents, private-key rejection, staged database
  creation, atomic state, read-only consumption, rollback, and replay rejection.
- CLI tests cover update command parsing and the dedicated failure exit code.
- Service tests cover managed/direct source exclusivity, required trusted keys,
  external store placement, operational exclusions, and existing policy bounds.
- A live harmless smoke test generated an ephemeral P-256 key, built a bundle,
  activated sequence 1 through the CLI, and confirmed the JSON status result.
- All five Windows PowerShell scripts parsed successfully. Service registration
  and ACL mutations were not executed on the development host.
- NuGet reported no known vulnerable direct or transitive packages.

### Known limitations

- Milestone 9 authenticates local bundle activation but does not fetch, schedule,
  retry, or distribute updates.
- The service loads one verified snapshot at startup and does not live-reload.
- Only the immediate previous version is addressable by the rollback command.
  Older version directories have no automated retention policy.
- Key rotation uses overlapping configured keys; there is no signed revocation
  object or automated compromise-recovery protocol.
- The anti-rollback floor is local. Offline disk rewriting by a local
  administrator remains within the trust boundary.
- Payload authenticity does not make the fixed-byte detection model equivalent
  to a production antivirus engine or kernel enforcement layer.

### Definition of done

- [x] Exact manifest bytes receive a detached cryptographic signature.
- [x] Both payloads are length- and SHA-256-bound to the signed manifest.
- [x] Unknown keys, malformed content, bad signatures, expiry, and rollback fail closed.
- [x] Validation and database construction finish before atomic activation.
- [x] Last-known-good rollback reverifies content and preserves the sequence floor.
- [x] Operator CLI, offline publisher, service startup, events, and ACLs are integrated.
- [x] The Windows service remains a read-only consumer of managed content.

### Next milestone

Add a separately privileged production updater around this authenticated
activation core. It should provide HTTPS retrieval, retry and backoff, staged
rollout telemetry, disk-retention bounds, and explicit signing-key rotation and
revocation while keeping the monitoring service read-only.

## 2026-10-20 — Milestone 10: production threat-intelligence updater

### Goal

Automate authenticated content retrieval without granting network or write
privileges to the endpoint monitor. Bound server-controlled input before large
downloads, preserve the Milestone 9 activation guarantees, make retries and disk
use predictable, and expose enough local telemetry for staged fleet rollout.

### Design and data flow

- `UtoAegis.Updater` is a separate .NET 10 worker and Windows service identity.
- Its channel is a fixed HTTPS directory URI. The production handler disables
  redirects, cookies, and decompression and enables certificate revocation checks.
- The downloader also compares every final response URI with the exact requested
  URI, requires HTTP 200 plus bounded `Content-Length`, and writes fixed filenames.
- Manifest and signature are downloaded first. The ECDSA signature, time window,
  and sequence are accepted before either payload request is sent.
- Full payload verification and strict parsing still occur through the Milestone
  9 staging and activation implementation, avoiding a second trust path.
- Only transient transport failures retry within a cycle. Backoff doubles from
  the configured initial delay to a configured cap and attempts remain bounded.
- Each cycle emits bounded JSON Lines records with run, deployment, ring,
  attempt, sequence, version, and result fields for external fleet collection.
- Post-activation retention always protects active and rollback references,
  keeps the newest optional versions, and rejects ambiguous filesystem entries.

```text
ring HTTPS directory -> manifest + signature -> authenticate and check sequence
                                             | rejected -> telemetry, no payloads
                                             v
                                fixed payload downloads -> Milestone 9 verifier
                                                        -> atomic activation
                                                        -> bounded retention
                                                        -> rollout telemetry
read-only monitor -> controlled restart -> reverify active content
```

### Security boundaries

- Configuration rejects HTTP, URI credentials, queries, fragments, and channel
  paths without a trailing slash.
- Writable content, download, and telemetry directories are external, distinct,
  non-nested, non-root, and non-reparse-point paths.
- Signing keys remain outside updater-writable paths. Only public P-256 material
  is loaded; private-key rejection remains in the shared trust-store loader.
- Key entries have explicit `Trusted` or `Revoked` status. Revoked entries are
  excluded from runtime verification while remaining visible to operators.
- The updater virtual account receives content-store write access. The monitor
  account retains read-only content and public-key access.
- TLS protects transport but does not replace detached content signatures. A
  locally compromised administrator, root trust, or signing key remains inside
  the documented trust boundary.

### Verification

- Locked restore and formatter verification completed successfully.
- The Release build completed on .NET 10 with zero warnings and zero errors.
- All 238 automated tests passed: 98 core, 75 infrastructure, 39 CLI, 16
  monitoring-service, and 10 updater tests.
- HTTPS downloader tests cover valid bundles, metadata-first authentication,
  bad signatures, transient server failures, signed-length mismatch, unsafe
  channel URIs, staging cleanup, and final-response URI crossing.
- Store tests cover active/rollback retention, optional recent retention,
  noncanonical entry refusal, and continued rollback after pruning.
- Updater tests cover configuration bounds, path isolation, explicit revocation,
  capped backoff, activation, current-version short circuit, retry exhaustion,
  and deployment/ring telemetry.
- The updater project builds under the same warning-as-error, deterministic,
  locked-dependency, and vulnerability-audit policy as the rest of UtoAegis.
- All nine Windows PowerShell scripts parse with the PowerShell abstract syntax
  tree parser. Service registration and ACL mutations were not run on the
  development host.
- A harmless validate-only smoke test loaded an ephemeral P-256 public key and
  isolated temporary content, download, and telemetry paths through environment
  configuration, then exited successfully without fetching or activating data.
- NuGet reported no known vulnerable direct or transitive packages in any of the
  ten projects.

### Known limitations

- The monitor still loads one snapshot at startup; updater activation becomes
  visible after a controlled monitor restart.
- Telemetry is a local collection source and has no built-in remote delivery.
- Key status is host-managed configuration rather than signed root metadata.
- The transport does not include built-in mTLS, bearer tokens, proxy secrets, or
  certificate pinning.
- Exponential backoff is bounded but does not add randomized jitter.

### Definition of done

- [x] A separate privileged worker performs scheduled HTTPS retrieval.
- [x] Metadata is authenticated before payload transfer and activation reuses the signed core.
- [x] Transient failures retry with bounded exponential backoff.
- [x] Rollout telemetry identifies deployment, ring, attempt, sequence, and result.
- [x] Active and rollback content survive bounded retention pruning.
- [x] Signing-key policy distinguishes trusted and revoked keys.
- [x] Publish, validation, one-shot, install, status, and removal workflows exist.
- [x] The monitoring service remains a read-only content consumer.

### Next milestone

Add safe live threat-content reload to the monitoring service. A new active
snapshot should be reverified read-only, swapped atomically between scan events,
reported through health telemetry, and abandoned without disrupting the current
detectors when reload validation fails.

## 2026-10-20 — Milestone 11: live threat-intelligence reloading

### Goal

Make authenticated updater activation visible to the running monitor without
giving that process content-store write access or restarting file monitoring.
Keep every scan internally consistent, preserve last-known-good detection after
a rejected candidate, and prevent retention cleanup from removing files still
used by an older in-flight scanner generation.

### Design and data flow

- `ReloadableFileScanner` captures one immutable scanner generation per scan and
  publishes replacements with an atomic reference exchange.
- A retired generation drains its active scans before releasing disposable
  resources. New scans immediately use the replacement generation.
- Managed service startup acquires a read lease and performs the existing full
  signature, payload, feed, and derived-database verification.
- The service polls the small state pointer at a bounded interval. Unchanged
  version/sequence identities avoid repeated payload work.
- A changed pointer receives a fresh read lease, full read-only verification,
  and complete scanner construction before the atomic swap.
- Expected validation failures retain the loaded generation. The first repeated
  failure emits Event 303; health telemetry keeps counting later attempts.
- Event 105 records successful replacement and Event 106 reports version,
  sequence, scanner generation, successful reloads, rejected reloads, and last
  check time.
- Store pruning probes an unreferenced reputation database for exclusive access.
  A generation leased by the monitor is reported and retained until a later run.

```text
privileged updater -> authenticate -> activate state pointer -> retention probe
                                       |                      | busy -> defer
read-only monitor -> poll changed state -> lease -> reverify -> build scanner
                                                     | failure -> keep current
                                                     v
                                          atomic generation replacement
old in-flight scans -> old generation -> complete -> lease released
```

### Security boundaries

- The monitor receives no content-store write permission. Its lease is a
  read-only database handle using Windows file-sharing semantics.
- State identity is only a cheap change signal. No candidate becomes usable
  until its signature, payloads, strict feeds, and database attestation pass.
- A scan cannot mix detection stages across generations because it acquires its
  generation before hashing and releases it after the complete composite scan.
- Rollback to a lower active sequence is allowed after store reverification,
  while the independent highest-accepted sequence floor remains unchanged.
- Candidate failure does not silently replace the active pointer or invoke
  privileged rollback from the monitor.
- Trust keys remain a startup configuration boundary; content cannot authorize
  a new signing key.

### Verification

- Atomic-scanner tests cover replacement routing, in-flight consistency, and
  deferred disposal until the final scan drains.
- Service tests cover unchanged pointers, successful replacement, failed
  candidate fallback, duplicate-warning suppression, and reload interval bounds.
- Store tests hold a real Windows read lease across multiple activations and
  prove that pruning removes an unleased version while retaining and reporting
  the leased generation.
- Updater tests prove that deferred retention emits rollout telemetry without
  undoing a successful activation.
- Locked restore and warning-level formatter verification completed cleanly.
- The Release build completed with zero warnings and zero errors.
- All 247 tests passed: 101 core, 76 infrastructure, 39 CLI, 20 monitoring
  service, and 11 updater tests.
- All nine PowerShell scripts parsed successfully, and all ten projects reported
  no known vulnerable direct or transitive NuGet packages.
- A validate-only service smoke test accepted the minimum five-second reload
  interval with isolated monitor and state paths; it did not register a service
  or mutate monitored files.

### Known limitations

- Reload discovery polls from 5 through 3,600 seconds; there is no cross-service
  event or push notification.
- Trust keys, direct content paths, and response policy still require a
  controlled service restart.
- A bad active pointer is retried while the process keeps its verified in-memory
  generation. The monitor does not mutate state or automatically roll back.
- Health counters reset with the process and Event Log records have no built-in
  durable remote delivery.
- File-sharing leases provide the intended guarantee on the Windows deployment
  target; local-administrator compromise remains inside the host trust boundary.

### Definition of done

- [x] Managed state changes are detected with a configurable bounded interval.
- [x] Candidates are fully reverified and built before publication.
- [x] Scanner replacement is atomic and scans never mix generations.
- [x] Invalid candidates preserve last-known-good detection.
- [x] In-flight generations remain pinned until their scans drain.
- [x] Retention reports and defers deletion of pinned versions.
- [x] Reload success, rejection, expiry, and health are operationally visible.
- [x] The monitor remains a read-only content-store consumer.

### Next milestone

Add tamper-evident security telemetry with bounded local spooling, durable
delivery checkpoints, and an authenticated collector boundary. Fleet operators
should be able to correlate detections, response decisions, updater rollout,
and live-reload health without granting the monitor broad network privileges.

## 2026-10-22 — Milestone 11 patch: read-only reload polling

### Problem found during the completion audit

The live-reload poll used the privileged store-status operation. That operation
creates missing storage directories and opens the updater lock for read/write
access. The installed monitor intentionally receives only read and execute
access to the content store, so its first reload poll could fail even though
initial content loading was correctly read-only.

### Correction

- Added a separate status reader that validates the existing store directories
  and reads the atomically replaced state file without creating directories or
  acquiring the updater's writable operation lock.
- Routed the monitoring service through the read-only status reader while
  retaining the original locked operation for privileged CLI and updater use.
- Added infrastructure and service regression tests that hold the updater lock
  exclusively while the read-only status path succeeds.

### Verification

- Locked restore and formatter verification completed successfully.
- The Release build completed with zero warnings and zero errors.
- All 249 tests passed: 101 core, 77 infrastructure, 39 CLI, 21 monitoring
  service, and 11 updater tests.
- All nine PowerShell scripts parsed successfully.
- All ten projects reported no known vulnerable direct or transitive NuGet
  packages.

## 2026-11-02 — Repository quality and ownership audit

### Scope

- Audited the current product repository, all eleven named milestone
  repositories, and the public documentation-only showcase.
- Checked build and dependency policy, committed lock files, CI coverage,
  ownership files, security reporting, ignored artifacts, source comments, and
  unfinished-work markers.
- Preserved each milestone's source as a historical snapshot; repository
  controls are maintained separately from milestone functionality.

### Corrections

- Added an editor policy so supported editors share the repository's whitespace
  and indentation rules.
- Added explicit code ownership, security-reporting, and proprietary
  contribution policies.
- Ignored local `output` and `tmp` working directories without deleting their
  contents.
- Extended CI to reject formatter drift and PowerShell syntax errors in
  addition to locked restore, Release build, tests, and dependency auditing.
- Added baseline CI and dependency-update configuration to the two earliest
  milestone repositories, which predated those controls.
- Refreshed the current product's direct dependencies to Microsoft.Data.Sqlite
  10.0.14, Microsoft.Extensions.Hosting.WindowsServices 10.0.14, and MSTest
  4.5.2, then regenerated every committed NuGet lock file.

### Comment audit

- Found no unfinished-work or temporary-workaround markers in the current
  source or milestone snapshots.
- Retained the 15 current C# comment lines: five short XML documentation blocks
  that explain public scanner and reload contracts.
- Added no narrative implementation comments; names, types, and tests remain
  the primary code documentation.

## 2026-11-11 — Milestone 12: tamper-evident security telemetry

### Goal

Make endpoint detections, response decisions, monitor health, content reloads,
and updater rollout events remotely observable without giving the monitor or
updater network credentials. Bound endpoint storage and make modification,
deletion, reordering, stale delivery state, and retention gaps explicit.

### Architecture and security decisions

- Added a storage-neutral security event contract and infrastructure-backed
  producer spools with canonical schema-versioned envelopes.
- Assigned every producer a monotonically increasing sequence and chained each
  record to the prior SHA-256 hash. Startup revalidates every retained record,
  the pruning anchor, and the committed chain head.
- Stored one event per bounded file and used atomic replacement for spool state
  and collector checkpoints. Checkpoints cannot move backward.
- Bounded producer spools by record count and record size. Pruning commits an
  anchor before removing old records so an interrupted deletion can be safely
  resumed; a collector behind that anchor receives an explicit gap error.
- Kept monitor and updater spools independent. They write locally but receive
  no collector key and perform no telemetry network requests.
- Added `UtoAegis.Telemetry`, a separate Windows worker with read-only access to
  producer spools, read access to an endpoint HMAC key, modify access only to
  checkpoint state, and HTTPS egress to one configured collector URI.
- Signed the exact method, escaped path and query, Unix timestamp, random nonce,
  and SHA-256 body digest with HMAC-SHA256. Redirects, cookies, and transparent
  response decompression remain disabled and certificate revocation is checked.
- Advanced a source checkpoint only after the collector returned the exact
  sequence and hash of the final record. Mismatched, partial, malformed, or
  failed responses leave the batch eligible for idempotent retry.
- Documented collector-side timestamp windows, nonce replay protection,
  constant-time HMAC comparison, durable anchors, and source authorization.

### Product integration

- The monitoring service emits lifecycle, periodic health, detection, response,
  content-reload, reload-rejection, and content-health records. A detection and
  its response decision share the scan correlation identifier.
- The updater preserves its bounded JSON Lines operations log and mirrors each
  rollout event to its independent tamper-evident spool.
- Added publish, validate, install, status, and recoverable removal workflows for
  the forwarding service. Installers create least-privilege spool grants for all
  three service identities.
- Added a deployment and collector integration guide covering the wire protocol,
  retention behavior, key provisioning, incident handling, and trust limits.

### Corrections found during review

The initial pruning path committed its new anchor before deleting old records,
which is the correct durable order, but startup still treated a pre-anchor file
left by an interruption as part of the retained chain. Startup and later pruning
now validate record names while ignoring only correctly named records already
covered by the committed anchor. Records at or after the anchor still fail
closed on any missing, modified, or reordered data. A regression test recreates
the interruption window.

### Trust limits

Hash chaining provides evidence relative to the collector's last accepted
anchor; it does not prevent a local administrator from stopping services or
deleting endpoint data. Bounded storage can intentionally create a visible gap
during a prolonged outage. HMAC key changes currently require a controlled
forwarder restart, and the system uses operating-system TLS trust rather than
built-in certificate pinning or mutual TLS.

### Verification

- Locked restore completed for all 12 projects and all 12 NuGet lock files.
- The Release build completed with zero warnings and zero errors.
- Formatter verification completed without changes.
- All 265 tests passed: 101 core, 83 infrastructure, 39 CLI, 23 monitoring
  service, 12 updater, and 7 telemetry tests.
- All 13 PowerShell deployment scripts parsed successfully.
- All 12 projects reported no known vulnerable direct or transitive NuGet
  packages against the current NuGet advisory index.
- The unfinished-work marker scan was clean. The 15 C# comment lines remain the
  same five short XML documentation blocks retained by the prior comment audit.

### Definition of done

- [x] Monitor and updater events use separate bounded local chains.
- [x] Retained chains and pruning anchors are verified before delivery.
- [x] Stale or mismatched checkpoints and retention gaps fail explicitly.
- [x] The network credential is isolated in a separate forwarding service.
- [x] Batches require HTTPS, replay-resistant HMAC authentication, and exact
  acknowledgements.
- [x] Checkpoints advance atomically only after collector acceptance.
- [x] Windows deployment preserves the intended privilege boundaries.
- [x] Tampering, pruning recovery, authentication, acknowledgement, and retry
  behavior are covered by automated tests.

### Next milestone

Harden production release and upgrade operations with signed distributable
artifacts, software bills of materials, reproducible release metadata, verified
upgrade and rollback workflows, and explicit Windows service recovery testing.

## 2026-11-12 — Milestone 13: signed releases and deployment hardening

### Goal

Turn locked, tested source into a reviewable Windows release candidate whose
contents, origin, dependencies, and upgrade path can be verified before any
service is changed. Make a failed multi-service upgrade recover the prior
service paths and running states instead of leaving a mixed deployment.

### Release trust and artifact design

- Added a dual-architecture release builder for `win-x64` and `win-arm64` that
  performs locked restore, the complete test suite, self-contained publishing,
  release verification, deterministic archive construction, and transport
  checksum generation.
- Added a CycloneDX 1.7 SBOM generator derived from the six committed production
  lock files. It records package hashes, direct and transitive use, project
  consumers, and the dependency graph while rejecting inconsistent lock data.
- Added a sorted manifest of every packaged relative path, byte length, and
  SHA-256 digest. Verification rejects missing, extra, duplicate, rooted,
  traversing, or reparse-point content before deployment.
- Added Authenticode signing for UtoAegis-owned executables and assemblies with
  SHA-256 and RFC 3161 timestamps. Third-party assemblies retain their original
  publisher bytes and are covered by the signed manifest.
- Added a detached CMS signature for the complete release manifest. Production
  verification requires a cryptographically valid signature from an explicitly
  allowed certificate thumbprint and valid Authenticode on UtoAegis binaries.
- Kept unsigned development candidates behind an explicit creation and
  verification override. The production path fails closed when signing evidence
  or the signer allowlist is absent.
- Added locked runtime graphs to all six production projects so both target
  architectures can be restored and published without changing dependencies.

### Transactional deployment and recovery

- Added side-effect-free upgrade planning that reports the current service
  paths, proposed paths, running states, and retained versions as JSON.
- Added versioned staging, configuration preservation, staged executable and
  configuration validation, bounded semantic-version retention, and atomic
  deployment-state replacement.
- Service path changes are treated as one transaction. Any stop, switch, or
  restart failure restores the previous paths and running states; the target is
  retained if rollback itself cannot be completed.
- Added explicit rollback to the prior recorded paths without lowering threat
  content anti-rollback floors or altering quarantine, databases, or telemetry
  checkpoints.
- Added an opt-in, administrator-only recovery test that proves each selected
  service restarts in a distinct process within the configured timeout.

### Protected release workflow

- Added a manual-only GitHub Actions workflow bound to the `release-signing`
  environment and pinned third-party actions.
- The workflow imports a PFX without making the private key exportable, verifies
  its expected thumbprint, signs and verifies both Windows architectures,
  uploads all evidence, creates only a draft GitHub release, and removes the
  certificate in its cleanup step.
- Signing credentials remain environment secrets, publication remains a human
  review decision, and concurrent runs for one version cannot cancel a release
  that may already have used the key.

### Verification

- Locked restore completed for all 12 projects and all 12 NuGet lock files.
- The Release build completed with zero warnings and zero errors, and formatter
  verification completed without changes.
- All 265 .NET tests passed: 101 core, 83 infrastructure, 39 CLI, 23 monitoring
  service, 12 updater, and 7 telemetry tests.
- Both PowerShell integration suites passed. They cover release inventory and
  tamper rejection plus a verified, side-effect-free deployment plan.
- All 23 PowerShell scripts parsed successfully, and the unfinished-work marker
  scan was clean. The 15 C# comment lines remain the five short XML
  documentation blocks retained by the prior comment audit.
- The official CycloneDX 1.7 JSON schema accepted the generated 37-component
  SBOM.
- All 12 projects reported no known vulnerable direct or transitive NuGet
  packages against the current NuGet advisory index.
- Locked publishing was exercised for both `win-x64` and `win-arm64`, and an
  extracted unsigned development archive passed complete inventory and SBOM
  verification.

### Trust limits

A production Authenticode and CMS run still requires a trusted code-signing
certificate; no suitable private key is installed in the development
environment, so only the deliberately unsigned development path can be executed
locally. The workflow's PFX option is less resistant to key extraction than an
HSM or managed signing service. Live Service Control Manager switching and the
deliberately disruptive restart test require a controlled, elevated Windows
host and are not run by CI. The release is a ZIP rather than an MSI or MSIX.

### Definition of done

- [x] Both Windows architectures publish from committed locked dependency graphs.
- [x] Every packaged byte is inventoried and the dependency graph has an SBOM.
- [x] Production artifacts require pinned CMS and Authenticode signing evidence.
- [x] Unsigned development output is explicit and rejected by production checks.
- [x] Upgrade planning is verifiable without changing the installation.
- [x] Multi-service upgrades roll back prior paths and running states on failure.
- [x] Operators can explicitly restore the prior recorded deployment.
- [x] Controlled recovery testing proves service process replacement.
- [x] GitHub produces reviewable draft releases through a protected environment.

### Next milestone

Protect endpoint runtime policy and installation state: authenticate policy
bundles, detect service configuration and ACL drift, emit tamper telemetry, and
add bounded automated recovery without granting services broader privileges.

## 2026-11-12 — Milestone 14: authenticated runtime policy and integrity guard

### Goal

Move response behavior and endpoint integrity expectations out of locally
editable configuration and into an offline-signed policy. Detect unauthorized
service, executable, and ACL changes, report them through the existing
tamper-evident telemetry boundary, and permit only explicitly authorized,
persistently rate-limited recovery without broadening the monitor, updater, or
forwarder service identities.

### Authenticated policy boundary

- Added a strict runtime policy model covering response rules, protected service
  paths and hashes, accounts, start modes, owner/group/DACL baselines, audit
  cadence, and recovery bounds.
- Added exact-byte ECDSA P-256/SHA-256 signatures with a two-file bundle format.
  The endpoint receives public keys only; policy private keys remain offline.
- Rejected unknown or duplicate JSON properties, unsafe or duplicate paths,
  unsupported algorithms, excessive collections, invalid bounds, future or
  expired policy, extra bundle files, reparse points, and invalid signatures.
- Persisted the highest accepted sequence and exact manifest hash with
  same-directory atomic replacement and an exclusive operation lock. Lower
  sequences and changed content at the same sequence fail closed, while an
  identical sequence and hash permit safe process restarts.
- Integrated policy verification before monitor startup. Authenticated response
  rules replace the local response section; quarantine still requires the
  separately configured restricted vault.
- Added policy identity, sequence, signer, expiration, and manifest hash to the
  Event Log and monitor telemetry startup record.

### Integrity Guard and recovery

- Added `UtoAegis.Guard`, a one-shot Windows console application intended for a
  protected SYSTEM scheduled task rather than another continuously privileged
  service.
- Added native SCM inspection for exact no-argument binary paths, service
  accounts, and automatic, delayed-automatic, manual, or disabled start modes.
- Added regular-file validation and streaming SHA-256 verification for every
  protected executable. Missing services, paths, and binaries, changed binaries,
  reparse points, and inspection failures remain nonrecoverable findings.
- Added normalized owner, group, and DACL inspection for selected regular files
  and directories. Only exact SDDL carried by authenticated policy can be
  restored.
- Required recovery authorization in both the signed policy and the scheduled
  task installation. Multiple findings for one service are coalesced into one
  operation.
- Persisted recovery reservations, pruned attempts only after the signed window,
  and failed closed at the signed maximum. A higher authenticated sequence begins
  a new budget; corrupt state does not silently reset it.
- Service recovery changes only signed SCM fields. A previously running service
  is stopped, corrected, restarted, and bounded to a 30-second state transition;
  a stopped service remains stopped and a disabled service is not restarted.
- Limited automatic account recovery to passwordless built-in or matching
  virtual service identities. Password-backed accounts remain auditable but
  require operator-controlled credential handling.

### Deployment, telemetry, and releases

- Added an elevated known-good baseline exporter and a separate offline policy
  signer. Signing exact exported bytes keeps the private key off endpoints.
- Added Guard publish, protected scheduled-task installation, status, and
  recoverable removal workflows. Recovery remains an explicit installer switch.
- Added explicit pre-creation of missing telemetry producer spools so deployment
  ordering cannot silently hide a misspelled source path.
- Added an independent `guard` telemetry chain. Audit records retain initial and
  remaining finding counts, bounded details, policy identity, recovery intent,
  recovery result, and rate-limit state. Native SCM and recovery failures are
  converted into failure telemetry.
- Added the Guard to both locked Windows release architectures, the CycloneDX
  project graph, archive inventory, code-signing selection, and operator scripts.
- Corrected production release verification to require Authenticode only on
  UtoAegis-owned binaries. Third-party assemblies retain their publishers' bytes
  and remain authenticated by the detached signed release manifest as designed.

### Verification

- Locked restore completed for all 14 projects and all 14 NuGet lock files.
- The Release build completed with zero warnings and zero errors, and formatter
  verification completed without changes.
- All 290 .NET tests passed: 104 core, 91 infrastructure, 39 CLI, 25 monitoring
  service, 12 updater, 7 telemetry, and 12 Guard tests.
- All three PowerShell integration suites passed: release metadata and tamper
  rejection, side-effect-free deployment planning, and runtime policy signing,
  validation, and tamper rejection.
- All 30 PowerShell scripts parsed successfully. The unfinished-work marker scan
  was clean, and the 15 C# comment lines remain the five short XML documentation
  blocks retained by the prior comment audit.
- All 14 projects reported no known vulnerable direct or transitive NuGet
  packages against the current advisory index.
- The official CycloneDX 1.7 schema accepted the generated 37-component SBOM.
- Clean-commit `win-x64` and `win-arm64` development candidates each contained
  and verified exactly 197 inventoried files. Both extracted archives included
  the Guard executable and baseline, signing, installation, status, and removal
  tools.
- GitHub's Windows runner exposed its temporary directory through an 8.3 alias
  while resolving the created test directory to its long path. The integration
  cleanup guard now resolves both sides before its containment check, preserving
  fail-safe deletion without making the test dependent on a path spelling. The
  harness also clears the expected nonzero native exit after it proves tamper
  rejection so GitHub's PowerShell wrapper does not reinterpret success as a
  failed step.

### Trust limits

The Guard detects drift relative to what the trusted operator signed; exporting
a baseline from an already compromised host authenticates the wrong state. A
local administrator or kernel compromise can disable Task Scheduler, stop
telemetry, delete endpoint state, or replace the operating system. Collector-side
anchors and missing-heartbeat alerting remain necessary.

Automated tests exercise policy authentication, parsing, anti-rollback state,
recovery decisions, persistent bounds, configuration isolation, telemetry
integration, packaging, and tamper rejection. Live SCM mutation, service restart,
and owner/group/DACL repair are intentionally not executed on the development
machine because they require installed test services and a controlled elevated
Windows host. Production Authenticode/CMS signing still requires a trusted
code-signing certificate that is not installed locally.

### Definition of done

- [x] Response behavior can be sourced from an offline-signed runtime policy.
- [x] Policy expiry, rollback, same-sequence changes, and tampering fail closed.
- [x] SCM configuration, executable hashes, and selected ACLs are audited.
- [x] Privileged repair is isolated from long-running endpoint services.
- [x] Recovery requires signed authorization plus explicit deployment opt-in.
- [x] Recovery attempts are persistent, bounded, and visible.
- [x] Missing or modified executable content is never reconstructed by the Guard.
- [x] Guard findings and failures use an independent tamper-evident chain.
- [x] Both Windows release architectures include the Guard and operator tooling.
- [x] Deployment and incident-response limits are documented.

### Next milestone

Add authenticated endpoint enrollment and policy distribution with per-device
identity, staged rollout rings, revocation, durable policy acknowledgement, and
fleet health visibility while keeping release and policy signing keys offline.

## 2026-11-17 — Milestone 15: endpoint enrollment and policy distribution

### Goal

Give every managed endpoint a non-transferable device identity and a bounded,
authenticated management channel. Use that channel to distribute only
offline-signed runtime policy authorized for the endpoint's rollout ring, carry
monotonic revocation state, and durably report exact policy application and a
privacy-limited health snapshot.

### Planned trust separation

- The endpoint generates its private key locally and never transmits it.
- A one-time bootstrap credential admits a device but cannot authorize policy.
- The online coordinator assigns rings, authenticates devices, distributes
  approved bundles, records acknowledgements, and revokes enrollments.
- The offline runtime-policy signer remains the only authority that can change
  response and integrity behavior.
- Endpoint anti-rollback state remains authoritative even if the coordinator is
  compromised or returns stale content.

### Initial implementation sequence

1. Add device identity, canonical signed requests, and durable strict state.
2. Add one-time enrollment and revocation credentials.
3. Add ring-scoped policy distribution and endpoint enforcement.
4. Add durable acknowledgements and bounded fleet health.
5. Add Windows deployment and end-to-end verification.

The complete protocol, security properties, data flow, privacy boundary, and
non-goals are documented in
`docs/endpoint-enrollment-and-policy-distribution.md` before code changes begin.

### Device identity and signed-request foundation

- Added a validated random device identifier, named-key reference, public-key
  fingerprint, and creation timestamp without storing private key material.
- Added deterministic canonical request bytes binding the device, enrollment,
  credential sequence, timestamp, nonce, HTTP method, path and query, and exact
  body SHA-256 digest.
- Added ECDSA P-256 signing and verification using fixed 64-byte IEEE P1363
  signatures. The signer refuses an identity whose persisted public-key
  fingerprint does not match the active key.
- Added strict, bounded device-identity persistence with duplicate and unknown
  JSON property rejection, reparse-point checks, an exclusive operation lock,
  atomic creation, and refusal to replace a conflicting identity.
- Added method, target, body, signature-format, key-mismatch, state-conflict,
  and malformed-state tests. The complete suite now passes 304 tests across the
  existing 14 projects.

### One-time bootstrap admission

- Added 256-bit cryptographically random bootstrap tokens encoded as canonical
  base64url. Secret access is explicit, string formatting is redacted, and
  disposal clears the in-memory secret bytes.
- Added a dedicated strict SQLite enrollment store that persists only token
  SHA-256 digests, assigned rollout rings, bounded validity, and consumption
  evidence. The schema carries a product identity and version so an unrelated
  SQLite database cannot be accepted accidentally.
- Consumed tokens with an immediate transaction and a conditional update, so
  concurrent requests can admit exactly one device. Reuse, unknown tokens, and
  tokens at or beyond expiration all return no admission.
- Restricted token validity to seven days, normalized device IDs, refused
  database roots and reparse-point directories, and used full durability for
  admission state.
- Added generation, canonical parsing, redaction, clearing, schema identity,
  expiry, one-use, concurrent-consumption, hash-only storage, and validity-bound
  tests. The complete suite now contains 316 passing tests.

### Enrollment proof and authenticated credentials

- Added a canonical proof-of-possession document that binds the device ID,
  SubjectPublicKeyInfo bytes and fingerprint, bootstrap-token digest, timestamp,
  nonce, and normalized HTTPS management origin.
- Signed enrollment proofs with the endpoint ECDSA P-256 key using fixed P1363
  signatures. Verification imports the submitted public key, requires P-256,
  checks the exact signature, enforces a bounded freshness window, and binds the
  proof to the presented bootstrap token and expected origin.
- Added strict server-issued enrollment credentials binding device and
  enrollment IDs, public-key fingerprint, rollout ring, credential sequence,
  active/suspended/revoked status, monotonic revocation generation, validity
  window, management origin, and enrollment-authority key ID.
- Required detached ECDSA P-256 credential signatures from a dedicated trusted
  public-key set, exact device-key binding, no more than 90 days of validity,
  and explicit not-yet-valid and expired rejection.
- Added proof authority, token, timestamp, public-key tamper, credential tamper,
  device mismatch, expiry, and authenticated revocation tests. The complete
  suite now contains 325 passing tests.

### Durable credential and revocation state

- Added strict, bounded enrollment state containing the exact credential hash,
  enrollment and device identity, public-key fingerprint, rollout ring, status,
  revocation generation, expiration, and management origin.
- Persisted state with an exclusive operation lock and atomic replacement.
  Lower credential sequences, changed bytes at the same sequence, lower
  revocation generations, identity replacement, and management-origin changes
  fail closed.
- Made revocation terminal for an enrollment record. Reactivation requires an
  explicit local reset and new enrollment rather than a later online response.

### Non-exportable Windows identity key

- Added a Windows CNG device-key store using the Microsoft Software Key Storage
  Provider, ECDSA P-256, signing-only usage, no export permission, and machine
  scope for production.
- Persisted only the CNG key name, random device ID, public-key fingerprint, and
  creation time. Missing keys, fingerprint changes, exportable keys, incorrect
  algorithms, and a pre-existing key without matching state all fail closed.
- Added current-user-scope integration tests that exercise the same key
  properties without requiring administrator access. They prove private-key
  export fails, reopening preserves the exact device ID and public key, and an
  untracked named key is not silently adopted.
- Added credential rollback, equivocation, revocation rollback, terminal
  revocation, identity replacement, persistent-key, and non-exportability tests.
  The complete suite now contains 334 passing tests.

### Replay reservation

- Added a durable SQLite nonce reservation store keyed by device ID and nonce.
  An immediate transaction prunes expired reservations, enforces a per-device
  bound, and atomically admits only the first use.
- Retained reservations for a caller-selected one-minute to 24-hour window.
  The same nonce remains independent across devices, while concurrent reuse for
  one device is rejected exactly once.
- Added duplicate, cross-device, expiry, and concurrent-reservation tests. The
  complete suite now contains 338 passing tests.

### Atomic coordinator enrollment

- Migrated the strict enrollment database from schema 1 to schema 2 with a
  device-enrollment table that binds a unique device ID and public-key
  fingerprint to its enrollment ID, ring, status, sequence, revocation
  generation, validity, and management origin.
- Added a coordinator flow that verifies proof of key possession and request
  freshness, reserves the nonce, atomically consumes the bootstrap token and
  creates the durable device record, then issues a detached signed credential.
- Kept the enrollment-authority key separate from runtime-policy signing keys.
  The issuer creates only enrollment credentials and cannot authorize endpoint
  response or integrity behavior.
- A repeated proof fails at replay reservation, a fresh proof cannot reuse a
  consumed token, and a duplicate-device database failure rolls back token
  consumption. Version-1 stores migrate without losing issued bootstrap tokens.
- Added end-to-end credential verification, replay, token reuse, transaction
  rollback, and schema migration tests. The complete suite now contains 343
  passing tests.

### Offline-authorized rollout distribution

- Added a strict signed distribution authorization that binds its sequence,
  exact runtime-policy ID and sequence, exact manifest SHA-256,
  allowed rollout rings, bounded validity, and offline policy-authority key.
- Added a closed package format containing only the existing signed runtime
  policy directory plus detached authorization bytes and signature. Reparse
  points, extra entries, invalid UTF-8, duplicate or unknown JSON properties,
  oversized inputs, and untrusted keys fail closed.
- Required the endpoint to have a currently active, unexpired enrollment in an
  authorized ring. Suspended, revoked, expired, and wrong-ring credentials are
  rejected locally even if the management service returns the package.
- Reused the existing runtime-policy signature, expiry, and durable
  anti-rollback path, then matched the offline authorization to the verified
  policy ID, sequence, and exact manifest digest before activation.
- Added valid-rollout, wrong-ring, authorization tamper, policy mismatch,
  expiration, inactive enrollment, malformed authorization, and package-shape
  tests. The complete suite now contains 354 passing tests.

### Persisted revocation enforcement

- Added one credential-processing path that verifies an enrollment-authority
  signature, commits the credential through the durable anti-rollback store,
  and only then permits active state to continue.
- Persisted authenticated suspension or revocation before returning a
  fail-closed result. Startup checks now reload durable state and reject missing,
  inactive, or expired enrollment rather than trusting a prior in-memory value.
- Changed rollout-policy verification to consume the durable enrollment
  snapshot, so policy cannot be authorized through a stale credential after a
  revocation was committed.
- Retained terminal revocation: a higher-sequence credential cannot reactivate
  the enrollment. Re-enrollment requires an explicit local reset rather than a
  remote state transition.
- Added persist-before-fail, restart, terminal-reactivation, and expiration
  tests. The complete suite now contains 358 passing tests.

### Unified management request admission

- Added strict coordinator-side enrollment lookup including the enrolled public
  key, current credential sequence, status, expiry, rollout ring, revocation
  generation, and management origin.
- Added one post-enrollment request admission coordinator that requires an
  active, current enrollment and a fresh timestamp before verifying the exact
  HTTP method, path and query, and body digest with the enrolled P-256 key.
- Verified the stored SubjectPublicKeyInfo fingerprint before using the key.
  Only a valid request may reserve its nonce, so invalid traffic cannot consume
  the endpoint's replay budget.
- Reserved admitted nonces durably for at least the complete request-validity
  window. A repeated request is rejected before a management handler can run.
- Added exact-request, replay, wrong-body, stale-time, credential-sequence,
  suspended, and revoked enrollment tests. The complete suite now contains 365
  passing tests.

### Durable policy acknowledgement and bounded fleet health

- Added canonical exact-policy acknowledgements binding a stable random
  acknowledgement ID to the device, enrollment, policy ID, sequence, exact
  manifest SHA-256, and application time.
- Added strict atomic acknowledgement persistence. Retries preserve the same
  acknowledgement bytes across restart, a higher policy cannot replace a
  pending acknowledgement, and enrollment identity cannot change implicitly.
- Required an exact acknowledgement-ID confirmation before marking delivery.
  Incorrect confirmations leave the record pending, while successful delivery
  permits the next higher policy acknowledgement without lowering the durable
  policy floor.
- Added a canonical fleet-health schema containing only protocol and agent
  versions, pseudonymous device/enrollment IDs, rollout ring, exact current
  policy identity, closed component states, timestamps, and at most 16 stable
  error identifiers. Paths, usernames, command lines, contents, and arbitrary
  log strings have no fields and fail identifier validation.
- Added canonicalization, privacy-bound, persistence, retry, confirmation,
  replacement, enrollment-binding, and malformed-state tests. The complete
  suite now contains 376 passing tests.

### Windows identity lifecycle foundation

- Separated identity creation from repair validation. Repair now requires both
  strict persisted state and its matching non-exportable P-256 CNG key and will
  never create a replacement for missing material.
- Added explicit rotation and removal operations requiring the exact current
  device ID. Both validate the state/key binding before changing anything.
- Added same-volume atomic state retirement with reparse-point, filesystem-root,
  pre-existing archive, wrong-device, and active-state replacement guards.
  Retired state remains available as recovery and audit evidence.
- Rotation deletes the old key only after state retirement, creates a fresh
  random device ID and non-exportable key, and leaves the endpoint requiring
  new enrollment. Removal archives state and deletes the named private key.
- Added state retirement/restoration, wrong-device, repair-without-creation,
  rotation, key replacement, and removal tests. The complete suite now contains
  381 passing tests.

### Windows enrollment lifecycle commands

- Added elevated PowerShell entry points for installation, repair, rotation,
  and removal, backed by one hardened lifecycle implementation rather than four
  divergent security paths.
- Added `ShouldProcess`/`WhatIf`, strict assembly and path validation,
  filesystem-root and reparse-point refusal, same-tree archives, exact device-ID
  confirmation for destructive actions, and structured operation results.
- Restricted the state tree by removing inherited ACLs and granting full
  control to Local System and Administrators. An explicitly selected state
  consumer may receive modify access without changing private-key export policy.
- Made repair validation-only, kept installation idempotent for the exact
  identity, and reported re-enrollment as required after rotation or removal.
  Archived state is preserved instead of being recursively deleted.
- Added parser and security-control tests for the shared lifecycle script and
  all four operator wrappers. The script test suite and all 381 .NET tests pass.

### Milestone 15 integration and release handoff

- Added the enrollment lifecycle security test and release-packaging contract
  to Windows CI alongside the existing 381-test solution, authenticated runtime
  policy integration, release metadata, and deployment-plan gates.
- Packaged every Windows enrollment lifecycle entry point through the existing
  signed release deployment tree. The tools publication carries the Core and
  Infrastructure assemblies used by the elevated lifecycle host.
- Added the endpoint enrollment, authenticated runtime policy, and signed
  release operator guides to the signed release payload and manifest rather
  than requiring network access during installation or recovery.
- Verified the complete milestone across real non-exportable CNG key tests,
  atomic enrollment, authenticated and replay-bound requests, offline-authorized
  rollout policy, terminal revocation, durable acknowledgements, bounded fleet
  health, lifecycle scripts, packaging, and CI.
- Milestone 15 is complete. The final suite contains 381 passing .NET tests plus
  PowerShell integration, lifecycle-security, release-integrity, packaging, and
  deployment-plan tests.

## Milestone 16 — Static PE executable analysis

Milestone 16 extracts bounded structural facts from Windows Portable Executable
files without invoking loader behavior. The trust boundary, status contract,
resource limits, planned checkpoints, and non-goals are documented in
`docs/static-pe-executable-analysis.md` before parser implementation begins.

The analyzer is intentionally verdict-neutral. Header fields, section layout,
imports, resources, metadata, certificate-table presence, and overlays become
evidence for Milestone 17; none is treated as proof of malware or safety in
isolation.

### Bounded PE recognition and header extraction

- Added a verdict-neutral analysis result with explicit analyzed, non-PE,
  unsupported, malformed, unsafe-input, and I/O states plus stable issue codes.
- Added configurable file-size and section-count limits. The analyzer rejects
  missing files, directories, reparse points, empty files, oversized inputs,
  and files whose length changes between inspection and the opened handle.
- Recognized the DOS signature before invoking the PE reader, distinguished
  ordinary non-PE files from truncated or malformed PE candidates, and retained
  cancellation semantics without exposing exception text as detection data.
- Extracted bounded PE32/PE32+ machine, timestamp, characteristics, subsystem,
  DLL characteristics, image base, entry point, alignments, image/header sizes,
  checksum, section count, and data-directory count using checked conversions.
- Added valid managed-assembly, non-PE, truncated MZ, invalid PE offset, empty,
  and configured-size-limit tests. The complete suite now contains 387 passing
  tests.

### Section mapping, overlap, and entropy facts

- Added bounded section records containing the eight-byte PE name, virtual and
  raw ranges, characteristics, Shannon entropy, raw/virtual alignment, header
  overlap, inter-section overlap, and entry-point containment facts.
- Converted every signed parser field through checked non-negative conversion
  and validated raw ends against the opened file length and mapped virtual ends
  against both `SizeOfImage` and the 32-bit RVA space.
- Calculated entropy with one pooled 64 KiB buffer and a fixed 256-counter
  histogram, so memory use does not scale with section size. Cancellation is
  observed on each bounded read and rented memory is cleared before return.
- Recorded raw and virtual overlaps symmetrically without converting a
  parseable structural anomaly into a malware verdict. Out-of-file and
  out-of-image ranges remain malformed and fail closed.
- Added real-assembly range/entropy checks plus synthetic out-of-file,
  overlapping-raw-section, and zero-entropy fixtures. The complete suite now
  contains 390 passing tests.

### Bounded imports, exports, and resources

- Added bounded traversal for normal and delay-load import descriptors, thunk
  tables, named imports, ordinal imports, hints, module names, and terminators.
- Added export-directory traversal with count validation, ordinal mapping,
  optional names, target RVAs, and bounded forwarder strings.
- Added a depth-bounded resource tree reader for type, name, language, data RVA,
  size, and code page. Directory cycles, invalid offsets, oversized names,
  truncated payload mappings, and configured count limits fail closed.
- Preserved the original numeric values of existing public issue codes while
  adding stable directory-specific failures and a shared limit-exceeded code.
- Added real managed-import coverage and synthetic delay-import, export,
  resource, and cyclic-resource fixtures. The complete suite now contains 394
  passing tests.

### Platform data-directory facts

- Added bounded debug-directory records with versions, type, timestamps, data
  locations, and file-range validation without loading debug payloads.
- Added PE32 and PE32+ TLS extraction with VA-to-RVA normalization, raw-data
  ranges, index and callback-table locations, and terminated callback traversal.
- Added size-versioned load-configuration extraction for global flags, critical
  section timeout, security-cookie RVA, SEH count, and guard flags.
- Added checked relocation-block traversal and architecture-aware exception
  records for AMD64, IA64, ARM, and ARM64, while retaining bounded directory
  summaries for other machine types.
- Added per-directory limits and stable issue codes plus positive combined and
  malformed-relocation fixtures. The complete suite now contains 396 passing
  tests.

### Managed metadata, certificates, and overlays

- Added bounded CLR metadata facts for runtime version, COR flags, entry point,
  metadata/resources/strong-name locations, module and assembly identity, and
  selected table counts without reflecting or loading managed types.
- Added checked `WIN_CERTIFICATE` traversal using file offsets, eight-byte
  alignment, section-separation validation, explicit table and record limits,
  and revision/type facts. Certificate presence remains verdict-neutral.
- Added trailing-data measurements from the final mapped section boundary and
  excluded the complete certificate table, including alignment padding, from
  the reported overlay size.
- Added real managed-assembly assertions plus synthetic appended-certificate
  and overlay fixtures. The complete suite now contains 398 passing tests.

### Scanner, CLI, history, and telemetry integration

- Added optional PE analysis to the composite scanner and enabled it in both
  CLI and service scanner construction. Cross-stage file changes discard PE
  facts and produce an incomplete combined result.
- Added complete bounded PE facts to file and directory JSON output, concise
  human summaries, operational JSON logs, and monitor events.
- Added stable per-file PE history summaries and a transactional SQLite schema
  version 2 migration while preserving version 1 data and compatibility.
- Added compact PE identity to detection-response security telemetry without
  emitting unbounded directory contents.
- Added scanner attachment and history migration/round-trip tests, then
  exercised the built CLI against a managed assembly. The complete suite now
  contains 400 passing tests.

### Malformed corpus, release packaging, and completion

- Added a data-driven malformed PE corpus covering delay-import attributes,
  export count exhaustion, resource cycles, debug alignment, unterminated TLS
  callbacks, load-configuration sizing, relocation overruns, exception-table
  alignment, and truncated certificates. Every case fails closed with its
  stable issue code.
- Added the static PE analysis guide to both Windows release architectures and
  a packaging contract test. CI now runs that contract beside release metadata,
  deployment-plan, and enrollment packaging verification.
- Expanded operator documentation with CLI usage, status interpretation,
  verdict-neutrality guidance, default limits, and corpus maintenance rules.
- Verified formatting, the complete 409-test .NET suite, PowerShell parsing and
  release packaging, locked dependency restore, and the vulnerability report.
- Milestone 16 is complete. Static PE facts are ready as bounded evidence for
  Milestone 17 explainable risk scoring; they do not independently assign a
  malware verdict.

## Milestone 17 — Explainable risk scoring and verdict aggregation

Milestone 17 turns completed detector output into a bounded, reproducible risk
assessment without treating heuristic correlation as certainty. The verdict
vocabulary, evidence precedence, confidence meaning, score contract, policy
identity requirements, trust boundary, planned checkpoints, and non-goals are
documented in `docs/explainable-risk-scoring.md` before scoring implementation
begins.

The default design is conservative: exact configured detections retain
precedence, heuristic categories are capped, incomplete evidence reduces
confidence, and only the final `Malicious` verdict authorizes existing automatic
response behavior. The complete baseline remains 409 passing .NET tests.

### Normalized PE risk features

- Added immutable risk features with bounded lowercase identifiers, explicit
  categories, and deterministic integer strength from 1 through 100.
- Extracted structural overlap, entry-point mapping, write/execute memory,
  executable entropy, import capability groups, ordinal imports, TLS callbacks,
  overlays, and missing ASLR/NX compatibility from the completed PE report.
- Kept raw import names, metadata, filenames, and paths out of feature output.
  Capability membership is converted only into trusted stable identifiers.
- Bounded each PE assessment to 32 sorted features and added constructor,
  malformed/non-PE, synthetic suspicious, and real-assembly determinism tests.
  The complete suite now contains 415 passing tests.

### Versioned weighted policy and score engine

- Added a schema-versioned immutable default policy with stable identity,
  monotonic policy version, validated review/detection thresholds, unique rule
  IDs, trusted explanations, and a cap for every feature category.
- Added checked integer scoring that combines feature strength and rule weight,
  sorts contributions deterministically, ignores unknown forward-compatible
  feature IDs, and caps correlated contributions before the total 0-100 cap.
- Kept raw and applied points in every contribution plus per-category raw,
  capped, and applied totals so every score is reproducible and explainable.
- Added policy validation, cap arithmetic, input-order determinism, and unknown
  feature tests. The complete suite now contains 421 passing tests.

### Verdict aggregation and evidence precedence

- Added the four-state `Inconclusive`, `NoKnownThreat`, `Review`, and
  `Malicious` verdict vocabulary with an explicit confidence value and typed,
  bounded evidence sources.
- Preserved exact SHA-256 reputation and byte-signature detections as the
  highest-precedence evidence. Exact matches remain malicious even if another
  configured stage is incomplete; heuristic detections remain distinguishable.
- Converted PE features into explainable contributions, made failed configured
  stages inconclusive, and kept malformed or unsupported PE confidence below a
  fully completed analysis.
- Added precedence, threshold, confidence, exact-versus-heuristic, incomplete,
  and clean-result tests. The complete suite now contains 427 passing tests.

### Assessment integration

- Attached a final risk assessment to every composite file scan, including
  inconclusive hash failures, and made the final malicious verdict the single
  detection decision used by directory scans and response handling.
- Added complete assessment output to CLI JSON, concise verdict/score/confidence
  and top-contribution output for operators, structured log fields, monitor
  events, and compact service security telemetry.
- Added a bounded history summary containing verdict, confidence, policy
  identity, score, exact-evidence state, and the five strongest feature IDs.
  SQLite history schema version 3 migrates the new JSON column transactionally.
- Preserved exact quarantine evidence and added policy-versioned evidence for
  heuristic detections. Scanner and history round-trip/migration coverage now
  accompany the 428-test suite.

### Calibration and false-positive controls

- Added a source-controlled calibration corpus covering clean completion,
  legacy hardening, isolated network capability, review-level independent
  signals, correlated-category caps, and a multi-category high-risk sample.
- Locked default-policy scores, verdict boundaries, policy identity/version,
  and byte-identical JSON output across feature permutations.
- Added false-positive regressions for the real managed test assembly and
  isolated common signals; neither can cross the review threshold alone.
- Verified adversarial correlated memory evidence cannot escape its category
  cap. The complete suite now contains 433 passing tests.

### Release and operator readiness

- Expanded the operator guide with verdict and confidence interpretation,
  exact-versus-heuristic handling, the default version-1 thresholds and category
  caps, and the required calibration/versioning workflow.
- Added the risk guide to release packages and a PowerShell contract that checks
  documentation sections, corpus breadth, and Milestone 17 completion.
- Added the contract to Windows CI alongside the existing packaging checks.
- Verified locked restore, a warning-free release build, formatting, all 433
  .NET tests, PowerShell parsing, every release/enrollment/runtime-policy
  contract, and the direct/transitive vulnerability audit. Milestone 17 is
  complete.

## Milestone 18 — Behavioral telemetry and detection

Milestone 18 begins with a documented local-first collection boundary before
any operating-system provider is enabled. The version-1 vocabulary covers only
process lifecycle, image load, file/registry change, network connection, and
provider-health facts needed for bounded correlation. Command lines, content,
memory, packet payloads, keystrokes, screenshots, environment data, and raw
registry values are explicitly excluded.

The contract defines immutable normalization, process-ID reuse protection,
monotonic receipt ordering, provider generations, deterministic eviction,
bounded queue/process/event/feature counts, a five-minute in-memory window, and
summary-only persistence. Event gaps and restarts reduce confidence or make a
negative conclusion inconclusive rather than silently producing a clean result.

Seven independently reviewable checkpoints cover core ingestion contracts,
Windows adapters, correlation and scoring, product integration, adversarial and
false-positive testing, and release readiness. The implementation begins from
the existing 433-test baseline.
