# Behavioral telemetry and detection

Milestone 18 adds bounded host activity correlation to UtoAegis. Behavioral
evidence complements exact hashes, byte signatures, and static PE facts; it does
not replace them. Collection remains local-first, does not execute inspected
content, and must fail visibly when event loss makes a conclusion unreliable.

## Security and trust boundary

- Treat every provider field as untrusted input, including paths, process IDs,
  timestamps, registry data, image names, addresses, and provider metadata.
- Convert provider records into immutable validated events before correlation.
  Reject unknown enum values, impossible sizes, invalid timestamps, and
  overlong or control-character-bearing strings.
- Never open, load, inject into, suspend, or execute a process while collecting
  telemetry. File content inspection continues through the existing scanner.
- Do not assume a process ID identifies one process forever. A process instance
  is identified by the collector generation, process ID, and observed start
  sequence; late events cannot attach to a reused process ID.
- Use monotonic receipt order for deterministic correlation. Provider
  timestamps are supporting evidence and cannot reorder already accepted data.
- A provider gap, queue overflow, restart, or correlation eviction is explicit
  health evidence. It reduces confidence and can make a result inconclusive;
  absence of events after loss is never evidence of safety.
- Behavioral rules and explanations are trusted, versioned content. No raw
  event text is copied into rule IDs or operator explanations.
- Automatic response requires a final policy-authorized `Malicious` verdict.
  A single low-confidence behavior observation cannot quarantine a file.

## Versioned event vocabulary

Every normalized event uses schema version 1 and contains a collector
generation ID, increasing receipt sequence, receipt time in UTC, optional
source time in UTC, event kind, process-instance subject, optional parent or
target process instance, source health state, and a bounded typed payload.

Initial event kinds are deliberately limited:

| Event kind | Required normalized facts | Excluded content |
| --- | --- | --- |
| `ProcessStarted` | Process instance, parent instance when known, executable identity, integrity class | Command line, environment, window text |
| `ProcessStopped` | Process instance, exit classification when available | Dumps and process memory |
| `ImageLoaded` | Process instance, module identity, signature state when already available | Module bytes |
| `FileChanged` | Process instance when attributable, operation class, local normalized path token | File contents |
| `RegistryChanged` | Process instance when attributable, key/value location class, operation class | Registry value data |
| `NetworkConnected` | Process instance, protocol, direction, address scope, destination port | Packet payload, DNS content, TLS content |
| `ProviderHealth` | Provider, state, dropped-count delta, generation | Provider-specific free-form messages |

Executable and module identity may contain a locally normalized path and a
SHA-256 already produced through the safe scanner. Correlation consumes typed
facts, never a provider's formatted message.

## Behavioral feature contract

Correlators emit stable lowercase identifiers under the `behavior.` namespace,
a category, integer strength from 1 through 100, the contributing event IDs,
and a trusted explanation selected by the active rule policy. Planned category
families are process execution, memory/module activity, persistence, defense
evasion, filesystem impact, and network activity.

An observation becomes stronger only through defined combinations within a
bounded time window. Common activity such as a process start, one network
connection, loading an unsigned module, writing a file, or changing a registry
value is not independently malicious. Correlated observations remain
heuristics and stay distinguishable from exact hash or byte-signature evidence.

## Bounds, backpressure, and retention

Schema version 1 establishes these implementation limits:

- At most 8,192 normalized events may wait in the collector queue.
- At most 4,096 active process instances may be correlated concurrently.
- At most 256 retained events and 64 emitted features are allowed per process
  instance.
- The live correlation window is at most five minutes. Raw normalized events
  expire from memory at the end of the window and are not written to scan
  history.
- A normalized string is at most 1,024 characters and an event is at most 16
  KiB after canonical JSON serialization. Longer provider values are rejected
  or deterministically truncated only where the field contract permits it.
- Queue overflow uses an explicit drop policy, increments a checked counter,
  and emits a `ProviderHealth` gap as soon as capacity returns.

Persisted history contains only a bounded assessment summary: policy identity,
verdict, score, confidence, categories, stable feature IDs, time range, event
count, and event-loss state. Existing retention and pruning remain responsible
for stored summaries.

## Privacy boundary

Collection is opt-in and disabled until the service configuration explicitly
enables a supported provider. UtoAegis does not collect keystrokes, clipboard
data, screenshots, document or packet contents, browser history, environment
variables, full command lines, registry values, or process memory.

Raw normalized paths and network endpoints may be used transiently on the host
for correlation and response. They are not included in forwarded behavioral
telemetry by default. Forwarded records use stable feature IDs, hashes already
approved for security telemetry, address scope rather than an address, port,
counts, policy identity, and provider-health metrics. Any future raw-field
export requires a separately signed policy and an explicit documentation and
privacy review.

## Failure and confidence semantics

- `Healthy`: all enabled providers are current and no relevant gap intersects
  the assessment window.
- `Degraded`: bounded loss or eviction occurred, but the remaining evidence can
  still support review. Confidence records the loss.
- `Unreliable`: initialization failed, sequence continuity is unknown, or loss
  exceeded the policy bound. Negative conclusions become `Inconclusive`.

Provider restart creates a new generation and closes all prior correlation
state. Rules cannot correlate across generations. Counters use checked integer
arithmetic, and state eviction is deterministic by oldest receipt sequence.

## Enabling collection safely

Behavioral collection is disabled in the shipped configuration. Enable it only
after the service is installed, its state directory ACL is protected, and the
host owner has approved the privacy boundary in this guide:

```json
"Behavior": {
  "Enabled": true,
  "Source": "KernelEtw",
  "HistoryPath": "C:\\ProgramData\\UtoAegis\\behavior-history.db",
  "QueueCapacity": 1024,
  "PollIntervalMilliseconds": 1000
}
```

`KernelEtw` is the production source. It subscribes to the Windows kernel
process, image, file-I/O, registry, and TCP/IP keywords through a private
real-time session. UtoAegis maps only process start/stop, image load, file
write/delete/rename, registry create/set/delete, and outbound TCP connect facts.
It does not request stacks, command lines, file contents, registry values, DNS
names, or packet payloads. The service account must be authorized by Windows to
start a kernel trace session. Authorization failure stops behavioral monitoring
and therefore stops the supervised service instead of silently falling back to
weaker evidence.

`ProcessSnapshot` is an explicit diagnostic fallback for hosts where kernel ETW
has not yet been authorized. It polls only process lifecycle and main-image
paths, so it cannot observe file, registry, or network correlations and should
not be represented as full behavioral detection. `PollIntervalMilliseconds`
applies only to this fallback. Both sources tokenize paths before correlation.

The installer grants the service identity modify access to the parent directory
of `HistoryPath` only when behavior is enabled. Keep that path outside the
monitored tree and installation directory. Start in `ObserveOnly`; a behavioral
assessment never directly quarantines a file because its event evidence does
not establish a safely re-openable artifact identity.

## Operations and recovery

- A healthy startup emits `behavior.started` with the source, collector
  generation, queue bound, and response mode. Non-clean assessments emit only
  bounded feature IDs, category points, policy identity, process-instance
  numbers, and provider health.
- ETW loss, local queue overflow, and correlation eviction are explicit health
  events. Review the Application log and security telemetry before trusting a
  negative result from the affected window.
- If `KernelEtw` initialization fails, verify Windows version, service-account
  trace authorization, and whether another policy blocks real-time kernel
  sessions. Do not switch to `ProcessSnapshot` without recording the coverage
  reduction.
- Restarting the service intentionally creates a new collector generation and
  discards raw in-memory events. The SQLite database retains bounded assessment
  summaries only; existing retention procedures may archive or remove it.
- Disable collection by setting `Enabled` to `false`, validating the
  configuration, and restarting the service. Removal preserves history for
  investigation; delete it only under the host's approved retention process.

## Validation and release gates

Every release must restore the committed NuGet graph in locked mode, build with
warnings as errors, pass formatting, and run all .NET, PowerShell, packaging,
and vulnerability checks. The behavioral packaging contract additionally
requires this guide, the calibration corpus, ETW in the production lock graph,
installer handling for the behavior-history ACL, and a completed Milestone 18
checklist. Release publishing includes this guide and records TraceEvent plus
its transitive packages in the generated CycloneDX SBOM.

## Milestone checkpoints

1. Define event vocabulary, privacy and trust boundaries, retention limits,
   failure semantics, and the implementation roadmap.
2. Add immutable event contracts, validation, bounded ingestion, process
   identity, provider health, and backpressure tests.
3. Add Windows provider adapters and privacy-preserving normalization for the
   approved process, image, file, registry, and network facts.
4. Add versioned deterministic correlation rules, behavioral features,
   category caps, scoring, explanations, and verdict aggregation.
5. Integrate configuration, service lifecycle, CLI diagnostics, history,
   tamper-evident telemetry, and policy-gated response.
6. Add synthetic attack sequences, benign workload calibration, determinism,
   overload/drop recovery, and long-running resource-bound tests.
7. Add operator documentation, release packaging, CI contracts, and final
   verification.

## Non-goals

- No kernel driver, packet capture, memory scanning, code injection, process
  termination, or autonomous remediation in this milestone.
- No cloud analytics, cross-device correlation, machine-learning classifier,
  or opaque probability score.
- No unrestricted event-log ingestion or permanent raw activity database.
- No weakening of exact detector precedence or existing signed response-policy
  controls.
