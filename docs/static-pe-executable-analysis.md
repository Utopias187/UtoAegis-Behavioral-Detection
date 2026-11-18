# Static PE executable analysis

Milestone 16 adds bounded, read-only structural analysis of Windows Portable
Executable files. It extracts authenticated facts for later detection stages;
it does not execute, load, emulate, unpack, repair, or assign a malware risk
score to the file.

## Security boundaries

- Open only an explicitly selected regular file and reject reparse points,
  directories, empty files, and files above the configured analysis limit.
- Parse through bounded random-access reads. Never map an untrusted image as an
  executable module or invoke Windows loader behavior.
- Use checked arithmetic for every file offset, relative virtual address, table
  length, section range, and count-derived allocation.
- Bound section, directory, import, export, resource, certificate, debug, and
  managed-metadata counts before allocating or iterating.
- Treat truncation, overlap, impossible alignment, cycles, unterminated strings,
  unsupported formats, and concurrent file changes as analysis issues rather
  than process crashes.
- Keep extracted names and version fields length-bounded. Do not interpret
  arbitrary file data as paths to open or commands to execute.
- Return structural observations, not a malicious/clean verdict. Explainable
  weighting and verdict aggregation belong to Milestone 17.

## Initial analysis contract

The analyzer distinguishes:

- a valid PE image with a complete bounded report;
- a non-PE file, which is not itself an error;
- an unsupported PE variant;
- malformed or truncated PE structure;
- an unsafe or oversized input; and
- an I/O failure or cancellation.

The report records file size, PE32/PE32+ format, target machine,
timestamp, image characteristics, subsystem, DLL characteristics, image base,
entry-point RVA, alignment values, image/header sizes, checksum, section count,
data-directory count, bounded section layout and entropy, normal and delayed
imports, exports, resource identities, debug entries, TLS callbacks,
load-configuration security fields, relocations, and architecture-aware
exception records. Later checkpoints add managed metadata, certificate-table
facts, and overlay measurements without changing that status model.

## Planned checkpoints

1. Bounded PE recognition, status model, and strict header extraction.
2. Section mapping, range validation, overlap detection, and entropy facts.
3. Bounded import, delay-import, export, and resource traversal.
4. Debug, TLS, load-configuration, relocation, and exception-table facts.
5. Managed metadata, Authenticode certificate-table facts, and overlay analysis.
6. Composite scanner, CLI, history, telemetry, and JSON integration.
7. Malformed corpus, regression/fuzz seeds, packaging, operator documentation,
   and CI verification.

## Non-goals

- No file execution, sandboxing, emulation, or dynamic behavior collection.
- No automatic unpacking or deobfuscation.
- No claim that a structurally valid or signed PE is safe.
- No heuristic score or response action in this milestone.
- No trust decision based only on timestamps, names, entropy, or signature
  presence.
