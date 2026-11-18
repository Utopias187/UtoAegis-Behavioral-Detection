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
exception records. Managed images also report bounded CLR metadata identity and
table counts. Authenticode certificate records and trailing overlay size are
measured without treating signature presence as trust.

## Scanner integration

The composite scanner runs PE analysis after hashing and preserves its result
beside reputation and signature results. Ordinary non-PE files remain completed
scans. Unsafe-input and I/O failures make the combined scan incomplete, while
malformed structure remains reportable evidence rather than a detection.

CLI JSON contains the complete bounded report. Human output and operational
logs contain a compact summary. Scan history schema version 2 stores a stable
summary for each file and migrates existing version 1 databases transactionally.
Service detection telemetry includes the same compact PE identity without
including unbounded names or directory contents.

## Operator use

Run a normal file or directory scan. No separate PE-analysis switch is needed:

```powershell
dotnet run --project src/UtoAegis.Cli -- scan --json -- .\sample.exe
```

Interpret `portableExecutable.status` before reading facts. `Analyzed` means the
bounded structural report completed; it does not mean the file is safe.
`NotPortableExecutable` is expected for ordinary files. `Malformed`,
`Unsupported`, `UnsafeInput`, and `IoError` retain a stable `issueCode` for
automation and investigation.

Imports, exports, resource names, entropy, managed identity, debug information,
certificate presence, and overlay size are observations only. Do not quarantine
or allow a file from any single field. Milestone 17 combines multiple facts into
an explainable score.

The default limits are 512 MiB per file, 96 sections, 8,192 imports and exports,
4,096 resources, 128 debug entries, 256 TLS callbacks, 131,072 relocations,
65,536 exception records, one million selected metadata rows, 64 certificates,
and 16 MiB of certificate data. Library callers can lower these limits with
`PortableExecutableAnalyzerOptions`.

## Regression corpus

`tests/UtoAegis.Core.Tests/Fixtures/PortableExecutable/malformed-corpus.json`
drives deterministic mutations covering delay imports, exports, resources,
debug, TLS, load configuration, relocations, exception records, and certificate
tables. Corpus cases must return their stable issue code without crashing or
allocating from untrusted counts. The release package includes this guide, and
CI enforces both the corpus contract and packaging entry.

## Completed checkpoints

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
