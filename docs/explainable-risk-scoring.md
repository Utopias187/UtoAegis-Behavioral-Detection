# Explainable risk scoring and verdict aggregation

Milestone 17 converts bounded detector facts into a deterministic risk
assessment. It explains why a file received its score and how exact reputation,
byte-signature, and heuristic evidence produced the final verdict. A score is
evidence for review and response; it is not proof that a file is malicious or
safe.

## Trust boundary

- Score only immutable results from completed scan stages. Never reopen a path,
  execute a file, load a module, resolve an import, or query the network while
  scoring.
- Assign every feature and contribution a stable identifier. Explanations are
  selected from trusted policy text rather than copied from untrusted file
  names, import strings, metadata, or paths.
- Normalize feature strength to a bounded range before applying a weight. Bound
  feature, contribution, category, and total counts before allocating.
- Use checked integer arithmetic and deterministic ordering. The same facts and
  policy version must produce byte-for-byte equivalent assessment data.
- Cap correlated evidence by category so several observations of one condition
  cannot dominate unrelated evidence.
- Preserve exact detector provenance. A known malicious hash or exact byte
  signature cannot be weakened by a low heuristic score.
- Treat incomplete, unsupported, malformed, or unavailable analysis as reduced
  confidence, never as evidence that the file is safe.
- Keep policy identity and version in every assessment, history record, JSON
  result, and telemetry event so decisions remain reproducible after upgrades.

## Verdict contract

The aggregate verdict vocabulary is deliberately narrow:

- `Inconclusive`: required evidence is unavailable or a scan stage failed.
- `NoKnownThreat`: completed configured detectors produced no detection. This
  does not claim the file is safe.
- `Review`: bounded heuristic evidence crossed the review threshold.
- `Malicious`: an exact configured detector matched, or the heuristic score
  crossed the explicitly configured detection threshold.

Exact hash reputation and byte-signature matches take precedence over heuristic
labels. Heuristics may raise a completed scan from `NoKnownThreat` to `Review`
or `Malicious`; they never lower exact evidence. Automatic quarantine remains
limited to the final `Malicious` verdict.

## Score contract

- Total score: integer from 0 through 100.
- Confidence: integer from 0 through 100 describing evidence completeness, not
  probability of malware.
- Contributions: stable feature ID, category, normalized strength, configured
  weight, applied points, and trusted explanation.
- Category totals: the sum of applied contributions after the policy cap.
- Policy: stable ID plus monotonically increasing schema and policy versions.

The default policy is conservative. Missing signatures, missing certificates,
timestamps, names, or entropy values are not malicious by themselves. Review
and detection thresholds require multiple independently capped categories.

## Operator interpretation

Treat the verdict as a response decision and the score as supporting context:

- `Inconclusive` means at least one configured stage failed. Correct the stage
  failure and rescan; do not treat the result as clean.
- `NoKnownThreat` means completed configured stages did not cross a threshold.
  It is not an allowlist decision and does not prove safety.
- `Review` should enter an analyst queue. Start with the highest applied
  contributions, then compare category raw points with applied caps.
- `Malicious` permits configured response. Check `HasExactDetection` to
  distinguish an exact reputation/signature match from a threshold decision.

Confidence measures completeness only. A score of 80 with 75% confidence is
not an 80% probability of malware. Exact matches report 100% confidence in the
configured match; malformed or unsupported PE analysis reports reduced
confidence, while failed hashing, reputation, signatures, or PE I/O produces an
inconclusive assessment.

Every report includes the policy ID and version. Preserve both with exported
evidence because the same file may receive a different score under a later,
explicitly recalibrated policy.

## Default policy version 1

Policy `utoaegis.pe.default` version 1 uses review threshold 35 and malicious
threshold 85. Category caps limit correlated observations:

| Category | Cap | Highest-weight observations |
| --- | ---: | --- |
| Structure | 25 | Unmapped entry point, overlapping section ranges |
| Memory | 30 | Process-injection imports, writable/executable sections |
| Packing | 25 | High executable entropy, substantial overlay |
| Execution | 25 | Writable entry point, dynamic resolution, TLS callbacks |
| Network | 15 | Network/download imports |
| Persistence | 15 | Service or registry persistence imports |
| Hardening | 8 | Missing ASLR or NX declarations |

The engine multiplies each trusted rule weight by normalized feature strength,
rounds with integer arithmetic, applies the category cap, then caps the total at
100. Full rule IDs, weights, and trusted explanations are defined in
`RiskScoringPolicy.Default`; CLI JSON returns every raw and applied contribution.

## Calibration and policy maintenance

The locked corpus at
`tests/UtoAegis.Core.Tests/Fixtures/RiskScoring/calibration-corpus.json` records
representative feature sets with expected score and verdict. Any policy change
must follow this sequence:

1. Add benign and suspicious regression cases that justify the proposed change.
2. Review false-positive impact, especially common hardening, overlay, network,
   and managed-assembly cases.
3. Increment the policy version; never reinterpret an existing version in place.
4. Update corpus expectations and explanations in the same reviewed change.
5. Run the complete test and release-contract suite before distribution.

Do not tune against filenames, publishers, timestamps, or a single sample. New
feature families need a stable identifier, bounded strength, trusted explanation,
category assignment, and a regression proving the category cap still holds.

## Completed checkpoints

1. Verdict vocabulary, evidence contract, threat boundary, and roadmap.
2. Normalized, bounded PE risk-feature extraction with stable identifiers.
3. Versioned weighted scoring policy, validation, category caps, and engine.
4. Exact-detector precedence, confidence, verdict aggregation, and response
   threshold behavior.
5. Scanner, CLI JSON, history, telemetry, monitoring, and service integration.
6. Calibration corpus, golden explanations, determinism, and false-positive
   regression coverage.
7. Release packaging, operator documentation, CI gates, and final verification.

## Non-goals

- No machine-learning model, cloud classification, reputation upload, or
  behavioral telemetry in this milestone.
- No claim that a score represents statistical malware probability.
- No automatic policy download or unsigned policy replacement.
- No use of filenames, paths, publisher names, timestamps, or certificate
  presence as standalone malicious evidence.
- No suppression of exact configured detections because heuristics disagree.
