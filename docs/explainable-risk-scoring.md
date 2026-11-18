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

## Planned checkpoints

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
