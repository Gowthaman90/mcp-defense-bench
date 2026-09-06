# Test cases

Each subdirectory is a **vector id** from [`../rubric/crosswalk.json`](../rubric/crosswalk.json).
Inside, each `NNN-name.json` is one concrete attack fixture plus the behavior a competent defender
should exhibit. Test cases are what turn a self-reported coverage *claim* into a *verified* score.

## Format

```jsonc
{
  "vector": "tool-poisoning",              // must match a rubric vector id
  "id": "tool-poisoning/001-…",
  "severity": "low|medium|high",
  "description": "what this exercises",
  "fixture": { "type": "…", "…": "the malicious input the defender sees" },
  "expected": { "detect": true, "enforce": true, "signal": "…", "rationale": "…" },
  "benignControl": { "…": "a near-identical benign input", "expected": { "detect": false } },
  "provenance": "synthetic | derived-from <source> — never a real exploit against a live target"
}
```

## Rules

- **Every malicious fixture needs a `benignControl`.** Coverage without a false-positive check is
  meaningless — a tool that flags everything scores 100% but is useless.
- **Fixtures are static data, not live exploits.** No fixture may attack a real endpoint. The
  attacker URL in examples is `attacker.example` (RFC 2606 reserved), never routable.
- **Cite provenance.** Synthetic is fine; say so. If derived from a paper's described attack, cite it.

## Coverage

**32 / 32 rubric vectors** have at least one test case (one malicious fixture + one benign control each),
generated from `scripts/gen-testcases.mjs` (the authoritative source — edit that, not the JSON by
hand; it validates every rubric vector is covered before writing). The eight 2026-07-28 vectors live in
`scripts/cases-2026-07-28.mjs` and carry `appliesTo: ["2026-07-28"]`.

| Breadth | Status |
|---|---|
| ≥1 malicious + benign fixture per vector (32/32) | ✅ |
| Realistic tool-neutral encodings (v2, 6 cases) | ✅ |
| Evasion-robustness variants (v3, 3 cases: zero-width/bidi, homoglyph, base64) | ✅ — see `../docs/ROBUSTNESS.md` |
| Protocol-revision 2026-07-28 vectors (16 cases, 8 vectors, verified against spec text) | ✅ v0.7.0 |
| **Held-out corpus** (48 cases, authored after defender freeze, pre-registered) | ✅ v0.7.0 — `../testcases-heldout/`, `../docs/HELD-OUT-PROTOCOL.md` |
| **Benign-only corpus** (337 items: 256 harvested real definitions + 81 hard negatives) | ✅ v0.7.0 — `../testcases-benign/` |
| Live adapter runner | ✅ `../bin/run.mjs <tool> [--corpus dev\|heldout\|benign]` |

**Development corpus: 51 cases** across 32 vectors. Fixtures with an `evasion` field are obfuscated
variants used by `../bin/robustness.mjs`. This directory is the *development* corpus: it has been used to
find and fix gaps in the reference proxy, which is why coverage on it is reported beside — never instead
of — coverage on the held-out corpus.
