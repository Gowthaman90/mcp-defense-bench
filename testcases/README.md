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

**22 / 22 rubric vectors** have a seed test case (one malicious fixture + one benign control each),
generated from `scripts/gen-testcases.mjs` (the authoritative source — edit that, not the JSON by
hand; it validates every rubric vector is covered before writing).

| Breadth | Status |
|---|---|
| ≥1 malicious + benign fixture per vector (22/22) | ✅ done |
| Multiple fixtures per vector (variants, evasions) | ⬜ next — deepen high-severity vectors first |
| Live adapter runner that executes fixtures against a tool | ⬜ next — turns claims into `verified: true` |

Next: a runner that feeds each fixture to an adapter and records detect/enforce, so the scorer
reports **verified** coverage instead of self-reported or `unknown` levels.
