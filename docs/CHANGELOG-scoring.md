# Scoring changelog

## 2026-07-24 — RobustCoverage headline (fix: per-vector max-aggregation defect)

**Reported by:** Massimiliano Brighindi (independent researcher), via LinkedIn on the "Measuring the
Defenders" write-up, 2026-07-24. Credit for the defect and the repair shape is his.

### The defect

`bin/run.mjs` aggregated each attack vector by keeping the **best** result across that vector's fixtures:

```
S(v) = max_i w(result(v, i))
```

For a vector with multiple fixtures — a base attack plus disguised **evasion variants** — this meant a
tool that *missed* an evasion variant kept full credit as long as it caught one fixture. A tool catching
1 of 1 variants and a tool catching 1 of N variants received identical coverage. The headline therefore
measured **"demonstrated capability on ≥1 fixture," not coverage of the attack vector.** A false positive
on one benign variant could also be masked by a clean pass on another.

### The repair

Each vector now publishes three numbers over its fixtures `i` (weights: enforce 1.0, detect 0.5, none 0):

| Metric | Definition | Role |
|---|---|---|
| **Capability** | `max_i w_i` | best-case; the old headline — kept as **secondary** evidence |
| **RobustCoverage** | `mean_i w_i` | reliability across **all** fixtures incl. evasion variants — the **new headline** |
| **Guaranteed** | `min_i w_i` | worst-case floor |

A false positive on any benign variant forces that fixture's weight to 0 (it already sets the fixture
level to `none`), so it now drags the vector's mean down and zeroes its guaranteed floor — it can no
longer be hidden by a clean pass on a sibling variant. Where RobustCoverage < Capability, the tool is
flagged **evasion-brittle** for that vector.

### Impact on the published numbers (rubric v0.1.0-draft, 24 vectors, 35 fixtures)

| Tool | RobustCoverage (new headline) | Capability (old headline) | Guaranteed | FPs |
|---|--:|--:|--:|--:|
| mcp-bastion | 13.25/24 (55%) | 15.0/24 (63%) | 11.5/24 (48%) | 0 |
| mcp-firewall | 2.0/24 (8%) | 3.0/24 (13%) | 1.0/24 (4%) | 0 |
| pipelock | 1.33/24 (6%) | 2.5/24 (10%) | 0.0/24 (0%) | 0 |
| null-baseline | 0 | 0 | 0 | 0 |

Relative ranking is unchanged; zero false positives preserved. mcp-bastion's evasion-brittle vectors
(RobustCoverage < Capability): `indirect-retrieval-injection, tool-transfer, mitm-transport,
server-impersonation, credential-token-theft, system-prompt-leakage`.

### Files changed

- `bin/run.mjs` — per-fixture retention + Capability/RobustCoverage/Guaranteed + evasion-brittle flag.
- `bin/score.mjs` — headline = RobustCoverage (falls back to capability weight for self-reported claims);
  adds `overallCapability`.
- `bin/leaderboard.mjs` — RobustCoverage headline column + Capability secondary column.
- `bin/assert-floor.mjs` — regression gate now checks RobustCoverage (default floor 13.0); zero-FP gate
  unchanged.

### Note on the in-review paper

The AISec 2026 submission ("Measuring the Defenders") reports the pre-fix Capability numbers. The paper
is frozen in review; this refinement will be folded into the camera-ready / limitations if accepted. The
**living leaderboard** uses RobustCoverage as of this change.
