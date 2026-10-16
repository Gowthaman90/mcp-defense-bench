# Scoring changelog

## 2026-10-16 — v0.9.0: delegation family promoted (5 vectors, pre-registered), scoreCap rule

Promotion of the family registered on 2026-10-15 (`docs/DELEGATION-PREREG.md`, tag
`delegation-prereg-2026-10-15`), in the registered order: defenders implemented blind to the held-out
set and frozen (`staging/delegation/MANIFEST.json → defenderFreeze`), every staged file verified
against its sha256, crosswalk adjudicated (`rubric/ratings/ADJUDICATION.md`, rubric 0.8.0 → **0.9.0**,
32 → **37** vectors), fixtures copied byte-identical into both corpora, dev run, held-out run **once**,
benign run. No fixture was removed (`removals` empty).

**Scorer change — `scoreCap` (prereg §6.4).** A case marked `"scoreCap": "detect"` is scored at most
`detect` even when a tool blocks, on every corpus, because RFC 8693 §4.1 makes prior actors
informational (they must not drive access control). It marks the chain-depth and chain-cycle fixtures.
In this run no tool blocked one, so the cap changed no score. Adapters may now also declare
`meta.fixtureTypes`; cases of other types are not run for them and their vectors stay `unknown`
(not counted as misses).

**Peers.** mcp-firewall 0.1.0 and pipelock 3.0.0 are wired `detect:false` for `delegated-request` after
inspecting their code (no delegate-token claim logic; JWT appears only as a secret/DLP pattern).
mcp-bastion is measured at unreleased commit `c18ff0f` (delegation checks, structural + signature mode).

**Two totals (CorpusRobustCoverage; held-out over the vectors the held-out corpus covers).**

| Tool | Published 32 — dev | Published 32 — held-out | All 37 — dev | All 37 — held-out | Matched-control FP (dev / held-out) | Benign FP (337 items) |
|---|--:|--:|--:|--:|--:|--:|
| mcp-bastion | 62% (19.9/32) | 44% (10.5/24) | **66% (24.6/37)** | **53% (15.3/29)** | 0/66 · 0/63 | 14 (4.2%, 2.5–6.9%) |
| mcp-firewall | 9% (3.0/32) | 10% (2.5/24) | 8% (3.0/37) | 9% (2.5/29) | 0/66 · 0/63 | 2 (0.6%, 0.2–2.1%) |
| pipelock | 4% (1.3/32) | 0% (0.0/24) | 4% (1.3/37) | 0% (0.0/29) | 0/66 · 0/63 | 3 (0.9%, 0.3–2.6%) |
| null-baseline | 0% | 0% | 0% (0.0/37) | 0% (0.0/29) | 0/66 · 0/63 | 0 (0.0%, 0.0–1.1%) |

Every outcome on the 32 previously published vectors is unchanged for every tool (all 51 dev and 48
held-out pre-existing cases compared case by case; benign flags identical). The changes in the "all 37"
columns come only from the new family and the larger denominator.

**Delegation family, per vector (RobustCoverage, dev → held-out; 3 + 3 fixtures each).**

| Vector | mcp-bastion | mcp-firewall | pipelock | null-baseline |
|---|--:|--:|--:|--:|
| delegation-audience-confusion | 100% → 100% | 0 → 0 | 0 → 0 | 0 → 0 |
| delegation-subject-mixing | 100% → 100% | 0 → 0 | 0 → 0 | 0 → 0 |
| delegation-stale-relay | 100% → 100% | 0 → 0 | 0 → 0 | 0 → 0 |
| delegation-chain-laundering | 67% → 83% | 0 → 0 | 0 → 0 | 0 → 0 |
| delegation-signature-forgery | 100% → 100% | 0 → 0 | 0 → 0 | 0 → 0 |
| **Family (5)** | **93% (4.7) → 97% (4.8); gap −3 pts** | 0 | 0 | 0 |

**Read these with the limits in mind.**
- mcp-bastion is the benchmark author's tool. The fixtures (dev and held-out) were registered before its
  delegation code existed, and its implementer worked from the dev fixtures only, but the author knew
  which properties a defender should check (prereg §9). The negative gap means only that the held-out
  set was not harder for it. It is not evidence of generality beyond the registered properties.
- Two held-out blocks came from mcp-bastion's strict decoding (`delegation-malformed`), not from the rule
  the fixture targets: a standard-base64 (padded) payload carrying a misrouted audience, and a
  numeric-string `exp` in the past. Both are refused fail-closed, which is the scored behaviour; the
  prereg names `time` as the intended reading of the second.
- The case-variant subject fixture (prereg §9's borderline case) is flagged as subject mixing:
  mcp-bastion compares `sub` case-sensitively, as RFC 7519 StringOrURI comparison requires.
- Chain laundering stays below 100% by design: chain depth and cycle are warn-only under `balanced`
  (detect = 0.5), and `scoreCap` would cap a block anyway.

## 2026-09-30 — mcp-bastion v1.1.0 re-measured (no metric or corpus change)

Tool change only; rubric v0.8.0, corpora and scorer unchanged. The adapter now calls `checkErrorSteering`
(wired into bastion's response scan on the tools/call path) in the tool-result case.

- Dev CorpusRobustCoverage 61% (19.4/32) → **62% (19.9/32)**; Capability 69% → 70%; uncovered 6 → **5**.
- 24 pre-existing vectors: dev 55% → 57%, held-out 43% → 44% (gap 13 → 14 pts). The held-out false-error
  fixtures were not consulted while writing the rule (docs/HELD-OUT-PROTOCOL.md); robust 0.25.
- Matched-control false positives unchanged: 0/51 dev, 0/48 held-out.
- Benign corpus 13 → **14** flags (3.9% → 4.2%, Wilson 2.5–6.9%): an EACCES error that suggests "elevated
  privileges". Kept as a disclosed cost rather than tuned away.
- bastion's new standing-grant elicitation check does not score: the consent-fatigue fixture is not
  elicitation-shaped, so the adapter still reports it as a miss.
- The v1.0.2 figures remain reproducible from the results at commit 00a78b0.

## 2026-09-08 — v0.8.0: EU AI Act + ISO/IEC 42001 crosswalk columns (no metric change)

Two framework dimensions added to every vector — `euAiAct` (Regulation (EU) 2024/1689 Arts. 12, 14,
15(5), 26, 55(1)(d), 72, 73) and `iso42001` (Annex A controls A.4.4, A.6.2.4, A.6.2.5, A.6.2.6, A.6.2.8,
A.7.5, A.8.4, A.9.2, A.10.3) — with per-dimension decision rules in `rubric/RATING-CODEBOOK.md` v1.2 and
scope notes in the rubric legend (the mapping states which obligation a vector's defence *serves*, not that
a given deployment is regulated). `bin/score.mjs` reports `byEuAiAct` / `byIso42001` rollups. **Single-rater
as of v0.8.0**; a second-rater pass over these two dimensions is the next agreement task. CorpusRobustCoverage
and every measured number are unchanged.

## 2026-09-05 — v0.7.0: per-revision coverage, held-out coverage, benign-corpus FP rate (no metric change)

**Trigger:** AISec 2026 Review #34A (expert). Three requests — a held-out attack set, more variants and a
broader benign set, and a second-rater agreement measure — plus the desk-reject lesson on anonymity.

**What changed in what is reported (CorpusRobustCoverage / Capability / Guaranteed are unchanged):**

1. **Corpus grows 35 → 51 development fixtures, 24 → 32 vectors.** The 8 new vectors are the surface
   introduced by the 2026-07-28 protocol revision and carry `appliesTo: ["2026-07-28"]`; the leaderboard now
   reports coverage **per protocol revision** and separately on the "new-only" 8. No pre-existing fixture changed.
2. **Held-out coverage** (`results/heldout/`, `docs/HELD-OUT-PROTOCOL.md`): 48 fixtures authored after the
   defender freeze under pre-registered rules; reported beside development coverage with the generalisation gap.
   Held-out runs never write `adapters/*/coverage.json`.
3. **Benign-corpus false-positive rate** (`results/benign/`): 337 benign-only items; FP rate with Wilson 95%
   interval, broken down by input kind. Complements (does not replace) matched-control FP on the paired corpora.
4. **Rater agreement** (`docs/AGREEMENT.md`, `bin/agreement.mjs`): κ / Jaccard between the primary crosswalk and a
   blind second pass; adjudication log in `rubric/ratings/ADJUDICATION.md` (crosswalk 0.7.0 → 0.7.1, 12 mappings).

**Impact on the reference proxy's numbers:** 24-vector development RobustCoverage 55% (unchanged since the
2026-07-24 fix); 32-vector 52% (16.8/32); **held-out 43% (10.3/24), a 13-point gap**; benign FP 13/337 (3.9%),
of which 4 are by-design TOFU flags on benign definition updates. Matched-control FP 0/51 and 0/48.

## 2026-07-26 — Headline renamed CorpusRobustCoverage; scope made explicit (not a procurement ranking)

**Credit:** Massimiliano Brighindi (independent researcher), blind-test structural audit, 2026-07-26.

**What changed.** The headline metric (RobustCoverage) is renamed **CorpusRobustCoverage**, and the
leaderboard now states its scope explicitly: it is a **descriptive coverage measure over a fixed,
non-exhaustive corpus — not a procurement or substitutability ranking.** No numbers changed; this is a
naming + claim-boundary clarification.

**Why.** A blind structural audit showed the single full-corpus aggregate is valid only for the narrow
descriptive claim ("mean verified coverage over this versioned 24-vector corpus"), not as a universal basis
for comparing one vendor tool against another. Falsifying case: a broad tool that adds coverage where a
deployment's existing stack is already sufficient can outrank the narrow tool that closes the only
*mandatory* uncovered requirement — reversing the correct procurement decision. The aggregate conflates
(a) architectural breadth, (b) effectiveness within a tool's control point, and (c) the sampled corpus
composition, and it assumes all vectors are equally decision-relevant and that partial successes can
compensate for a mandatory miss.

**Planned (roadmap, not yet implemented): `RequiredGapClosure`.** A decision-indexed companion metric that,
for a **frozen deployment profile** (required vectors, mandatory set, public weights, existing baseline
stack, protected layers), reports the fraction of the *still-required* protection that adding a tool
actually closes — with a **mandatory-vector eligibility gate** (a high aggregate must never compensate for
failing a mandatory requirement) and three preregistered falsification tests (irrelevant-expansion
invariance, required-vector sensitivity, non-substitutable-tool ranking). Because it requires a frozen
profile, it will ship as a per-profile calculator / worked examples, not a single leaderboard figure.
CorpusRobustCoverage remains the reproducible descriptive result for research use.

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
