# Crosswalk rating codebook v1.1 (for independent raters)

The crosswalk maps each MCP attack vector to six frameworks. This codebook lets a second rater
reproduce the mapping **without seeing the primary rater's answers**, so that agreement can be
measured and disagreements adjudicated in the open.

## What a rater sees

Only `rubric/ratings/vectors-for-rating.json`: for each vector its `id`, `name`, `aliases`, and
`description`. Nothing else from `rubric/crosswalk.json`. Do not open `crosswalk.json` before rating.

## What a rater produces

`rubric/ratings/rater-<X>.json`: for each vector id, the six fields below. Multi-valued fields are
sets (order-free). Put the **primary** value first in `mcpLayer` and `stride`.

| Field | Values | Decision rule |
|---|---|---|
| `mcpLayer` | `host-orchestration`, `client`, `transport`, `server`, `tool`, `registry-supply-chain` | Where is the **defence** best *placed* (the layer that can enforce), following the defense-placement view. First = primary. A vector may list a second layer only if a defence there is independently sufficient. |
| `stride` | `Spoofing`, `Tampering`, `Repudiation`, `InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege` | The threat class of the **attacker's primary goal**, then any second class the attack necessarily achieves. |
| `nistAiRmf` | `GOVERN`, `MAP`, `MEASURE`, `MANAGE` | Functions whose *outcomes are directly engaged* by defending this vector. `MEASURE` = the risk must be tested/monitored at runtime; `MANAGE` = a response/treatment is applied; `MAP` = the risk exists because of the system's context/ dependencies (third-party components, supply chain); `GOVERN` when a governance artefact (policy, baseline, approval record, provenance requirement) is *one of* the controls the defence relies on, not only when it is the primary control (clarified in v1.1 after adjudication). |
| `owaspLlm2025` | `LLM01`–`LLM10` | Every category whose canonical description covers the attack's mechanism **or** its direct impact. |
| `owaspAgentic2026` | `ASI01`–`ASI10` | Same rule, against the 2026 Agentic Top 10 titles. |
| `nsaGuidance` | `AUTH`, `LOG`, `SEG`, `RT` | Recommendation areas of the NSA MCP Security guidance (May 2026) that contain a control mitigating the vector. `RT` = runtime controls (egress filtering, DLP, sandboxing, message integrity, output filtering, local scans). `AUTH` = authentication/access control/least privilege/provenance. `LOG` = monitoring/logging of invocations. `SEG` = data classification & segmentation. |

Category titles for the two OWASP lists are in `rubric/crosswalk.json → _frameworks` and are
reproduced in `vectors-for-rating.json → _frameworks` so raters need not open the crosswalk.

## How agreement is scored (`bin/agreement.mjs`)

- **Primary-label agreement** (first element of `mcpLayer`, first of `stride`): Cohen's κ.
- **Set agreement** (all six fields): mean per-vector Jaccard index, plus per-label Cohen's κ on
  presence/absence pooled across vectors (reported per framework).
- Disagreements are listed vector-by-vector for adjudication. Adjudicated outcomes are written to
  `rubric/ratings/ADJUDICATION.md`; the crosswalk is then updated and its `version` bumped.

## Rater roster

| Rater | Who | Blind? | Scope |
|---|---|---|---|
| A | Benchmark author (primary crosswalk) | — | all vectors |
| B | LLM rater (Claude), following this codebook, given only `vectors-for-rating.json` | Blind to A's answers, except as disclosed in `rater-B.json → _disclosure` | 24 original vectors |
| C | *Open slot for an independent human rater.* Copy `rater-TEMPLATE.json`, fill it in, open a PR. | Yes | any |

Rater B is a documented, reproducible second pass. It is **not** an independent human, and the paper
says so. Its value is that the codebook is shown to be followable by a rater who did not write the
crosswalk, and that every disagreement is now public and adjudicated. Rater C is the stronger
evidence this benchmark still needs.
