# AISec 2026 submission #34 — reviews and how each point was addressed

_Paper: "Measuring the Defenders: A Layer-Aware, Framework-Mapped Benchmark for Model Context Protocol
Security Proxies". Submitted 2026-07-17 (Benchmark-paper track). Decision 2026-09-03: **desk reject**
(anonymity), with two reviews already filed. This document is the verbatim record plus the point-by-point
response, written for (a) ourselves and (b) the "prior reviews" appendix the next venue requires._

## 1. The decision

> **Administrator (chair):** "The paper breaks anonymity as the name of the main author of the benchmark is
> available in the Artifact Repository. We have hence desk rejected the paper."

**What happened.** The paper itself was anonymised (`anonymous` class option, "OurProxy"/"OurBench",
author block removed). The artifact was provided as an anonymous.4open.science mirror of the public
repository. That mirror still contained `CITATION.cff`, `.zenodo.json`, `package.json → author`, the README
byline, and the git history — all carrying the author's name. Our own pre-submission notes flagged this as an
"optional nicety" after the chair had approved the 4open.science approach in principle. It was not optional.

**Fix (process, permanent).**
- `scripts/make-anon-mirror.mjs` builds the review artifact from a `git archive` (no history), deletes
  identity-only files, rewrites every identity string *and the real tool names* to placeholders, then runs a
  leak grep over contents **and filenames** and refuses to complete if anything survives. It writes an
  `ANONYMIZATION-REPORT.md` into the mirror.
- `paper/SUBMISSION-CHECKLIST.md` — anonymity, venue, and content gates, run in order.
- Rule: the mirror is uploaded from the script's output directory, never from a clone.

## 2. Review #34A — Overall C (weak, "will not fight strongly against it"); expertise 4/4; confidence 3/3

> **Strengths.** "The paper addresses an underexplored gap in current MCP evaluations, namely how to measure
> the actual defensive coverage provided by security tools across the MCP attack surface. While many existing
> benchmarks ask whether an agent can be compromised or still complete a task safely, this work study how much
> of the known MCP attack surface is actually covered by a given defensive tool. This is important for
> practitioners who need to understand where a proxy or gateway is effective and where meaningful gaps still
> remain."

### W1 — benchmark and strongest tool co-developed; need a held-out set

> "My main concern is that the benchmark and the strongest tool are developed very closely together. The paper
> says that the benchmark was used to improve OurProxy from 9% to 63% coverage. This is useful to show that the
> benchmark can guide development, but it also makes the final 63% result less independent. I think a held-out
> set of attacks (not used during development) is key to showing that the reported coverage is not too closely
> tied to the benchmark used to improve the tool."

**Agreed, and this was the most valuable comment we received.** Response:

1. **Pre-registered protocol** (`docs/HELD-OUT-PROTOCOL.md`, registered 2026-09-05 *before* any fixture was
   written): defender freeze recorded by version/commit in `results/heldout/MANIFEST.json`; fixture authorship
   blind to detector source; four named transformation families (domain, lexical, surface, encoding) with an
   explicit list of development-corpus artefacts that may not be reused (enforced by the generator); no
   iteration after the first run; rolling retirement of each held-out set into the next development corpus.
2. **Held-out corpus**: 48 fixtures across all 24 pre-existing vectors (≥2 each, families D 23 / L 10 / S 5 /
   E 10), each with a matched benign control (`testcases-heldout/`, `scripts/gen-heldout.mjs`).
3. **Result, reported as measured on the first run**: the reference proxy's RobustCoverage on the same 24
   vectors is **55% on the development corpus and 43% held-out — a 13-point generalisation gap**, with 0 held-out
   false positives. Two vectors it covered in development it misses entirely held-out (tool poisoning and
   multi-tool split poisoning — its heuristics are phrase-brittle), and four more degrade. The second proxy is
   flat (8% → 10%); the egress firewall's development coverage (6%) **vanishes** held-out (0%), i.e. it was
   entirely corpus-specific. These are findings about the tools, and they are now in the paper's headline table.
4. The 9%→63% narrative is retained as *what the benchmark is for* (guiding development) but is now explicitly
   separated from the coverage claim, which is the held-out number.

### W2 — small corpus; "zero false positives" on 35 controls does not generalise

> "The benchmark corpus is limited and this also makes the 'zero false positives' result hard to generalize. Most
> attack vectors are represented by only one or two fixtures, and the paper itself shows that coverage can change
> depending on how an attack is encoded, even when the tool stays the same. In the same way, observing no false
> positives on 35 benign controls is encouraging, but the set is still quite small. I suggest the authors include
> more attack variants and a broader set of benign cases in order to make both the coverage and false-positive
> results more robust."

**Agreed.** Response:

1. **Attack variants**: the scored corpus grows from 35 to **51** development fixtures (24 → 32 vectors, the 8
   new ones being the surface introduced by the 2026-07-28 protocol revision) **plus 48 held-out fixtures**, so
   every pre-existing vector now has ≥3 attack fixtures across the two corpora (median 4).
2. **Benign corpus**: a separate **337-item benign-only corpus** (`testcases-benign/`): **256 verbatim tool
   definitions harvested from 21 public MCP servers** (`scripts/harvest-benign.mjs` — the servers are started as
   a user would start them and `tools/list` is recorded with package/version provenance), plus **81 authored hard
   negatives** across every fixture type — legitimate outputs and calls that mention passwords, deletion, shells,
   base64, the cloud-metadata address, "ignore my previous message", etc.
3. **False-positive rate with a 95% Wilson interval, per input kind**, replaces "zero false positives":
   reference proxy **13/337 = 3.9% (CI 2.3–6.5%)**; second proxy 0.6%; egress firewall 0.9%. Four of the
   reference proxy's thirteen are the *by-design* cost of trust-on-first-use pinning flagging benign definition
   updates — reported in their own row rather than hidden — and one is a real over-match on a verbatim
   third-party definition (a monitoring tool whose description mentions webhooks). Matched-control FP stays 0
   on both development and held-out corpora; the paper now says what each measure does and does not show.

### W3 — framework mapping is subjective, single-author; need a second rater / agreement

> "The framework mapping remains somewhat subjective, since the authors note that it is indicative and based on a
> single-author assessment. Given that the crosswalk is one of the paper's main contributions, I think a second
> independent mapping pass or some measure of agreement across assessors would help quantify the reliability of
> these assignments."

**Agreed.** Response:

1. **Rating codebook** (`rubric/RATING-CODEBOOK.md`): decision rules per framework dimension; raters see only
   `rubric/ratings/vectors-for-rating.json` (id, name, aliases, description), never the crosswalk.
2. **Agreement tooling** (`bin/agreement.mjs`): Cohen's κ on primary labels, mean Jaccard and pooled per-label κ
   on the multi-label sets, and a disagreement list for adjudication. Output in `docs/AGREEMENT.md`.
3. **Second blind pass (Rater B)** over the 24 pre-existing vectors: primary-layer **κ = 0.75**, STRIDE
   **κ = 0.94**, set-level Jaccard **0.64–0.85** across the six dimensions (substantial agreement). 62
   disagreements adjudicated in the open (`rubric/ratings/ADJUDICATION.md`); 12 mappings changed, one codebook
   rule clarified; the **pre-adjudication** figures remain the headline.
4. **Honest limit, stated in the paper**: Rater B is an LLM rater following the published codebook, not an
   independent human. It demonstrates that the codebook is followable and makes every disagreement public; a
   human Rater C slot (`rubric/ratings/rater-TEMPLATE.json`) is open and the site will report agreement per rater.
   The 8 new vectors are single-rater and are labelled as such.

## 3. Review #34B — Overall D (reject); expertise 2/4 ("some familiarity"); confidence 2/3. No written comments.

Nothing actionable was provided. We read the score, in combination with #34A, as reflecting the same three
concerns (self-benchmarking, small corpus, subjective mapping) and the optics of a four-tool board; all three
concerns are addressed above. On the board, we additionally (a) report coverage **per protocol revision** so the
2026-07-28 vectors are not silently counted against tools that predate the revision, and (b) list the adapter
expansion plan (AWS AgentCore Gateway, MCP-Scan, Docker MCP Gateway, IBM ContextForge) in the roadmap.

## 4. Additional changes since submission (not requested, but material)

- **Protocol revision 2026-07-28 modelled**: 8 new vectors verified against spec text
  (`docs/SPEC-VERIFICATION-2026-07-28.md`), rubric `appliesTo` axis, per-revision leaderboard. To our knowledge no
  other MCP security benchmark is spec-versioned.
- **Reference proxy v0.9.0**: header/body coherence (`-32020`) and cache-policy enforcement wired into the proxy
  path — measured at 44% (3.5/8) on the new vectors; MRTR/Tasks/Apps surfaces honestly scored as misses.
- **Adapter faithfulness**: one adapter bug found by the benign corpus (a "clamp" reported on list results that
  carry no cache hints, which the runtime does not do) was fixed before publication and is logged.

## 5. Where to resubmit

IEEE SaTML 2027 (abstract 2026-09-22, paper 2026-09-29; 12 pp IEEEtran; double-blind with mandatory anonymised
artifact within 3 days; prior reviews must be appended). `paper/satml2027/` holds the revised manuscript.
