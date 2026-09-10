<div align="center">

# 🧪 mcp-defense-bench

**A vendor-neutral benchmark that scores MCP security proxies/gateways on how much of the MCP attack
surface they actually defend — mapped to NIST AI RMF and the OWASP Top 10s.**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21346206.svg)](https://doi.org/10.5281/zenodo.21346206)

📊 **Live leaderboard: [gowthaman90.github.io/mcp-defense-bench](https://gowthaman90.github.io/mcp-defense-bench/)**

**Created & maintained by [Gowthaman Arumugam](https://github.com/Gowthaman90) · Independent Researcher**

</div>

> **Cite this work:** Arumugam, G. (2026). *Measuring the Defenders: A Layer-Aware, Framework-Mapped
> Benchmark for Model Context Protocol Security Proxies.* (v0.7.0 adds held-out, benign-corpus and
> rater-agreement results; see `paper/`.)
> Preprint: [10.6084/m9.figshare.32978657](https://doi.org/10.6084/m9.figshare.32978657) ·
> Benchmark archive: [10.5281/zenodo.21346206](https://doi.org/10.5281/zenodo.21346206)

---

## What this is (and what it is not)

Existing MCP security benchmarks measure one of two things. **MSB** (ICLR 2026) and **MCPTox**
measure **how well an LLM agent resists an attack**. **AgentDefense-Bench** does score defenses, but
on a different axis from ours — **detection accuracy** (detection rate / false-positive rate) over a
35k-case corpus. None of them measure **how much of the known attack surface a defensive tool covers
at all**. That is the gap this project fills.

- ✅ **This is** a *defense-side* benchmark. The unit under test is a **proxy/gateway/scanner**
  (mcp-bastion, MCP-Scan, MCP-Gateway, …). It asks: _against each known MCP attack vector, does this
  defender detect it, enforce against it, or miss it?_
- ✅ **This is** the first MCP benchmark whose results are **crosswalked to NIST AI RMF and the OWASP
  LLM 2025 + Agentic 2026 Top 10s** — the language compliance and procurement teams actually use.
- ❌ **This is not** another agent-resistance benchmark (that's MSB's job — we cite it, we don't
  duplicate it), nor a detection-accuracy benchmark (that's AgentDefense-Bench's — see the
  [taxonomy mapping](docs/CROSSWALK-agentdefense.md); the two are complementary).
- ❌ **This is not** owned by any tool it scores. mcp-bastion is just one `adapters/` entry.

See [`docs/PRIOR-ART.md`](docs/PRIOR-ART.md) for the full verified related-work map and the exact
novelty positioning — read it before citing this anywhere.

## How it works

```
 rubric/crosswalk.json         testcases/  testcases-heldout/  testcases-benign/     adapters/<tool>/
 (32 vectors + framework    →  (development · held-out · benign-only corpora)     →  (drives the tool's
  mappings + appliesTo axis)                                                          REAL code)
                                                  │
                                                  ▼
                              bin/run.mjs <tool> [--corpus dev|heldout|benign]
                                                  │
                                                  ▼
             results/ · results/heldout/ · results/benign/  →  bin/leaderboard.mjs → docs/LEADERBOARD.md
```

1. **Rubric** — [`rubric/crosswalk.json`](rubric/crosswalk.json): **32 MCP attack vectors** (24 pre-existing +
   8 introduced by the **2026-07-28 protocol revision**), each mapped to architectural layer, STRIDE, NIST AI
   RMF, NSA MCP guidance, OWASP LLM 2025, OWASP Agentic 2026, **EU AI Act obligations** (Arts. 12, 14, 15(5),
   26, 55(1)(d), 72, 73 — the language regulated buyers are audited against since GPAI enforcement began
   2026-08-02) and **ISO/IEC 42001 Annex A controls** (v0.8.0), and tagged with the protocol revisions it
   applies to (`appliesTo`). The scorer rolls coverage up per obligation and per control. Mapping reliability is measured: a blind second-rater pass and open adjudication
   live in [`rubric/RATING-CODEBOOK.md`](rubric/RATING-CODEBOOK.md), [`docs/AGREEMENT.md`](docs/AGREEMENT.md),
   [`rubric/ratings/ADJUDICATION.md`](rubric/ratings/ADJUDICATION.md). **A human third rater is invited** —
   copy `rubric/ratings/rater-TEMPLATE.json` and open a PR.
2. **Three corpora** —
   - `testcases/` — the **development** corpus (51 cases): used to find and fix gaps in the reference proxy.
   - `testcases-heldout/` — the **held-out** corpus (48 cases): authored *after* every defender was frozen,
     under the pre-registered [`docs/HELD-OUT-PROTOCOL.md`](docs/HELD-OUT-PROTOCOL.md) (domain / lexical /
     surface / encoding shifts; no development phrasing or hosts; no iteration after the first run).
   - `testcases-benign/` — the **benign-only** corpus (337 items): 256 *verbatim* tool definitions harvested
     from 21 public MCP servers + 81 authored hard negatives. Every flag is a false positive.
3. **Adapters** — `adapters/<tool>/`: a thin driver that runs a defender's real code against fixtures, under
   the integrity rule in [`adapters/CONTRACT.md`](adapters/CONTRACT.md): *report only what the tool inspects
   at runtime.*
4. **Scorer / leaderboard** — `bin/run.mjs`, `bin/leaderboard.mjs`: CorpusRobustCoverage per vector, **per
   protocol revision**, development **and** held-out side by side with the generalisation gap, and the
   benign-corpus FP rate with a Wilson 95% interval.

## Status — v0.8.0 (2026-09-08)

Full board: [docs/LEADERBOARD.md](docs/LEADERBOARD.md) · live site:
[gowthaman90.github.io/mcp-defense-bench](https://gowthaman90.github.io/mcp-defense-bench/).

**CorpusRobustCoverage on the 24 pre-existing vectors — development vs. held-out:**

| Tool | Class | Dev (24) | **Held-out (24)** | Gap | 2026-07-28-only (8) | Benign FP (n=337) |
|---|---|--:|--:|--:|--:|--:|
| `mcp-bastion` v1.0.2 | runtime proxy | 55% | **43%** | 13 pts | **77%** | 13 (3.9%, CI 2.3–6.5%) |
| `mcp-firewall` 0.1.0 | runtime proxy | 8% | **10%** | −2 pts | 13% | 2 (0.6%) |
| `pipelock` 3.0.0 | egress firewall | 6% | **0%** | 6 pts | 0% | 3 (0.9%) |
| `null-baseline` | control | 0% | 0% | 0 | 0% | 0 |

Matched-control false positives: 0/51 (dev) and 0/48 (held-out) for every tool.

**What the numbers say.**
- **The held-out gap is the headline.** mcp-bastion's structural checks (hash pinning, schema validation,
  data-flow tracking, command-injection parsing) hold on held-out fixtures; its *phrase heuristics* do not —
  four vectors it covered in development (tool poisoning, ShareLock split poisoning, transport MITM,
  system-prompt leakage) drop to zero. pipelock's development coverage was entirely corpus-specific.
- **Coverage is quoted per protocol revision.** The 8 vectors introduced on 2026-07-28 did not exist before
  it. mcp-bastion v0.9.0 covered 44% of them; the benchmark named the rest and v1.0.0 (rebuilt on the
  2026-07-28 SDK line: `requestState` custody, an in-band consent gate, legacy-transport refusal) covers
  **77%**. Still honest misses: Tasks (not served on the new era), MCP Apps, and the non-normative
  tool-state-handle case. The 24 pre-existing vectors and the held-out results are byte-identical across
  that rebuild — and the matched controls caught a real false positive in the new gate before release.
- **Benign FP has a denominator now.** 4 of mcp-bastion's 13 are the by-design cost of trust-on-first-use
  pinning flagging benign definition updates (reported in their own row, not excluded); 1/256 verbatim
  third-party definitions is flagged.
- **6 of 32 vectors are covered by no measured tool** — the five pre-existing registry/isolation/consent gaps
  plus MCP Apps conformance. A proxy is necessary but not sufficient.

**Why v0.7+ looks like this.** The v0.4 paper was reviewed at AISec 2026; the expert reviewer asked for a
held-out set, more attack variants and benign cases, and a second-rater agreement measure. All three are
here. The submission itself was desk-rejected because the anonymised artifact mirror still carried
identifying metadata — hence [`scripts/make-anon-mirror.mjs`](scripts/make-anon-mirror.mjs) and
[`paper/SUBMISSION-CHECKLIST.md`](paper/SUBMISSION-CHECKLIST.md). Verbatim reviews and responses:
[`paper/REVIEWS-AND-RESPONSE.md`](paper/REVIEWS-AND-RESPONSE.md).

**Reproduce:**

```bash
npm run gen:corpora && npm run bench:all && npm run bench:heldout && npm run bench:benign && npm run leaderboard
```

(`mcp-firewall` and `pipelock` need the local installs described in [`docs/ADAPTERS.md`](docs/ADAPTERS.md).)

**Evasion robustness** ([docs/ROBUSTNESS.md](docs/ROBUSTNESS.md)): on the development evasion set mcp-bastion
survives zero-width/bidi, homoglyph and base64 after its normalisation stage; the held-out **E** family shows
the limit — HTML/markdown-comment hiding, JSON-LD embedding and newline-separated command injection are
caught, base64 *shards* across tools and numbered sentence fragments are not.

> **Scope of the headline metric.** CorpusRobustCoverage is a descriptive coverage measure over a fixed,
> non-exhaustive corpus — **not** a procurement or substitutability ranking. Tools at different layers are
> complementary: mcp-firewall and pipelock *enforce* on vectors where mcp-bastion only warns. Read the
> per-vector matrix, per revision, before quoting any single number. Metric design credited in
> [`docs/CHANGELOG-scoring.md`](docs/CHANGELOG-scoring.md).

## Why this project exists

It is one of two open-source artifacts built to advance safe, reliable enterprise AI agent
infrastructure — a **threat→framework crosswalk** and this **defense-coverage benchmark** — targeting
gaps confirmed by an adversarially-verified 2026 literature review. Companion project:
[mcp-bastion](https://github.com/Gowthaman90/mcp-bastion), a reliability + security proxy for MCP.

## License

- Rubric data & docs: **CC-BY-4.0**
- Harness code: **Apache-2.0**
