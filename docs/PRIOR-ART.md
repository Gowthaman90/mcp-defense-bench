# Prior Art & Novelty Positioning

_MCP security research and tooling, as of mid-2026. Compiled from an adversarially-verified
literature sweep (24 sources, 24 verified claims). This file exists so every claim of novelty in
the crosswalk and the defense-side benchmark can be defended against a reviewer — or an immigration
examiner's expert — who knows the field._

> **Bottom line:** The MCP-security field is **no longer a green field**. Threat taxonomies,
> attack-side benchmarks, and cryptographic attestation schemes all already exist. Our contribution
> is deliberately positioned in the **confirmed, currently-unfilled gaps** between them.

---

## What already exists (must differentiate against)

### Threat taxonomies (academic)

| Work | What it is | Lens |
|---|---|---|
| **SoK: Security and Safety in the MCP Ecosystem** — [arXiv:2512.08290](https://arxiv.org/abs/2512.08290) | Systematization of knowledge; splits *adversarial security* (indirect prompt injection, tool poisoning) from *epistemic safety* hazards across the Resources / Prompts / Tools primitives. Surveys defenses incl. ETDI, runtime intent verification. | SoK |
| **Formal MCP threat framework** — [arXiv:2604.05969](https://arxiv.org/html/2604.05969v1) | 7 threat categories / **23 attack vectors** across 4 attack surfaces, grounded in 177,000+ real MCP tools. Table I scores existing benchmark coverage. | Formal taxonomy |
| **STRIDE/DREAD MCP threat model** — [arXiv:2603.22489](https://arxiv.org/abs/2603.22489) | STRIDE + DREAD over 5 MCP components; empirically tests 7 clients. Names **tool poisoning as the most prevalent, most impactful client-side vulnerability**. | STRIDE/DREAD |
| **MCP-DPT (Defense-Placement Taxonomy)** — [arXiv:2604.07551](https://arxiv.org/html/2604.07551v1) | Classifies defenses by *which architectural layer enforces them* across 6 layers. Finds coverage is "uneven and predominantly tool-centric." | Defense placement |

### Benchmarks (attack-side)

| Work | Scale / scope | What it measures |
|---|---|---|
| **MSB (MCP Security Bench)** — [arXiv:2510.15994](https://arxiv.org/abs/2510.15994), **ICLR 2026**, [code](https://github.com/dongsenzhang/MSB) | 12-attack taxonomy, ~2,000 attack instances, 10 scenarios, 65 tasks, 405 tools (304 benign + 101 malicious), ~10 LLM agents, **real MCP execution** | Resistance of the **LLM agent** across the full tool-use pipeline (planning → invocation → response handling) |
| **MCPTox** — arXiv:2508.14925 | Tool-poisoning-scoped | Covers **only 5 of 23** attack vectors fully (+2 partial) per 2604.05969 Table I |
| **AgentDefense-Bench** — [GitHub](https://github.com/arunsanna/AgentDefense-Bench) | 17 vectors / 6 domains; 35,546 attack + 443 benign cases in MCP JSON-RPC, aggregated from 13 sources | Solo-authored, ~14★, not peer-reviewed; **repackages general LLM-safety datasets** (WMDP, CySecBench) as MCP wrappers, not MCP-native attacks |
| **MCP-Bench (Accenture)** — arXiv:2508.20453, [code](https://github.com/Accenture/mcp-bench) | 28 servers, ~250 tools | **Capability only** — tool discovery/selection/use. **No** attack/security evaluation. |

### Attestation / tool integrity (specs)

| Work | Approach |
|---|---|
| **ETDI** — arXiv:2506.01333 (Bhatt, Narajala, Habler): "Mitigating Tool Squatting and Rug Pull Attacks in MCP by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control" | Signed JWTs + OAuth 2.0 scopes bind tool definitions to signatures that invalidate on modification. Cryptographic provenance + policy-based access control. |
| **Trustworthy MCP Registry blueprint** — Future Internet 2026, 18(5):243, [DOI](https://doi.org/10.3390/fi18050243) | Three-layer composition of **existing** standards: RFC 8615 well-known URIs (identity/discovery) + Sigstore keyless signing (artifact provenance) + RFC 8785 JCS/JWS (per-message runtime integrity). Explicitly *not* new cryptography. |
| **Official MCP registry** — [modelcontextprotocol.io/registry](https://modelcontextprotocol.io/registry/about) | **Unverified pointer/metaregistry**: indexes metadata pointing to NPM/PyPI/Docker/OCI. Namespace auth (GitHub OIDC / DNS TXT, Sept 2025) verifies **publisher identity, not artifact provenance**. Rug-pull / supply-chain poisoning remain open. |

### Commercial / open-source tooling (defense-side, under-sampled)

- **Invariant Labs MCP-Scan** (2,000+★): static scanner + runtime proxy; detects tool poisoning, prompt injection in descriptions, cross-origin/tool-shadowing.
- **MCP-Gateway**: strongest *surveyed* defense on layer coverage — yet still only ~50% transport, ~38% host-orchestration.
- **Lasso**, **Docker MCP Gateway/Catalog**, **Cloudflare enterprise MCP** — gateway/guardrail products; coverage varies, not independently benchmarked.

### Framework guidance (standards)

- **CSA Agentic MCP Security Best Practices v1** — dedicated MCP best-practices doc.
- **OWASP Top 10 for LLM Applications 2025** — LLM01 Prompt Injection (#1), … LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses (both new in 2025).
- **OWASP Top 10 for Agentic Applications 2026** (Dec 2025) — ASI01–ASI10; **extends, not replaces** the LLM Top 10; explicitly names third-party MCP servers as a supply-chain risk.
- **NIST AI RMF** — Govern / Map / Measure / Manage functions.

---

## Confirmed open gaps (our wedge)

Each of these was surfaced *and adversarially verified* in the sweep:

1. **Coverage is thin.** No benchmark covers the full vector space (best: MCPTox 5/23 fully).
2. **Defenses are lopsided by layer.** Transport ≈ **0%** across nearly all tools; host-orchestration peaks at **38%**; supply-chain weak. Protection is "predominantly tool-centric."
3. **No framework crosswalk.** *No surveyed benchmark maps MCP threats to NIST AI RMF or the OWASP LLM/Agentic Top 10.* ← **Artifact 1 (this crosswalk).**
4. **Nobody scores the defenders.** MSB and every attack-side benchmark measure the **LLM agent's** resistance. None score **defensive proxies/gateways** on attack-vector coverage. ← **Artifact 2 (defense-side leaderboard).**
5. **Bench and attestation never couple.** Executable benchmarks and cryptographic attestation live in separate artifacts; the official registry still lacks artifact-provenance verification. ← future Artifact 3.

## How our two lead artifacts avoid collision

| Their work | Our work | Why it doesn't collide |
|---|---|---|
| MSB, MCPTox, AgentDefense-Bench score **agent resistance** | We score **defensive gateway/proxy coverage** | Different unit under test (defender, not agent) |
| 2512.08290 / 2604.05969 taxonomize **threats** | We **crosswalk** threats → NIST AI RMF + OWASP LLM + OWASP Agentic | Mapping to national/industry frameworks is the confirmed gap, not the taxonomy itself |
| ETDI / Trustworthy Registry propose **signing** | We (later) provide an **executable conformance suite** for attestation, not a new scheme | We test conformance; we don't claim "first to sign" |

## Caveats to respect when citing

- Several key papers are **very recent, non-peer-reviewed preprints** (2603/2604 series, Mar–Apr 2026); their taxonomies are the authors' own constructs. Cite as "proposed by," not "established."
- The 23-vector count and the 0%/38% coverage figures come from **single papers' own surveyed sets** — reproduce, don't assert as field consensus.
- OWASP **Agentic** Top 10 (ASI01–ASI10) is distinct from the OWASP **LLM** Top 10 — do not conflate. All ten official 2026 labels are now confirmed (verified 2026-07-13) and filled into `crosswalk.json`.
- Commercial landscape (Descope, guardrail vendors) is under-sampled — do not claim "we are the only proxy that…" without a direct check.

_Source of record: deep-research run `wf_2431c96f-2de`, 2026-07-12._
