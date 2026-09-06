# Roadmap 2026 H2 — the spec shift, and what it means for the bench and bastion

**Status: planning. Does NOT change the reviewed v0.3–v0.6 corpus or its measured numbers**
(the "Measuring the Defenders" paper is under review at AISec 2026; decision **2026-09-03**). Everything
scored stays frozen until that decision. Companion to [`EMERGING-THREATS-2026.md`](EMERGING-THREATS-2026.md),
which this document **supplements, not replaces**.

**Prepared:** 2026-08-28. **Amended 2026-08-30** after primary-source verification — see
[`SPEC-VERIFICATION-2026-07-28.md`](SPEC-VERIFICATION-2026-07-28.md), which corrected three claims below
(marked ⚠️). Phase 0 is now complete; see the status note at the end of §6. Scope: enhancement candidates for **mcp-defense-bench** (A2) and **mcp-bastion** (A1),
derived from a sweep of MCP/agent-security literature and disclosures published *after* the 2026-08-23
emerging-threats sweep.

---

## 0. The headline: the emerging-threats sweep missed a protocol revision

On **2026-07-28 the MCP specification shipped a breaking architectural revision**, and neither the current
24-vector rubric nor the bastion feature set models it. This is the single largest gap in the program right
now, and it is also the largest opportunity:

- Every existing MCP security benchmark — **MSB** (ICLR '26), **MCPTox**, **MCPSecBench**, **AgentDefense-Bench**,
  and our own v0.6 corpus — was built against the **stateful** protocol (`initialize` handshake, `Mcp-Session-Id`,
  server-initiated requests over held-open SSE). All of that is gone or deprecated.
- As of this sweep, the only published analysis of the new surface is **vendor blogging** (Equixly 2026-08-05,
  Backslash, SecurityWeek). **No academic benchmark covers it.** That is an unclaimed wedge, and it is
  *directly* in our lane: the new surface is overwhelmingly a **gateway/proxy-layer** surface, which is
  exactly the unit under test in this benchmark and exactly what bastion is.

### What actually changed (verified against the spec blog + SDK docs)

| Change | Security consequence |
|---|---|
| `initialize`/`initialized` handshake **removed**; `Mcp-Session-Id` **removed** | State handles now travel **as data through the model context** — visible in chat logs and tool outputs, forgeable and replayable unless signed and principal-bound |
| **MRTR** (SEP-2322) replaces server-initiated requests: `resultType: "input_required"` + `inputRequests` + opaque `requestState` echoed back by the client | Approval/elicitation/sampling now ride **in-band**, model-visible; `requestState` is attacker-influenceable input |
| **Header-based routing**: `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` headers | Gateways route and authorize on headers **without parsing the body** → header/body desync. Spec defines `-32020 HeaderMismatch`; nobody has measured whether defenders enforce it |
| **Cacheable list results**: `ttlMs`, `cacheScope` | A poisoned `tools/list` can be **pinned for a long TTL across a wide scope** — and stale cached definitions blunt rug-pull detection |
| **Tasks** promoted to official extension (`io.modelcontextprotocol/tasks`): `tasks/get`, `tasks/update` | Long-running state without session pinning → task-ID enumeration, cross-principal result read/substitution |
| **Extensions framework** (reverse-DNS, independent versioning) incl. **MCP Apps** (SEP-1865: server-shipped HTML into IDE iframes) and **EMA** | Unbounded, individually-governed surface. MCP Apps invert the trust model: XSS / clickjacking / credential-capturing UI mimicry inside the host |
| **Roots deprecated** (12-month sunset) | The protocol's only structural filesystem-scope boundary is gone; scope enforcement moves into each implementation, applied inconsistently |
| **Sampling and Logging deprecated** | Downgrades the standalone `sampling-abuse` candidate — but sampling **resurfaces inside MRTR `inputRequests`**, so the threat moves rather than disappears |
| **DCR deprecated → CIMD**; **RFC 9207** `iss` validation now mandatory; credentials bound to issuer | The staged `oauth-confused-deputy` candidate was written against DCR and is now partly obsolete. CIMD introduces a **server-side fetch of a client-supplied URL** → SSRF, including the post-redirect revalidation gap already exploited in the wild (Backstage GHSA-qp4c-xg64-7c6x / CVE-2026-32236) |
| **HTTP+SSE transport deprecated** | Downgrade attacks: a defender that still accepts the legacy transport loses the new guarantees |

**SDK reality check.** The TS SDK shipped `@modelcontextprotocol/client` / `@modelcontextprotocol/server` **2.0**
as a *new package line*, not a version bump. bastion is on `@modelcontextprotocol/sdk ^1.12.0`, still reads
`mcp-session-id` in [`src/proxy/http-server.ts`](../../mcp_bastion/src/proxy/http-server.ts), and therefore
speaks the **old** protocol only. v1.x gets fixes for ~6 more months. Migration is real work, not a bump —
plan it, don't rush it.

---

## 1. Verdict on the rest of the sweep: what falls under this radar, and what does not

| Finding (post-2026-08-23) | In scope? | Where it lands |
|---|---|---|
| **MCP 2026-07-28 spec revision** (above) | ✅ **Yes — top priority** | New corpus vectors + bastion features (§2, §3) |
| **CIMD SSRF / issuer confusion** — Backstage GHSA-qp4c-xg64-7c6x; IETF `draft-ietf-oauth-client-id-metadata-document-01` (MUST reject RFC 6890 special-use addresses) | ✅ Yes | Merges into the staged `ssrf-url-param` + replaces the DCR half of `oauth-confused-deputy` |
| **Memory poisoning** — MPBench (arXiv:2606.04329), **MemSecBench** (arXiv:2607.27080), **MemPoison** (arXiv:2607.14651), forensic trajectory signatures (arXiv:2606.30566) | ⚠️ Partial | The field now has **three** dedicated benchmarks. Do **not** build a fourth. Keep the single staged `memory-poisoning` vector as a *coverage* question ("does the defender gate untrusted tool output before it reaches persistent memory?") and **cite** these for the attack science. |
| **Runtime reference monitors** — PCAS (arXiv:2602.16708), SafeAgent (arXiv:2604.17562), AgentSpec (ICSE '26), AIRGuard (arXiv:2605.28914), provable guardrails (arXiv:2605.29251) | ❌ Not the bench | Different unit under test: this benchmark scores a defender's *vector coverage*, not an out-of-band monitor's robustness under an adaptive attacker. Track only. |
| **A2A / multi-agent protocol security** — governance gaps (arXiv:2606.31498), agentic-web threats (arXiv:2603.01564), delegation contracts (arXiv:2603.18043) | ❌ Not now | Different protocol, different unit under test. Flag as a possible **A5**; do not dilute an MCP-scoped benchmark. |
| **Agent-resistance measurement** (MSB, MCPTox) | ❌ No | Unchanged: that is their axis, we cite them. |
| **EU AI Act GPAI enforcement live since 2026-08-02** (Arts. 88–94; fines to 3% turnover / €15M) + **ISO/IEC 42001** | ✅ Yes | Crosswalk expansion (§4) — this is the bench's actual differentiator and it just got more valuable |
| **Trustworthy MCP Registry** (Future Internet 18(5):243), Stacklok/ToolHive Sigstore verification, "A First Look…" (DSN '26, arXiv:2510.16558) | ✅ Relevant, but a different layer | Reinforces the attestation/provenance thesis this corpus already documents as structurally out of a runtime proxy's reach. No change to this benchmark. |
| **CASCADE** (arXiv:2604.17125), **MindGuard**, **MCP Pitfall Lab** (arXiv:2604.21477), privacy-leak detection (arXiv:2606.21338) | ✅ Yes | Adapter candidates — see §5 |

---

## 2. mcp-defense-bench: corpus v0.7 — spec-native vectors

Staged only (`testcases-staging/`), promoted after the 2026-09-03 decision. Ranked by
severity × novelty × verification. Each needs the standard SPEC contract: malicious fixture, **benign twin**,
and expected defender behavior.

| # | Proposed vector-id | What it tests (not in the 24, not in the 10 staged candidates) | Layer | Anchor | Confidence |
|---|---|---|---|---|---|
| 1 | `header-body-desync` | `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` headers disagree with the JSON-RPC body; gateway authorizes on the header, server executes the body. Does the defender emit `-32020 HeaderMismatch`? Includes CR/LF and token-syntax abuse in `Mcp-Param-*` | transport / gateway | spec 2026-07-28 (error code is normative) | **high** |
| 2 | ⚠️ `requeststate-forgery` (was `handle-forgery-replay`) | MRTR `requestState` unsigned / unbound / long-lived → tamper and cross-principal replay. **Split during verification:** `requestState` carries normative MUSTs (HMAC/AEAD, reject on failure); *tool state handles* are covered only by a section the spec marks non-normative, so they became a separate lower-severity fixture | session-state | spec `patterns/mrtr` §Server Requirements 4–5 | **high** for the MUSTs |
| 3 | `list-cache-poisoning` (+ `cache-scope-confusion`) | Malicious `ttlMs` pins a poisoned `tools/list`; over-broad `cacheScope` crosses principals; stale cache **suppresses rug-pull detection** (a defense-defeating variant — novel) | definition | spec + Equixly | **high** |
| 4 | `mrtr-input-phishing` | A server returns `input_required` carrying elicitation/sampling requests inline to phish secrets or forge an approval mid-call. **Supersedes** the staged `elicitation-phishing`; absorbs the live half of `sampling-abuse` | host / consent | spec (SEP-2322) + Unit 42 | **high** |
| 5 | ⚠️ `task-authz-bypass` (was `task-hijack`) | Task-ID entropy and per-request authorization. **There is no `tasks/list`** — it was deliberately removed, and the spec cites that removal as a security improvement, so the enumeration variant does not exist. Adds `Mcp-Name` ≠ `params.taskId` desync | host-orchestration | `ext-tasks` §Security Considerations | **high** (rescoped) |
| 6 | ⚠️ `mcp-app-sandbox-bypass` (was `extension-capability-smuggling`) | **Downgraded.** SEP-1865 already mandates a sandboxed iframe under a CSP that blocks external requests, and the extension is opt-in. The testable question is whether a host *enforces* that model — not that the feature is an open hole. Do not repeat the blog framing in a paper | host / client | SEP-1865 (Final 2026-01-26) | medium |
| 7 | `roots-scope-gap` | With Roots deprecated, is there any enforced filesystem boundary? Distinct in *cause* from `sandbox-escape` and the staged `path-traversal` | host | spec + Backslash | medium |
| 8 | `transport-downgrade` | Defender still accepts legacy HTTP+SSE / a pre-2026-07-28 `MCP-Protocol-Version`, losing the new guarantees | transport | spec deprecation | medium |

Merge, don't duplicate: fold **CIMD SSRF (incl. post-redirect revalidation)** into the staged `ssrf-url-param`,
and rewrite the staged `oauth-confused-deputy` around **CIMD + RFC 9207 `iss` + cross-issuer credential reuse**
instead of DCR.

### 2b. A structural change worth more than any single vector: a **spec-revision axis**

Add to `rubric/crosswalk.json` a per-vector `appliesTo: ["2025-06-18", "2026-03-26", "2026-07-28"]` field, and
report coverage **per protocol revision**.

Why this is the highest-leverage cheap change:
- It is **the honest fix** for a benchmark whose subject just moved under it. Coverage numbers are only
  meaningful relative to a protocol revision.
- No other MCP benchmark does this. "The first **spec-versioned** defense-coverage benchmark" is a defensible,
  narrow novelty claim on top of the existing framework-crosswalk claim.
- It converts a threat to the paper ("your corpus is obsolete") into a contribution ("we model protocol drift").
- It is metadata-only, so it can land **before** 2026-09-03 as a non-scoring field without touching any
  measured number.

---

## 3. mcp-bastion: the thesis that the spec shift hands us

> **In a stateless protocol, the gateway is the only place that can still be stateful — so security state
> has to live there.**

That is a stronger positioning statement than "reliability + security proxy," it is *caused* by the spec
change rather than asserted, and it maps to concrete features. bastion is at **v0.8.0** with a
1,761-line `src/security/` tree; this is an extension of the existing pipeline, not a rewrite.

### v0.9 — "stateless-era hardening" (buildable now, on the v1 SDK where applicable)

| Feature | Vectors | Fit | Effort |
|---|---|---|---|
| **Header/body coherence gate** — verify `Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version` against the parsed body before forwarding; reject `Mcp-Param-*` with CR/LF or bad token syntax; `-32020` | `header-body-desync`, `transport-downgrade` | bastion already terminates HTTP and parses every body — deterministic, zero-FP | **low** |
| **State-handle custody** — bastion mints/wraps handles and `requestState`: HMAC, bind to principal + originating request, short TTL, one-time-use, **redact from what the model sees** | `handle-forgery-replay` | This *is* the thesis feature. Nothing else in the path can do it | med |
| **Cache-policy enforcement** — clamp `ttlMs`, narrow `cacheScope` to per-principal, force invalidation when the definition hash changes (couples straight into existing `hashing.ts` + `tool-registry.ts` pinning) | `list-cache-poisoning`, hardens `rug-pull` | Natural extension of shipped pinning; cheap | **low** |
| **MRTR consent gate** — intercept `input_required`, consent-gate each `inputRequest`, strip server-injected system/tool content, budget + attribute | `mrtr-input-phishing` | Replaces the older "sampling + elicitation gating" design item, which the spec obsoleted | med |
| **Task authorization** — bind task IDs to the issuing principal; deny cross-principal `tasks/get`/`update`; rate-limit polling | `task-hijack` | Proxy-native | med |
| **SSRF / CIMD egress guard** — block RFC 6890 special-use + RFC 1918 + metadata IPs + `file://` on URL-valued params and CIMD `client_id` fetches, **re-validating after every redirect**; strip auth headers to untrusted hosts | `ssrf-url-param`, `cimd-ssrf` | Already designed in the emerging-threats doc; the Backstage CVE makes the redirect case mandatory | med |

### v1.0 — protocol migration

Dual-stack on `@modelcontextprotocol/client` / `server` **2.0** alongside v1.x, with explicit
**downgrade prevention** (refuse pre-2026-07-28 revisions when configured to). Do this **after** v0.9:
the security features above are what make the migration worth measuring, and v1.x is supported for ~6 more months.

**Honest ceiling note.** The old `SECURITY-ROADMAP.md` put a runtime proxy's ceiling at 13/22 (now 15/24, 63%).
The spec shift **raises** that ceiling: vectors 1–5 and 8 above are all proxy-native, because the new design
deliberately moves work to the gateway. Expect the realistic ceiling to move up meaningfully — but measure it,
don't claim it.

---

## 4. Crosswalk expansion (the differentiator, and it just appreciated)

The crosswalk currently maps: layer, STRIDE, NIST AI RMF, OWASP LLM 2025, OWASP Agentic 2026, NSA/CISA.

Add:
1. **EU AI Act** — GPAI enforcement began **2026-08-02** (Arts. 88–94; documentation requests, technical
   evaluations, market withdrawal, fines to 3% turnover / €15M). Map vectors to Art. 53/55 obligations
   (technical documentation, systemic-risk mitigation, incident reporting) and Art. 50 transparency.
2. **ISO/IEC 42001** — the control language procurement teams are actually being audited against.

This is cheap (rubric metadata), it is squarely the "no benchmark does framework crosswalks" gap the project
already owns, and enforcement going live turns it from a nice-to-have into procurement-relevant. It is also the
strongest available answer to "why does this benchmark matter to the United States / to regulated buyers."

---

## 5. Adapter expansion (also the best source of independent third-party contact)

Current board: `mcp-bastion`, `mcp-firewall`, `pipelock`, `null-baseline`. Four is thin for a
comparative-coverage claim, and every new adapter is a legitimate reason to contact another team.

Priority order:
1. **AWS AgentCore Gateway** — publicly claims 2026-07-28 support. The natural first target for the
   spec-native vectors, and a reviewer will ask why the biggest gateway isn't measured.
2. **Invariant Labs MCP-Scan** (~2k★) — the most-cited open defender; its absence is the most obvious hole.
3. **Docker MCP Gateway** / **IBM ContextForge** / **ToolHive** / **Cloudflare**.
4. **CASCADE** (arXiv:2604.17125) — a published cascaded MCP prompt-injection defense with reported numbers;
   measuring it on the coverage axis is a clean complementarity story (their 61% recall is an *accuracy*
   figure — different axis, ideal for the accuracy-vs-coverage framing already in `PRIOR-ART.md`).

---

## 6. Sequencing (respects the review window)

**Phase 0 — now → 2026-09-03 (AISec decision). Nothing scored may move.**
- Draft the eight v0.7 fixtures in `testcases-staging/` (not scored).
- Land the `appliesTo` spec-revision field as **non-scoring metadata**.
- Ship bastion **v0.9** items with the lowest FP risk first — header/body coherence and cache-policy
  enforcement — in the bastion repo (separate repo, zero corpus impact).
- Verify the vendor-sourced claims (MCP Apps, Roots gap, `-32020` semantics) against the **spec text and the
  SDK 2.0 source**, not blogs, before any of it reaches a paper.

**Phase 1 — Sept, post-decision.**
- Promote v0.7 (24 → ~30 vectors), re-measure every adapter, publish the coverage delta **per spec revision**.
- Add EU AI Act + ISO 42001 crosswalk columns.
- Ship bastion v0.9 in full; re-measure; expect a documented ceiling increase.

**Phase 2 — Oct–Dec.**
- Adapters 1–3 above; bastion v1.0 dual-stack migration.
- Write it up. The obvious form is a **short paper / benchmark note**: *"A protocol revision moved the MCP
  attack surface: measuring defender coverage across spec versions."* First mover, narrow claim, and it does
  not compete with the A2 paper — it extends it.

**Phase 3 — Jan 2027.** A separate workstream carries a hard deadline in late January. Nothing in this
plan should displace it.

---

## 7. Risks, stated plainly

- **Chasing a one-month-old spec.** Adoption is early; some of this surface may be re-specified. Mitigation:
  the `appliesTo` axis makes revision-scoped findings *correct* rather than fragile, and staging keeps the
  reviewed numbers untouched.
- **Vendor-blog sourcing.** Items 6–7 rest on Backslash/Equixly analysis. Verify against spec text before
  publication; label confidence in the fixture, as the existing corpus already does.
- **Scope creep.** Memory poisoning, A2A, and reference monitors are all interesting and all belong to other
  artifacts (or nobody's). The discipline that made A2 defensible — *one axis, one unit under test* — applies here.
- **Effort collision.** A separate workstream has a hard deadline in late January. Phase 0 and Phase 1 are
  small; Phase 2 is not. If something must slip, slip Phase 2.


---

## Phase 0 status — complete (2026-08-30)

Everything in Phase 0 has landed. Nothing scored moved: `testcases/`, `results/` and
`docs/LEADERBOARD.md` are byte-identical, and the only change to `rubric/crosswalk.json` is additive
metadata proven non-scoring by re-running `bin/leaderboard.mjs` and `bin/score.mjs` and diffing the
output against the pre-change baseline (identical).

| Item | Where | State |
|---|---|---|
| Eight candidate vectors drafted, unscored | `testcases-staging/` (16 cases), generated by `scripts/gen-staging.mjs` | done |
| Protocol-revision axis as non-scoring metadata | `rubric/crosswalk.json` — `appliesTo` on all 24 vectors, `revisionNotes` on 7, `_specRevisions` legend | done, proven non-scoring |
| Two zero-FP bastion checks | `mcp_bastion` — `src/security/headers.ts`, `src/security/cache-policy.ts`, 48 new tests | done, 191/191 green |
| Blog-sourced claims verified against spec text | [`SPEC-VERIFICATION-2026-07-28.md`](SPEC-VERIFICATION-2026-07-28.md) | done — 3 corrections |

**Phase 1 landed 2026-09-05 (v0.7.0)** after the AISec decision (desk reject on artifact anonymity; one
expert review — see `paper/REVIEWS-AND-RESPONSE.md`). Promoted the 8 vectors (24 → 32), re-measured every
adapter, published coverage per revision, and — driven by the review — added a pre-registered held-out
corpus, a 337-item benign-only corpus with FP intervals, and a rater-agreement protocol. bastion v0.9.0
wires the two Phase-0 checks. Still open from Phase 1: EU AI Act / ISO 42001 crosswalk columns (deferred to
v0.8). Next: Phase 2 adapters, and the SaTML 2027 resubmission (deadline 2026-09-29).
