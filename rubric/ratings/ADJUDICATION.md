# Adjudication of Rater A / Rater B disagreements — crosswalk v0.7.0 → v0.7.1

_Source: `docs/AGREEMENT.md` (62 set-level disagreements over 24 vectors). Adjudicated 2026-09-05._

**Who adjudicated, and the limit of that.** The adjudication below was performed in the same working
session that produced Rater B, with Rater A's mappings now visible. It is therefore *not* a neutral
third party; it is a documented reconciliation against the codebook's decision rules. The rule applied:
**adopt a change only where the codebook rule clearly supports the alternative**; where both readings
are defensible, the primary (Rater A) mapping stands and the disagreement is recorded as a known
ambiguity. Every adopted change is listed so a future Rater C can overrule it.

## Decision summary

| Dimension | Disagreements | A kept | B adopted | Union adopted |
|---|--:|--:|--:|--:|
| mcpLayer | 14 | 11 | 1 | 2 |
| stride | 7 | 6 | 0 | 1 |
| nistAiRmf | 14 | 8 | 3 | 3 |
| owaspLlm2025 | 10 | 7 | 1 | 2 |
| owaspAgentic2026 | 11 | 6 | 2 | 3 |
| nsaGuidance | 6 | 5 | 0 | 1 |
| **Total** | **62** | **43** | **7** | **12** |

## Adopted changes (applied to `rubric/crosswalk.json`)

| Vector | Dimension | Was (A) | Now | Why (codebook rule) |
|---|---|---|---|---|
| out-of-scope-params | mcpLayer | tool, server | server, tool | Argument validation is *enforced* at the server (or a proxy in front of it); the tool layer merely declares the schema. Primary → server. |
| dns-rebinding | mcpLayer | transport, host-orchestration | transport, server | The Origin/Host check runs in the *server's* HTTP listener; "host-orchestration" is not where the defence sits. |
| sandbox-escape | nistAiRmf | MANAGE | MANAGE, MEASURE | Escape attempts must be *detected at runtime* (MEASURE) as well as contained. |
| mitm-transport | nistAiRmf | MANAGE | MANAGE, MEASURE | Transport posture is tested/monitored (MEASURE), not only treated. |
| dns-rebinding | nistAiRmf | MANAGE | MANAGE, MEASURE | Same reasoning. |
| indirect-retrieval-injection | owaspLlm2025 | LLM01 | LLM01, LLM08 | LLM08 (Vector & Embedding Weaknesses) canonically covers retrieval-borne injection; its description names it. |
| sandbox-escape | owaspAgentic2026 | ASI02, ASI03 | ASI02, ASI03, ASI05 | ASI05 (Unexpected Code Execution) covers execution beyond the sandbox. |
| command-injection | owaspAgentic2026 | ASI02 | ASI02, ASI05 | OS command injection *is* unexpected code execution (ASI05); mechanism is tool misuse (ASI02). Union. |
| mitm-transport | owaspAgentic2026 | ASI03 | ASI03, ASI07 | ASI07 (Insecure Inter-Agent Communication) is the transport-integrity category. |
| dns-rebinding | owaspAgentic2026 | ASI03 | ASI03, ASI07 | Same. |
| response-injection | stride | Tampering | Tampering, ElevationOfPrivilege | An injected directive that the agent acts on necessarily escalates the attacker's privilege to the agent's. |
| tool-transfer | nsaGuidance | AUTH, SEG | AUTH, SEG, RT | Cross-server data-flow tracking is a runtime control (RT), and is the control that measured tools actually implement. |

## Kept as A (with reason)

- **Layer disagreements where B chose `client`/`host-orchestration` over `tool`** (tool-shadowing,
  response-injection, indirect-retrieval-injection, false-error-escalation, mid-session-tool-injection,
  multi-tool-split-poisoning, rug-pull): the codebook says "where the defence is best *placed*"; a
  content scan of definitions/results is *placed* at the tool layer in the defense-placement taxonomy
  the crosswalk follows (MCP-DPT), even though a proxy in the client path executes it. Known ambiguity:
  MCP-DPT's "tool" layer vs. an operational "who runs the scanner" reading. Recorded; A kept.
- **B dropped a second layer** (tool-transfer, schema-bypass, consent-fatigue): A's second layer is an
  independently sufficient defence placement in each case. Kept.
- **excessive-permission / credential-token-theft second layer** (A: server / transport; B: client):
  both defensible; kept A.
- **STRIDE**: A's extra classes (cross-tool-exfiltration +EoP, mitm +Spoofing, consent-fatigue
  +Repudiation, false-error +DoS, credential-theft +EoP) each describe an outcome the attack
  *necessarily* achieves under the codebook's "second class" rule; B's substitutes (Tampering for
  false-error; Spoofing for credential theft) were not clearly stronger. Kept.
- **NIST GOVERN** (package-squatting, supply-chain-poisoning, config-drift, server-impersonation,
  excessive-permission, credential-token-theft): A includes GOVERN where a policy structure (registry
  provenance policy, change control, least-privilege policy) is a primary control; B applied the
  codebook's "GOVERN only where primary" rule more strictly. Genuine ambiguity in the codebook —
  **codebook amended** (see below) rather than the mapping.
- **NIST MAP vs MEASURE** (tool-shadowing, tool-transfer, cross-tool-exfiltration): kept A.
- **OWASP LLM**: sandbox-escape (A LLM06 vs B LLM03), supply-chain +LLM04, out-of-scope +LLM05,
  rug-pull LLM06 vs LLM01, tool-shadowing LLM01 vs LLM06, mid-session LLM06 vs LLM03, dns-rebinding
  LLM06 vs ∅, tool-transfer +LLM01, schema-bypass +LLM06: kept A. dns-rebinding's LLM06 is the weakest
  mapping in the table and is flagged `mappingNotes` as indicative only.
- **OWASP Agentic**: tool-shadowing (ASI01 vs ASI02), rug-pull +ASI01, response/indirect +ASI06,
  tool-transfer ASI03 vs ASI01, schema-bypass +ASI05, consent-fatigue +ASI09: kept A.
- **NSA**: rug-pull, config-drift, credential-theft, system-prompt-leakage, mid-session, ShareLock:
  kept A (A's LOG/AUTH choices trace to specific recommendation text).

## Codebook amendment (v1.1)

`nistAiRmf → GOVERN`: clarified to "include GOVERN when a governance artefact (policy, baseline, approval
record, provenance requirement) is *one of* the controls the vector's defence relies on — not only when
it is the primary control." This is the rule A had applied implicitly; making it explicit should remove
the six GOVERN disagreements for future raters without changing any mapping.

## Effect on agreement

Re-running `bin/agreement.mjs` after these changes is **not** reported as the headline agreement figure:
post-adjudication agreement is inflated by construction. The headline stays the pre-adjudication
κ/Jaccard in `docs/AGREEMENT.md`. Crosswalk version bumped to **0.7.1** to mark the adjudicated mapping.

---

# Delegation family — crosswalk v0.9.0-staged → v0.9.0

_Source: `staging/delegation/ratings/AGREEMENT-pre-adjudication.md` (12 set-level disagreements over the
5 delegation vectors, six dimensions; `euAiAct` / `iso42001` are single-rater as of v0.8.0 and were not
in the agreement scope). Adjudicated 2026-10-16 at promotion (`docs/DELEGATION-PREREG.md` §7–§8)._

**Who adjudicated, and the limit of that.** Same as the v0.7.1 round: done in a working session with
both raters' rows visible, so it is a documented reconciliation against `RATING-CODEBOOK.md` v1.2, not a
neutral third party. Rule: **adopt a change only where a codebook rule clearly supports it**; where both
readings are defensible, Rater A stands and the disagreement is recorded. Pre-adjudication agreement in
the prereg (STRIDE primary κ 0.29, mcpLayer sets 5/5) stays the headline figure.

## Decision summary

| Dimension | Disagreements | A kept | Union adopted |
|---|--:|--:|--:|
| stride | 2 | 0 | 2 |
| nistAiRmf | 2 | 0 | 2 |
| owaspLlm2025 | 1 | 1 | 0 |
| owaspAgentic2026 | 3 | 1 | 2 |
| nsaGuidance | 4 | 3 | 1 |
| **Total** | **12** | **5** | **7** |

No change replaced an A label; every adopted change is a union (A's labels kept, B's added).

## Adopted changes (applied to `rubric/crosswalk.json`)

| Vector | Dimension | Was (A) | Now | Why (codebook rule) |
|---|---|---|---|---|
| delegation-stale-relay | stride | Spoofing | Spoofing, ElevationOfPrivilege | "Second class the attack necessarily achieves": relaying an expired or over-long token extends a grant beyond its intended use, which is an escalation; matches the Spoofing + EoP reading A gave audience confusion and subject mixing for the same outcome. Primary stays Spoofing. |
| delegation-signature-forgery | stride | Spoofing, Tampering | Spoofing, Tampering, ElevationOfPrivilege | A forged token carries whatever claims the attacker writes, so it necessarily confers authority (EoP). Tampering stays: the signature is an integrity control and post-signing tamper is one listed variant. |
| delegation-stale-relay | nistAiRmf | MEASURE, MANAGE | GOVERN, MEASURE, MANAGE | v1.1 GOVERN rule: a governance artefact is one of the controls. "Over-long" is defined against the deployment's delegation policy (maximum lifetime); A applied the same reasoning to chain laundering (allowed-actor policy). |
| delegation-signature-forgery | nistAiRmf | MEASURE, MANAGE | GOVERN, MEASURE, MANAGE | v1.1 GOVERN rule: the defence relies on a trusted key set (a provenance requirement) and an algorithm allow-list (a policy; RFC 8725 §3.1). |
| delegation-stale-relay | owaspAgentic2026 | ASI03 | ASI03, ASI07 | ASI07 (Insecure Inter-Agent Communication) covers freshness/replay of credentials on agent-to-agent hops; A gave ASI07 to the other relay-path vectors. |
| delegation-signature-forgery | owaspAgentic2026 | ASI03 | ASI03, ASI07 | Same category: an unauthenticated (forged) message on the inter-agent hop. |
| delegation-signature-forgery | nsaGuidance | AUTH | AUTH, RT | The codebook's `RT` explicitly lists *message integrity*; signature verification at the relay is that runtime control. |

## Kept as A (with reason)

- **delegation-signature-forgery / owaspLlm2025 LLM06 (B: ∅).** The codebook maps on mechanism *or*
  direct impact. No LLM category describes JWS forgery (B's reason), but the direct impact, an agent
  acting with authority it was not granted, is LLM06's. Both readings defensible; A kept and flagged in
  `mappingNotes` as indicative only, like dns-rebinding's LLM06.
- **delegation-chain-laundering / owaspAgentic2026 +ASI10 (B).** ASI10 (Rogue Agents) concerns an agent
  whose own behaviour deviates or is compromised. The vector is about authority recorded in delegation
  tokens: an unlisted current actor or a deep/cyclic chain does not require any agent to be rogue. Not
  clearly supported; A kept.
- **nsaGuidance LOG on delegation-audience-confusion, -subject-mixing, -stale-relay (B: AUTH only).**
  Per-invocation logging of the delegated identity ("who acted for whom") is the detective control for
  these misuses, and for subject mixing it is the only place the splice is visible after the fact. The
  codebook ties `euAiAct` Art.12 and `iso42001` A.6.2.8 to NSA LOG, so dropping LOG would change two other
  dimensions with no rule clearly requiring it. A kept on all three.

## Effect

Crosswalk version bumped to **0.9.0** (37 vectors; the 5 promoted rows carry `vectorFamily: "delegation"`).
Post-adjudication agreement is inflated by construction and is not reported as a headline.
