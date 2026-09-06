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
