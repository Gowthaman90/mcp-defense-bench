# Emerging MCP threats (2026) — roadmap for the next corpus version

**Status: planning / roadmap. Does NOT change the reviewed v0.3–v0.6 corpus or its measured numbers**
(the "Measuring the Defenders" paper is under review). These are candidate additions for a future corpus
version (v0.7+), captured from a 2026 survey of disclosed MCP CVEs and attack/defense research. Each item
notes whether it is genuinely new vs. the current 24 vectors, its anchor evidence, and its verification
confidence. **Verify aggregator-sourced CVEs against GHSA/vendor primary sources before citing in a paper.**

## Why this exists

MCP security scaled fast in 2026 (40+ CVEs). The current 24 vectors all remain relevant (command-injection
especially dense), but several disclosed classes and protocol features are not yet modeled. Keeping the
benchmark current is part of its value proposition.

## Candidate NEW vectors (ranked: severity × verification × uncovered)

| Proposed vector-id | What it tests (not in the 24) | Anchor evidence | Confidence |
|---|---|---|---|
| `ssrf-url-param` | SSRF via URL/URI-valued tool params → cloud-metadata → managed-identity **token theft**; distinct from `dns-rebinding`/`mitm-transport` | **CVE-2026-26118** Azure MCP (CVSS 8.8); CVE-2025-65513 Fetch MCP | high (26118 vendor-verified) |
| `missing-endpoint-auth` (+ `broken-object-authz`) | *Absent* authN/Z on a tool path / sibling endpoint / per-object authz (vs `excessive-permission` = over-scope) | **CVE-2026-33032** nginx-ui (9.8, *exploited ITW*); **CVE-2026-48039** Meta Ads; **CVE-2026-65594** n8n | high (GHSA-verified) |
| `sampling-abuse` | Malicious *server* drives *client* LLM via the `sampling` primitive (resource theft, covert tool calls, persistent-instruction injection); inverted trust direction | Palo Alto Unit 42 (2025-12-05) | high (design class; no CVE) |
| `oauth-confused-deputy` (+ `token-audience-confusion`) | OAuth-proxy one-click takeover (static client_id, cached consent, unbound state, open DCR redirect); token passthrough breaking RFC 8707 audience | Obsidian Security (2026-01-29); FastMCP **GHSA-rww4-4w9c-7733** | high |
| `path-traversal` | File/resource-tool traversal & blacklist bypass; only *implied* by `sandbox-escape`; ~82% reported prevalence | CVE-2026-40576, CVE-2025-67366/66689/68145 | medium (aggregator — verify) |
| `memory-poisoning` | Untrusted tool output committed to persistent agent memory with a delayed trigger ("poison once, exploit forever"); the 24 are session-scoped | arXiv:2606.04329 + MPBench | high (arXiv-verified) |
| `elicitation-phishing` | Server-initiated `elicitation/create` social-engineers the user for secrets/over-broad approval | Unit 42 / MCP 2026 guides | medium |
| `approval-view-mismatch` | Tool metadata shown at approval ≠ bytes sent to the model (invisible-Unicode concealment); render-vs-model byte equality | arXiv:2607.05744 | high (arXiv-verified) |
| `cross-client-state-leak` | Shared transport/JSON-RPC id collision routes one client's response to another | **CVE-2026-25536** (GHSA-345p-7cg4-v4c7) | high (GHSA-verified) |
| `provider-confusion` / `tool-chain-composition` | Wrong-provider execution / benign tools chained into a harmful composite under multi-server composition | arXiv:2602.11327; MCP-38 arXiv:2603.18063 | high (arXiv-verified) |

Fixture sketches (per the SPEC contract — malicious + benign twin + expected defender behavior):
- **`ssrf-url-param`**: a `fetch_resource(url)` tool; expect refusal of `http://169.254.169.254/…`, RFC-1918,
  `file://`, and redirect-to-internal, and that no auth header is attached to attacker-controlled hosts.
- **`missing-endpoint-auth`**: two routes / a per-user object; expect every tool-invocation path to enforce
  auth and that user A cannot invoke/read user B's object.
- **`sampling-abuse`**: a server issuing `sampling/createMessage`; expect per-call consent, budget/attribution,
  and stripping of server-injected system/tool-call content.
- **`approval-view-mismatch`**: tool description with hidden-Unicode/homoglyph/whitespace payload; expect
  Unicode normalization + TAG/bidi/zero-width stripping and an assertion that approval-view == model-view.

## Candidate mcp-bastion defenses (proxy-implementable)

| Defense | Addresses | Status |
|---|---|---|
| **Unicode / approval-view canonicalization** — strip TAG (U+E00xx)/zero-width/bidi; decode TAG-smuggled ASCII; `approvalViewFidelity()` asserts rendered-view == model-view; de-cloaked views fed to the poisoning scanner | `approval-view-mismatch`; strengthens `tool-poisoning` | **SHIPPED** in mcp-bastion `src/security/normalize.ts` (`stripInvisible`, `decodeUnicodeTags`, `approvalViewFidelity`); tests in `test/normalize.test.ts` |
| **Session-level IFC (SAMOS model)** — per-tool confidentiality + capability annotations, session taint, block high-read→low-write | `cross-tool-exfiltration`, `tool-chain-composition` | design — parallels A4 (FIDES IFC) + A3 (attestation) |
| **Sampling + elicitation gating** — intercept `sampling/createMessage` / `elicitation/create`; budget, attribute, consent-gate, sanitize | `sampling-abuse`, `elicitation-phishing` | design |
| **Token-audience validation** — reject tokens whose `aud`/RFC-8707 resource indicator ≠ target server | `token-audience-confusion` | design |
| **SSRF egress guard** — block metadata-IP/RFC-1918/`file://`/redirect-to-internal on URL params; strip auth headers to untrusted hosts | `ssrf-url-param` | design |
| **Provider/tool attestation pinning** — pin tool identity to an attested provider under composition | `provider-confusion` | ties to **Artifact 3** |

## Notable defense/benchmark literature (citation targets)

- **SAMOS** — gateway-level IFC for MCP, PACMI '25 (Brown + IBM), ACM 10.1145/3766882.3767177 — a reference
  design for a bastion-style proxy; independent validation that an inline gateway is the right layer.
- **MCPSHIELD** — formal defense-in-depth framework, arXiv:2604.05969 (177k tools; no single existing defense
  covers >34%).
- **MCP-DPT** — defense-placement taxonomy, arXiv:2604.07551 (protection is "predominantly tool-centric";
  host/transport/supply-chain gaps).
- **MCP-38** — threat taxonomy, arXiv:2603.18063 (parasitic tool chaining, dynamic trust violations).
- **"A First Look at the Security Issues in the MCP Ecosystem"** — arXiv:2510.16558 (DSN 2026): registry-level
  weak vetting enabling adversarial servers — **directly reinforces the Artifact-3 registry-provenance thesis.**
- Guidance: NSA/CISA CSI "MCP Security" (2026-06-02).

## Sequencing (respecting the review window)

1. Land the **bastion canonicalization** defense now (done — separate repo, no corpus impact).
2. Draft the new fixtures in a **staging area** so the *scored* corpus and the reviewed numbers stay fixed;
   promote to the corpus as **v0.7** only after the AISec decision.
3. Prioritize `ssrf-url-param`, `missing-endpoint-auth`, `sampling-abuse` first (highest severity × uncovered),
   then the OAuth pair and `approval-view-mismatch` (which the bastion defense already addresses).
