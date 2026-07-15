# Adapters — the tools we score

An **adapter** wraps one MCP defender so the benchmark can run it against the test-case fixtures and
record what it caught. This file is the verified landscape (checked 2026-07-13 against primary
sources) and the rule that decides which tools get a *score* vs only an *observation*.

## The reproducibility rule

> A defender can only be **scored** if its detection logic runs **locally and deterministically**.
> If detection is delegated to a proprietary cloud model, the result depends on a black box that can
> change between runs — so we **observe and describe** it, but do not put a number on it.

This split is itself a methodological contribution: it explains, honestly, why the scored leaderboard
is a small set of local proxies while the larger commercial landscape is an appendix.

## Tiers

### Control — `null` baseline
A defender with zero protection. Proves the fixtures actually fire and anchors the 0% end of the
scale. Built: `adapters/null-baseline/`.

### Scored peers — local, deterministic, self-hosted proxies

| Tool | Repo | Class | License | Notes |
|---|---|---|---|---|
| **mcp-bastion** | `Gowthaman90/mcp-bastion` | runtime proxy | Apache-2.0 | Reference entry. Poisoning, rug-pull, shadowing; hash-chain audit. |
| **mcp-firewall** | `ressl/mcp-firewall` | runtime proxy | AGPL-3.0 | 8 inbound + 4 outbound checks; policy allow/deny; Ed25519 hash-chain audit. Closest architectural peer to bastion. |
| **pipelock** | `luckyPipewrench/pipelock` | agent firewall | (verify) | Scans MCP/HTTP/A2A/WebSocket for exfiltration, SSRF, prompt injection; mediator-signed receipts. Help Net Security coverage May 2026. |

_AGPL only affects redistributing their code — running a tool to benchmark it and reporting scores is
fine. We do not vendor their source._

### Observed only — cloud-model guardrails (not reproducibly scoreable)

| Tool | Repo | Why observe-only |
|---|---|---|
| **Lasso MCP Gateway** | `lasso-security/mcp-gateway` | Plugin gateway; security scan routes through Lasso's API. |
| **EnkryptAI Secure MCP Gateway** | `enkryptai/secure-mcp-gateway` | Guardrails configured/enforced via Enkrypt platform; sandbox isolation (Docker/Podman/microVM) is local but detection is cloud. |

### Different class — context, not a peer (access-control / governance / isolation gateways)

These are legitimate MCP-security tools, but a **different mechanism class** from the scored set: they
enforce access-control policies, isolation, registry/identity, and input validation — not the
content-heuristic detection (poisoning/injection/exfiltration) the 24-vector content rubric emphasizes.
They are also **running servers**, so scoring them would require standing up + configuring the server
and routing traffic — heavy and config-dependent, breaking the reproducibility rule. Forcing them onto
the content rubric would show a misleading ~0% (they defend a *different thing*). Tracked here for
completeness; candidates for a future *class-appropriate* evaluation.

| Tool | Repo | Class / note |
|---|---|---|
| **Docker MCP Gateway** | `docker/mcp-gateway` | Isolation gateway — container isolation + signed images (supply-chain). Mounts docker.sock (root-equiv) — a caveat to cite. |
| **MCPX (lunar)** | `TheLunarCompany/lunar` (`/mcpx`) | Governance/access-control gateway — global/service/tool-level access policies, tool groups, audit logs, metrics. Open-source core (free non-prod). No content scanning. Runs locally/Docker. |
| **IBM ContextForge** | `IBM/mcp-context-forge` | AI gateway + registry — input validation (SecurityValidator: char/URL-scheme/JSON-depth limits), OAuth/OIDC access control, SSRF strict defaults, plugins. Overlaps a few vectors (schema-bypass, out-of-scope-params, SSRF/transport) — the **strongest future scored-adapter candidate** of the gateway class, but needs the running server. |

### Cited landscape only — not runnable neutrally

| Tool | Status |
|---|---|
| **Snyk agent-scan** (formerly Invariant Labs **MCP-Scan**) | Acquired by Snyk. Now requires `SNYK_TOKEN` + shares tool metadata with Snyk; offline `--local-only` mode no longer documented. 2.8k★. Cite as prior art / landscape; cannot be a reproducible adapter. |
| Cloudflare enterprise MCP, other commercial guardrails | Hosted/paid; cite for landscape. |

## Adapter file format

Each `adapters/<tool>/coverage.json`:
```jsonc
{
  "tool": "mcp-firewall",
  "repo": "https://github.com/ressl/mcp-firewall",
  "class": "runtime-proxy",
  "reproducible": true,          // false → observed-only, excluded from scored leaderboard
  "version": "…",
  "rubricVersion": "0.1.0-draft",
  "coverage": {
    "<vector-id>": { "level": "enforce|detect|observe|none|unknown", "evidence": "testcase id or note" }
  }
}
```
`level` is **claimed** until a passing test case backs it; the harness sets `verified: true` per
vector only when a fixture confirms it. `unknown` = not yet assessed (scored as 0, flagged).

## Wiring status (2026-07-13)

- ✅ **mcp-bastion** — wired, drives real `scanTool`/`hashToolDefinition`. Measured 9%.
- ✅ **mcp-firewall** — installed (py3.12 venv, v0.1.0), wired via `probe_server.py` → real SDK with
  committed `mcp-firewall.yaml`. Measured 5%. Verified fully local (no cloud key). Confirmed AGPL —
  we run it to benchmark, we don't redistribute its code.
- ✅ **pipelock** — v3.0.0 binary (checksum-verified), wired via two offline, deterministic interfaces:
  `pipelock explain --json <url>` (URL/egress: SSRF, cloud-metadata, DLP) **and** `pipelock mcp scan`
  (stdin MCP JSON-RPC → prompt-injection scan of tool results). Measured 11% (cross-tool-exfiltration
  via SSRF; indirect-retrieval, system-prompt-leak, and response-injection via injection scanning),
  0 false positives. Also robust to homoglyph + base64 evasions (see docs/ROBUSTNESS.md).
  **Remaining limitation:** poisoned tool *descriptions* (in `tools/list`) aren't flagged by the
  standalone `mcp scan` CLI, and the full DLP/tool_call eval endpoint (bearer-token HTTP server) is not
  driven — so this is still a lower bound on pipelock's total capability.

## Open verification tasks before publishing the leaderboard

- [ ] **Corpus v2**: multiple realistic, tool-neutral fixtures per vector (incl. private-IP egress,
      AWS-key-shaped secrets, SSRF URLs) so pattern/egress tools are fairly probed. This is the
      fairness prerequisite — current absolute scores are corpus-shape-dependent.
- [ ] Wire **pipelock** once corpus v2 exists.
- [ ] Re-check whether Lasso/Enkrypt expose any *fully-local* guardrail mode (would promote them to scored).
- [ ] Snap versions/commit SHAs of each scored tool at benchmark run time (reproducibility record).

_Landscape verified via WebSearch/WebFetch on 2026-07-13; primary sources are the linked GitHub repos._
