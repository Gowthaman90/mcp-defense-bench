<div align="center">

# 🧪 mcp-defense-bench

**A vendor-neutral benchmark that scores MCP security proxies/gateways on how much of the MCP attack
surface they actually defend — mapped to NIST AI RMF and the OWASP Top 10s.**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21346206.svg)](https://doi.org/10.5281/zenodo.21346206)

📊 **Live leaderboard: [gowthaman90.github.io/mcp-defense-bench](https://gowthaman90.github.io/mcp-defense-bench/)**

**Created & maintained by [Gowthaman Arumugam](https://github.com/Gowthaman90) · Independent Researcher**

</div>

> **Cite this work:** Arumugam, G. (2026). *Measuring the Defenders: A Layer-Aware, Framework-Mapped
> Benchmark for Model Context Protocol Security Proxies.*
> Preprint: [10.6084/m9.figshare.32978657](https://doi.org/10.6084/m9.figshare.32978657) ·
> Benchmark archive: [10.5281/zenodo.21346206](https://doi.org/10.5281/zenodo.21346206)

---

## What this is (and what it is not)

Existing MCP security benchmarks — **MSB** (ICLR 2026), **MCPTox**, **AgentDefense-Bench** — all
measure the same thing: **how well an LLM agent resists an attack.** None of them measure **how much
a defensive tool covers.** That is the gap this project fills.

- ✅ **This is** a *defense-side* benchmark. The unit under test is a **proxy/gateway/scanner**
  (mcp-bastion, MCP-Scan, MCP-Gateway, …). It asks: _against each known MCP attack vector, does this
  defender detect it, enforce against it, or miss it?_
- ✅ **This is** the first MCP benchmark whose results are **crosswalked to NIST AI RMF and the OWASP
  LLM 2025 + Agentic 2026 Top 10s** — the language compliance and procurement teams actually use.
- ❌ **This is not** another agent-resistance benchmark (that's MSB's job — we cite it, we don't
  duplicate it).
- ❌ **This is not** owned by any tool it scores. mcp-bastion is just one `adapters/` entry.

See [`docs/PRIOR-ART.md`](docs/PRIOR-ART.md) for the full verified related-work map and the exact
novelty positioning — read it before citing this anywhere.

## How it works

```
 rubric/crosswalk.json        testcases/<vector>/…            adapters/<tool>/
 (22 vectors + framework   →  (attack fixtures + expected  →  (adapter that runs the tool
  mappings — the rubric)       defender behavior)              under test against fixtures)
                                         │
                                         ▼
                                   bin/score.mjs
                                         │
                                         ▼
             results/<tool>.json  +  a coverage score per layer / per NIST fn / per OWASP cat
```

1. **Rubric** — [`rubric/crosswalk.json`](rubric/crosswalk.json): 22 MCP attack vectors, each mapped
   to architectural layer, STRIDE, NIST AI RMF, OWASP LLM 2025, OWASP Agentic 2026. Vendor-neutral.
2. **Test cases** — `testcases/<vector-id>/`: concrete attack fixtures + the behavior a competent
   defender should exhibit. This is what turns a *claim* into a *verified* score.
3. **Adapters** — `adapters/<tool>/`: a thin driver that runs a given defender against the fixtures
   and reports what it caught. `adapters/mcp-bastion/coverage.json` currently holds mcp-bastion's
   *self-reported* claim; the harness exists to **verify**, not trust, those claims.
4. **Scorer** — `bin/score.mjs`: joins verified results against the rubric and emits per-layer /
   per-framework coverage.

## Status

`v0.1.0-draft`. Rubric drafted (22 vectors), full test-case corpus (22 malicious + 22 benign), and a
live runner (`bin/run.mjs`) that drives each adapter's **real** detection code.

**First comparative results** (`node bin/run.mjs <tool>` → `node bin/leaderboard.mjs`, full board in
[docs/LEADERBOARD.md](docs/LEADERBOARD.md)):

Measured against the v2 corpus (28 cases: 22 v1 + 6 realistic/tool-neutral):

| Tool | Class | Weighted coverage | Verified | False positives |
|---|---|--:|---|---|
| `mcp-bastion` | runtime-proxy | **34% (7.5/22)** | 22/22 | 0 / 31 |
| `mcp-firewall` | runtime-proxy | **14% (3.0/22)** | 22/22 | 0 / 31 |
| `pipelock` | egress-firewall | **11% (2.5/22)** | 22/22 | 0 / 31 |
| `null-baseline` | control | 0% | 22/22 | 0 / 31 |

_Corpus: 31 cases (22 base + 6 realistic + 3 evasion). mcp-bastion coverage reflects v0.3–v0.6
features — response scanning, schema validation, transport hardening, sensitive-argument +
least-privilege scanning — each verified here (9% → 34%). pipelock is driven through both its URL/egress
scanner and its MCP injection scanner. 34% is a runtime proxy's realistic ceiling; the remaining 9
vectors need attestation / OS isolation._

**Evasion robustness** ([docs/ROBUSTNESS.md](docs/ROBUSTNESS.md)): obfuscated attack variants show the
tools are robust to *different* evasions — mcp-bastion catches zero-width/bidi (1/3), pipelock catches
homoglyph + base64 (2/3), and no tool survives all three. Defense-in-depth holds at the evasion layer too.

Each drives the tool's **real** code (bastion's `scanTool`/`scanText`/`hashToolDefinition`;
mcp-firewall's Python SDK; pipelock's `explain` scanner). The headline finding is **complementarity,
not ranking** — each tool guards a different layer:

- **mcp-bastion** → definition + response layers (poisoning, shadowing, rug-pull, response/retrieval
  injection, prompt-leak via its v0.3 response scanner).
- **mcp-firewall** → call + egress layers (credential-path & cloud-metadata exfil, secret leakage).
- **pipelock** → egress/SSRF layer (blocks exfiltration to cloud-metadata / private IPs).
- Together they cover **8 of 22 vectors; 14 are covered by none** — the whole
  transport/registry/supply-chain surface is undefended by any measured proxy.
- Conclusion: no single proxy suffices — defense-in-depth across layers is required.

_(pipelock's number is a lower bound: only its URL/egress scanner is wired, not its text-injection
mode — see `docs/ADAPTERS.md`.)_

> **Two methodology notes baked into these numbers.** (1) The v1 corpus under-probed egress/secret
> encodings, so mcp-firewall scored 5%; adding realistic v2 fixtures (AWS-key exfil, cloud-metadata
> egress) raised it to 14% — a fairness fix, not a tuning trick. (2) mcp-bastion rose from 9% because
> a real feature was added (tool-result scanning) and then verified here — the benchmark guided the
> improvement. The matrix (which vectors, not just totals) remains the honest read.

> **Measured (9%) is lower than the earlier self-reported 12% — on purpose.** The self-report credited
> six "observe" (audit-trail-only) vectors at a small weight; the runner scores them 0 because
> *observing a call in an audit log is not detecting an attack*. Strict, measured detection below
> self-reported coverage is the benchmark working as intended. Zero false positives across all 22
> benign controls is the key integrity result.

## Why this project exists

It is one of two open-source artifacts built to advance safe, reliable enterprise AI agent
infrastructure — a **threat→framework crosswalk** and this **defense-coverage benchmark** — targeting
gaps confirmed by an adversarially-verified 2026 literature review. Companion project:
[mcp-bastion](https://github.com/Gowthaman90/mcp-bastion), a reliability + security proxy for MCP.

## License

- Rubric data & docs: **CC-BY-4.0**
- Harness code: **Apache-2.0**
