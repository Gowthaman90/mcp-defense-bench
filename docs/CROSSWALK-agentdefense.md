# Taxonomy Mapping: mcp-defense-bench ↔ AgentDefense-Bench

_Aligns the **24 attack vectors** of [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench)
(MDB) with the **17 attack categories / 6 domains** of
[AgentDefense-Bench](https://github.com/arunsanna/AgentDefense-Bench) (ADB, A. Sanna, Apache-2.0)._

Prepared in response to [arunsanna/AgentDefense-Bench#1](https://github.com/arunsanna/AgentDefense-Bench/issues/1).
Mappings are indicative and reviewable, not a certification. Corrections welcome via issue or PR.

## Why the two are complementary

The benchmarks measure **orthogonal axes of the same problem**, and neither subsumes the other:

| | mcp-defense-bench | AgentDefense-Bench |
|---|---|---|
| **Axis** | Coverage completeness | Detection accuracy |
| **Question** | Of the mapped MCP attack surface, which vectors does this defender address *at all* — detect, enforce, or miss? | Given a large attack corpus, how accurately does this defender classify it — detection rate vs. false-positive rate? |
| **Unit under test** | A defensive proxy / gateway / scanner | A defensive proxy / gateway / scanner |
| **Corpus** | 24 framework-crosswalked vectors, MCP-native | 35,546 attack + 443 benign cases in MCP JSON-RPC, aggregated from 13 sources |
| **Framework mapping** | NIST AI RMF, OWASP LLM 2025, OWASP Agentic 2026, STRIDE, NSA MCP guidance (May 2026) | — |
| **Failure it catches** | A defender with excellent accuracy on the vectors it *does* implement, and total blindness to the rest | A defender that nominally "covers" a vector but misclassifies it in practice, or floods the operator with false positives |

A defender can score well on one and badly on the other, in **both** directions. Read together, they
give a fuller picture than either alone: MDB tells you what a defense *reaches*, ADB tells you how
well it *judges* what it reaches.

## ADB category → MDB vector

Match strength: **exact** = same phenomenon, same scope · **partial** = overlapping but one is
broader · **one-to-many** = the ADB category spans several MDB vectors · **out of scope** = real
attack, but outside the other benchmark's stated unit of analysis.

| # | ADB domain | ADB category | → MDB vector(s) | Match |
|---|---|---|---|---|
| 1 | Prompt | Direct Injection | — | **out of MDB scope** — model-layer, not an MCP protocol-surface vector |
| 2 | Prompt | Indirect Injection | 5 Prompt injection via tool results; 6 Indirect / retrieval injection | one-to-many |
| 3 | Prompt | Jailbreaks | — | **out of MDB scope** — model-alignment bypass, not MCP-mediated |
| 4 | Tool | Tool Poisoning | 1 Tool poisoning | exact |
| 5 | Tool | Tool Shadowing | 2 Tool name collision / shadowing | exact |
| 6 | Tool | Tool Misuse | 4 Out-of-scope parameter injection; 8 Tool-transfer / cross-server chaining; 18 Excessive permission / privilege escalation | one-to-many |
| 7 | Supply Chain | Package Squatting | 10 Package / name squatting in registry | exact |
| 8 | Supply Chain | Rug Pull | 3 Rug pull / dynamic capability mutation | exact |
| 9 | Supply Chain | Configuration Drift | 12 Configuration drift | exact |
| 10 | Infrastructure | Path Traversal | 14 Schema / validation bypass; 21 Command injection in tool execution | partial — MDB folds path traversal into server-side input validation rather than naming it |
| 11 | Infrastructure | Sandbox Escape | 13 Sandbox escape | exact |
| 12 | Infrastructure | Command Injection | 21 Command injection in tool execution | exact |
| 13 | Network | MITM | 15 Man-in-the-middle (transport) | exact |
| 14 | Network | DNS Rebinding | 16 DNS rebinding (local servers) | exact |
| 15 | Network | Data Exfiltration | 7 Cross-tool data exfiltration / confused deputy; 19 Credential / token theft via passthrough; 22 System-prompt / context leakage via tools | one-to-many |
| 16 | Protocol | Schema Bypass | 14 Schema / validation bypass | exact |
| 17 | Protocol | Vulnerable Client/Server | 11 Supply-chain poisoning (unverified provenance); 17 Server impersonation / identity spoofing | partial — ADB's CVE-class implementation flaws have no dedicated MDB vector |

## MDB vector → ADB category

| # | MDB vector | → ADB category | Match |
|---|---|---|---|
| 1 | Tool poisoning | Tool Poisoning | exact |
| 2 | Tool name collision / shadowing | Tool Shadowing | exact |
| 3 | Rug pull / dynamic capability mutation | Rug Pull | exact |
| 4 | Out-of-scope parameter injection | Tool Misuse | partial |
| 5 | Prompt injection via tool results | Indirect Injection | partial |
| 6 | Indirect / retrieval injection | Indirect Injection | exact |
| 7 | Cross-tool data exfiltration / confused deputy | Data Exfiltration | partial |
| 8 | Tool-transfer / cross-server chaining | Tool Misuse | partial |
| 9 | **False-error escalation** | — | **no ADB counterpart** |
| 10 | Package / name squatting in registry | Package Squatting | exact |
| 11 | Supply-chain poisoning (unverified provenance) | Vulnerable Client/Server | partial |
| 12 | Configuration drift | Configuration Drift | exact |
| 13 | Sandbox escape | Sandbox Escape | exact |
| 14 | Schema / validation bypass | Schema Bypass; Path Traversal | one-to-many |
| 15 | Man-in-the-middle (transport) | MITM | exact |
| 16 | DNS rebinding (local servers) | DNS Rebinding | exact |
| 17 | Server impersonation / identity spoofing | Vulnerable Client/Server | partial |
| 18 | Excessive permission / privilege escalation | Tool Misuse | partial |
| 19 | Credential / token theft via passthrough | Data Exfiltration | partial |
| 20 | **Consent fatigue / over-broad grants** | — | **no ADB counterpart** |
| 21 | Command injection in tool execution | Command Injection | exact |
| 22 | System-prompt / context leakage via tools | Data Exfiltration | partial |
| 23 | **Mid-session tool injection (MSTI)** | Rug Pull | partial — ADB's rug pull is approval-time capability mutation; MSTI is *intra-session* injection via tool-lifecycle races and metadata re-framing |
| 24 | **Multi-tool split poisoning (ShareLock)** | — | **no ADB counterpart** |

## Gap analysis

**In ADB, not reachable by MDB (2 of 17):** Direct Injection, Jailbreaks. Both are model-layer
attacks — they do not traverse an MCP tool boundary, so a proxy/gateway is not the enforcement point
and MDB's unit of analysis does not apply. ADB inherits these from its general LLM-safety source
datasets.

**In MDB, not represented in ADB (3 of 24 with no counterpart, 8 partial):**

- **9 False-error escalation** — a tool returning fabricated errors to coerce the agent into
  privilege-escalating retries. Behavioral, multi-turn; hard to express as a single JSON-RPC case.
- **20 Consent fatigue / over-broad grants** — authorization-lifecycle failure, not a malicious
  payload. There is no "attack string" to detect; the vector is an accumulated grant state.
- **24 Multi-tool split poisoning (ShareLock)** — a payload split across several benign-looking
  tool descriptions, reassembled by a covert trigger. A corpus of independent single-tool-call cases
  **structurally cannot represent it**: every individual case is benign by construction. This is a
  limitation of the corpus shape, not an oversight.
- Partial only: **11** supply-chain provenance, **17** server impersonation, **18** excessive
  permission, **19** credential passthrough theft, **4** parameter injection, **7/22** exfiltration
  sub-vectors, **8** cross-server chaining, **23** mid-session tool injection.

The pattern is consistent: **ADB is strongest where an attack has a detectable payload in a single
tool call; MDB reaches vectors that are stateful, authorization-shaped, cross-tool, or
transport-level**, where the question is whether the defender implements a control at all rather
than whether it classifies a string correctly. That asymmetry is the practical argument for reading both.

## Corrections this mapping surfaces in our own crosswalk

Building the mapping exposed stale `priorArtCoverage` entries in `rubric/crosswalk.json`. ADB in fact
covers more MDB vectors than we credited. **All seven are now corrected** in the rubric and the
regenerated `docs/CROSSWALK.md`:

| MDB vector | Currently credited | Should add |
|---|---|---|
| 5 Prompt injection via tool results | MSB, MCP-Scan | AgentDefense-Bench |
| 6 Indirect / retrieval injection | MSB | AgentDefense-Bench |
| 15 Man-in-the-middle (transport) | — | AgentDefense-Bench |
| 4 Out-of-scope parameter injection | MSB | AgentDefense-Bench (partial) |
| 18 Excessive permission / privilege escalation | MSB | AgentDefense-Bench (partial) |
| 19 Credential / token theft via passthrough | — | AgentDefense-Bench (partial) |
| 22 System-prompt / context leakage via tools | MSB | AgentDefense-Bench (partial) |

The rubric's `priorArtCoverage` field records plain benchmark names; the exact/partial nuance lives
in the tables above.

## Sources

- AgentDefense-Bench, `README.md` § Attack Categories, commit as of 2026-08-23 (repo `pushedAt` 2026-04-18).
- mcp-defense-bench, `rubric/crosswalk.json` v0.1.0-draft (24 vectors) → `docs/CROSSWALK.md`.
