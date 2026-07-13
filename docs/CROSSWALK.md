# MCP Threat–Control Crosswalk (rubric) — v0.1.0-draft

_Generated from `rubric/crosswalk.json` on 2026-07-13. Edit the JSON, not this file._

Vendor-neutral rubric: MCP attack vectors mapped to architectural layer, STRIDE, NIST AI RMF, OWASP LLM 2025, and OWASP Agentic 2026. Per-tool coverage lives in adapters/*, NOT here, so the rubric stays neutral.

**22 vectors** · **CC-BY-4.0**

| # | Vector | Layer | STRIDE | NIST AI RMF | OWASP LLM 2025 | OWASP Agentic 2026 | Prior-art benchmarks |
|---|---|---|---|---|---|---|---|
| 1 | **Tool poisoning** | tool, client | Tampering, ElevationOfPrivilege | MAP, MEASURE, MANAGE | LLM01, LLM06 | ASI01, ASI02 | MSB, MCPTox, AgentDefense-Bench, MCP-Scan |
| 2 | **Tool name collision / shadowing** | client, tool | Spoofing, Tampering | MAP, MANAGE | LLM01, LLM03 | ASI01, ASI04 | MSB, AgentDefense-Bench, MCP-Scan |
| 3 | **Rug pull / dynamic capability mutation** | tool, registry-supply-chain | Tampering | MEASURE, MANAGE | LLM03, LLM06 | ASI04 | MSB, AgentDefense-Bench |
| 4 | **Out-of-scope parameter injection** | tool, server | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM05, LLM06 | ASI02 | MSB |
| 5 | **Prompt injection via tool results** | tool, client | Tampering | MEASURE, MANAGE | LLM01, LLM05 | ASI01 | MSB, MCP-Scan |
| 6 | **Indirect / retrieval injection** | tool, server | Tampering | MEASURE, MANAGE | LLM01 | ASI01 | MSB |
| 7 | **Cross-tool data exfiltration / confused deputy** | client, host-orchestration | InformationDisclosure, ElevationOfPrivilege | MAP, MEASURE, MANAGE | LLM02, LLM06 | ASI02, ASI03 | MSB, AgentDefense-Bench |
| 8 | **Tool-transfer / cross-server chaining** | host-orchestration, client | ElevationOfPrivilege | MAP, MANAGE | LLM06 | ASI02, ASI03 | MSB |
| 9 | **False-error escalation** | tool, client | ElevationOfPrivilege, DenialOfService | MEASURE, MANAGE | LLM01, LLM06 | ASI01, ASI02 | MSB |
| 10 | **Package / name squatting in registry** | registry-supply-chain | Spoofing | GOVERN, MAP | LLM03 | ASI04 | AgentDefense-Bench |
| 11 | **Supply-chain poisoning (unverified provenance)** | registry-supply-chain | Tampering, Spoofing | GOVERN, MAP, MANAGE | LLM03, LLM04 | ASI04 | AgentDefense-Bench |
| 12 | **Configuration drift** | server, host-orchestration | Tampering | GOVERN, MEASURE, MANAGE | LLM03 | ASI04 | AgentDefense-Bench |
| 13 | **Sandbox escape** | server, host-orchestration | ElevationOfPrivilege | MANAGE | LLM06 | ASI02, ASI03 | AgentDefense-Bench |
| 14 | **Schema / validation bypass** | server, tool | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM05 | ASI02 | AgentDefense-Bench |
| 15 | **Man-in-the-middle (transport)** | transport | Tampering, InformationDisclosure, Spoofing | MANAGE | LLM02 | ASI03 | — |
| 16 | **DNS rebinding (local servers)** | transport, host-orchestration | Spoofing, ElevationOfPrivilege | MANAGE | LLM06 | ASI03 | AgentDefense-Bench |
| 17 | **Server impersonation / identity spoofing** | registry-supply-chain, transport | Spoofing | GOVERN, MAP, MANAGE | LLM03 | ASI03, ASI04 | — |
| 18 | **Excessive permission / privilege escalation** | host-orchestration, server | ElevationOfPrivilege | GOVERN, MAP, MANAGE | LLM06 | ASI03 | MSB |
| 19 | **Credential / token theft via passthrough** | host-orchestration, transport | InformationDisclosure, ElevationOfPrivilege | GOVERN, MANAGE | LLM02, LLM06 | ASI03 | — |
| 20 | **Consent fatigue / over-broad grants** | client, host-orchestration | ElevationOfPrivilege, Repudiation | GOVERN, MANAGE | LLM06 | ASI03 | — |
| 21 | **Command injection in tool execution** | server | ElevationOfPrivilege, Tampering | MEASURE, MANAGE | LLM05 | ASI02 | AgentDefense-Bench |
| 22 | **System-prompt / context leakage via tools** | client, tool | InformationDisclosure | MEASURE, MANAGE | LLM07, LLM02 | ASI01 | MSB |

_Mappings are indicative and reviewable, not a certification. See `docs/PRIOR-ART.md`._
