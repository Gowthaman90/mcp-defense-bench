# MCP Threat–Control Crosswalk (rubric) — v0.8.0

_Generated from `rubric/crosswalk.json` on 2026-09-08. Edit the JSON, not this file._

Vendor-neutral rubric: MCP attack vectors mapped to architectural layer, STRIDE, NIST AI RMF, OWASP LLM 2025, OWASP Agentic 2026, NSA MCP Security guidance, EU AI Act obligations (Arts. 12/14/15/26/55/72/73) and ISO/IEC 42001 Annex A controls (May 2026). Per-tool coverage lives in adapters/*, NOT here, so the rubric stays neutral.

**32 vectors** · **CC-BY-4.0**

| # | Vector | Layer | STRIDE | NIST AI RMF | OWASP LLM 2025 | OWASP Agentic 2026 | NSA (May 2026) | EU AI Act | ISO/IEC 42001 | Applies to | Prior-art benchmarks |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **Tool poisoning** | tool, client | Tampering, ElevationOfPrivilege | MAP, MEASURE, MANAGE | LLM01, LLM06 | ASI01, ASI02 | RT, AUTH | Art.15(5) | A.6.2.6, A.4.4, A.10.3 | all | MSB, MCPTox, AgentDefense-Bench, MCP-Scan |
| 2 | **Tool name collision / shadowing** | client, tool | Spoofing, Tampering | MAP, MANAGE | LLM01, LLM03 | ASI01, ASI04 | AUTH, RT | Art.15(5) | A.6.2.6, A.4.4, A.10.3 | all | MSB, AgentDefense-Bench, MCP-Scan |
| 3 | **Rug pull / dynamic capability mutation** | tool, registry-supply-chain | Tampering | MEASURE, MANAGE | LLM03, LLM06 | ASI04 | AUTH, RT | Art.15(5), Art.14, Art.55(1)(d), Art.72 | A.6.2.6, A.4.4, A.10.3 | all | MSB, AgentDefense-Bench |
| 4 | **Out-of-scope parameter injection** | server, tool | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM05, LLM06 | ASI02 | RT, AUTH | Art.15(5), Art.55(1)(d) | A.6.2.6, A.6.2.4, A.9.2 | all | MSB, AgentDefense-Bench |
| 5 | **Prompt injection via tool results** | tool, client | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM01, LLM05 | ASI01 | RT | Art.15(5) | A.6.2.6, A.7.5, A.10.3 | all | MSB, MCP-Scan, AgentDefense-Bench |
| 6 | **Indirect / retrieval injection** | tool, server | Tampering | MEASURE, MANAGE | LLM01, LLM08 | ASI01 | RT | Art.15(5), Art.55(1)(d) | A.6.2.6, A.7.5 | all | MSB, AgentDefense-Bench |
| 7 | **Cross-tool data exfiltration / confused deputy** | client, host-orchestration | InformationDisclosure, ElevationOfPrivilege | MAP, MEASURE, MANAGE | LLM02, LLM06 | ASI02, ASI03 | RT, SEG | Art.15(5), Art.73 | A.6.2.6, A.8.4 | all | MSB, AgentDefense-Bench |
| 8 | **Tool-transfer / cross-server chaining** | host-orchestration, client | ElevationOfPrivilege | MAP, MANAGE | LLM06 | ASI02, ASI03 | AUTH, SEG, RT | Art.15(5), Art.73 | A.6.2.6, A.10.3, A.8.4 | all | MSB |
| 9 | **False-error escalation** | tool, client | ElevationOfPrivilege, DenialOfService | MEASURE, MANAGE | LLM01, LLM06 | ASI01, ASI02 | RT, LOG | Art.15(5), Art.12, Art.14 | A.6.2.6, A.6.2.8, A.10.3 | all | MSB |
| 10 | **Package / name squatting in registry** | registry-supply-chain | Spoofing | GOVERN, MAP | LLM03 | ASI04 | AUTH | Art.15(5), Art.55(1)(d) | A.6.2.6, A.10.3 | all | AgentDefense-Bench |
| 11 | **Supply-chain poisoning (unverified provenance)** | registry-supply-chain | Tampering, Spoofing | GOVERN, MAP, MANAGE | LLM03, LLM04 | ASI04 | AUTH | Art.15(5), Art.55(1)(d), Art.73 | A.6.2.6, A.10.3, A.8.4 | all | AgentDefense-Bench |
| 12 | **Configuration drift** | server, host-orchestration | Tampering | GOVERN, MEASURE, MANAGE | LLM03 | ASI04 | LOG, AUTH | Art.15(5), Art.12, Art.26, Art.55(1)(d), Art.72 | A.6.2.6, A.6.2.8, A.6.2.5 | all | AgentDefense-Bench |
| 13 | **Sandbox escape** | server, host-orchestration | ElevationOfPrivilege | MANAGE, MEASURE | LLM06 | ASI02, ASI03, ASI05 | RT | Art.15(5), Art.55(1)(d), Art.73 | A.6.2.6, A.6.2.4, A.6.2.5, A.8.4 | all | AgentDefense-Bench |
| 14 | **Schema / validation bypass** | server, tool | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM05 | ASI02 | RT | Art.15(5), Art.55(1)(d) | A.6.2.6, A.6.2.4 | all | AgentDefense-Bench |
| 15 | **Man-in-the-middle (transport)** | transport | Tampering, InformationDisclosure, Spoofing | MANAGE, MEASURE | LLM02 | ASI03, ASI07 | RT, AUTH | Art.15(5), Art.55(1)(d) | A.6.2.6, A.6.2.5 | all | AgentDefense-Bench |
| 16 | **DNS rebinding (local servers)** | transport, server | Spoofing, ElevationOfPrivilege | MANAGE, MEASURE | LLM06 | ASI03, ASI07 | AUTH, RT | Art.15(5), Art.55(1)(d) | A.6.2.6, A.6.2.5 | all | AgentDefense-Bench |
| 17 | **Server impersonation / identity spoofing** | registry-supply-chain, transport | Spoofing | GOVERN, MAP, MANAGE | LLM03 | ASI03, ASI04 | AUTH | Art.15(5), Art.55(1)(d), Art.72 | A.6.2.6, A.10.3 | all | — |
| 18 | **Excessive permission / privilege escalation** | host-orchestration, server | ElevationOfPrivilege | GOVERN, MAP, MANAGE | LLM06 | ASI03 | AUTH | Art.15(5), Art.14, Art.26, Art.55(1)(d) | A.6.2.6, A.6.2.5, A.9.2 | all | MSB, AgentDefense-Bench |
| 19 | **Credential / token theft via passthrough** | host-orchestration, transport | InformationDisclosure, ElevationOfPrivilege | GOVERN, MANAGE | LLM02, LLM06 | ASI03 | RT, SEG, AUTH | Art.15(5), Art.55(1)(d), Art.73 | A.6.2.6, A.8.4 | all | AgentDefense-Bench |
| 20 | **Consent fatigue / over-broad grants** | client, host-orchestration | ElevationOfPrivilege, Repudiation | GOVERN, MANAGE | LLM06 | ASI03 | AUTH | Art.15(5), Art.14, Art.26 | A.6.2.6, A.6.2.5, A.9.2 | all | — |
| 21 | **Command injection in tool execution** | server | ElevationOfPrivilege, Tampering | MEASURE, MANAGE | LLM05 | ASI02, ASI05 | RT | Art.15(5), Art.55(1)(d), Art.73 | A.6.2.6, A.6.2.4, A.8.4 | all | AgentDefense-Bench |
| 22 | **System-prompt / context leakage via tools** | client, tool | InformationDisclosure | MEASURE, MANAGE | LLM07, LLM02 | ASI01 | RT, LOG | Art.15(5), Art.12 | A.6.2.6, A.6.2.8 | all | MSB, AgentDefense-Bench |
| 23 | **Mid-session tool injection (MSTI)** | client, tool | Tampering, Spoofing | MEASURE, MANAGE | LLM01, LLM06 | ASI01, ASI04 | AUTH, LOG | Art.15(5), Art.12, Art.14, Art.72 | A.6.2.6, A.6.2.8, A.4.4, A.10.3 | all | — |
| 24 | **Multi-tool split poisoning (ShareLock)** | tool, registry-supply-chain | Tampering | MEASURE, MANAGE | LLM01, LLM03 | ASI01, ASI04 | RT, LOG | Art.15(5), Art.12, Art.55(1)(d) | A.6.2.6, A.6.2.8, A.4.4, A.10.3 | all | — |
| 25 | **Header/body routing desync (HeaderMismatch)** | transport, host-orchestration | Tampering, ElevationOfPrivilege | MEASURE, MANAGE | LLM06 | ASI02, ASI03 | AUTH, RT | Art.15(5), Art.55(1)(d) | A.6.2.6, A.6.2.4 | 2026-07-28 | — |
| 26 | **MRTR requestState forgery / replay** | server, host-orchestration | Tampering, Spoofing, ElevationOfPrivilege | MEASURE, MANAGE | LLM06 | ASI03, ASI09 | AUTH, RT | Art.15(5), Art.55(1)(d), Art.73 | A.6.2.6, A.6.2.4, A.8.4 | 2026-07-28 | — |
| 27 | **List-result cache poisoning / stale-cache defense suppression** | client, tool | Tampering | MEASURE, MANAGE | LLM01, LLM03 | ASI01, ASI04, ASI06 | RT, LOG | Art.15(5), Art.12, Art.72 | A.6.2.6, A.6.2.8, A.4.4, A.10.3 | 2026-07-28 | — |
| 28 | **MRTR in-band input phishing / sampling injection** | client, host-orchestration | Spoofing, InformationDisclosure | MAP, MEASURE, MANAGE | LLM01, LLM02 | ASI01, ASI03, ASI09 | AUTH, RT | Art.15(5), Art.14 | A.6.2.6, A.10.3 | 2026-07-28 | — |
| 29 | **Task authorization bypass** | server, host-orchestration | ElevationOfPrivilege, InformationDisclosure, Spoofing | MEASURE, MANAGE | LLM02, LLM06 | ASI03 | AUTH, LOG | Art.15(5), Art.12, Art.55(1)(d) | A.6.2.6, A.6.2.8, A.6.2.4 | 2026-07-28 | — |
| 30 | **MCP Apps sandbox non-conformance** | host-orchestration, client | Tampering, InformationDisclosure | MAP, MANAGE | LLM05, LLM02 | ASI05, ASI09 | RT | Art.15(5), Art.14, Art.26 | A.6.2.6, A.6.2.5, A.10.3 | 2026-07-28 | — |
| 31 | **Roots deprecation: no enforced filesystem boundary** | host-orchestration, server | ElevationOfPrivilege, InformationDisclosure | MAP, MANAGE | LLM06, LLM02 | ASI02, ASI03 | SEG, AUTH | Art.15(5), Art.26, Art.55(1)(d) | A.6.2.6, A.6.2.4, A.6.2.5, A.9.2 | 2026-07-28 | — |
| 32 | **Transport / revision downgrade** | transport | Tampering, Spoofing | MEASURE, MANAGE |  | ASI07 | AUTH, RT | Art.15(5), Art.26, Art.55(1)(d) | A.6.2.6, A.6.2.5 | 2026-07-28 | — |

## Framework legends

### owaspLlm2025

- **LLM01** — Prompt Injection
- **LLM02** — Sensitive Information Disclosure
- **LLM03** — Supply Chain
- **LLM04** — Data and Model Poisoning
- **LLM05** — Improper Output Handling
- **LLM06** — Excessive Agency
- **LLM07** — System Prompt Leakage
- **LLM08** — Vector and Embedding Weaknesses
- **LLM09** — Misinformation
- **LLM10** — Unbounded Consumption

### owaspAgentic2026

- **ASI01** — Agent Goal Hijack
- **ASI02** — Tool Misuse and Exploitation
- **ASI03** — Identity and Privilege Abuse
- **ASI04** — Agentic Supply Chain Vulnerabilities
- **ASI05** — Unexpected Code Execution (RCE)
- **ASI06** — Memory & Context Poisoning
- **ASI07** — Insecure Inter-Agent Communication
- **ASI08** — Cascading Failures
- **ASI09** — Human-Agent Trust Exploitation
- **ASI10** — Rogue Agents

### nsaGuidance

- **AUTH** — Authentication & Access Control (verify every session; least-privilege tokens per action/tool; signed provenance for discovered servers)
- **LOG** — Monitoring & Logging (log all tool/model invocations with parameters, identities, and result hashes)
- **SEG** — Data Classification & Segmentation (align tools/models to data-classification zones)
- **RT** — Runtime Controls (egress-filtering proxy, DLP, sandboxing, message integrity, output filtering, local MCP scans)

### euAiAct

_Regulation (EU) 2024/1689. Articles 9–15 bind PROVIDERS of high-risk AI systems (Annex III), Art. 26 binds DEPLOYERS of high-risk systems, Arts. 53/55 bind providers of general-purpose AI models (GPAI obligations enforceable since 2026-08-02). An MCP deployment engages these only when the surrounding AI system is in scope; the mapping says which obligation a vector's defence serves, not that every MCP deployment is regulated._

- **Art.12** — Record-keeping — automatic logging of events over the system's lifetime (traceability)
- **Art.14** — Human oversight — measures enabling natural persons to oversee, understand, and intervene
- **Art.15(5)** — Accuracy, robustness and cybersecurity — resilience against unauthorised third parties altering use, outputs or performance by exploiting vulnerabilities (incl. data/model poisoning, adversarial examples, confidentiality attacks)
- **Art.26** — Obligations of deployers of high-risk AI systems — use per instructions, assign human oversight, monitor operation, keep logs
- **Art.55(1)(d)** — GPAI with systemic risk — ensure an adequate level of cybersecurity protection for the model and its physical infrastructure
- **Art.72** — Post-market monitoring — actively and systematically collect and analyse performance data over the lifetime
- **Art.73** — Reporting of serious incidents — track, document and report incidents and corrective measures

### iso42001

_ISO/IEC 42001:2023 Annex A reference controls (AI management system). Control titles per the standard; an organisation selects controls via its Statement of Applicability, so these are the controls a vector's defence would evidence._

- **A.4.4** — Tooling resources — document the tools and resources used by the AI system
- **A.6.2.4** — AI system verification and validation
- **A.6.2.5** — AI system deployment — deployment requirements incl. security configuration
- **A.6.2.6** — AI system operation and monitoring
- **A.6.2.8** — AI system recording of event logs
- **A.7.5** — Data provenance — provenance of data used by the AI system
- **A.8.4** — Communication of incidents
- **A.9.2** — Processes for responsible use of AI systems
- **A.10.3** — Suppliers — manage risks from third-party suppliers of components and services

_Mappings are indicative and reviewable, not a certification. Layer/STRIDE/NIST/OWASP/NSA columns have a blind second-rater pass (`docs/AGREEMENT.md`); the EU AI Act and ISO/IEC 42001 columns are single-rater as of v0.8.0 (decision rules in `rubric/RATING-CODEBOOK.md`). See `docs/PRIOR-ART.md`._
