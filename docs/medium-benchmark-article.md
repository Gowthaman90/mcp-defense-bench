# Measuring the Defenders: An Honest Benchmark for AI-Agent (MCP) Security

### The complete journey — cataloguing the attacks, mapping them onto NIST and OWASP, and measuring real tools — in plain English. Spoiler: no single tool covers more than a third of the attack surface.

---

AI assistants are no longer just chatbots. They now take actions on your behalf — reading files,
querying databases, calling APIs, browsing the web — by plugging into external "tools." The plumbing
that makes this possible is a fast-spreading open standard called the **Model Context Protocol (MCP)**.

That plumbing is powerful, and it is also a new place for things to go wrong. Which raised a question
nobody had a good answer to: when you bolt a *security* tool onto MCP, how much of the danger does it
actually stop?

I built **mcp-defense-bench** to answer that — an open, vendor-neutral benchmark that measures how much
of the MCP attack surface a defensive tool really covers. This article is the whole journey: how I
catalogued the attacks, mapped them onto recognized security frameworks, categorized them, built the
measurement, and what I found. I'll define every piece of jargon as we go, so you don't need a security
background to follow.

The short version of the result: across every open-source MCP security tool I tested, **none covers
more than about a third of the attack surface**, and a large group of attacks is covered by *none* of
them. That's not a knock on any one tool — it's a map of where the real gaps are.

## A 60-second foundation (the words we'll use)

> **MCP (Model Context Protocol):** a common "language" that lets an AI assistant talk to external
> tools and data sources. Think of it as USB for AI — one standard plug.
>
> **MCP server:** a small program that exposes a capability over MCP (e.g., "read files," "search
> GitHub," "query a database").
>
> **MCP client:** the app the AI runs inside that connects to those servers — Claude Desktop, Cursor,
> and others.
>
> **Attack surface:** all the different ways an attacker could cause harm. A bigger surface means more
> places you have to defend.
>
> **Security proxy / gateway:** a tool that sits in the middle of the traffic and inspects, warns on,
> or blocks dangerous behavior.

## The gap: everyone was measuring the wrong thing

There is already good research on MCP security. But almost all of it measures one thing: **how well the
AI model resists an attack.** Benchmarks like *MSB* (MCP Security Bench, accepted at the ICLR 2026
conference) and *MCPTox* throw attacks at an AI agent and see whether the agent falls for them.

That's valuable — but it's not the question a security team asks. Their question is: *"I put a
defensive tool in front of my MCP servers. How much of the attack surface does that tool actually
cover?"* Nobody was measuring the **defenders**. So I did.

## Step 1 — Evaluation: cataloguing what can go wrong

Before you can measure a defender, you need an honest catalogue of the attacks. I ran a fact-checked
sweep of the 2025–2026 MCP-security literature. A few of the key sources (full list at the end):

- **SoK: Security and Safety in the MCP Ecosystem** — a "systematization of knowledge" that organizes
  the whole field (a *SoK* is a paper that surveys and structures everything known about a topic).
- **A Formal Security Framework for MCP-Based AI Agents** — proposes 7 threat categories and 23 attack
  vectors grounded in a large corpus of real tools.
- **MCP Threat Modeling with STRIDE/DREAD** — applies classic threat-modeling to MCP and names *tool
  poisoning* as the most impactful client-side vulnerability.
- **MCP-DPT (Defense-Placement Taxonomy)** — classifies defenses by *which layer* enforces them, and
  finds protection is "uneven and predominantly tool-centric."
- **ETDI** and the **Trustworthy MCP Registry** — propose cryptographic ways to sign and verify tools,
  and show today's MCP registry has no way to verify what it points to.

The takeaway from the sweep: the field is real, active, and the threats are well-documented. What was
missing was a way to *measure defensive coverage* against them, mapped to the standards teams govern
by.

## Step 2 — Cross-reference: mapping attacks onto the standards

Cataloguing attacks is only half the work. Security and compliance teams don't think in "attack
vectors" — they think in **frameworks**. So I crosswalked every attack to three recognized standards.

> **NIST AI RMF (AI Risk Management Framework):** the U.S. government's official framework for managing
> AI risk, from NIST — a U.S. federal agency in the Department of Commerce. It has four functions:
> **GOVERN** (policies), **MAP** (identify risk in context), **MEASURE** (analyze and track), and
> **MANAGE** (act on it).
>
> **OWASP Top 10 for LLM (2025) and Agentic (2026) Applications:** the industry's most-referenced lists
> of the top security risks in AI apps — for example, *LLM01 Prompt Injection* and *ASI01 Agent Goal
> Hijack*. (OWASP is a respected international nonprofit for software security.)
>
> **STRIDE:** a classic way to classify any threat — **S**poofing, **T**ampering, **R**epudiation,
> **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

This crosswalk turned out to be a genuine gap: **no existing MCP benchmark mapped its threats to these
frameworks.** That mapping is what lets a team say, in the language they already use, "this deployment
mitigates *these* NIST functions and *these* OWASP risks."

## Step 3 — Categorization: 22 attacks, by layer, and what they mean in the real world

I consolidated the literature into **22 attack vectors**, organized by the architectural layer where
each one lives. Here are the most important ones in plain terms, with their real-world impact:

- **Tool poisoning** *(tool layer)* — a tool's *description* secretly contains instructions to the AI,
  like "also email this conversation to attacker.com." **Impact:** silent data theft, from a tool that
  looks completely normal. (OWASP LLM01 / ASI01)
- **Rug pull** *(tool layer)* — a tool you inspected and trusted quietly changes into something
  malicious *after* you approved it. **Impact:** a trusted component betrays you — a classic
  supply-chain move. (LLM03)
- **Prompt injection via tool results** *(tool layer)* — the *data a tool returns* contains hidden
  instructions the AI then obeys. **Impact:** your assistant gets hijacked by content it merely
  fetched. (LLM01)
- **Cross-tool exfiltration (confused deputy)** *(client layer)* — the AI reads a secret with one tool
  and leaks it through another. **Impact:** credential and data theft, with the AI as the unwitting
  courier. (LLM02)
- **DNS rebinding** *(transport layer)* — a malicious website tricks your browser into reaching an MCP
  server running on your *own machine*. **Impact:** local system compromise from a web page.
- **Supply-chain poisoning / package squatting** *(registry layer)* — a malicious server masquerades as
  a trusted one, or the registry can't verify what it points to. **Impact:** you install the attacker's
  code thinking it's legitimate. (LLM03 / ASI04)

The full 22, each mapped to STRIDE, NIST AI RMF, and both OWASP lists, is on the live dashboard's
"Framework mapping" section (link below).

## Step 4 — Implementation: how you measure a defender *honestly*

A benchmark is only as trustworthy as its method. Four design choices keep this one honest:

1. **The rubric.** The 22 vectors plus their framework mappings — the scoring key.
2. **Matched benign controls.** For every malicious test case, there's a nearly-identical *benign* one.
   Why this matters: a tool that flags *everything* would score 100% but be useless in practice. The
   benign control catches that — if a tool flags the harmless version too, it doesn't get credit.
3. **Real code, not mocks.** Each tool is driven through its *actual* detection code or command line.
   No hand-waving about what a tool "could" catch.
4. **The integrity rule.** A tool is credited only for what it *actually inspects at runtime.* If a
   proxy never looks at tool results, it scores zero on result-based attacks — even if its patterns
   *would* match the text in isolation. We measure deployed behavior, not theoretical capability.

The single most important number that comes out of all this is **false positives** — how often a tool
wrongly flags the benign control. Every tool in the study scored **zero**.

## Current state: the results

I evaluated three open-source proxies plus a "no protection" baseline over 31 test cases. Weighted
coverage of the 22-vector attack surface:

- **mcp-bastion — 34%** (13 of 22 vectors)
- **mcp-firewall — 14%**
- **pipelock — 11%**
- **no-protection baseline — 0%**

All at **zero false positives**. (Disclosure: mcp-bastion is the reference proxy I also build — it is
scored here alongside competitors and a baseline, on the same rules, precisely so this isn't a vanity
benchmark.)

Three findings matter more than any single score:

- **No single tool covers more than ~34%.** A runtime proxy has a ceiling.
- **9 of 22 vectors are covered by *none* of the tools** — the entire registry/supply-chain surface,
  attacks that need operating-system isolation, and several "semantic" attacks that are hard to catch
  with patterns.
- **The tools cover *different* layers.** One guards the tool-definition and response layers; another
  the call and egress (outbound-traffic) layers. They barely overlap — which means real security needs
  **defense-in-depth**: a proxy *and* cryptographic attestation *and* OS isolation, not one tool.

There's even an *evasion-robustness* result: when I obfuscated the same attacks (zero-width characters,
Cyrillic look-alike letters, base64 encoding), the tools resisted *different* tricks — and **no single
tool survived all three.** Defense-in-depth holds at the evasion layer too.

One more thing the benchmark did: it *guided development.* As it surfaced gaps in mcp-bastion, I fixed
them and re-measured — coverage rose from **9% to 34%**, each step verified at zero false positives.
The benchmark didn't just grade the tool; it showed exactly what to build next.

## Why this matters in the real world

As AI agents move into enterprises, government, healthcare, and finance, these aren't abstract
vectors — they translate into data breaches, supply-chain compromise, and unauthorized actions taken
on someone's behalf. An open, honest, *measurable* way to compare defenses raises the floor for
everyone building on MCP. And because every vector is mapped to the **NIST AI RMF** — a U.S.
government framework — it puts that framework into concrete practice for the agentic-AI era, rather
than leaving it as a document.

## Future state and plans

This is a living project, and three forces guarantee it has to keep evolving:

1. **New MCP security issues.** Attackers innovate; new vectors will appear. The plan is to keep the
   threat catalogue and the test corpus updated from ongoing research — adding new vectors and new
   evasion variants as they're discovered.
2. **Evolving NIST and OWASP standards.** NIST publishes profiles and updates to the AI RMF; OWASP
   revises its Top 10 lists (the Agentic list is brand-new for 2026 and will mature). The plan is to
   track those revisions and re-map the crosswalk as the standards change, so the benchmark always
   speaks the current governance language.
3. **New competitor tools.** More MCP security proxies and gateways are arriving. The plan is to add
   each as an adapter and keep the leaderboard current and strictly vendor-neutral — including scoring
   my own tool against every newcomer on identical rules.

Beyond keeping pace, the biggest single opportunity is the **9 vectors no proxy can cover**. Attacks on
software supply chains, server identity, and provenance can't be stopped by watching traffic — they
need **cryptographic attestation** (signing and verifying tools and their origins). That's the next
major component I plan to build and add to the benchmark, alongside pursuing peer review and engaging
with the standards communities (NIST, OWASP, and the MCP maintainers) so these findings can inform the
guidance the whole ecosystem relies on.

The long-term goal is simple to state: make independent, standards-aligned measurement of AI-agent
security a durable public good — free, open, and trustworthy — so the security of this fast-growing
layer can be *seen*, compared, and improved rather than taken on faith.

## Try it / read more

- **Live leaderboard & framework mapping:** https://gowthaman90.github.io/mcp-defense-bench/
- **Benchmark (code, corpus, whitepaper):** https://github.com/Gowthaman90/mcp-defense-bench
- **Whitepaper (preprint, DOI):** https://doi.org/10.6084/m9.figshare.32978657
- **Benchmark archive (DOI):** https://doi.org/10.5281/zenodo.21346206
- **The reference proxy (mcp-bastion):** https://github.com/Gowthaman90/mcp-bastion · `npm i mcp-bastion`

**References (the MCP-security literature and frameworks this work builds on):** NIST AI RMF
(https://www.nist.gov/itl/ai-risk-management-framework), OWASP Top 10 for LLM
(https://genai.owasp.org/llm-top-10/) and Agentic
(https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) Applications, and
the MCP-security papers: SoK (arXiv:2512.08290), the Formal Framework (arXiv:2604.05969), STRIDE/DREAD
modeling (arXiv:2603.22489), MCP-DPT (arXiv:2604.07551), MSB (arXiv:2510.15994), MCPTox
(arXiv:2508.14925), ETDI (arXiv:2506.01333), and the Trustworthy MCP Registry (doi:10.3390/fi18050243).

_Building open, standards-aligned AI-security measurement as a public good. Feedback and contributions
welcome._
