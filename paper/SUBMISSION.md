# Preprint submission packet

Copy-paste fields for submitting the whitepaper to a preprint server (TechRxiv, arXiv, etc.).
Upload file: **`paper/whitepaper.pdf`** (TechRxiv accepts PDF; arXiv prefers the `paper/whitepaper.tex` source).

---

## Title

Measuring the Defenders: A Layer-Aware, Framework-Mapped Benchmark for Model Context Protocol Security Proxies

## Author

Gowthaman Arumugam — Independent Researcher — agowthaman90@gmail.com

## Abstract (plain text)

The Model Context Protocol (MCP) has become a common way to connect large-language-model (LLM) agents to external tools and data, and a substantial 2025–2026 literature now documents its attack surface. Existing security benchmarks for MCP measure how well an LLM agent resists attacks. None, to our knowledge, measure how well a defensive proxy or gateway covers that attack surface, and none map their results to the governance frameworks organizations actually use — the NIST AI Risk Management Framework (AI RMF), the OWASP Top 10 for LLM and Agentic Applications, and the NSA MCP Security guidance. We present two artifacts to fill this gap: (1) a threat–control crosswalk of 24 MCP attack vectors mapped to architectural layer, STRIDE class, NIST AI RMF function, NSA MCP Security recommendation area, and OWASP category; and (2) an open, vendor-neutral defense-side benchmark that runs a candidate MCP security proxy against a corpus of attack fixtures with matched benign controls, and scores its coverage using the crosswalk as a rubric. Each tool is driven through its real code, not a mock. We evaluate three open-source proxies (mcp-bastion, mcp-firewall, pipelock) plus a null baseline over 33 test cases. The strongest proxy reaches 38% weighted coverage (15 of 24 vectors) — a proxy's realistic ceiling — and even the union of all three tools leaves 9 of 24 vectors covered by none: the entire registry/supply-chain surface, OS-isolation-dependent vectors, and several semantic vectors. All results carry zero false positives against matched benign controls. We argue this is direct, quantified evidence that a runtime proxy alone is insufficient and that defense-in-depth spanning distinct mechanism classes (proxy, cryptographic attestation, OS isolation) is required. We also report methodological findings observed first-hand: benchmark scores are sensitive to how attack fixtures are encoded (a fairness hazard); an evasion-robustness dimension shows the tools resist different obfuscations (zero-width, homoglyph, base64) with no single tool surviving all; the benchmark tracks newly-published attacks as a living instrument — two June-2026 attacks (mid-session tool injection and multi-tool split poisoning / ShareLock) were added as vectors 23–24, one covered by no measured tool until a cross-tool-correlation check was added; and the benchmark can guide a defender's development — over the study, mcp-bastion's coverage rose from 9% to 38% as gaps it surfaced were fixed and re-verified. We further separate the tool classes we score (content-scanning proxies) from access-control/isolation gateways we track but do not score, to avoid misleading numbers. A matched benign-control design and a "measure only what the tool inspects at runtime" integrity rule keep the results honest.

## Keywords

Model Context Protocol; MCP; AI security; LLM agents; agentic AI; security benchmark; tool poisoning; prompt injection; mid-session tool injection; split poisoning; NIST AI RMF; NSA MCP Security; OWASP LLM Top 10; OWASP Agentic Top 10; defense-in-depth

## Subject / category

- Primary: Computer Science — Security and Privacy (arXiv: cs.CR or cs.AI)
- Secondary: Artificial Intelligence (arXiv: cs.AI)

## License

CC BY 4.0 (Creative Commons Attribution)

## Statements (if asked)

- **Funding:** None.
- **Conflicts of interest:** The author develops one of the evaluated tools (mcp-bastion); the benchmark is vendor-neutral, driven through each tool's real code, and the author's tool is scored alongside competitors and a null baseline. Disclosed for transparency.
- **Ethics / responsible disclosure:** All attack fixtures are synthetic static data using reserved, non-routable hosts; no live exploits and no real systems are attacked.
- **Prior/related posting:** The benchmark artifact is archived on Zenodo, DOI 10.5281/zenodo.21346206 (software/data archive). Disclose this if asked whether the work has appeared elsewhere.
- **Status:** Preprint, not peer-reviewed.
