#!/usr/bin/env node
/**
 * Build the public leaderboard page (docs/index.html) for GitHub Pages.
 *
 * Reads the rubric + each measured adapter's coverage.json + per-case results, and bakes a
 * self-contained, theme-aware static page (no external assets — works offline and on GitHub Pages).
 * Re-run after any benchmark change: node bin/build-site.mjs
 */
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const rubric = JSON.parse(readFileSync(join(root, "rubric", "crosswalk.json"), "utf8"));
const WEIGHT = { enforce: 1, detect: 0.5, none: 0, unknown: 0 };

// --- gather measured tools ---
const tools = [];
for (const d of readdirSync(join(root, "adapters"))) {
  const cp = join(root, "adapters", d, "coverage.json");
  if (!existsSync(cp)) continue;
  const c = JSON.parse(readFileSync(cp, "utf8"));
  if (!c.measuredBy) continue;
  let fp = 0, cases = 0;
  const rp = join(root, "results", `${d}.json`);
  const byId = {};
  if (existsSync(rp)) {
    const r = JSON.parse(readFileSync(rp, "utf8"));
    fp = r.summary?.falsePositives ?? 0;
    cases = r.summary?.casesRun ?? 0;
    for (const pc of r.cases || []) byId[pc.id] = pc.level;
  }
  tools.push({ id: d, tool: c.tool, class: c.class || "?", coverage: c.coverage || {}, fp, cases, byId });
}
tools.sort((a, b) => weighted(b) - weighted(a));
function lvl(t, id) { return t.coverage[id]?.level ?? "unknown"; }
function weighted(t) { return rubric.vectors.reduce((a, v) => a + (WEIGHT[lvl(t, v.id)] ?? 0), 0); }

// --- evasion fixtures for the robustness table ---
const evasion = [];
const tcDir = join(root, "testcases");
for (const vec of readdirSync(tcDir)) {
  const p = join(tcDir, vec);
  if (!statSync(p).isDirectory() || vec.startsWith("_")) continue;
  for (const f of readdirSync(p).filter((x) => x.endsWith(".json"))) {
    const doc = JSON.parse(readFileSync(join(p, f), "utf8"));
    if (doc.evasion) evasion.push({ id: doc.id, encoding: doc.evasion, vector: doc.vector });
  }
}

const N = rubric.vectors.length;
const anyCovers = (id) => tools.some((t) => ["enforce", "detect"].includes(lvl(t, id)));
const coveredAny = rubric.vectors.filter((v) => anyCovers(v.id)).length;
const totalCases = tools.reduce((m, t) => Math.max(m, t.cases), 0);
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const pct = (t) => Math.round((weighted(t) / N) * 100);
const cell = (level) => `<td class="c ${level}" title="${level}">${{ enforce: "●", detect: "◐", none: "", unknown: "?" }[level] || ""}</td>`;

// --- render ---
const rows = tools
  .map((t) => {
    const n = { enforce: 0, detect: 0, none: 0, unknown: 0 };
    for (const v of rubric.vectors) n[lvl(t, v.id)]++;
    return `<tr><td class="tool">${esc(t.tool)}</td><td class="cls">${esc(t.class)}</td>
      <td class="num"><b>${pct(t)}%</b> <span class="muted">(${weighted(t).toFixed(1)}/${N})</span></td>
      <td class="num en">${n.enforce}</td><td class="num de">${n.detect}</td><td class="num">${n.none}</td>
      <td class="num">${t.fp} / ${t.cases}</td></tr>`;
  })
  .join("\n");

const matrixHead = tools.map((t) => `<th class="rot"><span>${esc(t.tool)}</span></th>`).join("");
const matrixRows = rubric.vectors
  .map((v) => `<tr><td class="vec">${esc(v.name)}</td><td class="layer">${esc(v.mcpLayer[0])}</td>${tools.map((t) => cell(lvl(t, v.id))).join("")}</tr>`)
  .join("\n");

const evHead = tools.map((t) => `<th class="rot"><span>${esc(t.tool)}</span></th>`).join("");
const evRows = evasion
  .map((e) => `<tr><td class="vec">${esc(e.vector)}</td><td class="layer">${esc(e.encoding)}</td>${tools.map((t) => cell(t.byId[e.id] ?? "unknown")).join("")}</tr>`)
  .join("\n");
const robust = tools.map((t) => `${esc(t.tool)} ${evasion.filter((e) => (t.byId[e.id] ?? "none") !== "none").length}/${evasion.length}`).join(" · ");

// Framework mapping: every vector -> STRIDE / NIST AI RMF / OWASP LLM 2025 / OWASP Agentic 2026.
const fwRows = rubric.vectors
  .map((v) => `<tr><td class="vec">${esc(v.name)}</td><td class="layer">${esc(v.mcpLayer[0])}</td><td class="layer">${esc(v.stride.join("/"))}</td><td>${esc(v.nistAiRmf.join(", "))}</td><td>${esc((v.owaspLlm2025 || []).join(", "))}</td><td>${esc((v.owaspAgentic2026 || []).join(", "))}</td><td>${esc((v.nsaGuidance || []).join(", "))}</td></tr>`)
  .join("\n");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Defense-Coverage Leaderboard</title>
<meta name="description" content="A vendor-neutral benchmark scoring MCP security proxies on attack-surface coverage, crosswalked to NIST AI RMF and OWASP.">
<style>
  :root{
    --bg:#f4f6f9;--paper:#fff;--ink:#151a22;--muted:#5a6473;--faint:#8a94a4;--border:#e3e8ef;--line:#cdd5e0;
    --accent:#0d6e78;--accent-ink:#0a565f;
    --enforce:#1f9d57;--enforce-bg:#e3f4ea;--detect:#c98a1a;--detect-bg:#faf1dc;--none-bg:#f0f2f5;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --serif:"Charter","Iowan Old Style","Palatino Linotype",Georgia,serif;
  }
  @media (prefers-color-scheme:dark){:root{
    --bg:#0c0f14;--paper:#141a22;--ink:#e7ebf1;--muted:#9aa5b5;--faint:#6b7688;--border:#232b36;--line:#313b48;
    --accent:#3bb7c4;--accent-ink:#6fd4de;
    --enforce:#4cc47e;--enforce-bg:#15321f;--detect:#d8b25a;--detect-bg:#332a12;--none-bg:#1a2029;
  }}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1000px;margin:0 auto;padding:44px 24px 72px}
  .eyebrow{font-family:var(--mono);font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent-ink);margin:0 0 12px}
  h1{font-family:var(--serif);font-size:clamp(26px,4vw,38px);line-height:1.12;margin:0 0 12px;letter-spacing:-.01em;text-wrap:balance}
  .lede{font-family:var(--serif);font-size:clamp(15px,2vw,18px);color:var(--muted);margin:0 0 20px;max-width:64ch}
  .meta{display:flex;flex-wrap:wrap;gap:8px 16px;font-family:var(--mono);font-size:12px;color:var(--faint);padding:14px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
  .meta a{color:var(--accent-ink);text-decoration:none}
  .meta a:hover{text-decoration:underline}
  h2{font-family:var(--mono);font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin:40px 0 14px}
  .card{background:var(--paper);border:1px solid var(--border);border-radius:12px;overflow:hidden}
  .scroll{overflow-x:auto}
  table{border-collapse:collapse;width:100%;font-size:13.5px}
  th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
  thead th{font-family:var(--mono);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--faint);font-weight:600}
  tbody tr:last-child td{border-bottom:none}
  .tool{font-weight:600}.cls{color:var(--muted);font-family:var(--mono);font-size:11.5px}
  .num{text-align:right;font-variant-numeric:tabular-nums}.muted{color:var(--faint)}
  .en{color:var(--enforce);font-weight:600}.de{color:var(--detect);font-weight:600}
  /* matrix */
  .mx td.vec{white-space:normal;min-width:180px}
  .mx td.layer{color:var(--muted);font-family:var(--mono);font-size:11px}
  .mx th.rot{text-align:center;font-weight:600;color:var(--ink);font-family:var(--sans);text-transform:none;letter-spacing:0}
  td.c{text-align:center;font-size:15px;width:64px}
  td.c.enforce{background:var(--enforce-bg);color:var(--enforce)}
  td.c.detect{background:var(--detect-bg);color:var(--detect)}
  td.c.none,td.c.unknown{background:var(--none-bg);color:var(--faint)}
  .legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--muted);margin:12px 2px 0}
  .sw{display:inline-block;width:12px;height:12px;border-radius:3px;vertical-align:-1px;margin-right:5px}
  .stat{display:flex;gap:22px;flex-wrap:wrap;margin:6px 2px}
  .stat b{font-size:22px;font-family:var(--serif)}
  .note{font-size:12.5px;color:var(--faint);line-height:1.6;margin-top:14px}
  .note b{color:var(--muted)}
  footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);font-size:11.5px;color:var(--faint)}
  @media(max-width:640px){td.c{width:auto}}
</style>
</head>
<body>
<div class="wrap">
  <p class="eyebrow">MCP Security · Defense-Coverage Benchmark</p>
  <h1>How much of the MCP attack surface does each security proxy actually cover?</h1>
  <p class="lede">A vendor-neutral benchmark. Each tool is driven through its <em>real</em> code against ${N} MCP attack vectors, crosswalked to the NIST AI RMF and the OWASP LLM &amp; Agentic Top 10. Results are measured, with matched benign controls — not self-reported.</p>
  <div class="meta">
    <span>Corpus: ${totalCases} cases</span>
    <span>Vectors: ${N}</span>
    <span>Covered by ≥ 1 tool: ${coveredAny}/${N}</span>
    <span><a href="https://github.com/Gowthaman90/mcp-defense-bench">Repository</a></span>
    <span><a href="https://doi.org/10.5281/zenodo.21346206">Zenodo DOI</a></span>
    <span><a href="https://doi.org/10.6084/m9.figshare.32978657">Preprint</a></span>
  </div>

  <h2>Coverage of the full attack surface</h2>
  <div class="card scroll"><table>
    <thead><tr><th>Tool</th><th>Class</th><th class="num">Weighted coverage</th><th class="num">● enforce</th><th class="num">◐ detect</th><th class="num">none</th><th class="num">False pos.</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>
  <p class="note"><b>Weighting:</b> enforce = 1.0, detect = 0.5, none = 0, over ${N} vectors. A vector counts only if the tool flags the attack <em>and</em> stays clean on the matched benign control (else it's a false positive). Zero false positives across all tools.</p>

  <h2>Per-vector coverage matrix</h2>
  <div class="card scroll"><table class="mx">
    <thead><tr><th>Vector</th><th>Layer</th>${matrixHead}</tr></thead>
    <tbody>${matrixRows}</tbody>
  </table></div>
  <div class="legend">
    <span><span class="sw" style="background:var(--enforce-bg);border:1px solid var(--enforce)"></span>● enforce (blocks)</span>
    <span><span class="sw" style="background:var(--detect-bg);border:1px solid var(--detect)"></span>◐ detect (warns)</span>
    <span><span class="sw" style="background:var(--none-bg);border:1px solid var(--line)"></span>not covered</span>
  </div>
  <p class="note"><b>Defense-in-depth:</b> the tools cover different layers; <b>${coveredAny} of ${N}</b> vectors are covered by at least one tool and <b>${N - coveredAny}</b> by none (registry/supply-chain, OS-isolation, and semantic vectors that lie outside a runtime proxy's reach). No single proxy is sufficient.</p>

  ${evasion.length ? `<h2>Evasion robustness</h2>
  <div class="card scroll"><table class="mx">
    <thead><tr><th>Attack</th><th>Encoding</th>${evHead}</tr></thead>
    <tbody>${evRows}</tbody>
  </table></div>
  <p class="note"><b>Robustness (evasion fixtures detected):</b> ${robust}. The tools are robust to <em>different</em> obfuscations — no single tool survives all of them.</p>` : ""}

  <h2>Framework mapping</h2>
  <p class="note">Every attack vector is crosswalked to the frameworks security and compliance teams govern by. NIST AI RMF is a U.S. federal framework (NIST, Dept. of Commerce); OWASP is an international open standard; STRIDE is the classic threat-modeling taxonomy.</p>
  <div class="card scroll"><table class="mx">
    <thead><tr><th>Vector</th><th>Layer</th><th>STRIDE</th><th>NIST AI RMF</th><th>OWASP LLM 2025</th><th>OWASP Agentic 2026</th><th>NSA guidance</th></tr></thead>
    <tbody>${fwRows}</tbody>
  </table></div>
  <p class="note"><b>NIST AI RMF:</b> GOVERN · MAP · MEASURE · MANAGE. <b>OWASP LLM:</b> LLM01 Prompt Injection · LLM02 Sensitive Info Disclosure · LLM03 Supply Chain · LLM04 Data/Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector/Embedding. <b>OWASP Agentic:</b> ASI01 Agent Goal Hijack · ASI02 Tool Misuse · ASI03 Identity &amp; Privilege Abuse · ASI04 Agentic Supply Chain. <b>NSA guidance (May 2026):</b> AUTH Authentication &amp; Access Control · LOG Monitoring &amp; Logging · SEG Data Classification &amp; Segmentation · RT Runtime Controls.</p>

  <h2>References</h2>
  <p class="note"><b>Frameworks:</b>
    <a href="https://www.nist.gov/itl/ai-risk-management-framework">NIST AI RMF 1.0</a> (U.S. federal) ·
    <a href="https://genai.owasp.org/llm-top-10/">OWASP Top 10 for LLM Apps (2025)</a> ·
    <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/">OWASP Top 10 for Agentic Apps (2026)</a> ·
    <a href="https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats">STRIDE</a> ·
    <a href="https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf">NSA MCP Security CSI</a> (U.S. federal — NSA AI Security Center, May 2026).<br>
    <b>MCP security research:</b>
    <a href="https://arxiv.org/abs/2512.08290">SoK 2512.08290</a> ·
    <a href="https://arxiv.org/abs/2604.05969">Formal framework 2604.05969</a> ·
    <a href="https://arxiv.org/abs/2603.22489">STRIDE/DREAD 2603.22489</a> ·
    <a href="https://arxiv.org/abs/2604.07551">MCP-DPT 2604.07551</a> ·
    <a href="https://arxiv.org/abs/2510.15994">MSB 2510.15994</a> ·
    <a href="https://arxiv.org/abs/2508.14925">MCPTox 2508.14925</a> ·
    <a href="https://arxiv.org/abs/2506.01333">ETDI 2506.01333</a> ·
    <a href="https://doi.org/10.3390/fi18050243">Trustworthy MCP Registry</a> ·
    <a href="https://arxiv.org/abs/2606.06387">WebMCP/MSTI 2606.06387</a> ·
    <a href="https://arxiv.org/abs/2606.27027">ShareLock 2606.27027</a>.<br>
    <b>MCP protocol:</b>
    <a href="https://modelcontextprotocol.io/specification">Specification</a> ·
    <a href="https://modelcontextprotocol.io/registry/about">Registry</a>.
  </p>

  <h2>Method &amp; honesty</h2>
  <p class="note">
    Each adapter drives the tool's actual detection code or CLI — never a mock. A defender is scored only on what it inspects at runtime (a proxy that ignores tool results scores <em>none</em> there, even if its rules would match the text in isolation). Absolute totals are corpus-dependent; the per-vector matrix is the more reliable read. Scored tools run locally and deterministically; cloud-model tools are observed, not scored. Full methodology, prior-art positioning, and the whitepaper are in the <a href="https://github.com/Gowthaman90/mcp-defense-bench">repository</a>.
  </p>

  <footer>
    mcp-defense-bench — data CC-BY-4.0, harness Apache-2.0. Cite: Arumugam, G. (2026), DOI
    <a href="https://doi.org/10.5281/zenodo.21346206">10.5281/zenodo.21346206</a>.
    Generated from measured results; re-run <code>bin/build-site.mjs</code> to refresh.
  </footer>
</div>
</body>
</html>
`;

writeFileSync(join(root, "docs", "index.html"), html);
console.log(`✓ wrote docs/index.html (${tools.length} tools, ${N} vectors, ${evasion.length} evasion fixtures)`);
