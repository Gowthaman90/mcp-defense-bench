#!/usr/bin/env node
/** Generate docs/CROSSWALK.md (human-readable) from ../rubric/crosswalk.json. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const c = JSON.parse(readFileSync(join(here, "..", "rubric", "crosswalk.json"), "utf8"));
const j = (a) => (Array.isArray(a) ? a.join(", ") : a);
const L = [];
L.push(`# ${c.artifact} — v${c.version}`, "");
L.push(`_Generated from \`rubric/crosswalk.json\` on ${c.date}. Edit the JSON, not this file._`, "");
L.push(c.description, "", `**${c.vectors.length} vectors** · **${c.license}**`, "");
L.push("| # | Vector | Layer | STRIDE | NIST AI RMF | OWASP LLM 2025 | OWASP Agentic 2026 | NSA (May 2026) | EU AI Act | ISO/IEC 42001 | Applies to | Prior-art benchmarks |");
L.push("|---|---|---|---|---|---|---|---|---|---|---|---|");
c.vectors.forEach((v, i) =>
  L.push(`| ${i + 1} | **${v.name}** | ${j(v.mcpLayer)} | ${j(v.stride)} | ${j(v.nistAiRmf)} | ${j(v.owaspLlm2025)} | ${j(v.owaspAgentic2026)} | ${j(v.nsaGuidance)} | ${j(v.euAiAct ?? [])} | ${j(v.iso42001 ?? [])} | ${Array.isArray(v.appliesTo) && v.appliesTo.length === 1 ? v.appliesTo[0] : "all"} | ${v.priorArtCoverage.length ? j(v.priorArtCoverage) : "—"} |`),
);
L.push("", "## Framework legends", "");
for (const [fw, legend] of Object.entries(c._frameworks)) {
  if (!legend || typeof legend !== "object" || Array.isArray(legend)) continue;
  L.push(`### ${fw}`, "");
  if (legend._scope) L.push(`_${legend._scope}_`, "");
  for (const [k, t] of Object.entries(legend)) if (k !== "_scope") L.push(`- **${k}** — ${t}`);
  L.push("");
}
L.push("_Mappings are indicative and reviewable, not a certification. Layer/STRIDE/NIST/OWASP/NSA columns have a blind second-rater pass (`docs/AGREEMENT.md`); the EU AI Act and ISO/IEC 42001 columns are single-rater as of v0.8.0 (decision rules in `rubric/RATING-CODEBOOK.md`). See `docs/PRIOR-ART.md`._");
process.stdout.write(L.join("\n") + "\n");
