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
L.push("| # | Vector | Layer | STRIDE | NIST AI RMF | OWASP LLM 2025 | OWASP Agentic 2026 | Prior-art benchmarks |");
L.push("|---|---|---|---|---|---|---|---|");
c.vectors.forEach((v, i) =>
  L.push(`| ${i + 1} | **${v.name}** | ${j(v.mcpLayer)} | ${j(v.stride)} | ${j(v.nistAiRmf)} | ${j(v.owaspLlm2025)} | ${j(v.owaspAgentic2026)} | ${v.priorArtCoverage.length ? j(v.priorArtCoverage) : "—"} |`),
);
L.push("", "_Mappings are indicative and reviewable, not a certification. See `docs/PRIOR-ART.md`._");
process.stdout.write(L.join("\n") + "\n");
