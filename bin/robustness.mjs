#!/usr/bin/env node
/**
 * Evasion-robustness report: for every evasion-tagged test case (obfuscated variants of an attack),
 * show which tools still detected it. Reveals whether a tool's detection is robust to encoding tricks
 * (zero-width/bidi, homoglyphs, base64) or brittle. Reads results/<tool>.json produced by bin/run.mjs.
 *
 * Usage: node bin/robustness.mjs
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

// Collect evasion-tagged test cases.
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
if (!evasion.length) {
  console.log("No evasion-tagged test cases found.");
  process.exit(0);
}

// Load each measured tool's per-case results.
const tools = [];
for (const d of readdirSync(join(root, "adapters"))) {
  const rp = join(root, "results", `${d}.json`);
  if (!existsSync(rp)) continue;
  const r = JSON.parse(readFileSync(rp, "utf8"));
  const byId = Object.fromEntries((r.cases || []).map((c) => [c.id, c]));
  tools.push({ tool: r.summary?.tool || d, byId });
}
tools.sort((a, b) => a.tool.localeCompare(b.tool));

// A case absent from a tool's results was not run for it (adapter not wired for that fixture type).
const glyph = (c) => (!c ? "?" : c.level === "enforce" ? "🟢" : c.level === "detect" ? "🟡" : "·");

console.log("# Evasion-robustness report\n");
console.log(`${evasion.length} evasion fixtures · ${tools.length} tools measured\n`);
console.log(`| Attack (encoding) | ${tools.map((t) => t.tool).join(" | ")} |`);
console.log(`|---|${tools.map(() => "--").join("|")}|`);
for (const e of evasion) {
  const cells = tools.map((t) => glyph(t.byId[e.id]));
  console.log(`| ${e.vector} — *${e.encoding}* | ${cells.join(" | ")} |`);
}

// Per-tool robustness ratio.
console.log("\n**Robustness (evasion fixtures detected):**");
for (const t of tools) {
  const run = evasion.filter((e) => t.byId[e.id]);
  const caught = run.filter((e) => t.byId[e.id].level !== "none").length;
  console.log(`- ${t.tool}: ${run.length ? `${caught}/${run.length}` : "not wired for these fixtures"}`);
}
console.log("\n🟢 enforce · 🟡 detect · · missed · ? not wired");
