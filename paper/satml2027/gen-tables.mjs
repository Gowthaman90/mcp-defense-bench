#!/usr/bin/env node
/**
 * Generate every number and table in the manuscript from results/ — nothing is typed by hand.
 * Emits paper/satml2027/generated/{numbers.tex,tab-*.tex}. Run before compiling.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const gen = join(here, "generated");
mkdirSync(gen, { recursive: true });
const J = (p) => JSON.parse(readFileSync(join(root, p), "utf8"));
const rubric = J("rubric/crosswalk.json");
const TOOLS = [["mcp-bastion", "OurProxy", "runtime proxy"], ["mcp-firewall", "mcp-firewall", "runtime proxy"], ["pipelock", "pipelock", "egress firewall"], ["null-baseline", "null baseline", "control"]];
const ANON = process.argv.includes("--anon");
const name = (t) => (ANON ? t[1] : t[0] === "mcp-bastion" ? "mcp-bastion" : t[1]);
const latest = rubric._specRevisions.latest;
const isNew = (v) => Array.isArray(v.appliesTo) && v.appliesTo.length === 1 && v.appliesTo[0] === latest;
const orig = rubric.vectors.filter((v) => !isNew(v)).map((v) => v.id);
const neu = rubric.vectors.filter(isNew).map((v) => v.id);
const all = rubric.vectors.map((v) => v.id);
const R = (cov, id) => cov?.[id]?.robustCoverage ?? 0;
const sum = (cov, ids) => ids.reduce((a, id) => a + R(cov, id), 0);
const pct = (x, n) => `${Math.round((x / n) * 100)}\\%`;
const f1 = (x) => x.toFixed(1);
const esc = (s) => s.replace(/&/g, "\\&").replace(/%/g, "\\%").replace(/_/g, "\\_");

const data = TOOLS.map(([id, label, cls]) => {
  const dev = J(`results/${id}.json`), ho = J(`results/heldout/${id}.json`), be = J(`results/benign/${id}.json`).summary;
  const cov = J(`adapters/${id}/coverage.json`).coverage;
  return { id, label: name([id, label]), cls, dev, ho, be, cov };
});
const nums = [];
const N = (k, v) => nums.push(`\\newcommand{\\${k}}{${v}}`);
const B = data[0];
N("nVectors", all.length); N("nOrig", orig.length); N("nNew", neu.length); N("nDev", B.dev.summary.casesRun); N("nHeldout", B.ho.summary.casesRun); N("nBenign", B.be.items);
const harvested = B.be.byKind["tool-definition"].n; N("nHarvested", harvested); N("nHardNeg", B.be.items - harvested);
N("bastDevAll", pct(sum(B.cov, all), all.length)); N("bastDevAllFrac", `${f1(sum(B.cov, all))}/${all.length}`);
N("bastDevOrig", pct(sum(B.cov, orig), orig.length)); N("bastDevOrigFrac", `${f1(sum(B.cov, orig))}/${orig.length}`);
N("bastHeldout", pct(sum(B.ho.coverage, orig), orig.length)); N("bastHeldoutFrac", `${f1(sum(B.ho.coverage, orig))}/${orig.length}`);
N("bastGap", Math.round(((sum(B.cov, orig) - sum(B.ho.coverage, orig)) / orig.length) * 100));
N("bastNew", pct(sum(B.cov, neu), neu.length)); N("bastNewFrac", `${f1(sum(B.cov, neu))}/${neu.length}`);
N("bastCapAll", pct(B.dev.summary.capability, all.length));
N("bastEnf", B.dev.summary.covered.enforce); N("bastDet", B.dev.summary.covered.detect); N("bastNone", B.dev.summary.covered.none);
N("bastBenignFP", `${B.be.falsePositives}/${B.be.items}`); N("bastBenignRate", `${(B.be.fpRate * 100).toFixed(1)}\\%`); N("bastBenignCI", `${(B.be.fpRate95ci.lo * 100).toFixed(1)}--${(B.be.fpRate95ci.hi * 100).toFixed(1)}\\%`);
N("bastBenignDefChange", `${B.be.byKind["definition-change"].fp}/${B.be.byKind["definition-change"].n}`);
N("bastBenignHarvestedFP", `${B.be.byKind["tool-definition"].fp}/${B.be.byKind["tool-definition"].n}`);
const FW = data[1], PL = data[2];
N("fwDevOrig", pct(sum(FW.cov, orig), orig.length)); N("fwHeldout", pct(sum(FW.ho.coverage, orig), orig.length)); N("fwBenignFP", `${FW.be.falsePositives}/${FW.be.items}`); N("fwBenignRate", `${(FW.be.fpRate * 100).toFixed(1)}\\%`);
N("plDevOrig", pct(sum(PL.cov, orig), orig.length)); N("plHeldout", pct(sum(PL.ho.coverage, orig), orig.length)); N("plBenignFP", `${PL.be.falsePositives}/${PL.be.items}`); N("plBenignRate", `${(PL.be.fpRate * 100).toFixed(1)}\\%`);
const anyCovers = (id) => data.some((d) => ["detect", "enforce"].includes(d.cov[id]?.level));
N("nCoveredAny", all.filter(anyCovers).length); N("nCoveredNone", all.filter((id) => !anyCovers(id)).length);
N("nCoveredNoneOrig", orig.filter((id) => !anyCovers(id)).length);
// held-out vectors bastion lost entirely
const lost = orig.filter((id) => R(B.cov, id) > 0 && R(B.ho.coverage, id) === 0);
N("bastLostVectors", lost.length);
// agreement numbers (parse docs/AGREEMENT.md table)
const ag = readFileSync(join(root, "docs", "AGREEMENT.md"), "utf8");
const row = (dim) => ag.split("\n").find((l) => l.startsWith(`| ${dim} |`))?.split("|").map((x) => x.trim());
const layer = row("mcpLayer"), stride = row("stride");
N("kappaLayer", layer[2]); N("kappaStride", stride[2]);
const jacs = ["mcpLayer", "stride", "nistAiRmf", "owaspLlm2025", "owaspAgentic2026", "nsaGuidance"].map((d) => Number(row(d)[3]));
N("jacMin", Math.min(...jacs).toFixed(2)); N("jacMax", Math.max(...jacs).toFixed(2));
N("nDisagree", (ag.match(/Disagreements for adjudication \((\d+)\)/) ?? [0, "?"])[1]);
writeFileSync(join(gen, "numbers.tex"), nums.join("\n") + "\n");

// Table: headline
let T = ["\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule", `Tool & Class & Dev (${orig.length}) & Held-out (${orig.length}) & Gap & ${latest}-only (${neu.length}) & Benign FP (n=${B.be.items}) \\\\`, "\\midrule"];
for (const d of data) {
  const dv = sum(d.cov, orig), hv = sum(d.ho.coverage, orig), nv = sum(d.cov, neu);
  T.push(`${esc(d.label)} & ${d.cls} & ${pct(dv, orig.length)} & ${pct(hv, orig.length)} & ${Math.round(((dv - hv) / orig.length) * 100)} & ${pct(nv, neu.length)} & ${d.be.falsePositives} (${(d.be.fpRate * 100).toFixed(1)}\\%) \\\\`);
}
T.push("\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-headline.tex"), T.join("\n") + "\n");

// Table: per-vector matrix dev→heldout for bastion + firewall + pipelock (original 24), plus new 8 dev only
const g = (lvl) => (lvl === "enforce" ? "E" : lvl === "detect" ? "D" : "--");
const cell = (d, id, ho = false) => { const c = ho ? d.ho.coverage[id] : d.cov[id]; return c?.verified ? `${g(c.level)}\\,${Math.round((c.robustCoverage ?? 0) * 100)}` : "n/a"; };
T = ["\\begin{tabular}{@{}rl ccc ccc@{}}", "\\toprule", ` & & \\multicolumn{3}{c}{${esc(data[0].label)}} & \\multicolumn{3}{c}{mcp-firewall / pipelock} \\\\`, "\\# & Vector & dev & held-out & $\\Delta$ & fw dev & fw h-o & pl dev / h-o \\\\", "\\midrule"];
rubric.vectors.forEach((v, i) => {
  const b = data[0], fw = data[1], pl = data[2];
  if (isNew(v)) { T.push(`${i + 1} & ${esc(v.name)}$^{\\dagger}$ & ${cell(b, v.id)} & \\multicolumn{1}{c}{--} & -- & ${cell(fw, v.id)} & -- & ${cell(pl, v.id)} / -- \\\\`); return; }
  const delta = Math.round((R(b.ho.coverage, v.id) - R(b.cov, v.id)) * 100);
  T.push(`${i + 1} & ${esc(v.name)} & ${cell(b, v.id)} & ${cell(b, v.id, true)} & ${delta === 0 ? "0" : (delta > 0 ? "+" : "") + delta} & ${cell(fw, v.id)} & ${cell(fw, v.id, true)} & ${cell(pl, v.id)} / ${cell(pl, v.id, true)} \\\\`);
});
T.push("\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-matrix.tex"), T.join("\n") + "\n");

// Table: benign FP by kind (bastion + firewall + pipelock)
const kinds = Object.keys(B.be.byKind).sort((a, b) => B.be.byKind[b].n - B.be.byKind[a].n);
T = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", `Input kind & n & ${esc(data[0].label)} & mcp-firewall & pipelock \\\\`, "\\midrule"];
for (const k of kinds) T.push(`${esc(k)} & ${B.be.byKind[k].n} & ${B.be.byKind[k].fp} & ${FW.be.byKind[k]?.fp ?? 0} & ${PL.be.byKind[k]?.fp ?? 0} \\\\`);
T.push("\\midrule", `Total & ${B.be.items} & ${B.be.falsePositives} (${(B.be.fpRate * 100).toFixed(1)}\\%, CI ${(B.be.fpRate95ci.lo * 100).toFixed(1)}--${(B.be.fpRate95ci.hi * 100).toFixed(1)}) & ${FW.be.falsePositives} (${(FW.be.fpRate * 100).toFixed(1)}\\%) & ${PL.be.falsePositives} (${(PL.be.fpRate * 100).toFixed(1)}\\%) \\\\`, "\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-benign.tex"), T.join("\n") + "\n");

// Table: agreement
T = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", "Dimension & Primary $\\kappa$ & Mean Jaccard & Pooled $\\kappa$ & Exact \\\\", "\\midrule"];
for (const d of ["mcpLayer", "stride", "nistAiRmf", "owaspLlm2025", "owaspAgentic2026", "nsaGuidance"]) { const r = row(d); T.push(`${esc(d)} & ${r[2]} & ${r[3]} & ${r[4]} & ${r[5]} \\\\`); }
T.push("\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-agreement.tex"), T.join("\n") + "\n");

// Table: new vectors
T = ["\\begin{tabular}{@{}rp{4.2cm}p{1.9cm}p{4.6cm}@{}}", "\\toprule", "\\# & Vector & Layer & Also known as \\\\", "\\midrule"];
rubric.vectors.filter(isNew).forEach((v) => T.push(`${all.indexOf(v.id) + 1} & ${esc(v.name)} & ${v.mcpLayer[0]} & ${esc((v.aliases ?? []).slice(0, 2).join("; "))} \\\\`));
T.push("\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-new.tex"), T.join("\n") + "\n");
// Table: coverage per EU AI Act obligation and ISO/IEC 42001 control (reference proxy), from bin/score.mjs.
const score = JSON.parse(spawnSync(process.execPath, [join(root, "bin", "score.mjs"), join(root, "adapters", "mcp-bastion", "coverage.json")], { encoding: "utf8" }).stdout.replace(/^[^{]*/, ""));
const legendEU = rubric._frameworks.euAiAct ?? {}, legendISO = rubric._frameworks.iso42001 ?? {};
const short = (t) => esc(String(t).split(" — ")[0].split(" (")[0]);
T = ["\\begin{tabular}{@{}llr@{}}", "\\toprule", "Framework & Obligation / control & \\proxy{} coverage \\\\", "\\midrule"];
for (const [k, v] of Object.entries(score.byEuAiAct ?? {}).sort()) T.push(`EU AI Act & ${esc(k)} ${short(legendEU[k] ?? "")} & ${esc(v)} \\\\`);
T.push("\\midrule");
for (const [k, v] of Object.entries(score.byIso42001 ?? {}).sort()) T.push(`ISO/IEC 42001 & ${esc(k)} ${short(legendISO[k] ?? "")} & ${esc(v)} \\\\`);
T.push("\\bottomrule", "\\end{tabular}");
writeFileSync(join(gen, "tab-frameworks.tex"), T.join("\n") + "\n");
// Historical: the reference proxy's coverage of the 2026-07-28-only vectors BEFORE its SDK-2.0 rebuild
// (v0.9.0, measured at mcp-defense-bench v0.7.0, commit 2771b2a): 3.5/8.
N("bastNewPrev", "44\\%"); N("bastNewPrevFrac", "3.5/8");
writeFileSync(join(gen, "numbers.tex"), nums.join("\n") + "\n");
console.log("generated:", nums.length, "numbers; tables: headline, matrix, benign, agreement, new, frameworks. anon =", ANON);
