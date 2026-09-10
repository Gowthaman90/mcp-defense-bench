#!/usr/bin/env node
/**
 * Build a fully anonymised copy of this repository for double-blind artifact review, and REFUSE to
 * finish if any identity leak survives.
 *
 * Why this exists: the AISec 2026 submission was desk-rejected because the anonymised artifact
 * mirror still carried the author's name (CITATION.cff, README, .zenodo.json, package.json,
 * git history). Anonymity is a property of the *whole artifact*, not of the PDF.
 *
 * What it does:
 *   1. `git archive HEAD` into <out> (so no .git history travels — history is the leak most people
 *      forget; anonymous.4open.science and Zenodo both preserve it if you upload a clone).
 *   2. Deletes files that exist only to carry identity (CITATION.cff, .zenodo.json, LICENSE header
 *      lines are rewritten, .github/FUNDING, social/blog drafts, the NIW-facing docs).
 *   3. Rewrites identity strings and REAL TOOL NAMES to placeholders in every text file
 *      (the reference proxy → "OurProxy", this benchmark → "OurBench", GitHub handle, name,
 *      e-mail, DOIs, personal URLs).
 *   4. Scans the result with a leak grep; exits non-zero and lists hits if anything remains.
 *   5. Writes ANONYMIZATION-REPORT.md into the mirror listing every substitution made, so reviewers
 *      can see the artifact was scrubbed rather than fabricated.
 *
 * Usage: node scripts/make-anon-mirror.mjs <output-dir> [--extra "Regex"]...
 * Then upload <output-dir> (NOT the git repo) to anonymous.4open.science / Zenodo restricted.
 */
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, statSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const args = process.argv.slice(2);
const out = args.find((a) => !a.startsWith("--"));
if (!out) { console.error("usage: node scripts/make-anon-mirror.mjs <output-dir>"); process.exit(1); }
// --anon-url <base>: the real anonymous.4open.science base once it exists, so the mirror's internal links resolve.
const ANON_URL = (args.includes("--anon-url") ? args[args.indexOf("--anon-url") + 1] : "https://anonymous.4open.science/r/OurBench").replace(/\/$/, "");
const extra = args.flatMap((a, i) => (a === "--extra" ? [new RegExp(args[i + 1], "gi")] : []));

// ── identity → placeholder substitutions (ORDER MATTERS: longer / more specific first) ──────────
const SUBS = [
  [/https?:\/\/(www\.)?github\.com\/Gowthaman90\/mcp-defense-bench[^\s)"'`]*/gi, `${ANON_URL}`],
  [/https?:\/\/(www\.)?github\.com\/Gowthaman90\/mcp-bastion[^\s)"'`]*/gi, `${ANON_URL}/adapters/OurProxy`],
  [/https?:\/\/gowthaman90\.github\.io\/mcp-defense-bench\/?/gi, `${ANON_URL}/docs/`],
  [/https?:\/\/gowthaman90\.github\.io\/?/gi, `${ANON_URL}/docs/`],
  [/gowthaman90\.github\.io/gi, "anonymous.example"],
  [/10\.5281\/zenodo\.21346206/g, "10.5281/zenodo.XXXXXXX"],
  [/10\.6084\/m9\.figshare\.32978657/g, "10.6084/m9.figshare.XXXXXXXX"],
  [/io\.github\.Gowthaman90\/mcp-bastion/gi, "io.example.anon/OurProxy"],
  [/agowthaman90@gmail\.com/gi, "anonymous@example.org"],
  [/Gowthaman\s+Arumugam/g, "Anonymous Author"],
  [/Arumugam,\s*G(owthaman|\.)?/g, "Anonymous, A."],
  [/Gowthaman90/g, "anonymous-author"],
  [/Gowthaman/g, "Anonymous"],
  [/Arumugam/g, "Anonymous"],
  [/mcp-defense-bench/g, "OurBench"],
  [/mcp_defense_bench/g, "OurBench"],
  [/mcp-bastion/g, "OurProxy"],
  [/mcp_bastion/g, "OurProxy"],
  [/\bbastion\b/g, "ourproxy"],
  [/\bBastion\b/g, "OurProxy"],
  [/Massimiliano Brighindi|M\. Brighindi|Brighindi/g, "an independent reviewer"],
  // Affiliation-like bylines and venue history are de-anonymising wording under the SaTML CfP.
  [/\s*·\s*Independent Researcher/g, ""],
  [/Independent Researcher/g, "Anonymous affiliation"],
  [/AISec\s*(2026|'26)?/g, "a 2026 security workshop"],
  // Self-referential hints (prior preprint, public availability, social write-ups) are de-anonymising too.
  [/^> Preprint: .*$/gm, ""],
  [/<span><a href="https:\/\/doi\.org\/10\.6084\/m9\.figshare\.X+">Preprint<\/a><\/span>\s*/g, ""],
  [/one of two open-source artifacts/g, "one of two artifacts"],
  [/via LinkedIn on the "Measuring the\s+Defenders" write-up/g, "on a public write-up"],
  [/via LinkedIn/g, "in public"],
  // The mirror drops the review/checklist files; don't leave the README pointing at them.
  [/ — hence \[`scripts\/make-anon-mirror\.mjs`\]\([^)]*\) and\s*\[`paper\/SUBMISSION-CHECKLIST\.md`\]\([^)]*\)\. Verbatim reviews and responses:\s*\[`paper\/REVIEWS-AND-RESPONSE\.md`\]\([^)]*\)\./g, ". The reviews and the point-by-point response are appended to the paper."],
  [/Arun Sanna|A\. Sanna|arunsanna/g, "a peer-benchmark author"],
  ...extra.map((re) => [re, "[REDACTED]"]),
];
// Anything matching these after substitution is a leak.
const LEAKS = [/gowthaman/i, /arumugam/i, /agowthaman90/i, /zenodo\.21346206/, /figshare\.32978657/, /mcp-bastion/i, /mcp_bastion/i, /mcp-defense-bench/i, /brighindi/i, /Co-Authored-By/i, /Gowthaman90/];
// Files that exist to carry identity or are out of scope for review.
const DROP = ["CITATION.cff", ".zenodo.json", "paper/arxiv", "paper/SUBMISSION.md", "paper/whitepaper.md", "paper/whitepaper.tex", "paper/whitepaper.pdf", "docs/social-launch-kit.md", "docs/medium-benchmark-article.md", "docs/medium-measuring-defenders-63.md", "docs/devto-measuring-defenders-63.md", "paper/aisec2026", "paper/REVIEWS-AND-RESPONSE.md", "paper/SUBMISSION-CHECKLIST.md", "scripts/make-anon-mirror.mjs", ".github"];
const TEXT = /\.(md|json|mjs|js|ts|tex|bib|yaml|yml|txt|html|css|cff|toml|py|sh)$/i;
// Binaries cannot be scrubbed, so they never travel (the paper PDF goes through the submission system).
const BINARY = /\.(pdf|zip|tar\.gz|tgz|png|jpg|jpeg|gif|docx|pptx|xlsx)$/i;
// Path segments carrying identity are renamed with the same placeholders as text.
const PATH_SUBS = [[/mcp-defense-bench/gi, "OurBench"], [/mcp_defense_bench/gi, "OurBench"], [/mcp-bastion/gi, "OurProxy"], [/mcp_bastion/gi, "OurProxy"], [/gowthaman90/gi, "anonymous-author"]];

// 1. export HEAD (no history)
if (existsSync(out)) rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
execSync(`git -C "${root}" archive HEAD | tar -x -C "${out}"`, { stdio: "inherit" });

// 2. drop identity-only files
for (const d of DROP) if (existsSync(join(out, d))) rmSync(join(out, d), { recursive: true, force: true });
// harvested benign definitions carry `harvestedAt`/command lines but no author identity; keep.

// 3. rewrite text files
const report = new Map();
const walk = (dir) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) { if (f !== "node_modules" && f !== ".tools") walk(p); continue; }
    if (!TEXT.test(f)) continue;
    let s = readFileSync(p, "utf8"); const before = s;
    for (const [re, to] of SUBS) { const n = (s.match(re) ?? []).length; if (n) { report.set(String(re), (report.get(String(re)) ?? 0) + n); s = s.replace(re, to); } }
    if (s !== before) writeFileSync(p, s);
  }
};
walk(out);
// package.json author field
const pkgPath = join(out, "package.json");
if (existsSync(pkgPath)) { const pkg = JSON.parse(readFileSync(pkgPath, "utf8")); pkg.author = "Anonymous Author(s) <anonymous@example.org>"; pkg.name = "ourbench"; delete pkg.repository; delete pkg.homepage; delete pkg.bugs; writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n"); }

// 3b. drop binaries and rename identity-carrying paths (deepest first so parents rename cleanly)
import { renameSync } from "node:fs";
const paths = [];
const collect = (dir) => { for (const f of readdirSync(dir)) { const p = join(dir, f); paths.push(p); if (statSync(p).isDirectory()) collect(p); } };
collect(out);
for (const p of paths.slice().reverse()) {
  if (!existsSync(p)) continue;
  const base = p.slice(p.lastIndexOf("/") + 1);
  if (!statSync(p).isDirectory() && BINARY.test(base)) { rmSync(p); report.set("<binary dropped>", (report.get("<binary dropped>") ?? 0) + 1); continue; }
  let nb = base; for (const [re, to] of PATH_SUBS) nb = nb.replace(re, to);
  if (nb !== base) { renameSync(p, join(p.slice(0, p.lastIndexOf("/")), nb)); report.set("<path renamed>", (report.get("<path renamed>") ?? 0) + 1); }
}

// 4. leak scan (contents AND file names)
const hits = [];
const scan = (dir) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f); const rel = relative(out, p);
    for (const re of LEAKS) if (re.test(f)) hits.push(`${rel}: filename matches ${re}`);
    if (statSync(p).isDirectory()) { scan(p); continue; }
    if (!TEXT.test(f)) continue;
    const s = readFileSync(p, "utf8");
    s.split("\n").forEach((line, i) => { for (const re of LEAKS) if (re.test(line)) hits.push(`${rel}:${i + 1}: ${line.trim().slice(0, 100)}`); });
  }
};
scan(out);

// 5. report
// The report must not itself carry the identity strings it removed: describe each substitution by an
// opaque label and its category, never by the pattern source.
const CATEGORY = (k) => (/OurBench|OurProxy|bastion|defense-bench/i.test(k) ? "tool name → placeholder" : /github\.io|4open|anonymous\.example/i.test(k) ? "personal URL → placeholder" : /zenodo|figshare/i.test(k) ? "DOI → placeholder" : /@|example\.org/i.test(k) ? "e-mail → placeholder" : /binary|renamed/i.test(k) ? k : "author / contributor name → placeholder");
const lines = ["# Anonymization report", "", `Generated ${new Date().toISOString()} by the benchmark's anonymisation script from a \`git archive\` of the release commit (no history included). Patterns are described by category only; the identity strings themselves are deliberately not reproduced here.`, "", "| # | Category | Substitutions |", "|---|---|--:|", ...[...report.entries()].map(([k, v], i) => `| ${i + 1} | ${CATEGORY(k)} | ${v} |`), "", "Files removed because they exist only to carry identity: " + DROP.join(", "), "", hits.length ? `## ⚠️ ${hits.length} residual leak(s)\n\n` + hits.map((h) => "- " + h).join("\n") : "## Leak scan: clean"];
writeFileSync(join(out, "ANONYMIZATION-REPORT.md"), lines.join("\n") + "\n");
// The report is part of the artifact: it must pass the same scan.
readFileSync(join(out, "ANONYMIZATION-REPORT.md"), "utf8").split("\n").forEach((line, i) => { for (const re of LEAKS) if (re.test(line)) hits.push(`ANONYMIZATION-REPORT.md:${i + 1}: ${line.trim().slice(0, 100)}`); });
if (hits.length) { console.error(`✗ ${hits.length} residual identity leak(s) in ${out}:\n` + hits.slice(0, 40).map((h) => "  " + h).join("\n")); process.exit(2); }
console.log(`✓ anonymised mirror at ${out} — ${[...report.values()].reduce((a, b) => a + b, 0)} substitutions, leak scan clean. Upload THIS directory, not the git repo.`);
