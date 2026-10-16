#!/usr/bin/env node
/**
 * One-shot generator for the STAGED delegation family (docs/DELEGATION-PREREG.md).
 *
 * Writes staging/delegation/{dev,heldout}/<vector>/NNN-slug.json and staging/delegation/MANIFEST.json
 * (sha256 of every emitted file). Keys are generated in memory and only public JWKs are emitted;
 * structural tokens are HS256 with a discarded random secret. Running it again therefore produces
 * DIFFERENT tokens, which is why it refuses to overwrite an existing set: once registered (committed
 * + tagged), the fixtures are frozen and are only ever removed-and-logged, never regenerated.
 *
 * Usage: node scripts/gen-delegation.mjs [--force]   (--force only before registration)
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { devCases } from "./delegation/dev-cases.mjs";
import { heldoutCases } from "./delegation/heldout-cases.mjs";
import { newKey, strictDecode, violations } from "./delegation/tokens.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(root, "staging", "delegation");
const rows = JSON.parse(readFileSync(join(out, "crosswalk-rows.json"), "utf8")).vectors;
const vectorIds = new Set(rows.map((r) => r.id));

if (existsSync(join(out, "MANIFEST.json")) && !process.argv.includes("--force")) {
  console.error("staging/delegation/MANIFEST.json exists: this set may already be registered. Refusing to regenerate (tokens would change). Use --force only before registration.");
  process.exit(1);
}

const now = Date.UTC(2026, 9, 14, 0, 0, 0) / 1000; // fixed clock for every fixture: 2026-10-14T00:00:00Z
const keys = {
  travel: newKey("ES256", "travel-2026-10"),
  claims: newKey("EdDSA", "claims-ed-1"),
  freight: newKey("ES256", "freight-k1"),
  attacker: newKey("ES256", "travel-2026-10"), // same kid as the trusted key, different key material
  attacker2: newKey("ES256", "edge-rot-7"),
};

const dev = devCases({ now, keys });
const held = heldoutCases({ now, keys });

// ── validate ────────────────────────────────────────────────────────────────────────────────
const errors = [];
const tokensOf = (fx) => Object.values(fx.request.headers).map((t) => strictDecode(t)?.payload ?? null).filter(Boolean);
// Development artefacts that may not appear in the held-out set (incl. inside decoded tokens).
const FORBIDDEN = [/travel\.test/, /trip-orchestrator/, /x-delegate-/, /x-user-assertion/, /ana\.k/, /ravi\.m/, /flights|hotels|payments/, /bulk-export-agent/, /itinerary-planner/];

function check(c, corpus) {
  const where = `${corpus}:${c.vector}/${c.slug}`;
  if (!vectorIds.has(c.vector)) errors.push(`${where}: unknown vector`);
  for (const k of ["description", "fixture", "benignControl", "expected", "provenance", "violates"]) if (!c[k]) errors.push(`${where}: missing ${k}`);
  if (corpus === "heldout" && !/^[DLSE]$/.test(c.family ?? "")) errors.push(`${where}: missing family tag`);
  const mal = violations(c.fixture);
  const ben = violations(c.benignControl);
  const want = [...c.violates].sort();
  if (JSON.stringify(mal) !== JSON.stringify(want)) errors.push(`${where}: attack violates ${JSON.stringify(mal)}, declared ${JSON.stringify(want)}`);
  if (ben.length) errors.push(`${where}: benign control violates ${JSON.stringify(ben)}`);
  if (c.fixture.request.target !== c.benignControl.request.target || c.fixture.request.method !== c.benignControl.request.method)
    errors.push(`${where}: control differs from attack in target/method (controls must be near-identical)`);
  if (corpus === "heldout") {
    const blob = JSON.stringify(c) + JSON.stringify([...tokensOf(c.fixture), ...tokensOf(c.benignControl)]);
    for (const re of FORBIDDEN) if (re.test(blob)) errors.push(`${where}: reuses development artefact ${re}`);
  }
}
dev.forEach((c) => check(c, "dev"));
held.forEach((c) => check(c, "heldout"));

for (const id of vectorIds) {
  const d = dev.filter((c) => c.vector === id).length;
  const h = held.filter((c) => c.vector === id);
  if (d < 3) errors.push(`${id}: ${d} dev fixtures (need ≥ 3)`);
  if (h.length < 2) errors.push(`${id}: ${h.length} held-out fixtures (need ≥ 2)`);
  if (!h.some((c) => c.family === "D" || c.family === "L")) errors.push(`${id}: no held-out D or L fixture`);
}
const slugs = [...dev, ...held].map((c) => `${c.vector}/${c.slug}`);
if (new Set(slugs).size !== slugs.length) errors.push("duplicate slugs");
if (errors.length) {
  console.error(errors.join("\n"));
  console.error(`\n${errors.length} error(s) — nothing written.`);
  process.exit(1);
}

// ── emit ────────────────────────────────────────────────────────────────────────────────────
for (const d of ["dev", "heldout"]) rmSync(join(out, d), { recursive: true, force: true });
const written = [];
function emit(c, corpus) {
  const dir = join(out, corpus, c.vector);
  mkdirSync(dir, { recursive: true });
  const n = (emit.seq[`${corpus}/${c.vector}`] = (emit.seq[`${corpus}/${c.vector}`] ?? 0) + 1);
  const num = String(n).padStart(3, "0");
  const doc = {
    vector: c.vector,
    id: `${corpus === "heldout" ? "heldout/" : ""}${c.vector}/${num}-${c.slug}`,
    staged: true,
    ...(corpus === "heldout" ? { heldout: true, family: c.family } : {}),
    severity: c.severity,
    description: c.description,
    fixture: c.fixture,
    expected: { ...c.expected },
    ...(c.scoreCap ? { scoreCap: c.scoreCap } : {}),
    benignControl: { ...c.benignControl, expected: { detect: false, enforce: false } },
    intent: { violates: [...c.violates].sort() },
    provenance: c.provenance,
  };
  const path = join(dir, `${num}-${c.slug}.json`);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  written.push(path);
}
emit.seq = {};
dev.forEach((c) => emit(c, "dev"));
held.forEach((c) => emit(c, "heldout"));

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const generators = ["scripts/gen-delegation.mjs", "scripts/delegation/tokens.mjs", "scripts/delegation/dev-cases.mjs", "scripts/delegation/heldout-cases.mjs"];
const fam = held.reduce((a, c) => ((a[c.family] = (a[c.family] ?? 0) + 1), a), {});
const manifest = {
  protocol: "docs/DELEGATION-PREREG.md",
  status: "staged-unscored",
  generatedAt: new Date().toISOString(),
  fixtureClock: { now, iso: new Date(now * 1000).toISOString() },
  node: process.version,
  privateKeysPersisted: false,
  structuralSecretPersisted: false,
  publicKeys: Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, v.jwk])),
  counts: { vectors: vectorIds.size, dev: dev.length, heldout: held.length, heldoutFamilies: fam },
  defenderFreeze: null,
  removals: [],
  generators: Object.fromEntries(generators.map((g) => [g, sha(join(root, g))])),
  crosswalkRows: sha(join(out, "crosswalk-rows.json")),
  files: Object.fromEntries(written.map((p) => [relative(root, p), sha(p)])),
};
writeFileSync(join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`✓ staged ${dev.length} dev + ${held.length} held-out fixtures across ${vectorIds.size} vectors; held-out families ${JSON.stringify(fam)}`);
