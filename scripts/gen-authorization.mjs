#!/usr/bin/env node
/**
 * One-shot generator for the STAGED authorization family (docs/AUTHORIZATION-PREREG.md).
 *
 * Writes staging/authorization/{dev,heldout}/<vector>/NNN-slug.json and
 * staging/authorization/MANIFEST.json (sha256 of every emitted file). Unlike the delegation family
 * there is no key material, so the output is deterministic; it still refuses to overwrite a
 * registered set, because registered fixtures are only ever removed-and-logged, never regenerated.
 *
 * Usage: node scripts/gen-authorization.mjs [--force]   (--force only before registration)
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { devCases } from "./authorization/dev-cases.mjs";
import { heldoutCases } from "./authorization/heldout-cases.mjs";
import { identitiesOf, schemaErrors, violations } from "./authorization/policy.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(root, "staging", "authorization");
const rows = JSON.parse(readFileSync(join(out, "crosswalk-rows.json"), "utf8")).vectors;
const vectorIds = new Set(rows.map((r) => r.id));

if (existsSync(join(out, "MANIFEST.json")) && !process.argv.includes("--force")) {
  console.error("staging/authorization/MANIFEST.json exists: this set may already be registered. Refusing to regenerate. Use --force only before registration.");
  process.exit(1);
}

const dev = devCases();
const held = heldoutCases();

// ── validate ────────────────────────────────────────────────────────────────────────────────
const errors = [];
// Development artefacts that may not appear in a held-out fixture.
const FORBIDDEN = [/forge\.test/, /docs-bot|release-bot|triage-bot|ci-bot/, /triage-agent|release-agent|platform-agent/, /mei\.l|omar\.s/, /repo__|deploy__|ci__|issues__/, /\/srv\/checkouts/, /runAs/, /x-forwarded-user/i];
const COMPONENTS = [
  ["caller", (f) => f.caller],
  ["request.name", (f) => f.request.name],
  ["request.arguments", (f) => f.request.arguments],
  ["request.headers", (f) => f.request.headers],
  ["request.meta", (f) => f.request.meta],
  ["request.inputResponses", (f) => f.request.inputResponses],
  ["request.retryOf", (f) => f.request.retryOf],
];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Resolve a dotted path whose keys may themselves contain dots (longest key wins). */
function resolve(obj, path) {
  let o = obj;
  let rest = path;
  while (rest !== "") {
    if (!o || typeof o !== "object") return undefined;
    const key = Object.keys(o).filter((k) => rest === k || rest.startsWith(`${k}.`)).sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return undefined;
    o = o[key];
    rest = rest === key ? "" : rest.slice(key.length + 1);
  }
  return o;
}

function checkFixtureShape(f, where) {
  if (f.type !== "authorized-call") errors.push(`${where}: type must be authorized-call`);
  if (f.policy?.default !== "deny") errors.push(`${where}: policy.default must be "deny"`);
  if (f.request?.method !== "tools/call") errors.push(`${where}: method must be tools/call`);
  const tool = f.tools.find((t) => t.name === f.request.name);
  if (!tool) errors.push(`${where}: request.name ${f.request.name} is not in tools`);
  else for (const e of schemaErrors(tool.inputSchema, f.request.arguments)) errors.push(`${where}: arguments not schema-valid: ${e}`);
  for (const r of f.policy.rules) {
    if (r.principal !== "*" && Object.keys(r.principal ?? {}).length !== 1) errors.push(`${where}: rule principal must have exactly one key`);
    for (const p of r.tools) if (p.indexOf("*") !== -1 && p.indexOf("*") !== p.length - 1) errors.push(`${where}: tool pattern ${p} may only end in *`);
  }
  if (identitiesOf(f.caller).length === 0) errors.push(`${where}: caller carries no identity`);
}

function check(c, corpus) {
  const where = `${corpus}:${c.vector}/${c.slug}`;
  if (!vectorIds.has(c.vector)) errors.push(`${where}: unknown vector`);
  for (const k of ["description", "fixture", "benignControl", "expected", "provenance", "violates", "severity"]) if (!c[k]) errors.push(`${where}: missing ${k}`);
  if (corpus === "heldout" && !/^[DLSE]$/.test(c.family ?? "")) errors.push(`${where}: missing family tag`);
  checkFixtureShape(c.fixture, `${where} (attack)`);
  checkFixtureShape(c.benignControl, `${where} (control)`);

  const mal = violations(c.fixture);
  const ben = violations(c.benignControl);
  const want = [...c.violates].sort();
  if (!same(mal, want)) errors.push(`${where}: attack violates ${JSON.stringify(mal)}, declared ${JSON.stringify(want)}`);
  if (ben.length) errors.push(`${where}: control violates ${JSON.stringify(ben)}`);

  // Near-identical control: same tools and policy, exactly one request/caller component differs.
  for (const k of ["type", "separator", "tools", "policy"]) if (!same(c.fixture[k], c.benignControl[k])) errors.push(`${where}: control differs in ${k}`);
  const diff = COMPONENTS.filter(([, get]) => !same(get(c.fixture), get(c.benignControl))).map(([n]) => n);
  if (diff.length !== 1) errors.push(`${where}: control must differ from the attack in exactly one component, differs in ${JSON.stringify(diff)}`);

  // Vector-specific shape.
  if (c.vector === "authz-delegated-agent-overreach") {
    if (!(c.fixture.caller.user && c.fixture.caller.agent)) errors.push(`${where}: caller must carry a user and an agent`);
    if (!mal.every((v) => v.startsWith("user:") || v.startsWith("agent:"))) errors.push(`${where}: violation must be the user's or the agent's`);
  }
  if (c.vector === "authz-asserted-identity") {
    const a = c.assertedIdentity;
    if (!a) errors.push(`${where}: missing assertedIdentity`);
    else {
      const [[kind, value]] = Object.entries(a.as);
      if (resolve(c.fixture, a.where) !== value) errors.push(`${where}: assertion not found at ${a.where}`);
      if (c.fixture.caller[kind] === value) errors.push(`${where}: asserted identity equals the authenticated one`);
      const lured = { ...c.fixture, caller: { ...c.fixture.caller, [kind]: value } };
      if (violations(lured).length) errors.push(`${where}: lure does not work (the asserted identity would also be refused)`);
    }
  } else if (c.assertedIdentity) errors.push(`${where}: assertedIdentity only belongs to authz-asserted-identity`);

  if (corpus === "heldout") {
    const blob = JSON.stringify(c);
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
const seq = {};
function emit(c, corpus) {
  const dir = join(out, corpus, c.vector);
  mkdirSync(dir, { recursive: true });
  const n = (seq[`${corpus}/${c.vector}`] = (seq[`${corpus}/${c.vector}`] ?? 0) + 1);
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
    benignControl: { ...c.benignControl, expected: { detect: false, enforce: false } },
    intent: { violates: [...c.violates].sort(), ...(c.assertedIdentity ? { assertedIdentity: c.assertedIdentity } : {}) },
    provenance: c.provenance,
  };
  const path = join(dir, `${num}-${c.slug}.json`);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  written.push(path);
}
dev.forEach((c) => emit(c, "dev"));
held.forEach((c) => emit(c, "heldout"));

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const generators = ["scripts/gen-authorization.mjs", "scripts/authorization/policy.mjs", "scripts/authorization/dev-cases.mjs", "scripts/authorization/heldout-cases.mjs"];
const fam = held.reduce((a, c) => ((a[c.family] = (a[c.family] ?? 0) + 1), a), {});
const manifest = {
  protocol: "docs/AUTHORIZATION-PREREG.md",
  status: "staged-unscored",
  generatedAt: new Date().toISOString(),
  node: process.version,
  deterministic: true,
  counts: { vectors: vectorIds.size, dev: dev.length, heldout: held.length, heldoutFamilies: fam },
  defenderFreeze: null,
  removals: [],
  deviations: [],
  generators: Object.fromEntries(generators.map((g) => [g, sha(join(root, g))])),
  crosswalkRows: sha(join(out, "crosswalk-rows.json")),
  files: Object.fromEntries(written.map((p) => [relative(root, p), sha(p)])),
};
writeFileSync(join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`✓ staged ${dev.length} dev + ${held.length} held-out fixtures across ${vectorIds.size} vectors; held-out families ${JSON.stringify(fam)}`);
