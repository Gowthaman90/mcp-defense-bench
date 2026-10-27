/**
 * Reference semantics for the STAGED authorization family (docs/AUTHORIZATION-PREREG.md §4).
 *
 * `violations(fixture)` returns the sorted list of reasons the call must be refused under the
 * registered intended semantics (empty = the call must be allowed). It is used ONLY by
 * scripts/gen-authorization.mjs to reject malformed fixtures at generation time. It is never run
 * against a defender, and no defender may import it.
 *
 * Deliberately small and dependency-free so that a reviewer can check it against §4 line by line.
 */
import { posix } from "node:path";

const IDENTITY_KINDS = ["client", "user", "agent"];

/** Identities the call carries, from the AUTHENTICATED caller only. Prior agents grant nothing. */
export function identitiesOf(caller) {
  return IDENTITY_KINDS.filter((k) => typeof caller?.[k] === "string").map((k) => [k, caller[k]]);
}

function principalMatches(principal, kind, value) {
  if (principal === "*") return true;
  if (!principal || typeof principal !== "object") return false;
  const keys = Object.keys(principal);
  return keys.length === 1 && keys[0] === kind && principal[kind] === value;
}

/** Tool patterns: exact namespaced name, or a single trailing `*` (prefix match). */
export function toolMatches(patterns, name) {
  return patterns.some((p) => (p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p));
}

const isScalar = (v) => typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));

/** `pathWithin`: absolute POSIX path, no NUL, normalised, equal to the base or below it at a `/` boundary. */
export function pathWithin(value, base) {
  if (typeof value !== "string" || value.includes("\u0000") || !value.startsWith("/")) return false;
  const norm = posix.normalize(value);
  const b = base.endsWith("/") ? base.slice(0, -1) : base;
  return norm === b || norm.startsWith(`${b}/`);
}

function constraintHolds(value, c) {
  if (value === undefined) return false; // a constrained argument that is missing fails closed
  if ("equals" in c && !(isScalar(value) && value === c.equals)) return false;
  if ("in" in c && !(isScalar(value) && c.in.includes(value))) return false;
  if ("max" in c && !(typeof value === "number" && Number.isFinite(value) && value <= c.max)) return false;
  if ("min" in c && !(typeof value === "number" && Number.isFinite(value) && value >= c.min)) return false;
  if ("pathWithin" in c && !pathWithin(value, c.pathWithin)) return false;
  return true;
}

export function argsMatch(rule, args) {
  return Object.entries(rule.args ?? {}).every(([name, c]) => constraintHolds(args?.[name], c));
}

/** The decision for one identity: null (permitted), or the reason it is not. */
function decide(policy, kind, value, request) {
  const rules = policy.rules.filter((r) => principalMatches(r.principal, kind, value) && toolMatches(r.tools, request.name));
  if (rules.some((r) => r.effect === "deny" && argsMatch(r, request.arguments))) return "denied";
  const allows = rules.filter((r) => r.effect === "allow");
  if (allows.length === 0) return "no-grant";
  if (!allows.some((r) => argsMatch(r, request.arguments))) return "argument";
  return null;
}

/**
 * Every identity the authenticated caller carries must be permitted (intersection). Identities
 * asserted anywhere in the request (arguments, headers, meta, input responses) are ignored.
 */
export function violations(fx) {
  if (fx.type !== "authorized-call") return ["malformed"];
  if (fx.policy?.default !== "deny") return ["malformed"];
  const ids = identitiesOf(fx.caller);
  if (ids.length === 0) return ["unauthenticated"];
  const out = new Set();
  for (const [kind, value] of ids) {
    const why = decide(fx.policy, kind, value, fx.request);
    if (why) out.add(`${kind}:${why}`);
  }
  return [...out].sort();
}

/** Minimal JSON-Schema check used to prove every fixture's arguments are schema-valid. */
export function schemaErrors(schema, args) {
  const errs = [];
  const typeOk = (v, t) =>
    (Array.isArray(t) ? t : [t]).some((tt) =>
      tt === "integer" ? Number.isInteger(v) : tt === "number" ? typeof v === "number" : tt === "array" ? Array.isArray(v) : tt === "object" ? v && typeof v === "object" && !Array.isArray(v) : typeof v === tt,
    );
  for (const r of schema.required ?? []) if (!(r in (args ?? {}))) errs.push(`missing required "${r}"`);
  for (const [k, v] of Object.entries(args ?? {})) {
    const p = schema.properties?.[k];
    if (!p) {
      if (schema.additionalProperties === false) errs.push(`undeclared "${k}"`);
      continue;
    }
    if (p.type && !typeOk(v, p.type)) errs.push(`"${k}" has the wrong type`);
  }
  return errs;
}
