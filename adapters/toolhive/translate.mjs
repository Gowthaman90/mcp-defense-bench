/**
 * Fixture policy (docs/AUTHORIZATION-PREREG.md §4) → ToolHive Cedar policies (cedarv1).
 * The reasoning behind every choice is in AUTHORIZATION-TRANSLATION.md.
 *
 * What ToolHive v0.57.0 gives a Cedar policy on a `tools/call` (pkg/authz/authorizers/cedar):
 *   - principal = Client::"<sub>"; every JWT claim as `claim_<name>` on principal and context,
 *     nested objects as records (so `principal.claim_act.sub`);
 *   - resource = Tool::"<tool name>", `resource.name` = the tool name;
 *   - every top-level argument as `resource.arg_<name>` (and in context): strings as String,
 *     booleans as Bool, every JSON number as a Cedar `decimal` (4 fractional digits; a number
 *     outside decimal range is dropped); objects and arrays only as `arg_<name>_present`;
 *   - forbid overrides permit, default deny, and ANY policy evaluation error denies the request.
 */

export class Untranslatable extends Error {}

export const KINDS = ["client", "user", "agent"];

/** Cedar string literal: Cedar takes \" \\ \n \r \t \0 and \u{…}, not JSON's \uXXXX. */
export function lit(s) {
  let out = '"';
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c === 0) out += "\\0";
    else if (c < 0x20 || c === 0x7f) out += `\\u{${c.toString(16)}}`;
    else out += ch;
  }
  return out + '"';
}

/** Cedar `like` pattern: a literal prefix followed by `*` (literal `*` escaped as `\*`). */
const likePrefix = (prefix) => lit(prefix).slice(0, -1).replaceAll("*", "\\*") + '*"';

const or = (xs) => (xs.length === 0 ? "false" : xs.length === 1 ? xs[0] : `(${xs.join(" || ")})`);
const and = (xs) => (xs.length === 0 ? "true" : xs.length === 1 ? xs[0] : `(${xs.join(" && ")})`);

/**
 * Where each identity lives in the verified token (see the adapter's callerClaims):
 *   client → `client_id`; agent → `act.sub` (RFC 8693); user → `sub`.
 * ToolHive requires `sub`, so a token with no user carries `sub` = the client (RFC 9068 §2.2,
 * client-credentials grant) or, for an agent alone, `sub` = the agent acting for itself. A token
 * therefore carries a user exactly when its `sub` is neither its `client_id` nor its `act.sub`.
 */
const AGENT_PRESENT = "(principal has claim_act && principal.claim_act has sub)";
export const PRESENT = {
  client: "(principal has claim_client_id)",
  agent: AGENT_PRESENT,
  user:
    "(principal has claim_sub" +
    " && !(principal has claim_client_id && principal.claim_sub == principal.claim_client_id)" +
    ` && !(${AGENT_PRESENT} && principal.claim_act.sub == principal.claim_sub))`,
};
const VALUE = { client: "principal.claim_client_id", user: "principal.claim_sub", agent: "principal.claim_act.sub" };

/** §4 rule 4: exact namespaced name, or one trailing `*` as a prefix match. */
function toolMatch(patterns) {
  if (!Array.isArray(patterns) || patterns.length === 0) throw new Untranslatable("rule.tools is not a non-empty list");
  return or(
    patterns.map((p) => {
      if (typeof p !== "string") throw new Untranslatable("a tool pattern is not a string");
      const star = p.indexOf("*");
      if (star === -1) return `resource == Tool::${lit(p)}`;
      if (star !== p.length - 1) throw new Untranslatable(`tool pattern "${p}" has a "*" that is not trailing`);
      return `resource.name like ${likePrefix(p.slice(0, -1))}`;
    }),
  );
}

/** The CEDAR condition "rule r applies to identity kind k", or null when it never does. */
function principalFor(r, k) {
  if (r.principal === "*") return PRESENT[k];
  if (r.principal && typeof r.principal === "object") {
    const named = Object.keys(r.principal);
    if (named.some((n) => !KINDS.includes(n))) throw new Untranslatable(`unknown principal kind in ${JSON.stringify(r.principal)}`);
    if (named.length !== 1) throw new Untranslatable("a rule principal names more than one identity");
    if (named[0] !== k) return null;
    if (typeof r.principal[k] !== "string") throw new Untranslatable("a rule principal value is not a string");
    return and([PRESENT[k], `${VALUE[k]} == ${lit(r.principal[k])}`]);
  }
  throw new Untranslatable(`unsupported principal ${JSON.stringify(r.principal)}`);
}

/**
 * A fixture number as a Cedar decimal literal. ToolHive turns every JSON number argument into a
 * decimal with four fractional digits, so a bound or value that is not exactly such a decimal
 * cannot be compared faithfully: the rule is reported as untranslatable.
 */
function decimalLit(x) {
  if (typeof x !== "number" || !Number.isFinite(x)) throw new Untranslatable(`${JSON.stringify(x)} is not a finite number`);
  const s = x.toFixed(4);
  if (Number(s) !== x || Math.abs(x) > 922337203685477) {
    throw new Untranslatable(`${x} is not representable as a Cedar decimal (4 fractional digits)`);
  }
  const [i, f] = s.split(".");
  return `decimal(${lit(`${i}.${f.replace(/0+$/, "") || "0"}`)})`;
}

/** §4 rule 5 equality: same JSON type, exactly equal. Strings, booleans and numbers only. */
function equalsCedar(v, x) {
  if (typeof x === "string") return `${v} == ${lit(x)}`;
  if (typeof x === "boolean") return `${v} == ${x}`;
  if (typeof x === "number") return `${v} == ${decimalLit(x)}`;
  return "false"; // §4 compares strings, booleans and finite numbers only: nothing equals it
}

/**
 * pathWithin. Cedar has no path normalisation, so the translation is exact for paths without
 * `.`/`..` or empty segments and FAILS CLOSED for every other path: inside an allow rule such a
 * path never satisfies the constraint, inside a deny rule it always does.
 */
function pathWithin(v, base, inDeny) {
  if (typeof base !== "string" || !base.startsWith("/") || base.includes("\0")) {
    throw new Untranslatable(`pathWithin base ${JSON.stringify(base)} is not an absolute path`);
  }
  let b = base.replace(/\/+/g, "/");
  const segs = [];
  for (const s of b.split("/").slice(1)) {
    if (s === "" || s === ".") continue;
    if (s === "..") segs.pop();
    else segs.push(s);
  }
  b = "/" + segs.join("/");
  const nonCanonical = or([`${v} like "*//*"`, `${v} like "*/./*"`, `${v} like "*/../*"`, `${v} like "*/."`, `${v} like "*/.."`]);
  const inside = b === "/" ? "true" : or([`${v} == ${lit(b)}`, `${v} like ${likePrefix(b + "/")}`]);
  const absolute = and([`${v} like "/*"`, `!(${v} like "*\\0*")`]);
  return inDeny ? and([absolute, or([nonCanonical, inside])]) : and([absolute, `!${nonCanonical}`, inside]);
}

/** All of a rule's argument constraints (§4 rule 5); a missing constrained argument fails. */
function argsCedar(args, inDeny) {
  if (args === undefined) return "true";
  if (!args || typeof args !== "object" || Array.isArray(args)) throw new Untranslatable("rule.args is not an object");
  const parts = [];
  for (const [name, c] of Object.entries(args)) {
    const attr = `arg_${name}`;
    const v = `resource[${lit(attr)}]`;
    const checks = [`resource has ${lit(attr)}`];
    if (!c || typeof c !== "object" || Object.keys(c).length === 0) throw new Untranslatable(`constraint on "${name}" is empty`);
    for (const [op, x] of Object.entries(c)) {
      if (op === "equals") checks.push(equalsCedar(v, x));
      else if (op === "in") {
        if (!Array.isArray(x)) throw new Untranslatable("`in` is not a list");
        checks.push(or(x.map((y) => equalsCedar(v, y))));
      } else if (op === "max") checks.push(`${v}.lessThanOrEqual(${decimalLit(x)})`);
      else if (op === "min") checks.push(`${v}.greaterThanOrEqual(${decimalLit(x)})`);
      else if (op === "pathWithin") checks.push(pathWithin(v, x, inDeny));
      else throw new Untranslatable(`unknown argument constraint "${op}"`);
    }
    parts.push(and(checks));
  }
  return and(parts);
}

const CALL = 'principal, action == Action::"call_tool", resource';

/**
 * The whole policy as Cedar:
 *   1. one permit for any authenticated caller (every identity is checked by the forbids below);
 *   2. per identity kind: forbid when the token carries that identity and NO allow rule for it
 *      matches the tool with its arguments satisfied (§4 rule 3 "no-grant" / "argument", and the
 *      §4 rule 2 intersection: every carried identity needs its own grant);
 *   3. per deny rule: forbid when it applies to a carried identity, matches the tool, and its
 *      arguments are satisfied (deny overrides allow).
 * Returns { policies, notes } where notes lists the documented approximations in force.
 */
export function translatePolicy(policy) {
  if (!policy || policy.default !== "deny") throw new Untranslatable(`policy.default is not "deny"`);
  const rules = policy.rules ?? [];
  if (!Array.isArray(rules)) throw new Untranslatable("policy.rules is not a list");
  for (const r of rules) if (r?.effect !== "allow" && r?.effect !== "deny") throw new Untranslatable("a rule has an unknown effect");
  const allows = rules.filter((r) => r.effect === "allow");
  const denies = rules.filter((r) => r.effect === "deny");

  const policies = [`permit(${CALL}) when { principal has claim_sub };`];
  for (const k of KINDS) {
    const grants = allows.flatMap((r) => {
      const p = principalFor(r, k);
      return p === null ? [] : [and([p, toolMatch(r.tools), argsCedar(r.args, false)])];
    });
    policies.push(`forbid(${CALL}) when { ${PRESENT[k]} && !${or(grants)} };`);
  }
  for (const r of denies) {
    const who = or(KINDS.map((k) => principalFor(r, k)).filter((p) => p !== null));
    policies.push(`forbid(${CALL}) when { ${and([who, toolMatch(r.tools), argsCedar(r.args, true)])} };`);
  }
  const notes = [];
  if (rules.some((r) => r.args && Object.values(r.args).some((c) => c && "pathWithin" in c))) {
    notes.push("pathWithin fails closed on paths with ./../empty segments (no path normalisation in Cedar)");
  }
  return { policies, notes };
}
