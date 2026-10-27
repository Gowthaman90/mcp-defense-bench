/**
 * agentgateway adapter — drives the REAL agentgateway v1.6.0 binary (Apache-2.0), not a model of it.
 *
 * Measured on one family only: `authorized-call` (docs/AUTHORIZATION-PREREG.md §4, commitment 6.5).
 * For each call to assess(), the adapter:
 *   1. starts a dependency-free mock MCP server (one target, the fixture's tools under their full
 *      namespaced names) that records every `tools/call` it receives;
 *   2. writes an agentgateway config: one MCP route with `jwtAuth` (strict, a local ES256 test JWKS),
 *      `mcpAuthorization` (layer A) and route `authorization` (layer B), both compiled from the
 *      fixture's policy (see AUTHORIZATION-TRANSLATION.md);
 *   3. starts `.tools/agentgateway/agentgateway -f <config>` on a free loopback port;
 *   4. mints one JWT for the caller (`client_id` = client, `sub` = user, `act.sub` = agent, nested
 *      `act` for prior agents) and sends `initialize` then the fixture's `tools/call` over MCP
 *      streamable HTTP, with `request.headers` as HTTP headers and `request.meta` as `_meta`.
 *
 * enforce = detect = agentgateway refused the judged call (HTTP error, JSON-RPC error or isError) AND
 * the mock saw no `tools/call` during it. The benign control runs the same way.
 *
 * Integrity (adapters/CONTRACT.md): every decision comes from agentgateway's own CEL evaluation. The
 * adapter never looks at the fixture's `intent`, never special-cases a fixture, and reports a policy it
 * cannot translate as a miss with the reason in `signal`.
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";

export const meta = {
  tool: "agentgateway",
  class: "runtime-proxy",
  reproducible: true,
  version: "1.6.0",
  fixtureTypes: ["authorized-call"],
};

const BIN = fileURLToPath(new URL("../../.tools/agentgateway/agentgateway", import.meta.url));

/** sha256 of the v1.6.0 release binaries (GitHub release asset digests, checked against the .sha256 files). */
const PINNED_SHA256 = {
  "darwin-arm64": "6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685",
  "linux-x64": "496ed27e6a96b55a9ad7cabe5c2be7172511f44a3cb113e533d22bf93a7f079d",
  "linux-arm64": "b59ecac31103bb317d1377fd42b0cb25cd9a21f8c3f1d9ee14c3ff05f3f91abf",
};

let binaryChecked = false;
function ensureBinary() {
  if (binaryChecked) return;
  if (!existsSync(BIN)) {
    throw new Error(
      `agentgateway binary not found at ${BIN}. Download agentgateway-<os>-<arch> from ` +
        `https://github.com/agentgateway/agentgateway/releases/tag/v1.6.0, verify it against the release .sha256, ` +
        `and save it as .tools/agentgateway/agentgateway (chmod +x).`,
    );
  }
  const want = PINNED_SHA256[`${process.platform}-${process.arch}`];
  const got = createHash("sha256").update(readFileSync(BIN)).digest("hex");
  if (want && got !== want) {
    throw new Error(`agentgateway binary sha256 ${got} is not the pinned v1.6.0 release (${want}).`);
  }
  binaryChecked = true;
}

// ------------------------------------------------------------------------------------------------
// Policy translation: fixture policy (prereg §4) → agentgateway CEL. AUTHORIZATION-TRANSLATION.md.
// ------------------------------------------------------------------------------------------------

const KINDS = ["client", "user", "agent"];
/** Where each identity lives in the verified JWT. */
const PRESENT = {
  client: "has(jwt.client_id)",
  user: "has(jwt.sub)",
  agent: "(has(jwt.act) && has(jwt.act.sub))",
};
const VALUE = { client: "jwt.client_id", user: "jwt.sub", agent: "jwt.act.sub" };
const ANY_IDENTITY = `(${KINDS.map((k) => PRESENT[k]).join(" || ")})`;

/** CEL string literal (CEL accepts the JSON escapes \" \\ \n \uXXXX). */
const lit = (s) => JSON.stringify(String(s));
const or = (xs) => (xs.length === 0 ? "false" : xs.length === 1 ? xs[0] : `(${xs.join(" || ")})`);
const and = (xs) => (xs.length === 0 ? "true" : xs.length === 1 ? xs[0] : `(${xs.join(" && ")})`);

class Untranslatable extends Error {}

/** §4 rule 4: exact namespaced name, or one trailing `*` as a prefix match. */
function toolMatch(patterns) {
  if (!Array.isArray(patterns)) throw new Untranslatable("rule.tools is not a list");
  return or(
    patterns.map((p) =>
      typeof p === "string" && p.endsWith("*") && !p.slice(0, -1).includes("*")
        ? `mcp.tool.name.startsWith(${lit(p.slice(0, -1))})`
        : `mcp.tool.name == ${lit(p)}`,
    ),
  );
}

/** Does rule `r` apply to identity kind `k`? Returns a CEL condition, or null when it never does. */
function principalFor(r, k) {
  if (r.principal === "*") return "true";
  if (r.principal && typeof r.principal === "object" && typeof r.principal[k] === "string") {
    return `${VALUE[k]} == ${lit(r.principal[k])}`;
  }
  return null;
}

const NUMBER = (v) => `type(${v}) in [int, uint, double]`;

/** §4 rule 5 equality: same JSON type, exactly equal, no coercion. */
function equalsCel(v, x) {
  if (typeof x === "string") return `(type(${v}) == string && ${v} == ${lit(x)})`;
  if (typeof x === "boolean") return `(type(${v}) == bool && ${v} == ${x})`;
  if (typeof x === "number" && Number.isFinite(x)) return `(${NUMBER(v)} && double(${v}) == double(${x}))`;
  return "false"; // §4 compares strings, booleans and finite numbers only
}

/**
 * One path rewrite: `//` → `/`, `/./` → `/`, or `/<segment>/../` → `/` (a segment that is not `.` or
 * `..`). agentgateway's `regexReplace` replaces the FIRST match only (Rust `Regex::replace`), so each
 * pass applies one rewrite; NORMALISE_PASSES bounds how many a path may need.
 */
const NORMALISE_PASSES = 64;
const ONE_REWRITE = String.raw`//+|/\./|/(?:[^/.][^/]*|\.[^/.][^/]*|\.\.[^/]+)/\.\./`;

/**
 * pathWithin in CEL. agentgateway's CEL has no path-normalisation function, so `.`/`..` are resolved
 * with its `regexReplace` extension: NORMALISE_PASSES single rewrites (each preserves the resolved
 * path), then `..` at the root is dropped. A path still holding `//`, `/./` or `/../` after that (more
 * rewrites than the bound) is refused: the translation fails closed, it never guesses.
 */
function pathWithinCel(v, base) {
  if (typeof base !== "string" || !base.startsWith("/")) return "false";
  let b = posix.normalize(base);
  if (b.length > 1 && b.endsWith("/")) b = b.slice(0, -1);
  let n = `(${v} + "/")`;
  for (let i = 0; i < NORMALISE_PASSES; i++) n = `${n}.regexReplace(${lit(ONE_REWRITE)}, "/")`;
  n = `${n}.regexReplace(${lit(String.raw`^(/\.\.)+/`)}, "/")`;
  // `[x].all(p, …)` binds the normalised path once (CEL has no `let`). `n` ends in "/", so the base
  // itself and every path below it at a "/" boundary both start with `<base>/`.
  const inside = b === "/" ? "true" : `p.startsWith(${lit(b + "/")})`;
  return and([
    `type(${v}) == string`,
    `${v}.startsWith("/")`,
    `!${v}.contains("\\u0000")`,
    `[${n}].all(p, !p.contains("//") && !p.contains("/./") && !p.contains("/../") && ${inside})`,
  ]);
}

/** All of a rule's argument constraints (§4 rule 5); a missing constrained argument fails. */
function argsCel(args) {
  if (args === undefined) return "true";
  if (!args || typeof args !== "object") throw new Untranslatable("rule.args is not an object");
  const parts = [];
  for (const [name, c] of Object.entries(args)) {
    const v = `mcp.tool.arguments[${lit(name)}]`;
    const checks = [`has(mcp.tool.arguments)`, `${lit(name)} in mcp.tool.arguments`];
    for (const [op, x] of Object.entries(c ?? {})) {
      if (op === "equals") checks.push(equalsCel(v, x));
      else if (op === "in") {
        if (!Array.isArray(x)) throw new Untranslatable("`in` is not a list");
        checks.push(or(x.map((y) => equalsCel(v, y))));
      } else if (op === "max" || op === "min") {
        if (typeof x !== "number" || !Number.isFinite(x)) checks.push("false");
        else checks.push(`(${NUMBER(v)} && double(${v}) ${op === "max" ? "<=" : ">="} double(${x}))`);
      } else if (op === "pathWithin") checks.push(pathWithinCel(v, x));
      else throw new Untranslatable(`unknown argument constraint "${op}"`);
    }
    parts.push(and(checks));
  }
  return and(parts);
}

/**
 * Compile the fixture policy into agentgateway's two rule sets.
 *  - Layer A, `mcpAuthorization` (MCP-native; sees identity + tool name, NOT arguments — documented):
 *    one `allow` = the intersection over every identity the token carries of "some allow rule for that
 *    identity names this tool", plus one `require: !(…)` per deny rule without `args` (deny overrides).
 *  - Layer B, route `authorization` (the only agentgateway CEL context with `mcp.tool.arguments`):
 *    for `tools/call`, every carried identity that has a tool-matching allow rule must have one whose
 *    `args` hold, and no deny rule with `args` may match. Other MCP methods pass layer B.
 * A AND B is §4: per identity, deny → no-grant → argument; every carried identity must pass.
 */
export function translatePolicy(policy) {
  if (!policy || policy.default !== "deny") throw new Untranslatable(`policy.default is not "deny"`);
  const rules = policy.rules ?? [];
  const allows = rules.filter((r) => r.effect === "allow");
  const denies = rules.filter((r) => r.effect === "deny");
  if (allows.length + denies.length !== rules.length) throw new Untranslatable("a rule has an unknown effect");

  const grantA = KINDS.map((k) => {
    const g = allows.flatMap((r) => {
      const p = principalFor(r, k);
      return p === null ? [] : [and([p, toolMatch(r.tools)])];
    });
    return `(!${PRESENT[k]} || ${or(g)})`;
  });
  const layerA = [{ allow: and([ANY_IDENTITY, ...grantA]) }];

  const denyMatch = (r) =>
    or(
      KINDS.flatMap((k) => {
        const p = principalFor(r, k);
        return p === null ? [] : [and([PRESENT[k], p])];
      }),
    );
  for (const r of denies.filter((r) => r.args === undefined)) {
    layerA.push({ require: `!${and([denyMatch(r), toolMatch(r.tools)])}` });
  }

  const argsB = KINDS.map((k) => {
    const mine = allows.flatMap((r) => {
      const p = principalFor(r, k);
      return p === null ? [] : [{ m: and([p, toolMatch(r.tools)]), a: argsCel(r.args) }];
    });
    if (!mine.some((x) => x.a !== "true")) return null; // no argument-scoped grant for this kind
    return `(!${PRESENT[k]} || !${or(mine.map((x) => x.m))} || ${or(mine.map((x) => and([x.m, x.a])))})`;
  }).filter(Boolean);
  const denyB = denies
    .filter((r) => r.args !== undefined)
    .map((r) => `!${and([denyMatch(r), toolMatch(r.tools), argsCel(r.args)])}`);
  const checksB = [...argsB, ...denyB];
  const layerB = checksB.length === 0
    ? []
    : [{ require: `mcp.methodName != "tools/call" || ${and(["has(mcp.tool)", ...checksB])}` }];
  return { mcpAuthorization: layerA, authorization: layerB };
}

// ------------------------------------------------------------------------------------------------
// Identities → JWT (local test IdP).
// ------------------------------------------------------------------------------------------------

const ISSUER = "https://idp.bench.invalid";
const AUDIENCE = "bench-agentgateway";
const b64url = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");

function callerToken(privateKey, caller) {
  const now = Math.floor(Date.now() / 1000);
  let act;
  if (caller.agent !== undefined) {
    for (const prior of [...(caller.priorAgents ?? [])].reverse()) act = { sub: prior, ...(act ? { act } : {}) };
    act = { sub: caller.agent, ...(act ? { act } : {}) };
  }
  const claims = {
    iss: ISSUER,
    aud: AUDIENCE,
    iat: now - 5,
    exp: now + 300,
    jti: randomBytes(8).toString("hex"),
    ...(caller.client !== undefined ? { client_id: caller.client } : {}),
    ...(caller.user !== undefined ? { sub: caller.user } : {}),
    ...(act ? { act } : {}),
  };
  const input = `${b64url({ alg: "ES256", kid: "bench-k1", typ: "JWT" })}.${b64url(claims)}`;
  const sig = cryptoSign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

// ------------------------------------------------------------------------------------------------
// Mock MCP upstream and the MCP client side.
// ------------------------------------------------------------------------------------------------

/**
 * A stateless JSON-RPC MCP server (2025-06-18) serving `tools` under their full names. Every
 * `tools/call` is recorded. A call without `inputResponses` to a retry fixture's tool answers with an
 * `input_required`-shaped result (2026-07-28 MRTR) so the retry round has a state to carry.
 */
async function startUpstream(tools, mrtr) {
  const calls = [];
  const server = createServer(async (req, res) => {
    if (req.method !== "POST") return void res.writeHead(405, { allow: "POST" }).end();
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let msg;
    try {
      msg = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return void res.writeHead(400).end();
    }
    if (msg.id === undefined) return void res.writeHead(202).end();
    let result;
    if (msg.method === "initialize") {
      result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "bench-upstream", version: "0" } };
    } else if (msg.method === "tools/list") {
      result = { tools: tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? { type: "object" } })) };
    } else if (msg.method === "tools/call") {
      const p = msg.params ?? {};
      calls.push({ name: p.name, arguments: p.arguments ?? {} });
      result =
        mrtr && !p.inputResponses
          ? {
              resultType: "input_required",
              inputRequests: { confirm: { method: "elicitation/create", params: { message: "Confirm?", requestedSchema: { type: "object", properties: { ok: { type: "boolean" } } } } } },
              requestState: "bench-upstream-state",
            }
          : { content: [{ type: "text", text: `ran ${p.name}` }] };
    } else if (msg.method === "ping") {
      result = {};
    } else {
      return void res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } }));
    }
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}/mcp`,
    calls,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

/** One JSON-RPC request through agentgateway; returns { status, msg }. */
async function rpc(url, headers, id, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      ...headers,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2025-06-18",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const text = await res.text();
  let msg;
  try {
    const messages = (res.headers.get("content-type") ?? "").includes("text/event-stream")
      ? text.split("\n").filter((l) => l.startsWith("data:")).map((l) => JSON.parse(l.slice(5)))
      : [JSON.parse(text)];
    msg = messages.find((m) => m.id === id);
  } catch {
    msg = undefined;
  }
  return { status: res.status, msg: msg ?? { error: { message: text.slice(0, 120) || `HTTP ${res.status}` } } };
}

/** Start agentgateway with `configPath`; resolves once the route answers, rejects if it exits. */
async function startGateway(configPath, port) {
  const child = spawn(BIN, ["-f", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  let exited = null;
  child.on("exit", (code) => (exited = code ?? -1));
  const stop = () =>
    new Promise((r) => {
      if (exited !== null) return r();
      child.once("exit", () => r());
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 2000).unref();
    });
  const url = `http://127.0.0.1:${port}/mcp`;
  for (let i = 0; i < 200; i++) {
    if (exited !== null) {
      const why = out.split("\n").filter((l) => /error/i.test(l)).slice(0, 2).join(" ").slice(0, 200);
      throw Object.assign(new Error(`agentgateway exited (${exited}): ${why || out.slice(0, 200)}`), { configRejected: true });
    }
    try {
      const r = await fetch(url, { method: "GET" });
      await r.text();
      if (r.status !== 404) return { url, stop, log: () => out };
    } catch {
      /* not listening yet */
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  await stop();
  throw new Error("agentgateway did not become ready");
}

/** Fixture headers, lower-cased; values go on the wire as UTF-8 bytes (fetch takes a byte string). */
const lowerHeaders = (h) =>
  Object.fromEntries(
    Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), Buffer.from(String(v), "utf8").toString("latin1")]),
  );

const reason = (r) =>
  (r.msg?.error?.message ?? (r.msg?.result?.content ?? []).map((c) => c?.text ?? "").join("")).slice(0, 120);

async function assessAuthorized(input) {
  ensureBinary();
  let translated;
  try {
    translated = translatePolicy(input.policy);
  } catch (e) {
    if (e instanceof Untranslatable) return { detect: false, enforce: false, signal: `not translatable to agentgateway CEL: ${e.message}` };
    throw e;
  }
  const req = input.request ?? {};
  const retry = req.retryOf === "input_required";
  const dir = mkdtempSync(join(tmpdir(), "bench-agw-"));
  const cleanups = [() => rmSync(dir, { recursive: true, force: true })];
  try {
    const upstream = await startUpstream(input.tools ?? [], retry);
    cleanups.push(() => upstream.close());

    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "bench-k1", alg: "ES256", use: "sig" };
    writeFileSync(join(dir, "jwks.json"), JSON.stringify({ keys: [jwk] }));

    const port = await freePort();
    const policies = {
      jwtAuth: { mode: "strict", issuer: ISSUER, audiences: [AUDIENCE], jwks: { file: join(dir, "jwks.json") } },
      mcpAuthorization: { rules: translated.mcpAuthorization },
      ...(translated.authorization.length ? { authorization: { rules: translated.authorization } } : {}),
    };
    const config = {
      config: { adminAddr: "off", statsAddr: "off", readinessAddr: "off" },
      binds: [
        {
          port,
          listeners: [
            {
              routes: [
                {
                  backends: [{ mcp: { statefulMode: "stateless", targets: [{ name: "bench", mcp: { host: upstream.url } }] } }],
                  policies,
                },
              ],
            },
          ],
        },
      ],
    };
    const configPath = join(dir, "config.yaml"); // JSON is valid YAML
    writeFileSync(configPath, JSON.stringify(config, null, 2));

    let gw;
    try {
      gw = await startGateway(configPath, port);
    } catch (e) {
      if (e.configRejected) return { detect: false, enforce: false, signal: `config rejected by agentgateway: ${e.message}` };
      throw e;
    }
    cleanups.push(() => gw.stop());

    const headers = { ...lowerHeaders(req.headers), authorization: `Bearer ${callerToken(privateKey, input.caller ?? {})}` };
    await rpc(gw.url, headers, 1, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "mcp-defense-bench", version: "0" },
    });
    const params = { name: req.name, arguments: req.arguments ?? {}, ...(req.meta ? { _meta: req.meta } : {}) };
    let judgedParams = params;
    if (retry) {
      // Round 1 (no input responses). If agentgateway lets it through, the upstream's state is carried.
      const first = await rpc(gw.url, headers, 2, "tools/call", params);
      const state = first.msg?.result?.requestState;
      judgedParams = { ...params, inputResponses: req.inputResponses ?? {}, ...(state ? { requestState: state } : {}) };
    }
    const before = upstream.calls.length;
    const judged = await rpc(gw.url, headers, 3, "tools/call", judgedParams);
    const reached = upstream.calls.length > before;
    const errored = judged.status >= 400 || judged.msg?.error !== undefined || judged.msg?.result?.isError === true;
    if (reached || !errored) return { detect: false, enforce: false };
    const layer = judged.status === 403 ? "route authorization (arguments)" : "mcpAuthorization";
    return { detect: true, enforce: true, signal: `refused by ${layer} before upstream contact: HTTP ${judged.status} ${reason(judged)}` };
  } finally {
    for (const fn of cleanups.reverse()) await Promise.resolve().then(fn).catch(() => undefined);
  }
}

export async function assess(input, _testcase) {
  if (input?.type === "authorized-call") return assessAuthorized(input);
  return { detect: false, enforce: false, signal: "not wired: agentgateway is measured on authorized-call only" };
}
