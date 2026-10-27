/**
 * ToolHive adapter — drives the REAL ToolHive v0.57.0 `thv` binary (Apache-2.0), not a model of it.
 *
 * Measured on one family only: `authorized-call` (docs/AUTHORIZATION-PREREG.md §4, commitment 6.5).
 * Measured configuration: the direct proxy, `thv run <remote URL> --foreground` (no container is
 * created for a remote URL). For each call to assess(), the adapter:
 *   1. starts a local test IdP (discovery + JWKS over loopback HTTP) and one dependency-free mock MCP
 *      server serving the fixture's tools under their full namespaced names, recording every
 *      `tools/call` it receives;
 *   2. writes a ToolHive `cedarv1` authz config compiled from the fixture's policy (translate.mjs,
 *      AUTHORIZATION-TRANSLATION.md);
 *   3. starts `.tools/toolhive/thv run <mock URL> --foreground` on a free loopback port with
 *      `--oidc-issuer/--oidc-jwks-url/--oidc-audience` (local IdP) and `--authz-config`. HOME and the
 *      XDG directories point at a temporary directory (the user's own ToolHive state is untouched),
 *      and the container-runtime socket is the dedicated `mcpbench` Colima profile only (see
 *      RUNTIME_SOCKET: thv v0.57.0 refuses to run without one, even for a remote URL);
 *   4. mints one ES256 JWT for the caller (`client_id` = client, `sub` = user, `act.sub` = agent,
 *      nested `act` for prior agents) and sends `initialize`, then the fixture's `tools/call` over MCP
 *      streamable HTTP, with `request.headers` as HTTP headers and `request.meta` as `_meta`.
 *
 * enforce = detect = ToolHive answered the judged call with an HTTP or JSON-RPC error (or isError)
 * AND the mock saw no `tools/call` during it. The benign control runs the same way.
 *
 * Integrity (adapters/CONTRACT.md): every decision comes from ToolHive's own OIDC validation and Cedar
 * evaluation. The adapter never looks at the fixture's `intent`, never special-cases a fixture, and
 * reports a policy it cannot translate as a miss with the reason in `signal`.
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { translatePolicy, Untranslatable } from "./translate.mjs";

export const meta = {
  tool: "toolhive",
  class: "runtime-proxy",
  reproducible: true,
  version: "0.57.0",
  fixtureTypes: ["authorized-call"],
};

const BIN = fileURLToPath(new URL("../../.tools/toolhive/thv", import.meta.url));

/** sha256 of the `thv` binary inside each v0.57.0 release archive (archives checked against toolhive_0.57.0_checksums.txt). */
const PINNED_SHA256 = {
  "darwin-arm64": "327906368a1756380fe8bd7f1530b181251821a8c6a25f9131840ff0cec51698",
  "darwin-x64": "62953eb8407f05dbdc0f99137572a0683273b1b6927d27750414bd698826c947",
  "linux-x64": "f68c4462320d9b14f87817940b389d12d2b5885300e639ebb69ec7652ef24f0e",
  "linux-arm64": "9908d2a056aea3984ad465e1356523a7f7126517ee787e2c4117a10ce24d4001",
};

let binaryChecked = false;
function ensureBinary() {
  if (binaryChecked) return;
  if (!existsSync(BIN)) {
    throw new Error(
      `thv binary not found at ${BIN}. Download toolhive_0.57.0_<os>_<arch>.tar.gz from ` +
        `https://github.com/stacklok/toolhive/releases/tag/v0.57.0, verify it against toolhive_0.57.0_checksums.txt, ` +
        `and extract \`thv\` to .tools/toolhive/thv.`,
    );
  }
  const got = createHash("sha256").update(readFileSync(BIN)).digest("hex");
  const want = PINNED_SHA256[`${process.platform}-${process.arch}`];
  if (want && got !== want) throw new Error(`thv sha256 ${got} is not the pinned v0.57.0 release binary (${want}).`);
  if (!want) throw new Error(`no pinned v0.57.0 thv sha256 for ${process.platform}-${process.arch}; add it from the release archive first.`);
  binaryChecked = true;
}

// ------------------------------------------------------------------------------------------------
// Identities → JWT (local test IdP).
// ------------------------------------------------------------------------------------------------

const AUDIENCE = "bench-toolhive";
const b64url = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");

/**
 * The caller's token claims. `client_id` = client; `sub` = user; `act` = agent ⊃ prior agents
 * (RFC 8693 §4.1). ToolHive requires `sub`: with no user it is the client (RFC 9068 §2.2), or the
 * agent itself when the caller is an agent alone. translate.mjs reads the identities back the same way.
 */
export function callerClaims(caller) {
  let act;
  if (caller.agent !== undefined) {
    for (const prior of [...(caller.priorAgents ?? [])].reverse()) act = { sub: prior, ...(act ? { act } : {}) };
    act = { sub: caller.agent, ...(act ? { act } : {}) };
  }
  const sub = caller.user ?? caller.client ?? caller.agent;
  return {
    ...(sub !== undefined ? { sub } : {}),
    ...(caller.client !== undefined ? { client_id: caller.client } : {}),
    ...(act ? { act } : {}),
  };
}

function callerToken(privateKey, issuer, caller) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: AUDIENCE, iat: now - 5, exp: now + 300, jti: randomBytes(8).toString("hex"), ...callerClaims(caller) };
  const input = `${b64url({ alg: "ES256", kid: "bench-k1", typ: "JWT" })}.${b64url(claims)}`;
  const sig = cryptoSign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

/** A loopback OIDC issuer: discovery document + JWKS. */
async function startIdp(jwk) {
  const server = createServer((req, res) => {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    const body = req.url?.startsWith("/jwks") ? { keys: [jwk] } : { issuer, jwks_uri: `${issuer}/jwks` };
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const issuer = `http://127.0.0.1:${server.address().port}`;
  return { issuer, jwksUrl: `${issuer}/jwks`, close: () => new Promise((r) => server.close(() => r())) };
}

// ------------------------------------------------------------------------------------------------
// Mock MCP backends and the MCP client side.
// ------------------------------------------------------------------------------------------------

/**
 * A stateless JSON-RPC MCP server serving `tools` under the names given. Every `tools/call` is pushed to
 * `calls`. A call without `inputResponses` to a retry fixture's tool answers with an
 * `input_required`-shaped result (2026-07-28 MRTR) so the retry round has a state to carry.
 */
async function startBackend(name, tools, calls, mrtr) {
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
      result = {
        protocolVersion: msg.params?.protocolVersion ?? "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: `bench-${name}`, version: "0" },
      };
    } else if (msg.method === "tools/list") {
      result = { tools: tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? { type: "object" } })) };
    } else if (msg.method === "tools/call") {
      const p = msg.params ?? {};
      calls.push({ backend: name, name: p.name, arguments: p.arguments ?? {} });
      result =
        mrtr && !p.inputResponses
          ? {
              resultType: "input_required",
              inputRequests: { confirm: { method: "elicitation/create", params: { message: "Confirm?", requestedSchema: { type: "object", properties: { ok: { type: "boolean" } } } } } },
              requestState: "bench-upstream-state",
            }
          : { content: [{ type: "text", text: `ran ${name}/${p.name}` }] };
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
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, close: () => new Promise((r) => server.close(() => r())) };
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

const PROTOCOL = "2025-06-18";

/** One JSON-RPC message to ToolHive; returns { status, msg, sessionId }. Notifications return msg = null. */
async function rpc(url, headers, id, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": PROTOCOL },
    body: JSON.stringify({ jsonrpc: "2.0", ...(id !== null ? { id } : {}), method, ...(params !== undefined ? { params } : {}) }),
  });
  const text = await res.text();
  const sessionId = res.headers.get("mcp-session-id");
  if (id === null) return { status: res.status, msg: null, sessionId };
  let msg;
  try {
    const messages = (res.headers.get("content-type") ?? "").includes("text/event-stream")
      ? text.split("\n").filter((l) => l.startsWith("data:")).map((l) => JSON.parse(l.slice(5)))
      : [JSON.parse(text)];
    msg = messages.find((m) => m.id === id);
  } catch {
    msg = undefined;
  }
  return { status: res.status, msg: msg ?? { error: { message: text.slice(0, 120) || `HTTP ${res.status}` } }, sessionId };
}

/**
 * `thv run` needs a reachable container runtime even for a remote URL (cmd/thv/main.go gates on it,
 * and runSingleServer builds a runtime client), although it creates no container for one. The bench
 * uses a dedicated Colima profile, `mcpbench`, and points ToolHive at that socket ONLY, through
 * TOOLHIVE_DOCKER_SOCKET (an explicit override with no fallback in pkg/container/docker/sdk). The
 * child also gets a throwaway HOME, so ToolHive cannot discover any other socket or state.
 */
const RUNTIME_SOCKET =
  process.env.MCPBENCH_TOOLHIVE_DOCKER_SOCKET ?? join(homedir(), ".colima", "mcpbench", "docker.sock");

function ensureRuntimeSocket() {
  if (!existsSync(RUNTIME_SOCKET)) {
    throw new Error(
      `ToolHive's container-runtime socket ${RUNTIME_SOCKET} is missing. thv v0.57.0 \`run\` refuses to start without ` +
        `one even for a remote URL. Start the dedicated profile: \`colima start --profile mcpbench --cpu 2 --memory 2 --disk 10\` ` +
        `(or set MCPBENCH_TOOLHIVE_DOCKER_SOCKET). The adapter does not fall back to another socket or to vMCP.`,
    );
  }
}

/**
 * Start `thv run <url> --foreground` with incoming OIDC and the Cedar authz config; resolves once the
 * proxy answers HTTP, rejects with configRejected if thv exits first.
 */
async function startToolHive(upstreamUrl, port, home, oidc, authzPath) {
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_STATE_HOME: join(home, ".state"),
    XDG_DATA_HOME: join(home, ".data"),
    XDG_CACHE_HOME: join(home, ".cache"),
    TOOLHIVE_SKIP_UPDATE_CHECK: "true",
    TOOLHIVE_DOCKER_SOCKET: RUNTIME_SOCKET,
    DOCKER_HOST: `unix://${RUNTIME_SOCKET}`,
  };
  const args = [
    "run", upstreamUrl,
    "--name", `bench-${randomBytes(4).toString("hex")}`,
    "--foreground",
    "--transport", "streamable-http",
    "--host", "127.0.0.1",
    "--proxy-port", String(port),
    "--oidc-issuer", oidc.issuer,
    "--oidc-jwks-url", oidc.jwksUrl,
    "--oidc-audience", AUDIENCE,
    "--oidc-insecure-allow-http",
    "--jwks-allow-private-ip",
    "--authz-config", authzPath,
  ];
  const child = spawn(BIN, args, { env, stdio: ["ignore", "pipe", "pipe"] });
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
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
    });
  const url = `http://127.0.0.1:${port}${new URL(upstreamUrl).pathname}`;
  for (let i = 0; i < 1200; i++) {
    if (exited !== null) {
      const why = out.split("\n").filter((l) => /error/i.test(l)).slice(0, 2).join(" ").slice(0, 240);
      throw Object.assign(new Error(`thv exited (${exited}): ${why || out.slice(-240)}`), { configRejected: true });
    }
    try {
      // Unauthenticated probe: any HTTP answer (401 from the OIDC middleware) means the proxy is up.
      const r = await fetch(url, { method: "GET" });
      await r.text();
      return { url, stop, log: () => out };
    } catch {
      /* not listening yet */
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  await stop();
  throw new Error(`thv run did not become ready: ${out.slice(-240)}`);
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
    if (e instanceof Untranslatable) return { detect: false, enforce: false, signal: `not translatable to ToolHive Cedar: ${e.message}` };
    throw e;
  }
  ensureRuntimeSocket();
  const req = input.request ?? {};
  const retry = req.retryOf === "input_required";
  const dir = mkdtempSync(join(tmpdir(), "bench-thv-"));
  const cleanups = [() => rmSync(dir, { recursive: true, force: true })];
  try {
    // One remote MCP server serving the fixture's tools under their full namespaced names, as a
    // gateway would expose them; `thv run <url>` proxies exactly one server.
    const calls = [];
    const backend = await startBackend("bench", input.tools ?? [], calls, retry);
    cleanups.push(() => backend.close());

    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "bench-k1", alg: "ES256", use: "sig" };
    const idp = await startIdp(jwk);
    cleanups.push(() => idp.close());

    const authzPath = join(dir, "authz.json");
    writeFileSync(
      authzPath,
      JSON.stringify({ version: "1.0", type: "cedarv1", cedar: { policies: translated.policies, entities_json: "[]" } }, null, 2),
    );
    const home = join(dir, "home");
    mkdirSync(home);

    let thv;
    try {
      thv = await startToolHive(backend.url, await freePort(), home, idp, authzPath);
    } catch (e) {
      if (e.configRejected) return { detect: false, enforce: false, signal: `config rejected by ToolHive: ${e.message}` };
      throw e;
    }
    cleanups.push(() => thv.stop());

    const headers = { ...lowerHeaders(req.headers), authorization: `Bearer ${callerToken(privateKey, idp.issuer, input.caller ?? {})}` };
    const init = await rpc(thv.url, headers, 1, "initialize", {
      protocolVersion: PROTOCOL,
      capabilities: {},
      clientInfo: { name: "mcp-defense-bench", version: "0" },
    });
    if (init.sessionId) headers["mcp-session-id"] = init.sessionId;
    await rpc(thv.url, headers, null, "notifications/initialized");

    const params = { name: req.name, arguments: req.arguments ?? {}, ...(req.meta ? { _meta: req.meta } : {}) };
    let judgedParams = params;
    if (retry) {
      // Round 1 (no input responses). If ToolHive lets it through, the backend's state is carried.
      const first = await rpc(thv.url, headers, 2, "tools/call", params);
      const state = first.msg?.result?.requestState;
      judgedParams = { ...params, inputResponses: req.inputResponses ?? {}, ...(state ? { requestState: state } : {}) };
    }
    const before = calls.length;
    const judged = await rpc(thv.url, headers, 3, "tools/call", judgedParams);
    const reached = calls.length > before;
    const errored = judged.status >= 400 || judged.msg?.error !== undefined || judged.msg?.result?.isError === true;
    const note = translated.notes.length ? ` [${translated.notes.join("; ")}]` : "";
    if (reached) return { detect: false, enforce: false, signal: `forwarded to upstream: HTTP ${judged.status}${note}` };
    if (!errored) return { detect: false, enforce: false, signal: `not refused (upstream not reached): HTTP ${judged.status} ${reason(judged)}${note}` };
    return { detect: true, enforce: true, signal: `refused before upstream contact: HTTP ${judged.status} ${reason(judged)}${note}` };
  } finally {
    for (const fn of cleanups.reverse()) await Promise.resolve().then(fn).catch(() => undefined);
  }
}

export async function assess(input, _testcase) {
  if (input?.type === "authorized-call") return assessAuthorized(input);
  return { detect: false, enforce: false, signal: "not wired: ToolHive is measured on authorized-call only" };
}
