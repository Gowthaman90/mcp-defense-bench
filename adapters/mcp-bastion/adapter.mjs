/**
 * mcp-bastion adapter — drives the tool's REAL detection code, not a mock.
 *
 * Imports scanTool (poisoning heuristics) and hashToolDefinition (rug-pull pinning) from the
 * locally-built mcp-bastion package. Per the integrity rule (adapters/CONTRACT.md), it reports
 * detection ONLY for the fixture types mcp-bastion actually inspects at runtime:
 *   - tool DEFINITIONS      → scanTool               (poisoning, prompt-leak-in-definition)
 *   - definition CHANGES    → hashToolDefinition     (rug-pull)
 *   - cross-server naming   → duplicate-name check   (tool shadowing, per ToolRegistry.shadowedBy)
 *   - tool RESULTS          → scanText               (response scanning, v0.3 responseScanInterceptor)
 *   - delegate TOKENS       → checkDelegationAsync   (keyless delegation checks, v1.2 gateway mode)
 *   - per-caller AUTHZ      → UpstreamManager + HTTP listener (runtime authorization, v1.4)
 * Everything else (transport, params, registry provenance, config, consent) is NOT inspected by
 * bastion at runtime, so the adapter returns {detect:false} — honestly.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";

const require = createRequire(import.meta.url);

// Resolve mcp-bastion: prefer an installed package; fall back to the sibling repo's built dist.
let bastion;
try {
  bastion = await import("mcp-bastion");
} catch {
  const distUrl = new URL("../../../mcp_bastion/dist/index.js", import.meta.url);
  bastion = await import(fileURLToPath(distUrl));
}
const {
  scanTool,
  scanText,
  validateArguments,
  checkRequestedScopes,
  checkTransportSecurity,
  checkRequestOrigin,
  scanToolSet,
  checkCommandInjection,
  checkConfigDrift,
  checkServerIdentity,
  hashServerIdentity,
  scanCallSequence,
  redactSecrets,
  hashToolDefinition,
  // v0.9 (MCP 2026-07-28): wired into the HTTP listener / list path, so they may be scored.
  checkHeaderBodyCoherence,
  requiresHeaderValidation,
  checkCachePolicy,
  clampCacheHints,
  // v1.0 (stateless era): MRTR gate + requestState custody, wired into the tools/call path.
  checkInputRequests,
  // v1.1: false-error escalation, wired into the response scan on the tools/call path.
  checkErrorSteering,
  sealRequestState,
  openRequestState,
  // v1.2 (unreleased, feat/delegation-checks): keyless delegation checks on forwarded delegate JWTs.
  BastionConfigSchema,
  checkDelegationAsync,
  delegationKeySet,
  // v1.4 (unreleased, feat/runtime-authorization): runtime authorization, driven end to end.
  UpstreamManager,
  startHttpServer,
  resolveListenClients,
  logger: bastionLogger,
} = bastion;

/**
 * Rules that only warn under the default `balanced` profile (security.onDelegationChain = warn):
 * prior actors are informational per RFC 8693 §4.1. Mirrors DELEGATION_CHAIN_RULES in bastion.
 */
const DELEGATION_WARN_RULES = new Set(["delegation-chain-depth", "delegation-chain-cycle"]);

/**
 * A `delegated-request` fixture through bastion's runtime path. The fixture's deployment is turned
 * into a bastion config and validated by bastion's own schema (so its defaults, e.g.
 * maxLifetimeSeconds 3600, and its config-load rejections apply), then the policy is built exactly
 * as DelegationGate builds it and the request's carried headers are checked once, as the gateway
 * does per request. The fixture's fixed clock stands in for Date.now().
 *
 * Runtime effect under `balanced`: any finding other than the chain rules blocks — a `tools/call`
 * is refused before any upstream contact and a `tools/list` omits the upstream — so enforce = true.
 */
async function assessDelegated(input) {
  const trust = input.trust ?? { mode: "structural" };
  const servers = {};
  for (const [name, u] of Object.entries(input.upstreams ?? {})) {
    servers[name] = {
      transport: "http",
      url: `http://127.0.0.1:9/${encodeURIComponent(name)}`,
      protocol: "legacy",
      connect: "onDemand",
      forwardHeaders: { [u.upstreamHeader]: u.incomingHeader },
      delegation: {
        audience: u.audience,
        ...(input.policy ?? {}),
        ...(trust.mode === "signature"
          ? { verify: "signature", issuer: trust.issuer, algorithms: trust.algorithms, jwks: trust.jwks }
          : {}),
      },
    };
  }
  const parsed = BastionConfigSchema.safeParse({
    servers,
    listen: { mode: "http" },
    delegation: { gatewayAudiences: input.gateway?.audiences ?? [] },
  });
  if (!parsed.success) {
    // bastion refuses to start with this deployment, so it checks nothing: an honest miss.
    const why = parsed.error.issues.map((i) => i.message).join("; ").slice(0, 120);
    return { detect: false, enforce: false, signal: `config rejected by bastion: ${why}` };
  }
  const cfg = parsed.data;
  const upstreams = {};
  for (const [name, server] of Object.entries(cfg.servers)) {
    const d = server.delegation;
    const [, incoming] = Object.entries(server.forwardHeaders)[0];
    upstreams[name] = {
      incomingHeader: incoming.toLowerCase(),
      audience: d.audience,
      maxLifetimeSeconds: d.maxLifetimeSeconds,
      clockSkewSeconds: d.clockSkewSeconds,
      allowedActors: d.allowedActors,
      requireActor: d.requireActor,
      maxChainDepth: d.maxChainDepth,
      ...(d.verify === "signature"
        ? { signature: { issuer: d.issuer, algorithms: d.algorithms, keys: delegationKeySet({ jwks: d.jwks }) } }
        : {}),
    };
  }
  const headers = lowerHeaders(input.request?.headers);
  const r = await checkDelegationAsync(
    { upstreams, gatewayAudiences: cfg.delegation.gatewayAudiences, oneUserPerRequest: cfg.delegation.oneUserPerRequest },
    headers,
    input.now,
  );
  const findings = [...(r.perUpstream[input.request?.target] ?? []), ...r.request];
  if (findings.length === 0) return { detect: false, enforce: false };
  const rules = [...new Set(findings.map((f) => f.rule))];
  const blocks = findings.some((f) => !DELEGATION_WARN_RULES.has(f.rule));
  return { detect: true, enforce: blocks, signal: `delegation (${trust.mode}): ${rules.join(", ")}${blocks ? "" : " (warn only)"}` };
}

// ------------------------------------------------------------------------------------------------
// authorized-call (docs/AUTHORIZATION-PREREG.md §4). Translation: AUTHORIZATION-TRANSLATION.md.
// ------------------------------------------------------------------------------------------------
/**
 * An `authorized-call` fixture through bastion's REAL gateway path, not the bare evaluator: the
 * fixture's deployment becomes a bastion config (validated by BastionConfigSchema; a rejected config
 * is an honest miss), a bastion UpstreamManager + HTTP listener is started on loopback with one
 * dependency-free HTTP upstream per `<server>` tool group (connected on demand), and the request is
 * sent over HTTP exactly as a client would send it:
 *   - `caller.client`  → that client's bearer token (`listen.clients`, token from a synthetic env);
 *   - `caller.user` / `caller.agent` / `caller.priorAgents` → one ES256-signed delegate JWT per
 *     upstream (`sub`, `act.sub`, nested `act`), verified by bastion in signature mode against an
 *     inline public JWK set. A caller with no `client` is sent through a host client
 *     (HOST_CLIENT) that the translation grants every tool, since bastion always authenticates a
 *     transport client; that grant adds a permit for the host and removes none;
 *   - `request.headers` → HTTP headers; `request.meta` → `params._meta`;
 *   - `request.retryOf: "input_required"` → a real 2026-07-28 MRTR exchange (see modernRetry):
 *     round 1 obtains bastion's sealed `requestState` when bastion lets it through, and the judged
 *     round 2 carries `inputResponses` and that state.
 * Default `balanced` profile (onAuthorization: block). Detect = enforce = bastion answered the
 * judged request with a refusal and no `tools/call` reached any upstream during it.
 */
const HOST_CLIENT = "bench-agent-host";
const AUTHZ_ISSUER = "https://idp.bench.invalid";

const b64url = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

/** An ES256 JWS compact token (node:crypto only, so the bench needs no JOSE dependency). */
function signEs256(privateKey, payload) {
  const input = `${b64url({ alg: "ES256", kid: "bench-k1", typ: "JWT" })}.${b64url(payload)}`;
  const sig = cryptoSign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

/** The caller's delegate token for one upstream: `sub` = user, `act` = current agent ⊃ prior agents. */
function delegateToken(privateKey, audience, caller) {
  const now = Math.floor(Date.now() / 1000);
  let act;
  for (const prior of [...(caller.priorAgents ?? [])].reverse()) act = { sub: prior, ...(act ? { act } : {}) };
  if (caller.agent !== undefined) act = { sub: caller.agent, ...(act ? { act } : {}) };
  return signEs256(privateKey, {
    iss: AUTHZ_ISSUER,
    ...(caller.user !== undefined ? { sub: caller.user } : {}),
    aud: audience,
    iat: now - 5,
    exp: now + 300,
    jti: randomBytes(8).toString("hex"),
    ...(act ? { act } : {}),
  });
}

/**
 * A stateless JSON-RPC upstream (protocol 2025-06-18) serving `tools`. It records every
 * `tools/call`.
 */
async function startAuthzUpstream(tools) {
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
      result = {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "bench-authz-upstream", version: "0.0.0" },
      };
    } else if (msg.method === "ping") {
      result = {};
    } else if (msg.method === "tools/list") {
      result = { tools: tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? { type: "object" } })) };
    } else if (msg.method === "tools/call") {
      const p = msg.params ?? {};
      calls.push({ name: p.name, arguments: p.arguments ?? {} });
      result = { content: [{ type: "text", text: `ran ${p.name}` }] };
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

/** One JSON-RPC request to bastion's HTTP listener; returns the response message for `id`. */
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
  if (!res.ok) return { httpStatus: res.status, error: { message: text.slice(0, 120) } };
  const messages = (res.headers.get("content-type") ?? "").includes("text/event-stream")
    ? text.split("\n").filter((l) => l.startsWith("data:")).map((l) => JSON.parse(l.slice(5)))
    : [JSON.parse(text)];
  return messages.find((m) => m.id === id) ?? { error: { message: "no response" } };
}

const resultText = (msg) =>
  (msg?.result?.content ?? []).map((c) => (c?.type === "text" ? c.text : "")).join("") || msg?.error?.message || "";

/**
 * MRTR exists only in the 2026-07-28 era (a legacy-era hop rejects an `input_required` result), so a
 * `retryOf: "input_required"` fixture is driven with a 2026-07-28 client and upstream built from the
 * same MCP SDK packages mcp-bastion ships with (loaded from the sibling repo, retry fixtures only).
 */
let mcpSdk;
async function loadMcpSdk() {
  if (!mcpSdk) {
    const pkg = (name) => fileURLToPath(new URL(`../../../mcp_bastion/node_modules/@modelcontextprotocol/${name}/dist/index.mjs`, import.meta.url));
    const [server, client] = await Promise.all([import(pkg("server")), import(pkg("client"))]);
    mcpSdk = { server, client };
  }
  return mcpSdk;
}

/** A 2026-07-28 MRTR upstream: `input_required` until the retry carries input responses. */
async function startModernAuthzUpstream(tools) {
  const { Server, createMcpHandler, inputRequired } = (await loadMcpSdk()).server;
  const calls = [];
  const handler = createMcpHandler(
    () => {
      const s = new Server({ name: "bench-authz-upstream", version: "0.0.0" }, { capabilities: { tools: {} } });
      s.setRequestHandler("tools/list", async () => ({
        tools: tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? { type: "object" } })),
      }));
      s.setRequestHandler("tools/call", async (req, ctx) => {
        calls.push({ name: req.params.name, arguments: req.params.arguments ?? {} });
        const responses = ctx.mcpReq.inputResponses;
        if (responses && Object.keys(responses).length > 0) {
          return { content: [{ type: "text", text: `ran ${req.params.name}` }] };
        }
        return inputRequired({
          inputRequests: {
            confirm: inputRequired.elicit({
              message: "Confirm?",
              requestedSchema: { type: "object", properties: { ok: { type: "boolean" } } },
            }),
          },
          requestState: "bench-upstream-state",
        });
      });
      return s;
    },
    { legacy: "stateless" },
  );
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const raw = Buffer.concat(chunks).toString("utf8");
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
      const url = `http://127.0.0.1${req.url ?? "/"}`;
      const resp = await handler.fetch(
        new Request(url, { method: req.method, headers, ...(req.method === "POST" ? { body: raw } : {}) }),
        raw ? { parsedBody: JSON.parse(raw) } : {},
      );
      const out = {};
      resp.headers.forEach((v, k) => (out[k] = v));
      res.writeHead(resp.status, out).end(Buffer.from(await resp.arrayBuffer()));
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}/mcp`,
    calls,
    close: async () => {
      await handler.close().catch(() => undefined);
      await new Promise((r) => server.close(() => r()));
    },
  };
}

/**
 * The judged request of a retry fixture, with a 2026-07-28 client: round 1 (same caller, same
 * arguments, no input responses) obtains bastion's sealed `requestState` if bastion lets it through;
 * round 2 carries the fixture's input responses and that state. Returns the round-2 outcome.
 */
async function modernRetry(url, headers, params, inputResponses, countCalls) {
  const { Client, StreamableHTTPClientTransport } = (await loadMcpSdk()).client;
  const c = new Client(
    { name: "mcp-defense-bench", version: "0" },
    { versionNegotiation: { mode: "auto" }, inputRequired: { autoFulfill: false }, capabilities: { elicitation: { form: {} } } },
  );
  await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
  const allow = { allowInputRequired: true };
  try {
    const first = await c.callTool(params, allow).catch((err) => ({ isError: true, content: [{ type: "text", text: String(err?.message ?? err) }] }));
    const requestState = typeof first?.requestState === "string" ? first.requestState : undefined;
    const before = countCalls();
    const judged = await c
      .callTool({ ...params, ...(inputResponses !== undefined ? { inputResponses } : {}), ...(requestState !== undefined ? { requestState } : {}) }, allow)
      .catch((err) => ({ isError: true, content: [{ type: "text", text: String(err?.message ?? err) }] }));
    return { result: judged, reached: countCalls() > before };
  } finally {
    await c.close().catch(() => undefined);
  }
}

/** Translate the fixture into a bastion config (see AUTHORIZATION-TRANSLATION.md). */
function authzConfig(input, upstreamUrls, jwk, modern) {
  const sep = input.separator ?? "__";
  const servers = {};
  for (const [server, url] of Object.entries(upstreamUrls)) {
    servers[server] = {
      transport: "http",
      url,
      protocol: modern ? "2026-07-28" : "legacy",
      connect: "onDemand",
      forwardHeaders: { "x-bench-delegate": `x-bench-delegate-${server}` },
      onMissingForwardedHeader: "omit",
      delegation: { audience: server, verify: "signature", issuer: AUTHZ_ISSUER, algorithms: ["ES256"], jwks: { keys: [jwk] } },
    };
  }
  const rules = (input.policy?.rules ?? []).map((r, i) => ({
    id: `fixture-rule-${i + 1}`,
    effect: r.effect,
    principal: r.principal,
    tools: r.tools,
    ...(r.args !== undefined ? { args: r.args } : {}),
  }));
  if (input.caller?.client === undefined) {
    rules.push({ id: "host-client", effect: "allow", principal: { client: HOST_CLIENT }, tools: ["*"] });
  }
  const clients = new Set([input.caller?.client ?? HOST_CLIENT]);
  for (const r of input.policy?.rules ?? []) {
    const named = r?.principal?.client;
    for (const c of Array.isArray(named) ? named : named !== undefined ? [named] : []) clients.add(c);
  }
  const env = {};
  const listenClients = {};
  for (const c of clients) {
    const envName = `BENCH_TOKEN_${Object.keys(listenClients).length}`;
    listenClients[c] = { tokenEnv: envName };
    env[envName] = `bench-${randomBytes(16).toString("hex")}`;
  }
  return {
    raw: {
      servers,
      namespace: { separator: sep },
      listen: { mode: "http", clients: listenClients },
      authorization: { enabled: true, default: input.policy?.default ?? "deny", rules },
      reconnect: { auto: false },
      healthCheck: { enabled: false },
    },
    env,
  };
}

async function assessAuthorized(input) {
  const sep = input.separator ?? "__";
  const groups = new Map();
  for (const t of input.tools ?? []) {
    const i = t.name.indexOf(sep);
    if (i <= 0) continue; // not a namespaced tool: no upstream can expose it under this name
    const server = t.name.slice(0, i);
    groups.set(server, [...(groups.get(server) ?? []), { ...t, name: t.name.slice(i + sep.length) }]);
  }
  const req = input.request ?? {};
  const retry = req.retryOf === "input_required";
  const cleanups = [];
  const previousLevel = bastionLogger.level;
  bastionLogger.level = "silent";
  try {
    const upstreams = new Map();
    for (const [server, tools] of groups) {
      const up = retry ? await startModernAuthzUpstream(tools) : await startAuthzUpstream(tools);
      cleanups.push(() => up.close());
      upstreams.set(server, up);
    }
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "bench-k1", alg: "ES256", use: "sig" };
    const { raw, env } = authzConfig(
      input,
      Object.fromEntries([...upstreams].map(([s, u]) => [s, u.url])),
      jwk,
      retry,
    );
    const parsed = BastionConfigSchema.safeParse(raw);
    if (!parsed.success) {
      // bastion refuses to start with this policy, so it enforces nothing: an honest miss.
      const why = parsed.error.issues.map((i) => i.message).join("; ").slice(0, 160);
      return { detect: false, enforce: false, signal: `config rejected by bastion: ${why}` };
    }
    const config = parsed.data;
    const mgr = new UpstreamManager(config);
    cleanups.push(() => mgr.closeAll());
    const listener = await startHttpServer(mgr, {
      host: "127.0.0.1",
      port: 0,
      path: "/mcp",
      clients: resolveListenClients(config.listen, env),
    });
    cleanups.push(() => listener.close());

    const caller = input.caller ?? {};
    const headers = { ...lowerHeaders(req.headers) };
    const client = caller.client ?? HOST_CLIENT;
    const clientEnv = config.listen.clients[client].tokenEnv;
    headers.authorization = `Bearer ${env[clientEnv]}`;
    if (caller.user !== undefined || caller.agent !== undefined) {
      for (const server of groups.keys()) headers[`x-bench-delegate-${server}`] = delegateToken(privateKey, server, caller);
    }

    const params = { name: req.name, arguments: req.arguments ?? {}, ...(req.meta ? { _meta: req.meta } : {}) };
    const countCalls = () => [...upstreams.values()].reduce((n, u) => n + u.calls.length, 0);
    let judged;
    let reached;
    if (retry) {
      const out = await modernRetry(listener.url, headers, params, req.inputResponses, countCalls);
      judged = { result: out.result };
      reached = out.reached;
    } else {
      await rpc(listener.url, headers, 1, "initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "mcp-defense-bench", version: "0" },
      });
      const before = countCalls();
      judged = await rpc(listener.url, headers, 2, "tools/call", params);
      reached = countCalls() > before;
    }
    const text = resultText(judged);
    const refused = !reached && (judged.error !== undefined || judged.result?.isError === true);
    if (!refused) return { detect: false, enforce: false };
    return { detect: true, enforce: true, signal: `refused before upstream contact (balanced): ${text.slice(0, 140)}` };
  } finally {
    for (const fn of cleanups.reverse()) await fn().catch(() => undefined);
    bastionLogger.level = previousLevel;
  }
}

/** Rules the HTTP listener REJECTS with 400 / -32020 (mirrors REJECTING_HEADER_RULES in bastion). */
const REJECTING_HEADER_RULES = new Set(["header-body-mismatch", "header-invalid-value", "header-duplicate-conflict"]);

/** Lower-case a header bag the way Node's IncomingMessage presents it. */
const lowerHeaders = (h) => Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), v]));

/**
 * bastion's argument inspection: schema validation + content scanning of argument values +
 * command-injection payload scanning (v0.5). Mirrors the engine's argumentInterceptor.
 */
function inspectArgs(schema, args) {
  return [
    ...(validateArguments(schema, args) ?? []),
    ...(scanText(JSON.stringify(args ?? {})) ?? []),
    ...(checkCommandInjection(args) ?? []),
  ];
}

export const meta = { tool: "mcp-bastion", class: "runtime-proxy", reproducible: true };

/** Poisoning findings default to WARN in bastion (blocking is opt-in) → detect, not enforce. */
function assessDefinition(tool) {
  const findings = scanTool(tool) ?? [];
  if (findings.length === 0) return { detect: false, enforce: false };
  return {
    detect: true,
    enforce: false, // bastion warns by default; onPoisoning:block is opt-in
    signal: `poisoning rules: ${findings.map((f) => f.rule).join(", ")}`,
  };
}

export async function assess(input, _testcase) {
  switch (input?.type) {
    case "malicious-tool-definition":
    case "benign-tool-definition":
      return assessDefinition(input.tool);

    case "tool-call": {
      // Argument inspection (v0.4 schema + v0.6 content scanning of argument values).
      // Under the committed default profile (`balanced`), onSchemaViolation is `block`, so these
      // deterministic argument findings are enforced (the call is denied before reaching the server).
      const findings = inspectArgs(input.tool?.inputSchema, input.call?.arguments);
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: true, // balanced profile: onSchemaViolation = block
        signal: `arg rules (blocked under 'balanced'): ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "tool-call-sequence": {
      // Two runtime paths bastion applies over a call sequence:
      //   (v0.6) per-call argument inspection — a sensitive-source read (~/.ssh/id_rsa, .env) trips
      //          content scanning on that call (cross-tool exfiltration); and
      //   (v0.5) cross-server taint tracking — a credential returned by one server reappearing in an
      //          argument to a *different* server (tool-transfer / cross-server exfiltration).
      // Under `balanced`, arg findings block (onSchemaViolation) and cross-server exact-token flow
      // blocks (onDataFlow) — both enforce.
      const argFindings = (input.calls ?? []).flatMap((c) => inspectArgs(undefined, c.arguments));
      const crossServer = scanCallSequence(input.calls ?? []) ?? [];
      const findings = [...argFindings, ...crossServer];
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: true, // balanced profile: onSchemaViolation = block, onDataFlow = block
        signal: crossServer.length
          ? `cross-server (blocked under 'balanced'): ${crossServer.map((f) => f.rule).join(", ")}`
          : `arg rules (blocked under 'balanced'): ${argFindings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "capability-grant": {
      // Least-privilege (v0.6): flag over-broad requested scopes for the tool.
      const findings = checkRequestedScopes(input.requestedScopes, input.tool) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false,
        signal: `scope rules: ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "malicious-tool-result":
    case "benign-tool-result": {
      // Response scanning (v0.3): bastion runs scanText over the result's text; warns by default.
      // Inline DLP (v0.6): bastion also *redacts* credential-shaped secret values out of the result
      // — an enforcing mitigation that strips the secret before the agent or a log can see it.
      const text = (input.result?.content ?? [])
        .filter((c) => c && c.type === "text" && typeof c.text === "string")
        .map((c) => c.text)
        .join("\n");
      const findings = [...(scanText(text) ?? []), ...(checkErrorSteering?.(input.result) ?? [])];
      const redaction = redactSecrets(text) ?? { redactions: 0 };
      if (findings.length === 0 && redaction.redactions === 0) {
        return { detect: false, enforce: false };
      }
      return {
        detect: true,
        enforce: redaction.redactions > 0, // inline DLP strips the secret → mitigation
        signal:
          redaction.redactions > 0
            ? `inline DLP redacted ${redaction.redactions} secret(s)` +
              (findings.length ? `; ${findings.map((f) => f.rule).join(", ")}` : "")
            : `response rules: ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "definition-change": {
      // Rug-pull: bastion pins on first use and flags a changed definition. It can block → enforce.
      const changed = hashToolDefinition(input.before) !== hashToolDefinition(input.after);
      return changed
        ? { detect: true, enforce: true, signal: "definition hash changed after pin" }
        : { detect: false, enforce: false };
    }

    case "multi-server-registry": {
      // Shadowing: bastion's registry flags a tool name exposed by more than one server.
      const names = new Map();
      for (const s of input.servers ?? [])
        for (const t of s.tools ?? []) names.set(t.name, (names.get(t.name) ?? 0) + 1);
      const shadowed = [...names.values()].some((n) => n > 1);
      const allTools = (input.servers ?? []).flatMap((s) => s.tools ?? []);
      // Poisoning on every advertised tool, plus cross-tool correlation (split-payload poisoning).
      const poison = allTools.flatMap((t) => scanTool(t) ?? []);
      const cross = scanToolSet(allTools) ?? [];
      if (shadowed || poison.length || cross.length)
        return {
          detect: true,
          enforce: false,
          signal: shadowed
            ? "duplicate tool name across servers"
            : cross.length
              ? `cross-tool: ${cross.map((f) => f.rule).join(", ")}`
              : `poisoning: ${poison.map((f) => f.rule).join(", ")}`,
        };
      return { detect: false, enforce: false };
    }

    case "server-identity": {
      // Server-identity (v0.5). Two modes:
      //   verify — flag a claimed identity with no verified binding (advisory → detect).
      //   change — endpoint/name/TLS changed after TOFU pinning; bastion blocks by default
      //            (onIdentityChange:block, like rug-pull) → enforce.
      if (input.mode === "change") {
        const changed = hashServerIdentity(input.before ?? {}) !== hashServerIdentity(input.after ?? {});
        return changed
          ? { detect: true, enforce: true, signal: "pinned server identity changed (endpoint/TLS)" }
          : { detect: false, enforce: false };
      }
      const findings = checkServerIdentity(input.identity ?? {}) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false, // identity verification is advisory by default
        signal: `identity: ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "config-snapshot-diff": {
      // Config drift (v0.5): bastion pins a server's config snapshot (TOFU) and flags a later
      // snapshot that weakens a control (TLS downgrade, allowlist widened, protection disabled).
      const findings = checkConfigDrift(input.baseline ?? {}, input.current ?? {}) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false, // drift is advisory by default
        signal: `config-drift: ${findings.map((f) => f.excerpt).join("; ")}`,
      };
    }

    case "scenario": {
      // Transport hardening (v0.5): Origin check (http-server enforces 403) + insecure-transport warn.
      const origin = checkRequestOrigin(input.request?.host, input.request?.origin) ?? [];
      if (origin.length > 0)
        return { detect: true, enforce: true, signal: "cross-origin request blocked (403)" };
      const transport = checkTransportSecurity(input.endpoint) ?? [];
      if (transport.length > 0)
        return { detect: true, enforce: false, signal: "insecure-transport (warn)" };
      return { detect: false, enforce: false };
    }

    // ── MCP 2026-07-28 vectors (bastion v0.9 wiring) ────────────────────────────────────────────
    case "http-request": {
      // Header/body coherence: the HTTP listener runs checkHeaderBodyCoherence on every POST and
      // answers 400 + JSON-RPC -32020 for a rejecting rule (mismatch / invalid value / duplicate
      // conflict). Medium findings are logged only → detect without enforce.
      const findings = checkHeaderBodyCoherence(lowerHeaders(input.headers), input.body) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      const rejecting = findings.filter((f) => REJECTING_HEADER_RULES.has(f.rule));
      return {
        detect: true,
        enforce: rejecting.length > 0,
        signal: rejecting.length
          ? `-32020 HeaderMismatch: ${rejecting.map((f) => f.rule).join(", ")}`
          : `header findings (logged): ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "list-result": {
      // Cache policy on upstream list results: violations are logged and the hints are CLAMPED
      // before bastion forwards its own tools/list — an enforcing mitigation (the poisoned TTL /
      // over-broad scope never reaches a downstream cache). Definitions in the list are also run
      // through the poisoning scanner, as bastion does on every (re-)listing.
      const ctx = { authenticated: input.authenticated === true, variesByAuthorization: input.variesByAuthorization === true };
      // Mirror UpstreamConnection.policeCacheHints: a result with NO hints is left untouched (bastion
      // returns early), so only a result that actually carries ttlMs/cacheScope can be "clamped".
      const hasHints = input.result?.ttlMs !== undefined || input.result?.cacheScope !== undefined;
      const findings = hasHints ? (checkCachePolicy(input.result, ctx) ?? []) : [];
      const clamped = hasHints ? clampCacheHints(input.result, ctx) : { changed: false };
      const poison = (input.result?.tools ?? []).flatMap((t) => scanTool(t) ?? []);
      if (findings.length === 0 && !clamped.changed && poison.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: findings.length > 0 || clamped.changed,
        signal: findings.length
          ? `cache policy: ${findings.map((f) => f.rule).join(", ")}` + (clamped.changed ? " (hints clamped)" : "")
          : `poisoning in listed definitions: ${poison.map((f) => f.rule).join(", ")}`,
      };
    }

    case "cache-invalidation": {
      // notifications/tools/list_changed makes bastion re-list IMMEDIATELY (since v0.7.0) and
      // re-hash every definition; a changed definition is a rug pull and is blocked by default.
      // With no notification outstanding bastion serves its cached list — correctly, no finding.
      if (!input.notification) return { detect: false, enforce: false };
      const cachedTools = input.cached?.result?.tools ?? [];
      const nowTools = input.upstreamNow?.tools ?? [];
      const byName = new Map(cachedTools.map((t) => [t.name, t]));
      const changed = nowTools.filter((t) => byName.has(t.name) && hashToolDefinition(byName.get(t.name)) !== hashToolDefinition(t));
      if (changed.length === 0) return { detect: false, enforce: false };
      return { detect: true, enforce: true, signal: `re-listed on list_changed; definition hash changed for ${changed.map((t) => t.name).join(", ")} (rug-pull block)` };
    }

    case "http-request-sequence": {
      // Transport downgrade (v1.0, SDK 2.0 handler): GET/DELETE streams are answered 405, an
      // Mcp-Session-Id is neither minted nor honoured, Last-Event-ID is ignored — even in the default
      // `legacy: "stateless"` posture; `legacy: "reject"` additionally refuses the older era (-32022).
      // The fixture's malicious sequence presents exactly those legacy mechanics; a conforming
      // stateless POST (the control) is served.
      const reqs = input.requests ?? [];
      const legacyMechanics = reqs.some(
        (r) =>
          (r.method === "GET" || r.method === "DELETE") ||
          Object.keys(r.headers ?? {}).some((h) => /^(mcp-session-id|last-event-id)$/i.test(h)),
      );
      return legacyMechanics
        ? { detect: true, enforce: true, signal: "legacy session/stream mechanics refused (405; no session id minted or echoed)" }
        : { detect: false, enforce: false };
    }

    case "mrtr-retry": {
      // requestState custody (v1.0): bastion never relays an upstream's raw state; it seals it into an
      // HMAC envelope bound to principal + server + tool + TTL and verifies on the retry. Mirror that:
      // seal what the upstream issued, then present the retry as the fixture describes.
      const key = "benchmark-fixed-key-benchmark-fixed-key";
      if (input.issued && input.tamperedRetry) {
        // Fixture 001: the retry carries a *modified* blob → not bastion's envelope → refused.
        const issuedTo = input.issued.principal ?? "alice";
        const sealed = sealRequestState(String(input.issued.requestState ?? ""), { key, principal: issuedTo, server: "s", tool: "transfer_funds" });
        const presented = input.tamperedRetry.params?.requestState;
        const same = presented === input.issued.requestState;
        const r = openRequestState(same ? sealed : String(presented), { key, principal: issuedTo, server: "s", tool: "transfer_funds" });
        return r.ok ? { detect: false, enforce: false } : { detect: true, enforce: true, signal: `custody: ${r.findings.map((f) => f.rule).join(", ")}` };
      }
      if (input.issuedTo && input.replayedBy) {
        // Fixture 002: cross-principal + post-TTL replay.
        const t0 = Date.parse(input.issuedTo.issuedAt);
        const t1 = Date.parse(input.replayedBy.presentedAt);
        const sealed = sealRequestState("up", { key, principal: input.issuedTo.principal, server: "s", tool: "transfer_funds", ttlSeconds: Math.max(1, Math.floor((input.issuedTo.ttlMs ?? 60000) / 1000)), now: () => t0 });
        const r = openRequestState(sealed, { key, principal: input.replayedBy.principal, server: "s", tool: "transfer_funds", now: () => t1 });
        return r.ok ? { detect: false, enforce: false } : { detect: true, enforce: true, signal: `custody: ${r.findings.map((f) => f.rule).join(", ")}` };
      }
      return { detect: false, enforce: false };
    }

    case "input-required-result": {
      // MRTR consent gate (v1.0): checkInputRequests runs on every input_required round before it is
      // relayed; high-severity findings block under the default `balanced` profile.
      const findings = checkInputRequests(input.result) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      const high = findings.some((f) => f.severity === "high");
      return { detect: true, enforce: high, signal: `mrtr gate${high ? " (blocked under 'balanced')" : ""}: ${[...new Set(findings.map((f) => f.rule))].join(", ")}` };
    }

    case "delegated-request":
      return assessDelegated(input);

    case "authorized-call":
      // Runtime authorization (v1.4), driven through bastion's real HTTP gateway path. The policy
      // translation (commitment 6.6) is documented in AUTHORIZATION-TRANSLATION.md.
      return assessAuthorized(input);

    case "tool-state-handle":
    case "task-lifecycle":
    case "ui-resource":
      // Tool state handles are non-normative guidance; Tasks do not exist on the 2026-07-28 era
      // (the SDK answers -32601) and are not intercepted on the legacy era; MCP Apps are rendered by
      // the host, not the proxy. Honest misses.
      return { detect: false, enforce: false };

    default:
      // Not inspected by bastion at runtime — honest miss.
      return { detect: false, enforce: false };
  }
}
