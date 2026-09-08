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
 * Everything else (transport, params, registry provenance, config, consent) is NOT inspected by
 * bastion at runtime, so the adapter returns {detect:false} — honestly.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

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
  sealRequestState,
  openRequestState,
} = bastion;

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
      const findings = scanText(text) ?? [];
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
