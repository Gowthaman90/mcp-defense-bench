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
} = bastion;

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

    default:
      // Not inspected by bastion at runtime — honest miss.
      return { detect: false, enforce: false };
  }
}
