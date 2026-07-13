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
  hashToolDefinition,
} = bastion;

/** bastion's argument inspection: schema validation + content scanning of argument values. */
function inspectArgs(schema, args) {
  return [...(validateArguments(schema, args) ?? []), ...(scanText(JSON.stringify(args ?? {})) ?? [])];
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
      const findings = inspectArgs(input.tool?.inputSchema, input.call?.arguments);
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false, // onSchemaViolation defaults to warn
        signal: `arg rules: ${findings.map((f) => f.rule).join(", ")}`,
      };
    }

    case "tool-call-sequence": {
      // Cross-tool exfiltration (v0.6): bastion inspects each call's arguments; a sensitive-source
      // read (e.g. ~/.ssh/id_rsa, .env) trips content scanning on that call.
      const findings = (input.calls ?? []).flatMap((c) => inspectArgs(undefined, c.arguments));
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false,
        signal: `arg rules: ${findings.map((f) => f.rule).join(", ")}`,
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
      const text = (input.result?.content ?? [])
        .filter((c) => c && c.type === "text" && typeof c.text === "string")
        .map((c) => c.text)
        .join("\n");
      const findings = scanText(text) ?? [];
      if (findings.length === 0) return { detect: false, enforce: false };
      return {
        detect: true,
        enforce: false, // onResponse defaults to warn (blocking is opt-in)
        signal: `response rules: ${findings.map((f) => f.rule).join(", ")}`,
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
      // Also run poisoning on every advertised tool.
      const poison = (input.servers ?? [])
        .flatMap((s) => s.tools ?? [])
        .flatMap((t) => scanTool(t) ?? []);
      if (shadowed || poison.length)
        return {
          detect: true,
          enforce: false,
          signal: shadowed ? "duplicate tool name across servers" : `poisoning: ${poison.map((f) => f.rule).join(", ")}`,
        };
      return { detect: false, enforce: false };
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
