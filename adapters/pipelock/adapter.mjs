/**
 * pipelock adapter — drives the tool's REAL scanners, offline and deterministically:
 *   - `pipelock explain --json <url>`  → URL/egress verdict (SSRF, cloud-metadata, private-IP, DLP)
 *   - `pipelock mcp scan --json` (stdin) → prompt-injection scan of an MCP JSON-RPC response
 *
 * Neither needs the network or a running server. Per the integrity rule (adapters/CONTRACT.md),
 * pipelock inspects (a) destination URLs and (b) response content, so this adapter checks exactly
 * those: it extracts destination URLs from a fixture and scans them, and for tool-result fixtures it
 * wraps the returned content in an MCP response and runs pipelock's injection scanner. Fixtures with
 * neither a destination nor a scannable response (tool definitions, registry entries, consent) are
 * not something pipelock inspects here → detect=false, honestly.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

export const meta = { tool: "pipelock", class: "egress-firewall", reproducible: true };

const bin = fileURLToPath(new URL("../../.tools/pipelock/pipelock", import.meta.url));
const URL_RE = /https?:\/\/[^\s"'<>)\]]+/g;

let checked = false;
function ensureSetup() {
  if (checked) return;
  if (!existsSync(bin)) {
    throw new Error(
      `pipelock binary not found at ${bin}. See docs/ADAPTERS.md (download + checksum-verify the release into .tools/pipelock/).`,
    );
  }
  checked = true;
}

/** Destination URLs a fixture implies: URL literals + a URL built from an outbound `endpoint` field. */
function urlsIn(input) {
  const found = new Set();
  const walk = (v) => {
    if (typeof v === "string") {
      const m = v.match(URL_RE);
      if (m) m.forEach((u) => found.add(u));
    } else if (Array.isArray(v)) {
      v.forEach(walk);
    } else if (v && typeof v === "object") {
      for (const [k, val] of Object.entries(v)) {
        if (k === "endpoint" && typeof val === "string" && !/^https?:\/\//.test(val)) {
          found.add(`http://${val}`);
        }
        walk(val);
      }
    }
  };
  walk(input);
  return [...found];
}

/** Scan one URL through pipelock's offline SSRF/DLP/egress layers. */
function scanUrl(u) {
  const res = spawnSync(bin, ["explain", "--json", u], { encoding: "utf8", timeout: 15000 });
  const out = (res.stdout || "").trim();
  if (!out) return null;
  try {
    return JSON.parse(out.slice(out.indexOf("{")));
  } catch {
    return null;
  }
}

/** Run pipelock's MCP prompt-injection scanner over a tool result's returned content. */
function scanResponse(input) {
  const content = input.result?.content;
  if (!Array.isArray(content)) return null;
  const rpc = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content } });
  const res = spawnSync(bin, ["mcp", "scan", "--json"], { input: rpc + "\n", encoding: "utf8", timeout: 15000 });
  const line = (res.stdout || "").trim().split("\n").filter((l) => l.startsWith("{")).pop();
  if (!line) return null;
  try {
    return JSON.parse(line); // { clean, action, matches }
  } catch {
    return null;
  }
}

export async function assess(input, _testcase) {
  ensureSetup();

  // (a) Destination/egress scanning — a blocked URL is an outright enforce.
  for (const u of urlsIn(input)) {
    const v = scanUrl(u);
    if (v && v.allowed === false) {
      return { detect: true, enforce: true, signal: `${v.scanner ?? "block"}: ${(v.reason ?? "blocked").toString().slice(0, 60)}` };
    }
  }

  // (b) Response content scanning — prompt injection in a tool result.
  if (input.type === "malicious-tool-result" || input.type === "benign-tool-result") {
    const v = scanResponse(input);
    if (v && v.clean === false) {
      const enforce = v.action === "block" || v.action === "strip";
      const rules = (v.matches ?? []).map((m) => m.pattern_name).join(", ");
      return { detect: true, enforce, signal: `mcp-injection: ${rules || v.action}` };
    }
  }

  return { detect: false, enforce: false };
}
