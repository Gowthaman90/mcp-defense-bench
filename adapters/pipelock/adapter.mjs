/**
 * pipelock adapter — drives the tool's REAL scanner via `pipelock explain --json`.
 *
 * pipelock (Go, Apache-2.0 core) is a network/egress firewall: it decides whether a destination URL
 * is safe (SSRF, cloud-metadata, private-IP, DLP, blocklist, path traversal). `explain` runs the
 * offline, pre-DNS layers and emits a structured verdict — deterministic and safe (no network).
 *
 * Integrity rule (adapters/CONTRACT.md): pipelock inspects DESTINATIONS. So this adapter extracts the
 * URLs a fixture would cause the agent to reach (URL literals anywhere, plus a URL built from an
 * explicit host/endpoint field) and scans each. Fixtures with no destination (tool definitions,
 * registry entries, consent) are not something pipelock inspects → detect=false, honestly.
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
      `pipelock binary not found at ${bin}. See docs/ADAPTERS.md (download + checksum-verify the ` +
        `darwin/linux release into .tools/pipelock/).`,
    );
  }
  checked = true;
}

/** Every destination URL a fixture implies: URL literals + a URL built from a host/endpoint field. */
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
        // A bare outbound endpoint the agent would connect to. NB: only `endpoint` — not `host`,
        // which in these fixtures is an INBOUND local target, not an egress destination pipelock sees.
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

function scanUrl(u) {
  const res = spawnSync(bin, ["explain", "--json", u], { encoding: "utf8", timeout: 15000 });
  const out = (res.stdout || "").trim();
  if (!out) return null;
  try {
    // explain may prepend advisory lines; take the JSON object.
    const json = out.slice(out.indexOf("{"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export async function assess(input, _testcase) {
  ensureSetup();
  const urls = urlsIn(input);
  if (urls.length === 0) return { detect: false, enforce: false };

  for (const u of urls) {
    const v = scanUrl(u);
    if (v && v.allowed === false) {
      return {
        detect: true,
        enforce: true, // pipelock blocks the destination outright
        signal: `${v.scanner ?? "block"}: ${(v.reason ?? "blocked").toString().slice(0, 70)}`,
      };
    }
  }
  return { detect: false, enforce: false };
}
