/**
 * mcp-firewall adapter — drives the tool's REAL Python SDK via its probe.
 *
 * mcp-firewall (Python, AGPL-3.0) is installed in .tools/mcpfw-venv (see docs/ADAPTERS.md setup).
 * Each assess() runs probe_server.py once, passing the fixture on stdin and reading a verdict line.
 * The probe maps the fixture to Gateway.check() / Gateway.scan_response() using the committed
 * mcp-firewall.yaml, so the score reflects the tool's actual configured behavior — not a mock.
 * (~0.1s/call → a full 22-vector run is a few seconds; simple and deadlock-free.)
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

/**
 * mcp-firewall 0.1.0 has per-agent RBAC (`agents: { <id>: { allow, deny } }`), reachable through its Python SDK (`check(agent=...)`); its stdio proxy never sets an agent id. Commitment 6.5 of docs/AUTHORIZATION-PREREG.md allows `detect:false` only after confirming a peer has no per-caller authorization, so `authorized-call` stays unknown until a real SDK-path adapter is built (by an implementer blind to the held-out set).
 */
export const meta = { tool: "mcp-firewall", class: "runtime-proxy", reproducible: true, unwiredFixtureTypes: ["authorized-call"] };

const venvPython = fileURLToPath(new URL("../../.tools/mcpfw-venv/bin/python", import.meta.url));
const probe = fileURLToPath(new URL("./probe_server.py", import.meta.url));

let checked = false;
function ensureSetup() {
  if (checked) return;
  if (!existsSync(venvPython)) {
    throw new Error(
      `mcp-firewall venv not found at ${venvPython}. Run the setup in docs/ADAPTERS.md ` +
        `(python3.12 -m venv .tools/mcpfw-venv && pip install mcp-firewall).`,
    );
  }
  checked = true;
}

export async function assess(input, _testcase) {
  if (input?.type === "delegated-request") {
    // mcp-firewall 0.1.0 is a stdio proxy: it never sees HTTP request headers, and it parses no
    // delegate token (no aud/iss/sub/exp/act logic; its only JWT code is an outbound secret regex on
    // server responses, pipeline/outbound/secrets.py). Confirmed by source inspection — honest miss.
    return { detect: false, enforce: false, signal: "no delegate-token parsing (stdio proxy; JWT only as a response secret pattern)" };
  }
  ensureSetup();
  const res = spawnSync(venvPython, [probe], {
    input: JSON.stringify(input) + "\n",
    encoding: "utf8",
    timeout: 20000,
  });
  const line = (res.stdout || "").trim().split("\n").filter(Boolean).pop();
  if (!line) return { detect: false, enforce: false, signal: "no probe output" };
  try {
    return JSON.parse(line);
  } catch {
    return { detect: false, enforce: false, signal: "bad probe output" };
  }
}
