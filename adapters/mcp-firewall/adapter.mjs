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
 * `authorized-call` (docs/AUTHORIZATION-PREREG.md): mcp-firewall 0.1.0 has per-agent RBAC
 * (`agents: { <id>: { allow, deny } }`), reachable through its Python SDK (`check(agent=...)`); its stdio
 * proxy never sets an agent id, so the SDK path is the one measured. probe_authz.py translates the
 * fixture policy into that config and calls the real Gateway.check(). What the config cannot express
 * (multi-identity callers, argument constraints) is a measured gap: detect:false with the reason.
 * Translation: AUTHORIZATION-TRANSLATION.md. Written from the dev fixtures only.
 */
export const meta = { tool: "mcp-firewall", class: "runtime-proxy", reproducible: true };

const venvPython = fileURLToPath(new URL("../../.tools/mcpfw-venv/bin/python", import.meta.url));
const probe = fileURLToPath(new URL("./probe_server.py", import.meta.url));
const authzProbe = fileURLToPath(new URL("./probe_authz.py", import.meta.url));

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
  if (input?.type === "authorized-call") {
    // One isolated probe run per call: fresh Gateway, fresh rate-limit and chain-detector state.
    const r = spawnSync(venvPython, ["-I", authzProbe], { input: JSON.stringify(input), encoding: "utf8", timeout: 20000 });
    const out = (r.stdout || "").trim().split("\n").filter(Boolean).pop();
    if (!out) return { detect: false, enforce: false, signal: `no authz probe output${r.stderr ? ": " + r.stderr.trim().slice(-160) : ""}` };
    try {
      const v = JSON.parse(out);
      return { detect: !!v.detect, enforce: !!v.enforce, signal: v.error ? `probe error: ${v.error}` : v.signal ?? null };
    } catch {
      return { detect: false, enforce: false, signal: "bad authz probe output" };
    }
  }
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
