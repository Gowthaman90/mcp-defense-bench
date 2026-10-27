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
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";

/**
 * `authorized-call` (docs/AUTHORIZATION-PREREG.md, commitment 6.5): wired as a confirmed miss.
 *
 * The benchmark measures the freely available pipelock 3.0.0 binary with NO licence key. Checked on
 * that binary on 2026-10-27 (commands and outputs in AUTHORIZATION-TRANSLATION.md):
 *   - Named agent profiles (per-agent identity, MCP tool policy, listeners) need the paid `agents`
 *     licence feature (ELv2 `enterprise/`). Without a key the binary strips them with a warning,
 *     refuses `pipelock mcp proxy --agent <name>` ("unknown agent profile"), and never binds the
 *     per-agent listener ports.
 *   - Free-edition MCP tool-call decisions (tool policy, input scanning, learn-and-lock contracts)
 *     are made per listener, never per caller: `X-Pipelock-Agent` and `?agent=` do not change them,
 *     and the contract gate always resolves the listener's profile, which without a licence is
 *     `_default`.
 * So the free edition has no per-caller tool authorization, and no translation of the fixture
 * policy is possible. The adapter does not approximate one (no per-caller routing done by the
 * adapter itself). It refuses to run if the binary is not the pinned 3.0.0 build or if pipelock
 * reports any licence, because the finding holds only for the free, unlicensed build.
 */
export const meta = { tool: "pipelock", class: "egress-firewall", reproducible: true };

/** sha256 of `.tools/pipelock/pipelock` from pipelock_3.0.0_darwin_arm64.tar.gz (git 9d2e37d). */
const PINNED_SHA256 = "96843f7f3b5415384230b9e1b8ecfb925d89df2e57849ee74ab63c15b6d02444";
const AUTHZ_MISS_SIGNAL =
  "free edition, no licence: no per-caller tool authorization (agent profiles need the paid 'agents' feature; MCP decisions are per listener, not per caller)";

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

let freeEditionChecked = false;
/**
 * The authorized-call finding is about the unlicensed 3.0.0 build. Check that this is the build in
 * .tools (pinned darwin-arm64 hash, or on another platform the 3.0.0 version line and git commit)
 * and that pipelock itself reports no licence (it reads PIPELOCK_LICENSE_KEY and its home dir).
 */
function ensureFreeEdition() {
  if (freeEditionChecked) return;
  ensureSetup();
  const sha = createHash("sha256").update(readFileSync(bin)).digest("hex");
  if (sha !== PINNED_SHA256) {
    const v = spawnSync(bin, ["version"], { encoding: "utf8", timeout: 15000 }).stdout || "";
    if (!/pipelock version 3\.0\.0\b/.test(v) || !/git commit: 9d2e37d\b/.test(v)) {
      throw new Error(`pipelock binary is not the pinned 3.0.0 build (sha256 ${sha}); authorized-call was assessed on 3.0.0 only`);
    }
  }
  const lic = spawnSync(bin, ["license", "status"], { encoding: "utf8", timeout: 15000 });
  if (!/License status: missing/.test(`${lic.stdout}${lic.stderr}`)) {
    throw new Error("pipelock reports a licence; the benchmark measures the free, unlicensed edition only");
  }
  freeEditionChecked = true;
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
  if (input?.type === "authorized-call") {
    // No caller-dependent decision exists in the free edition, so there is nothing to translate the
    // fixture policy into (prereg 6.5, 6.6). Same answer for the attack and its benign control.
    ensureFreeEdition();
    return { detect: false, enforce: false, signal: AUTHZ_MISS_SIGNAL };
  }
  if (input?.type === "delegated-request") {
    // pipelock 3.0.0 inspects egress destinations, bodies and headers for DLP / injection. It has a
    // "JWT Token" DLP pattern, but it parses no delegate-token claims (no aud/iss/sub/exp/act policy;
    // its "audience" options belong to the Conductor fleet control plane). A JWT-shaped value would
    // match that pattern on the attack and its benign control alike, so it cannot discriminate. The
    // audience URLs in the fixture are token claims, not destinations, so they are not scanned as
    // egress. Confirmed by inspecting the v3.0.0 binary's strings and docs — honest miss.
    return { detect: false, enforce: false, signal: "no delegate-token parsing (JWT only as a DLP secret pattern)" };
  }
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
