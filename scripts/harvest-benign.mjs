#!/usr/bin/env node
/**
 * Harvest REAL tool definitions from public MCP servers for the benign (false-positive) corpus.
 *
 * Each server is started exactly as an end user would (npx / uvx), `tools/list` is called through
 * the official SDK client, and the verbatim definitions are written to
 * testcases-benign/harvested/<server>.json with package + version provenance. Nothing is invented:
 * these are the tool descriptions that real agents see every day, which is exactly the population a
 * defender must NOT flag.
 *
 * Servers that need an API key at start-up and refuse to list tools without one are recorded as
 * `skipped` so the corpus stays honest about its provenance.
 *
 * Usage: node scripts/harvest-benign.mjs [--only name]
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const outDir = join(root, "testcases-benign", "harvested");
mkdirSync(outDir, { recursive: true });

// Reuse the SDK already installed for the sibling proxy so the harvest needs no extra install.
const require = createRequire(join(root, "..", "mcp_bastion", "package.json"));
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");

const scratch = process.env.HARVEST_SCRATCH ?? join(root, ".tools", "harvest-scratch");
mkdirSync(scratch, { recursive: true });

const SERVERS = [
  { name: "server-filesystem", pkg: "@modelcontextprotocol/server-filesystem", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", scratch] },
  { name: "server-memory", pkg: "@modelcontextprotocol/server-memory", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-memory"] },
  { name: "server-sequential-thinking", pkg: "@modelcontextprotocol/server-sequential-thinking", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-sequential-thinking"] },
  { name: "server-everything", pkg: "@modelcontextprotocol/server-everything", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-everything"] },
  { name: "server-pdf", pkg: "@modelcontextprotocol/server-pdf", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-pdf"] },
  { name: "server-github", pkg: "@modelcontextprotocol/server-github", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "harvest-placeholder" } },
  { name: "server-slack", pkg: "@modelcontextprotocol/server-slack", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-slack"], env: { SLACK_BOT_TOKEN: "xoxb-harvest-placeholder", SLACK_TEAM_ID: "T000" } },
  { name: "server-postgres", pkg: "@modelcontextprotocol/server-postgres", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/harvest"] },
  { name: "server-brave-search", pkg: "@modelcontextprotocol/server-brave-search", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-brave-search"], env: { BRAVE_API_KEY: "harvest-placeholder" } },
  { name: "server-google-maps", pkg: "@modelcontextprotocol/server-google-maps", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-google-maps"], env: { GOOGLE_MAPS_API_KEY: "harvest-placeholder" } },
  { name: "server-puppeteer", pkg: "@modelcontextprotocol/server-puppeteer", cmd: "npx", args: ["-y", "@modelcontextprotocol/server-puppeteer"], env: { PUPPETEER_SKIP_DOWNLOAD: "1" } },
  { name: "server-sqlite", pkg: "mcp-server-sqlite-npx", cmd: "npx", args: ["-y", "mcp-server-sqlite-npx", join(scratch, "harvest.db")] },
  { name: "playwright-mcp", pkg: "@playwright/mcp", cmd: "npx", args: ["-y", "@playwright/mcp@latest"] },
  { name: "context7-mcp", pkg: "@upstash/context7-mcp", cmd: "npx", args: ["-y", "@upstash/context7-mcp"] },
  { name: "notion-mcp-server", pkg: "@notionhq/notion-mcp-server", cmd: "npx", args: ["-y", "@notionhq/notion-mcp-server"], env: { OPENAPI_MCP_HEADERS: '{"Authorization":"Bearer harvest-placeholder","Notion-Version":"2022-06-28"}' } },
  { name: "firecrawl-mcp", pkg: "firecrawl-mcp", cmd: "npx", args: ["-y", "firecrawl-mcp"], env: { FIRECRAWL_API_KEY: "fc-harvest-placeholder" } },
  { name: "tavily-mcp", pkg: "tavily-mcp", cmd: "npx", args: ["-y", "tavily-mcp"], env: { TAVILY_API_KEY: "tvly-harvest-placeholder" } },
  { name: "sentry-mcp", pkg: "@sentry/mcp-server", cmd: "npx", args: ["-y", "@sentry/mcp-server"], env: { SENTRY_ACCESS_TOKEN: "harvest-placeholder", SENTRY_HOST: "sentry.io" } },
  { name: "stripe-mcp", pkg: "@stripe/mcp", cmd: "npx", args: ["-y", "@stripe/mcp", "--tools=all", "--api-key=sk_test_harvestplaceholder"] },
  { name: "supabase-mcp", pkg: "@supabase/mcp-server-supabase", cmd: "npx", args: ["-y", "@supabase/mcp-server-supabase", "--access-token", "sbp_harvestplaceholder"] },
  { name: "mcp-server-fetch", pkg: "mcp-server-fetch", cmd: "uvx", args: ["mcp-server-fetch"] },
  { name: "mcp-server-git", pkg: "mcp-server-git", cmd: "uvx", args: ["mcp-server-git", "--repository", root] },
  { name: "mcp-server-time", pkg: "mcp-server-time", cmd: "uvx", args: ["mcp-server-time"] },
  { name: "mcp-server-kubernetes", pkg: "mcp-server-kubernetes", cmd: "npx", args: ["-y", "mcp-server-kubernetes"] },
  { name: "aws-documentation-mcp", pkg: "awslabs.aws-documentation-mcp-server", cmd: "uvx", args: ["awslabs.aws-documentation-mcp-server@latest"] },
  { name: "docker-mcp", pkg: "docker-mcp", cmd: "uvx", args: ["docker-mcp"] },
];

const only = process.argv.includes("--only") ? process.argv[process.argv.indexOf("--only") + 1] : null;

async function harvest(s) {
  const started = Date.now();
  const transport = new StdioClientTransport({
    command: s.cmd,
    args: s.args,
    env: { ...process.env, ...(s.env ?? {}) },
    stderr: "pipe",
  });
  const client = new Client({ name: "mcp-defense-bench-harvest", version: "0.7.0" }, { capabilities: {} });
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("timeout after 240s")), 240_000));
  try {
    await Promise.race([client.connect(transport), timeout]);
    const serverInfo = client.getServerVersion?.() ?? null;
    const { tools } = await Promise.race([client.listTools(), timeout]);
    const doc = {
      source: { package: s.pkg, command: [s.cmd, ...s.args.map((a) => (a.startsWith(scratch) ? "<scratch>" : a.includes("placeholder") ? "<placeholder>" : a === root ? "<repo>" : a))], serverInfo },
      harvestedAt: new Date().toISOString(),
      note: "Verbatim tools/list output from a public MCP server started as a user would start it. Benign by construction; used only as false-positive controls.",
      tools,
    };
    writeFileSync(join(outDir, `${s.name}.json`), JSON.stringify(doc, null, 2) + "\n");
    console.log(`✓ ${s.name}: ${tools.length} tools (${((Date.now() - started) / 1000).toFixed(0)}s)`);
  } catch (e) {
    console.log(`✗ ${s.name}: ${String(e.message ?? e).split("\n")[0].slice(0, 120)}`);
    writeFileSync(join(outDir, `${s.name}.skipped.json`), JSON.stringify({ source: { package: s.pkg }, skipped: String(e.message ?? e).slice(0, 300) }, null, 2) + "\n");
  } finally {
    try { await client.close(); } catch {}
    try { await transport.close(); } catch {}
  }
}

for (const s of SERVERS) {
  if (only && s.name !== only) continue;
  await harvest(s);
}
console.log("done");
