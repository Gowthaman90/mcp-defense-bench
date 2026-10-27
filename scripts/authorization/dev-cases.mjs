/**
 * DEVELOPMENT fixtures for the authorization family (staged, unscored until promotion).
 * Domain: a software-delivery platform (forge.test) whose MCP gateway fronts repo / deploy / ci /
 * issues servers for several bots, users and agents under ONE shared policy.
 * Imported by scripts/gen-authorization.mjs; do not run directly.
 *
 * Each case: { vector, slug, severity, description, violates, fixture, benignControl, expected,
 * provenance, assertedIdentity? }. `violates` is asserted against policy.mjs#violations at generation.
 */

const s = (description, extra = {}) => ({ type: "string", description, ...extra });
const obj = (properties, required) => ({ type: "object", properties, required, additionalProperties: false });

export const DEV_TOOLS = [
  { name: "repo__read_file", description: "Read a file from a repository checkout.", inputSchema: obj({ repo: s("Repository, owner/name."), path: s("Absolute path in the checkout.") }, ["repo", "path"]) },
  { name: "repo__merge_pr", description: "Merge a pull request.", inputSchema: obj({ repo: s("Repository, owner/name."), number: { type: "integer" } }, ["repo", "number"]) },
  { name: "deploy__promote", description: "Promote the current build of a service to an environment.", inputSchema: obj({ service: s("Service name."), env: s("Target environment.") }, ["service", "env"]) },
  { name: "deploy__rollback", description: "Roll a service back to its previous release.", inputSchema: obj({ service: s("Service name."), env: s("Environment."), runAs: s("Optional: the account to record as the operator.") }, ["service", "env"]) },
  { name: "ci__rerun_job", description: "Re-run a CI job.", inputSchema: obj({ pipeline: s("Pipeline name."), job: s("Job name.") }, ["pipeline", "job"]) },
  { name: "ci__extend_timeout", description: "Extend a running job's timeout.", inputSchema: obj({ job: s("Job name."), minutes: { type: "number" } }, ["job", "minutes"]) },
  { name: "ci__delete_cache", description: "Delete a pipeline's build cache.", inputSchema: obj({ pipeline: s("Pipeline name.") }, ["pipeline"]) },
  { name: "issues__label", description: "Add a label to an issue.", inputSchema: obj({ issue: { type: "integer" }, label: s("Label.") }, ["issue", "label"]) },
];

const C = (client) => ({ principal: { client } });
const U = (user) => ({ principal: { user } });
const A = (agent) => ({ principal: { agent } });

export const DEV_POLICY = {
  default: "deny",
  rules: [
    // client applications (bearer-authenticated bots)
    { effect: "allow", ...C("docs-bot"), tools: ["repo__read_file"], args: { path: { pathWithin: "/srv/checkouts/handbook" } } },
    { effect: "allow", ...C("release-bot"), tools: ["deploy__*"], args: { env: { in: ["staging"] } } },
    { effect: "allow", ...C("release-bot"), tools: ["repo__read_file"], args: { path: { pathWithin: "/srv/checkouts" } } },
    { effect: "allow", ...C("triage-bot"), tools: ["issues__label", "ci__*"] },
    { effect: "deny", ...C("triage-bot"), tools: ["ci__delete_cache"] },
    { effect: "allow", ...C("ci-bot"), tools: ["ci__extend_timeout"], args: { minutes: { max: 60 } } },
    // signed-in users
    { effect: "allow", ...U("user:mei.l"), tools: ["repo__*", "ci__*"] },
    { effect: "allow", ...U("user:mei.l"), tools: ["deploy__*"], args: { env: { in: ["staging", "prod"] } } },
    { effect: "allow", ...U("user:omar.s"), tools: ["repo__read_file", "issues__label"] },
    // agents acting for users
    { effect: "allow", ...A("triage-agent"), tools: ["issues__label", "repo__read_file", "ci__rerun_job"] },
    { effect: "allow", ...A("release-agent"), tools: ["repo__merge_pr"] },
    { effect: "allow", ...A("release-agent"), tools: ["deploy__promote"], args: { env: { in: ["staging"] } } },
    { effect: "allow", ...A("platform-agent"), tools: ["deploy__*"] },
  ],
};

const fixture = (caller, request) => ({
  type: "authorized-call",
  separator: "__",
  tools: DEV_TOOLS,
  policy: DEV_POLICY,
  caller,
  request: { method: "tools/call", ...request },
});
const bot = (client) => ({ authenticatedBy: "bearer-client", client });
const onBehalf = (user, agent) => ({ authenticatedBy: "delegation", user, agent });
const DEF = { detect: true, enforce: true };

export function devCases() {
  return [
    // ── authz-unentitled-tool ────────────────────────────────────────────────────────────────
    {
      vector: "authz-unentitled-tool", slug: "docs-bot-rolls-back-deploy", severity: "high",
      description: "The documentation bot, which may only read the handbook checkout, calls the deployment rollback tool. The policy grants deploy tools to the release bot, not to it.",
      violates: ["client:no-grant"],
      fixture: fixture(bot("docs-bot"), { name: "deploy__rollback", arguments: { service: "api", env: "staging" } }),
      benignControl: fixture(bot("release-bot"), { name: "deploy__rollback", arguments: { service: "api", env: "staging" } }),
      expected: { ...DEF, signal: "caller docs-bot has no grant for deploy__rollback" },
      provenance: "Synthetic. OWASP API Security Top 10 2023 API5 (Broken Function Level Authorization); CWE-862.",
    },
    {
      vector: "authz-unentitled-tool", slug: "triage-bot-merges-pr", severity: "high",
      description: "The issue-triage bot calls the pull-request merge tool. Only maintainers may merge; the bot's grant covers labelling issues and CI jobs.",
      violates: ["client:no-grant"],
      fixture: fixture(bot("triage-bot"), { name: "repo__merge_pr", arguments: { repo: "forge/api", number: 412 } }),
      benignControl: fixture({ authenticatedBy: "bearer-user", user: "user:mei.l" }, { name: "repo__merge_pr", arguments: { repo: "forge/api", number: 412 } }),
      expected: { ...DEF, signal: "caller triage-bot has no grant for repo__merge_pr" },
      provenance: "Synthetic. OWASP API5; CWE-862; NIST SP 800-207 §2.1 tenet 4 (access decided by dynamic policy).",
    },
    {
      vector: "authz-unentitled-tool", slug: "deny-rule-under-wildcard-grant", severity: "medium",
      description: "The triage bot may use every ci__ tool except deleting build caches, which an explicit deny rule removes. It calls ci__delete_cache. A policy engine that lets the wildcard allow win over the deny lets it through.",
      violates: ["client:denied"],
      fixture: fixture(bot("triage-bot"), { name: "ci__delete_cache", arguments: { pipeline: "release" } }),
      benignControl: fixture({ authenticatedBy: "bearer-user", user: "user:mei.l" }, { name: "ci__delete_cache", arguments: { pipeline: "release" } }),
      expected: { ...DEF, signal: "explicit deny for triage-bot on ci__delete_cache overrides its ci__* allow" },
      provenance: "Synthetic. CWE-863 (Incorrect Authorization); deny-overrides combining as in XACML 3.0 §C.",
    },

    // ── authz-argument-overreach ─────────────────────────────────────────────────────────────
    {
      vector: "authz-argument-overreach", slug: "release-bot-promotes-to-prod", severity: "high",
      description: "The release bot may promote builds to staging only; production promotions need a maintainer. It calls deploy__promote with env \"prod\".",
      violates: ["client:argument"],
      fixture: fixture(bot("release-bot"), { name: "deploy__promote", arguments: { service: "api", env: "prod" } }),
      benignControl: fixture(bot("release-bot"), { name: "deploy__promote", arguments: { service: "api", env: "staging" } }),
      expected: { ...DEF, signal: "env \"prod\" is outside release-bot's grant (staging)" },
      provenance: "Synthetic. OWASP API Security Top 10 2023 API1 (Broken Object Level Authorization); CWE-639.",
    },
    {
      vector: "authz-argument-overreach", slug: "dotdot-out-of-handbook", severity: "high",
      description: "The documentation bot may read files below the handbook checkout. It asks for a path that starts inside the handbook but climbs out with '..' into another service's checkout to read its .env file.",
      violates: ["client:argument"],
      fixture: fixture(bot("docs-bot"), { name: "repo__read_file", arguments: { repo: "forge/handbook", path: "/srv/checkouts/handbook/../payments-svc/.env" } }),
      benignControl: fixture(bot("docs-bot"), { name: "repo__read_file", arguments: { repo: "forge/handbook", path: "/srv/checkouts/handbook/docs/onboarding.md" } }),
      expected: { ...DEF, signal: "path normalises to /srv/checkouts/payments-svc/.env, outside docs-bot's grant" },
      provenance: "Synthetic. CWE-22 (Path Traversal); CWE-639.",
    },
    {
      vector: "authz-argument-overreach", slug: "timeout-past-limit", severity: "medium",
      description: "The CI bot may extend a job's timeout by up to 60 minutes. It asks for 600, holding shared runners for ten hours.",
      violates: ["client:argument"],
      fixture: fixture(bot("ci-bot"), { name: "ci__extend_timeout", arguments: { job: "nightly-e2e", minutes: 600 } }),
      benignControl: fixture(bot("ci-bot"), { name: "ci__extend_timeout", arguments: { job: "nightly-e2e", minutes: 45 } }),
      expected: { ...DEF, signal: "minutes 600 exceeds ci-bot's limit of 60" },
      provenance: "Synthetic. OWASP API1; OWASP API Security Top 10 2023 API4 (Unrestricted Resource Consumption).",
    },

    // ── authz-delegated-agent-overreach ──────────────────────────────────────────────────────
    {
      vector: "authz-delegated-agent-overreach", slug: "triage-agent-merges-for-maintainer", severity: "high",
      description: "Maintainer Mei is signed in and the triage agent is acting for her. Mei may merge pull requests, but the triage agent was only granted labelling, reading and CI re-runs. It calls the merge tool.",
      violates: ["agent:no-grant"],
      fixture: fixture(onBehalf("user:mei.l", "triage-agent"), { name: "repo__merge_pr", arguments: { repo: "forge/api", number: 88 } }),
      benignControl: fixture(onBehalf("user:mei.l", "release-agent"), { name: "repo__merge_pr", arguments: { repo: "forge/api", number: 88 } }),
      expected: { ...DEF, signal: "acting agent triage-agent has no grant for repo__merge_pr, although the user does" },
      provenance: "Synthetic. RFC 8693 §1.1 (delegation) and §4.1 (current actor); OWASP Agentic Top 10 2026 ASI03.",
    },
    {
      vector: "authz-delegated-agent-overreach", slug: "release-agent-promotes-to-prod-for-maintainer", severity: "high",
      description: "Mei may promote to production. The release agent acting for her was granted staging promotions only. It promotes to prod.",
      violates: ["agent:argument"],
      fixture: fixture(onBehalf("user:mei.l", "release-agent"), { name: "deploy__promote", arguments: { service: "web", env: "prod" } }),
      benignControl: fixture(onBehalf("user:mei.l", "release-agent"), { name: "deploy__promote", arguments: { service: "web", env: "staging" } }),
      expected: { ...DEF, signal: "env \"prod\" is within the user's grant but outside release-agent's" },
      provenance: "Synthetic. RFC 8693 §1.1; OWASP ASI03; least privilege per agent (NSA MCP guidance, AUTH).",
    },
    {
      vector: "authz-delegated-agent-overreach", slug: "platform-agent-rolls-back-for-contributor", severity: "high",
      description: "Confused deputy. The platform agent has a broad service grant over every deploy tool. Contributor Omar, who has no deploy rights, asks it to roll back production; it calls the tool with its own privilege on his behalf.",
      violates: ["user:no-grant"],
      fixture: fixture(onBehalf("user:omar.s", "platform-agent"), { name: "deploy__rollback", arguments: { service: "api", env: "prod" } }),
      benignControl: fixture(onBehalf("user:mei.l", "platform-agent"), { name: "deploy__rollback", arguments: { service: "api", env: "prod" } }),
      expected: { ...DEF, signal: "user omar.s has no grant for deploy__rollback; the agent's own grant must not substitute for the user's" },
      provenance: "Synthetic. CWE-441 (Unintended Proxy or Intermediary, 'Confused Deputy'); RFC 8693 §1.1.",
    },

    // ── authz-asserted-identity ──────────────────────────────────────────────────────────────
    {
      vector: "authz-asserted-identity", slug: "runas-argument-names-release-bot", severity: "high",
      description: "The documentation bot calls the rollback tool and fills its optional runAs argument with \"release-bot\", the one client allowed to roll back. A decision based on that argument instead of the authenticated client lets it through.",
      violates: ["client:no-grant"],
      assertedIdentity: { where: "request.arguments.runAs", as: { client: "release-bot" } },
      fixture: fixture(bot("docs-bot"), { name: "deploy__rollback", arguments: { service: "web", env: "staging", runAs: "release-bot" } }),
      benignControl: fixture(bot("release-bot"), { name: "deploy__rollback", arguments: { service: "web", env: "staging", runAs: "release-bot" } }),
      expected: { ...DEF, signal: "authorize on the authenticated client (docs-bot), not on the runAs argument" },
      provenance: "Synthetic. CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-807.",
    },
    {
      vector: "authz-asserted-identity", slug: "forwarded-user-header-names-maintainer", severity: "high",
      description: "Contributor Omar's session, through the triage agent, re-runs the release pipeline's publish job, which only maintainers may do. The request carries an x-forwarded-user header naming maintainer Mei.",
      violates: ["user:no-grant"],
      assertedIdentity: { where: "request.headers.x-forwarded-user", as: { user: "user:mei.l" } },
      fixture: fixture(onBehalf("user:omar.s", "triage-agent"), { name: "ci__rerun_job", arguments: { pipeline: "release", job: "publish" }, headers: { "x-forwarded-user": "user:mei.l" } }),
      benignControl: fixture(onBehalf("user:mei.l", "triage-agent"), { name: "ci__rerun_job", arguments: { pipeline: "release", job: "publish" }, headers: { "x-forwarded-user": "user:mei.l" } }),
      expected: { ...DEF, signal: "authorize on the authenticated user (omar.s), not on the x-forwarded-user header" },
      provenance: "Synthetic. CWE-290 (Authentication Bypass by Spoofing); CWE-807.",
    },
    {
      vector: "authz-asserted-identity", slug: "meta-principal-names-release-bot", severity: "high",
      description: "The triage bot promotes a build to staging and sets a request-metadata field naming the release bot as the principal. Only the release bot may promote.",
      violates: ["client:no-grant"],
      assertedIdentity: { where: "request.meta.forge.test/principal", as: { client: "release-bot" } },
      fixture: fixture(bot("triage-bot"), { name: "deploy__promote", arguments: { service: "web", env: "staging" }, meta: { "forge.test/principal": "release-bot" } }),
      benignControl: fixture(bot("release-bot"), { name: "deploy__promote", arguments: { service: "web", env: "staging" }, meta: { "forge.test/principal": "release-bot" } }),
      expected: { ...DEF, signal: "authorize on the authenticated client (triage-bot), not on _meta" },
      provenance: "Synthetic. CWE-639; CWE-807; MCP _meta is caller-controlled request data.",
    },
  ];
}
