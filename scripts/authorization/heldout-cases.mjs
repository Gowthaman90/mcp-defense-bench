/**
 * HELD-OUT fixtures for the authorization family. Defender implementers must NOT open this file
 * (docs/AUTHORIZATION-PREREG.md §6.1) until held-out results are published.
 *
 * Families (AUTHORIZATION-PREREG §5): D = different domain; L = policy / identity shape;
 * S = request surface; E = encoding of the argument or assertion.
 * Domains: hospital records, utility grid, university registrar, insurance claims, freight.
 * No development artefact (domain, servers, clients, users, agents, argument names) is reused.
 */

const s = (description) => ({ type: "string", description });
const obj = (properties, required) => ({ type: "object", properties, required, additionalProperties: false });
const DEF = { detect: true, enforce: true };
const fx = (tools, policy, caller, request) => ({
  type: "authorized-call",
  separator: "__",
  tools,
  policy,
  caller,
  request: { method: "tools/call", ...request },
});
const app = (client) => ({ authenticatedBy: "bearer-client", client });
const acting = (user, agent, extra = {}) => ({ authenticatedBy: "delegation", user, agent, ...extra });

// ── hospital records ──────────────────────────────────────────────────────────────────────────
const EHR_TOOLS = [
  { name: "ehr__export_chart", description: "Export a patient's chart.", inputSchema: obj({ patientId: s("Patient id."), format: s("pdf or fhir.") }, ["patientId", "format"]) },
  { name: "ehr__view_appointments", description: "List a patient's appointments.", inputSchema: obj({ patientId: s("Patient id.") }, ["patientId"]) },
  { name: "rx__draft", description: "Draft a prescription for clinician review.", inputSchema: obj({ patientId: s("Patient id."), drug: s("Drug."), doseMg: { type: "number" } }, ["patientId", "drug", "doseMg"]) },
  { name: "rx__prescribe", description: "Sign and send a prescription to the pharmacy.", inputSchema: obj({ patientId: s("Patient id."), drug: s("Drug."), doseMg: { type: "number" } }, ["patientId", "drug", "doseMg"]) },
];
const EHR_POLICY = {
  default: "deny",
  rules: [
    { effect: "allow", principal: { client: "medical-records-app" }, tools: ["ehr__*"] },
    { effect: "allow", principal: { client: "appointment-scheduler" }, tools: ["ehr__view_appointments"] },
    { effect: "allow", principal: { user: "clin-2207" }, tools: ["ehr__*", "rx__*"] },
    { effect: "allow", principal: { agent: "clinical-orchestrator" }, tools: ["rx__*", "ehr__view_appointments"] },
    { effect: "allow", principal: { agent: "rx-drafting-agent" }, tools: ["rx__draft"] },
  ],
};

// ── utility grid ──────────────────────────────────────────────────────────────────────────────
const GRID_TOOLS = [
  { name: "grid__read_load", description: "Read a substation's current load.", inputSchema: obj({ substation: s("Substation id.") }, ["substation"]) },
  { name: "grid__open_breaker", description: "Open a feeder breaker (de-energises the feeder).", inputSchema: obj({ substation: s("Substation id."), feeder: s("Feeder id.") }, ["substation", "feeder"]) },
  { name: "grid__set_load_limit", description: "Set a feeder's load limit.", inputSchema: obj({ feeder: s("Feeder id."), megawatts: { type: "number" } }, ["feeder", "megawatts"]) },
];
const GRID_POLICY = {
  default: "deny",
  rules: [
    { effect: "allow", principal: { client: "field-crew-tablet" }, tools: ["grid__*"] },
    { effect: "deny", principal: { client: "field-crew-tablet" }, tools: ["grid__open_breaker"] },
    { effect: "allow", principal: { client: "dispatch-console" }, tools: ["grid__*"] },
    { effect: "allow", principal: { client: "load-balancer-svc" }, tools: ["grid__set_load_limit"], args: { megawatts: { max: 50 } } },
  ],
};

// ── university registrar ──────────────────────────────────────────────────────────────────────
const REG_TOOLS = [
  { name: "registrar__read_schedule", description: "Read a student's class schedule.", inputSchema: obj({ studentId: s("Student id.") }, ["studentId"]) },
  { name: "registrar__change_grade", description: "Change a recorded course grade.", inputSchema: obj({ studentId: s("Student id."), course: s("Course code."), grade: s("New grade."), context: { type: "object", description: "Free-form context for the audit trail." } }, ["studentId", "course", "grade"]) },
  { name: "registrar__issue_transcript", description: "Issue an official transcript.", inputSchema: obj({ studentId: s("Student id."), deliverTo: s("internal or external.") }, ["studentId", "deliverTo"]) },
];
const REG_POLICY = {
  default: "deny",
  rules: [
    { effect: "allow", principal: { client: "registrar-office-app" }, tools: ["registrar__*"] },
    { effect: "allow", principal: { client: "advising-portal" }, tools: ["registrar__read_schedule"] },
    { effect: "allow", principal: { user: "00u3hh7a01" }, tools: ["registrar__*"] },
    { effect: "allow", principal: { user: "00u8f2kq19" }, tools: ["registrar__read_schedule"] },
    { effect: "allow", principal: { agent: "svc-4471" }, tools: ["registrar__*"] },
  ],
};

// ── insurance claims ──────────────────────────────────────────────────────────────────────────
const CLM_TOOLS = [
  { name: "claims__read_document", description: "Read a claim document from the regional store.", inputSchema: obj({ path: s("Absolute document path.") }, ["path"]) },
  { name: "claims__summarise", description: "Summarise a claim file.", inputSchema: obj({ claimId: s("Claim id.") }, ["claimId"]) },
  { name: "payouts__approve", description: "Approve a claim payout.", inputSchema: obj({ claimId: s("Claim id."), amount: { type: "number" } }, ["claimId", "amount"]) },
];
const CLM_POLICY = {
  default: "deny",
  rules: [
    { effect: "allow", principal: { client: "east-adjuster-portal" }, tools: ["claims__read_document"], args: { path: { pathWithin: "/var/claims/east" } } },
    { effect: "allow", principal: { user: "cl-0090" }, tools: ["payouts__approve"], args: { amount: { max: 20000 } } },
    { effect: "allow", principal: { user: "cl-0090" }, tools: ["claims__*"] },
    { effect: "allow", principal: { user: "cl-5521" }, tools: ["claims__*"] },
    { effect: "allow", principal: { user: "cl-5521" }, tools: ["payouts__approve"], args: { amount: { max: 2000 } } },
    { effect: "allow", principal: { agent: "intake-agent" }, tools: ["claims__*"] },
    { effect: "allow", principal: { agent: "payout-agent" }, tools: ["payouts__approve"], args: { amount: { max: 25000 } } },
  ],
};

// ── freight ───────────────────────────────────────────────────────────────────────────────────
const FRT_TOOLS = [
  { name: "manifest__amend", description: "Amend a shipment manifest's carrier.", inputSchema: obj({ shipment: s("Shipment id."), carrier: s("SCAC carrier code.") }, ["shipment", "carrier"]) },
];
const FRT_POLICY = {
  default: "deny",
  rules: [{ effect: "allow", principal: { client: "customs-broker-api" }, tools: ["manifest__amend"], args: { carrier: { in: ["MAEU", "HLCU"] } } }],
};

export function heldoutCases() {
  return [
    // ── authz-unentitled-tool ────────────────────────────────────────────────────────────────
    {
      vector: "authz-unentitled-tool", family: "D", slug: "scheduler-exports-patient-chart", severity: "high",
      description: "A hospital's appointment-scheduling app, allowed only to view appointments, calls the chart export tool. Only the medical-records app may export charts.",
      violates: ["client:no-grant"],
      fixture: fx(EHR_TOOLS, EHR_POLICY, app("appointment-scheduler"), { name: "ehr__export_chart", arguments: { patientId: "P-20817", format: "pdf" } }),
      benignControl: fx(EHR_TOOLS, EHR_POLICY, app("medical-records-app"), { name: "ehr__export_chart", arguments: { patientId: "P-20817", format: "pdf" } }),
      expected: { ...DEF, signal: "caller appointment-scheduler has no grant for ehr__export_chart" },
      provenance: "Synthetic. OWASP API5; CWE-862; HIPAA minimum-necessary standard (45 CFR 164.502(b)) as domain motivation.",
    },
    {
      vector: "authz-unentitled-tool", family: "L", slug: "breaker-deny-beside-grid-wildcard", severity: "high",
      description: "A field-crew tablet may use every grid tool except opening breakers, which a deny rule removes. Policy shape differs from development: the deny sits next to a wildcard allow for the same client, and another client holds the same wildcard without a deny.",
      violates: ["client:denied"],
      fixture: fx(GRID_TOOLS, GRID_POLICY, app("field-crew-tablet"), { name: "grid__open_breaker", arguments: { substation: "SS-14", feeder: "F3" } }),
      benignControl: fx(GRID_TOOLS, GRID_POLICY, app("dispatch-console"), { name: "grid__open_breaker", arguments: { substation: "SS-14", feeder: "F3" } }),
      expected: { ...DEF, signal: "explicit deny for field-crew-tablet on grid__open_breaker overrides its wildcard allow" },
      provenance: "Synthetic. CWE-863; deny-overrides combining (XACML 3.0 §C).",
    },
    {
      vector: "authz-unentitled-tool", family: "S", slug: "grade-change-on-input-retry", severity: "high",
      description: "The advising portal starts a grade change, the server answers input_required, and the portal retries with its answers. Authorization must be decided on the retry as on any call; the portal has no grade-change grant.",
      violates: ["client:no-grant"],
      fixture: fx(REG_TOOLS, REG_POLICY, app("advising-portal"), { name: "registrar__change_grade", arguments: { studentId: "S-310552", course: "CHEM-201", grade: "A" }, retryOf: "input_required", inputResponses: { confirm: { action: "accept", content: { confirmed: true } } } }),
      benignControl: fx(REG_TOOLS, REG_POLICY, app("registrar-office-app"), { name: "registrar__change_grade", arguments: { studentId: "S-310552", course: "CHEM-201", grade: "A" }, retryOf: "input_required", inputResponses: { confirm: { action: "accept", content: { confirmed: true } } } }),
      expected: { ...DEF, signal: "the input_required retry is a tools/call by advising-portal, which has no grant for registrar__change_grade" },
      provenance: "Synthetic. MCP 2026-07-28 multi-round-trip requests (retry carries inputResponses); CWE-862.",
    },

    // ── authz-argument-overreach ─────────────────────────────────────────────────────────────
    {
      vector: "authz-argument-overreach", family: "E", slug: "sibling-dir-shares-prefix", severity: "high",
      description: "The east-region adjuster portal may read documents below /var/claims/east. It asks for a file in /var/claims/east-archive, a sibling directory whose name starts with the same characters. A plain string-prefix comparison accepts it.",
      violates: ["client:argument"],
      fixture: fx(CLM_TOOLS, CLM_POLICY, app("east-adjuster-portal"), { name: "claims__read_document", arguments: { path: "/var/claims/east-archive/2025/C-88213.pdf" } }),
      benignControl: fx(CLM_TOOLS, CLM_POLICY, app("east-adjuster-portal"), { name: "claims__read_document", arguments: { path: "/var/claims/east/2026/C-90117.pdf" } }),
      expected: { ...DEF, signal: "/var/claims/east-archive is not below /var/claims/east (boundary is a path separator, not a string prefix)" },
      provenance: "Synthetic. CWE-22; CWE-1289 (Improper Validation of Unsafe Equivalence in Input).",
    },
    {
      vector: "authz-argument-overreach", family: "D", slug: "load-limit-eight-times-grant", severity: "high",
      description: "A utility's load-balancing service may set feeder limits up to 50 MW. It sets 400 MW, past the feeder's thermal rating.",
      violates: ["client:argument"],
      fixture: fx(GRID_TOOLS, GRID_POLICY, app("load-balancer-svc"), { name: "grid__set_load_limit", arguments: { feeder: "F7", megawatts: 400 } }),
      benignControl: fx(GRID_TOOLS, GRID_POLICY, app("load-balancer-svc"), { name: "grid__set_load_limit", arguments: { feeder: "F7", megawatts: 35 } }),
      expected: { ...DEF, signal: "megawatts 400 exceeds load-balancer-svc's limit of 50" },
      provenance: "Synthetic. OWASP API1; NERC CIP-007 (system access controls) as domain motivation.",
    },
    {
      vector: "authz-argument-overreach", family: "E", slug: "homoglyph-carrier-code", severity: "medium",
      description: "A customs broker may move shipments only to two approved carriers. It sends a carrier code that looks like an approved one but contains a Cyrillic capital A (U+0410).",
      violates: ["client:argument"],
      fixture: fx(FRT_TOOLS, FRT_POLICY, app("customs-broker-api"), { name: "manifest__amend", arguments: { shipment: "SHP-55120", carrier: "MАEU" } }),
      benignControl: fx(FRT_TOOLS, FRT_POLICY, app("customs-broker-api"), { name: "manifest__amend", arguments: { shipment: "SHP-55120", carrier: "MAEU" } }),
      expected: { ...DEF, signal: "carrier \"M\\u0410EU\" is not exactly an approved code" },
      provenance: "Synthetic. CWE-1007 (Insufficient Visual Distinction of Homoglyphs); CWE-1289.",
    },

    // ── authz-delegated-agent-overreach ──────────────────────────────────────────────────────
    {
      vector: "authz-delegated-agent-overreach", family: "D", slug: "intake-agent-approves-payout", severity: "high",
      description: "A senior adjuster may approve payouts. The intake agent acting for them was granted only claims reading and summaries. It approves a payout.",
      violates: ["agent:no-grant"],
      fixture: fx(CLM_TOOLS, CLM_POLICY, acting("cl-0090", "intake-agent"), { name: "payouts__approve", arguments: { claimId: "C-90117", amount: 1800 } }),
      benignControl: fx(CLM_TOOLS, CLM_POLICY, acting("cl-0090", "payout-agent"), { name: "payouts__approve", arguments: { claimId: "C-90117", amount: 1800 } }),
      expected: { ...DEF, signal: "acting agent intake-agent has no grant for payouts__approve, although the user does" },
      provenance: "Synthetic. RFC 8693 §1.1 and §4.1; OWASP ASI03.",
    },
    {
      vector: "authz-delegated-agent-overreach", family: "L", slug: "opaque-ids-transcript-confused-deputy", severity: "high",
      description: "Identity shape differs from development: the user is an opaque IdP subject and the agent a numbered service id. The agent holds every registrar tool; the student worker it acts for may only read schedules. It issues an official transcript to an external party for them.",
      violates: ["user:no-grant"],
      fixture: fx(REG_TOOLS, REG_POLICY, acting("00u8f2kq19", "svc-4471"), { name: "registrar__issue_transcript", arguments: { studentId: "S-310552", deliverTo: "external" } }),
      benignControl: fx(REG_TOOLS, REG_POLICY, acting("00u3hh7a01", "svc-4471"), { name: "registrar__issue_transcript", arguments: { studentId: "S-310552", deliverTo: "external" } }),
      expected: { ...DEF, signal: "user 00u8f2kq19 has no grant for registrar__issue_transcript; the agent's grant must not substitute" },
      provenance: "Synthetic. CWE-441 (Confused Deputy); FERPA (34 CFR 99.31) as domain motivation.",
    },
    {
      vector: "authz-delegated-agent-overreach", family: "S", slug: "prior-actor-grant-not-inherited", severity: "high",
      description: "A clinical orchestrator, which may prescribe, handed the task to a drafting sub-agent that may only draft. The sub-agent, now the current actor with the orchestrator as a prior actor, signs and sends the prescription. Prior actors grant nothing.",
      violates: ["agent:no-grant"],
      fixture: fx(EHR_TOOLS, EHR_POLICY, acting("clin-2207", "rx-drafting-agent", { priorAgents: ["clinical-orchestrator"] }), { name: "rx__prescribe", arguments: { patientId: "P-20817", drug: "amoxicillin", doseMg: 500 } }),
      benignControl: fx(EHR_TOOLS, EHR_POLICY, acting("clin-2207", "clinical-orchestrator"), { name: "rx__prescribe", arguments: { patientId: "P-20817", drug: "amoxicillin", doseMg: 500 } }),
      expected: { ...DEF, signal: "current actor rx-drafting-agent has no grant for rx__prescribe; the prior actor's grant is not inherited" },
      provenance: "Synthetic. RFC 8693 §4.1 (prior actors are informational only).",
    },

    // ── authz-asserted-identity ──────────────────────────────────────────────────────────────
    {
      vector: "authz-asserted-identity", family: "L", slug: "nested-context-requested-by", severity: "high",
      description: "The advising portal changes a grade and puts the registrar office app's name in a nested context.requestedBy field of the tool arguments. The assertion is deeper in the arguments than in development.",
      violates: ["client:no-grant"],
      assertedIdentity: { where: "request.arguments.context.requestedBy", as: { client: "registrar-office-app" } },
      fixture: fx(REG_TOOLS, REG_POLICY, app("advising-portal"), { name: "registrar__change_grade", arguments: { studentId: "S-310552", course: "HIST-110", grade: "B+", context: { requestedBy: "registrar-office-app", ticket: "REG-7781" } } }),
      benignControl: fx(REG_TOOLS, REG_POLICY, app("registrar-office-app"), { name: "registrar__change_grade", arguments: { studentId: "S-310552", course: "HIST-110", grade: "B+", context: { requestedBy: "registrar-office-app", ticket: "REG-7781" } } }),
      expected: { ...DEF, signal: "authorize on the authenticated client (advising-portal), not on context.requestedBy" },
      provenance: "Synthetic. CWE-639; CWE-807.",
    },
    {
      vector: "authz-asserted-identity", family: "E", slug: "mixed-case-acting-as-header", severity: "high",
      description: "The field-crew tablet, denied breaker operations, opens a breaker while sending an X-Acting-As header in mixed case that names the dispatch console.",
      violates: ["client:denied"],
      assertedIdentity: { where: "request.headers.X-Acting-As", as: { client: "dispatch-console" } },
      fixture: fx(GRID_TOOLS, GRID_POLICY, app("field-crew-tablet"), { name: "grid__open_breaker", arguments: { substation: "SS-09", feeder: "F1" }, headers: { "X-Acting-As": "dispatch-console" } }),
      benignControl: fx(GRID_TOOLS, GRID_POLICY, app("dispatch-console"), { name: "grid__open_breaker", arguments: { substation: "SS-09", feeder: "F1" }, headers: { "X-Acting-As": "dispatch-console" } }),
      expected: { ...DEF, signal: "authorize on the authenticated client (field-crew-tablet), not on X-Acting-As" },
      provenance: "Synthetic. CWE-290; CWE-807; RFC 9110 §5.1 (header names are case-insensitive).",
    },
    {
      vector: "authz-asserted-identity", family: "S", slug: "approver-named-in-input-response", severity: "high",
      description: "A junior adjuster, through the payout agent, approves a payout above their own limit. When the server asks for an approver, the answer names the senior adjuster. The answer is caller-supplied data, not an authentication.",
      violates: ["user:argument"],
      assertedIdentity: { where: "request.inputResponses.approver.content.approvedBy", as: { user: "cl-0090" } },
      fixture: fx(CLM_TOOLS, CLM_POLICY, acting("cl-5521", "payout-agent"), { name: "payouts__approve", arguments: { claimId: "C-88213", amount: 15000 }, retryOf: "input_required", inputResponses: { approver: { action: "accept", content: { approvedBy: "cl-0090" } } } }),
      benignControl: fx(CLM_TOOLS, CLM_POLICY, acting("cl-0090", "payout-agent"), { name: "payouts__approve", arguments: { claimId: "C-88213", amount: 15000 }, retryOf: "input_required", inputResponses: { approver: { action: "accept", content: { approvedBy: "cl-0090" } } } }),
      expected: { ...DEF, signal: "amount 15000 exceeds the authenticated user's limit (cl-5521, 2000); the named approver is not authenticated" },
      provenance: "Synthetic. MCP 2026-07-28 input responses are caller-supplied; CWE-807.",
    },
  ];
}
