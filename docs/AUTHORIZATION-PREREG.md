# Authorization family: pre-registration

**Registered:** 2026-10-26, as git tag `authorization-prereg-2026-10-26`, **before any measured defender
by the benchmark author implements per-caller tool authorization.** This file is the commitment;
`staging/authorization/` is the registered material. Reviewers should compare the two, and compare
every fixture with the sha256 recorded in `staging/authorization/MANIFEST.json`.

Status: **staged, unscored.** Nothing here changes the published v0.9.0 numbers. The family is
promoted into the scored rubric only by the procedure in §8.

## 1. Why this family exists

An MCP gateway or shared server usually serves several callers: client applications, signed-in users,
and agents acting for those users. The MCP authorization specification authenticates the client to
the server. Which tools, and which argument values, an authenticated caller may use is left to the
deployment. The benchmark has no vector for that decision today:

- `excessive-permission` is a privilege a tool or server holds for **everyone**.
- `roots-scope-gap` is **one** filesystem boundary for every caller.
- `task-authz-bypass` is about addressing task state by ID.
- `delegation-chain-laundering` asks whether an agent may present tokens to an upstream **at all**.

None of them covers the case this family is built on: **the same call is correct for one caller and
wrong for another.** Every fixture's benign control differs from its attack in exactly one thing,
usually the caller, so a tool that refuses a call by tool name alone fails the control.

Per-caller MCP tool authorization already exists in other gateways, for example agentgateway (CEL
rules over tool name, arguments and JWT claims) and ToolHive (Cedar policies over the token subject
and tool). ETDI (arXiv:2506.01333) proposed policy-based access control for tool invocation. This
family measures the decision; it does not claim the idea is new.

## 2. The objection this design answers

The AISec 2026 review objected that the benchmark and its strongest measured tool share an author.
As for the delegation family, **the vector definitions, the development fixtures and the held-out
fixtures are registered before the author's tool (mcp-bastion, at v1.3.1 when registered) has any
per-caller authorization code.** Two independent tools that already implement authorization are
committed as peers (§6.5), so the family can show whether it favours the author's design.

## 3. Vectors (4)

| id | What goes wrong | Grounding |
|---|---|---|
| `authz-unentitled-tool` | A caller uses a tool that the policy grants to other callers but not to it, or that an explicit deny rule removes from its grant | OWASP API Security Top 10 2023 API5; CWE-862, CWE-863; NIST SP 800-207 §2.1 tenets 3–4 |
| `authz-argument-overreach` | A caller may use the tool, but not with this argument value: environment, path, amount, code; sometimes encoded (`..`, a sibling directory sharing a prefix, a look-alike character) | OWASP API1; CWE-639, CWE-22, CWE-1289 |
| `authz-delegated-agent-overreach` | An agent acting for a user exceeds what the user **and** the agent are both granted: the agent lacks the grant, or the user lacks it and the agent's own grant is used for them (confused deputy). Prior actors grant nothing | RFC 8693 §1.1, §4.1; CWE-441; OWASP Agentic ASI03 |
| `authz-asserted-identity` | The authenticated caller is not entitled, but the request names an entitled principal in caller-controlled data: an argument, a header, `_meta`, or an input response | CWE-639, CWE-290, CWE-807 |

Crosswalk rows (Rater A, pre-adjudication): `staging/authorization/crosswalk-rows.json`.

**Two choices made while authoring, recorded here:**
- *Hiding denied tools from `tools/list` is deliberately not a vector.* It is a sensible hardening
  property (agentgateway documents it), but an exposed name is not by itself a successful attack. It
  belongs in prose.
- *Authenticating the caller is out of scope.* Every fixture states the caller's identities as already
  authenticated. Whether a token or bearer credential is genuine is what the delegation family and
  transport vectors test.

## 4. Fixture type `authorized-call` and its intended semantics

```jsonc
{
  "type": "authorized-call",
  "separator": "__",                          // namespaced tool names are <server>__<tool>
  "tools":  [ { "name": "…", "description": "…", "inputSchema": { … } } ],
  "policy": { "default": "deny",
              "rules": [ { "effect": "allow"|"deny",
                           "principal": { "client"|"user"|"agent": "…" } | "*",
                           "tools": ["server__tool", "server__*"],
                           "args?": { "<name>": { "equals"|"in"|"max"|"min"|"pathWithin": … } } } ] },
  "caller":  { "authenticatedBy": "bearer-client"|"bearer-user"|"delegation",
               "client?": "…", "user?": "…", "agent?": "…", "priorAgents?": ["…"] },
  "request": { "method": "tools/call", "name": "…", "arguments": { … },
               "headers?": { … }, "meta?": { … }, "retryOf?": "input_required", "inputResponses?": { … } }
}
```

What `intent.violates` means (encoded in `scripts/authorization/policy.mjs#violations`, used only to
reject malformed fixtures at generation time, never run against a defender):

1. **Identities.** The call carries each of `client`, `user`, `agent` present in `caller`, and nothing
   else. `priorAgents` are informational (RFC 8693 §4.1) and grant nothing. Identities named anywhere
   in `request` (arguments, headers, meta, input responses) are ignored.
2. **Intersection.** The call is allowed only if **every** identity it carries is permitted. An agent
   acting for a user therefore needs both the user's grant and its own.
3. **Per identity:** the rules that apply are those whose `principal` is `"*"` or names exactly that
   identity and whose `tools` match the request. Then, in order:
   - a matching `deny` rule (with its `args`, if any, satisfied) → `<kind>:denied` (**deny overrides allow**);
   - no `allow` rule → `<kind>:no-grant`;
   - no `allow` rule whose `args` are all satisfied → `<kind>:argument`.
4. **Tool patterns:** exact namespaced name, or one trailing `*` as a prefix match.
5. **Argument constraints** (top-level argument names; all listed constraints must hold):
   - `equals`, `in`: the value is a JSON string, boolean or finite number and is exactly equal
     (no case folding, no Unicode normalisation, no type coercion).
   - `max`, `min`: the value is a JSON number within the bound. A numeric string fails.
   - `pathWithin`: the value is an absolute POSIX path without NUL; after resolving `.` and `..` it
     equals the base or lies below it at a `/` boundary (`/a/b-archive` is not below `/a/b`).
   - A constrained argument that is missing fails.
6. `policy.default` is `"deny"` in every registered fixture.

Every fixture's arguments validate against the tool's `inputSchema`, so no fixture can be passed by
schema validation alone. Each attack has a near-identical benign control: same tools and policy, and
exactly one of {caller, tool name, arguments, headers, meta, input responses, retry flag} differs.
For `authz-asserted-identity` the generator also checks that the lure works: substituting the asserted
identity for the authenticated one makes the call allowed.

## 5. Held-out families (adapted from HELD-OUT-PROTOCOL §3)

- **D:** different domains (hospital records, utility grid, insurance claims); the dev domain is a
  software-delivery platform.
- **L:** policy and identity shape: a deny beside a wildcard allow, opaque IdP subjects and numbered
  service ids, an assertion nested deeper in the arguments.
- **S:** surface: an `input_required` retry, a current actor with a prior actor, an identity asserted in
  an input response.
- **E:** encoding: a sibling directory sharing a name prefix, a look-alike (Cyrillic) character, a
  mixed-case header.

The generator enforces ≥ 3 dev and ≥ 2 held-out fixtures per vector, at least one held-out D or L per
vector, and that no development artefact (domain, servers, clients, users, agents, the assertion
argument and header names) appears in a held-out fixture. Registered: **12 dev + 12 held-out**
(families D 3, L 3, S 3, E 3). There is no key material; the generator is deterministic and still
refuses to overwrite a registered set.

## 6. Commitments

1. **Implementer blindness.** Whoever implements a measured defender's authorization works from §3–§4
   of this file, the crosswalk rows and the **dev** fixtures only. They do not open
   `scripts/authorization/heldout-cases.mjs` or `staging/authorization/heldout/` until the held-out
   numbers are published. These fixtures were written with an AI assistant; the mcp-bastion
   implementation will be done in a separate working session that is given only the permitted material.
2. **Defender freeze.** Before the first held-out run, each defender's version or commit is written to
   `staging/authorization/MANIFEST.json → defenderFreeze`. No defender changes between that run and
   publication.
3. **One run.** Held-out results are published as first measured. A malformed fixture is removed and the
   removal logged in `MANIFEST.json → removals`; no fixture is ever edited or regenerated.
4. **No score cap.** Every decision in this family is deterministic under §4, so `detect` and `enforce`
   are both expected and no fixture carries `scoreCap`.
5. **Peers.** Measured: `null-baseline`, `mcp-bastion`, `mcp-firewall`, `pipelock` (each wired as
   `detect:false` only after confirming it has no per-caller authorization, otherwise `unknown`), plus
   **agentgateway** (MCP authorization, CEL) and **ToolHive** (Cedar authorization), both Apache-2.0,
   each at a release pinned at the freeze. Adapters drive each tool's real code; the adapter integrity
   rule (`adapters/CONTRACT.md`) applies. A peer whose real code cannot be driven is reported as not
   measured, with the reason, never estimated.
6. **Policy translation.** Each adapter translates the fixture's policy into the tool's own policy
   language and maps the caller's identities to credentials the tool verifies natively. A rule the
   tool cannot express (for example traversal-safe path containment) is a measured gap: that fixture is
   scored as not defended and the reason is listed. Translations are published with the adapter.
7. **Two totals.** Results after promotion are reported over the 37 published vectors and over the 41
   vectors including this family, with a `docs/CHANGELOG-scoring.md` entry.

## 7. Crosswalk agreement

Rater A (primary) rows and a blind Rater B pass (an LLM, given only the codebook and
`staging/authorization/ratings/vectors-for-rating.json`) are registered in
`staging/authorization/ratings/`. Pre-adjudication agreement over these 4 vectors: STRIDE primary κ
1.00; nistAiRmf sets 4/4 exact; **mcpLayer sets 0/4 exact.** Rater A placed the defence at
`host-orchestration` (the gateway), Rater B at `server` (the gateway as the server callers reach). That
is a real ambiguity in the codebook for gateway-placed controls and is adjudicated openly at promotion
(`rubric/ratings/ADJUDICATION.md`). Nine disagreements are listed in
`staging/authorization/ratings/AGREEMENT-pre-adjudication.md`. Rater A's rows were not changed after
Rater B's sheet was read. A human Rater C remains an open invitation.

## 8. Promotion procedure

1. Implement and freeze defenders (commitments 1–2).
2. Verify every staged file still matches its MANIFEST hash.
3. Adjudicate the crosswalk rows; merge them into `rubric/crosswalk.json` (version bump).
4. Add `authorized-call` to `adapters/CONTRACT.md` and to every peer adapter.
5. Move dev fixtures into `testcases/` and held-out fixtures into the held-out corpus, byte-identical
   (checked against the hashes).
6. Run dev, then held-out once, for every peer; run the benign corpus; regenerate the leaderboard.

## 9. Limits, stated plainly

- **Same author, known design.** On the day of registration the benchmark author also wrote a private
  implementation plan for mcp-bastion 1.4.0 that names deny-overrides, intersection for delegated
  agents and traversal-safe path containment. The §4 semantics match that plan. Blindness is therefore
  to **code**, not to intent. The mitigations are the standards cited for each rule, the two
  independent peers in §6.5, and the open invitation for externally authored fixtures.
- **Small.** 24 fixtures over 4 vectors. Held-out numbers on 12 fixtures are indicative, not precise.
- **One reading.** §4 is one reasonable reading of the cited sources. Where a tool's reading differs on
  a borderline case (numeric strings failing closed, exact matching without Unicode normalisation),
  that is reported, not hidden.
- **Authentication assumed.** These fixtures say nothing about whether a caller's credential is genuine.

## 10. Deviations from registration (logged after the fact)

§1–§9 above are the registered text and are not edited. Deviations are recorded here and in
`staging/authorization/MANIFEST.json → deviations`. None so far.
