# agentgateway: `authorized-call` policy translation

Commitment 6.6 of `docs/AUTHORIZATION-PREREG.md`. `adapter.mjs` uses this translation
(`translatePolicy`). It was written from prereg §3, §4 and §6, `adapters/CONTRACT.md`, the crosswalk
rows and the 12 **dev** fixtures only.

## What runs

- **Binary.** The real agentgateway **v1.6.0** release binary (Apache-2.0, git revision
  `ea5608642b9d5c94c5baf5fd9f2f9849b808e963`), downloaded from the GitHub release into
  `.tools/agentgateway/agentgateway` (gitignored). Its hash was checked against the release `.sha256`
  file and GitHub's asset digest. The adapter refuses to run a binary whose sha256 is not the pinned one:
  - darwin-arm64: `6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685`
  - linux-amd64: `496ed27e6a96b55a9ad7cabe5c2be7172511f44a3cb113e533d22bf93a7f079d`
  - linux-arm64: `b59ecac31103bb317d1377fd42b0cb25cd9a21f8c3f1d9ee14c3ff05f3f91abf`
- **One gateway per assessment.** The gateway is started as `agentgateway -f <config>` on a free
  loopback port. Its config has one MCP route with one target, `bench`: a dependency-free mock MCP
  server that serves the fixture's `tools` under their full namespaced names and records every
  `tools/call`. With one target, agentgateway does not prefix tool names, so the names agentgateway
  evaluates are the fixture's names, byte for byte. Admin, stats and readiness listeners are off.
- **Scoring.** `detect = enforce = true` when agentgateway answers the judged `tools/call` with a
  refusal (HTTP error, JSON-RPC error or `isError`) **and** the mock saw no `tools/call` during it.
  Otherwise the result is `{detect: false}`. The benign control runs the same way. If agentgateway
  rejects the config and exits, it enforces nothing, and the result is a miss with the error in `signal`.

## Two layers, because of where agentgateway exposes arguments

agentgateway's MCP-native `mcpAuthorization` evaluates CEL over the identity (`jwt.*`) and the
resource (`mcp.tool.name`, `mcp.tool.target`) only. Its docs say `mcp.tool.arguments` "isn't set
when `mcpAuthorization` rules run". The v1.6.0 source agrees: the context is built from the resource
alone, and the unit test `test_rbac_mcp_context_is_identity_only` asserts `!has(mcp.tool.arguments)`.
For decisions based on arguments, the docs point to the route-level `authorization` policy. That
policy's CEL context does carry `mcp.tool.name` and `mcp.tool.arguments` for a `tools/call`. So the
fixture policy is compiled into both layers, each doing what only it can do:

| Layer | agentgateway policy | Decides | Refusal seen by the client |
|---|---|---|---|
| A | `policies.mcpAuthorization` | whether every identity the token carries is entitled to the **tool**; deny rules without `args` | the tool is hidden from `tools/list`, and a call gets JSON-RPC `-32602 Unknown tool` (HTTP 400) |
| B | `policies.authorization` (route) | for `tools/call`: whether each carried identity's tool-matching grant has its `args` satisfied; deny rules with `args` | HTTP 403 `authorization failed` |

Both run before any upstream contact. B runs first (it is an HTTP route policy), then A runs inside
MCP processing. A call is allowed only if both allow it, so A AND B is §4 rule 3 (see below).

Both layers use agentgateway's own rule kinds: `allow` (OR-ed; if any allow rules exist and none
matches, the request is denied) and `require` (all must hold). Deny rules are written as
`require: "!(<match>)"`, not as agentgateway's `deny:` kind. agentgateway documents that `deny`
fails open when its expression errors and recommends `allow`/`require`. With `require`, an
evaluation error refuses the call.

## Identities (caller → JWT verified by agentgateway)

`jwtAuth` runs in `strict` mode: a fixed issuer, a fixed audience, and an inline ES256 JWKS generated
per run (the local test IdP). The caller's single bearer token carries:

| Fixture `caller` | JWT claim | CEL presence / value |
|---|---|---|
| `client` | `client_id` (RFC 9068 §2.2) | `has(jwt.client_id)` / `jwt.client_id` |
| `user` | `sub` | `has(jwt.sub)` / `jwt.sub` |
| `agent` | `act.sub` (RFC 8693 §4.1) | `has(jwt.act) && has(jwt.act.sub)` / `jwt.act.sub` |
| `priorAgents` | nested `act` inside `act` | never read: prior actors grant nothing (§4 rule 1) |

A client-only token has no `sub`. The policy never reads anything from the request (arguments,
headers, `_meta`, input responses) as an identity.

## Policy (§4 → CEL)

| Fixture (§4) | CEL |
|---|---|
| `principal: {client\|user\|agent: X}` | applies to that identity kind only: `<value> == "X"` |
| `principal: "*"` | applies to every carried identity kind: `true` |
| `tools: ["a__b"]` | `mcp.tool.name == "a__b"` |
| `tools: ["a__*"]` (one trailing `*`) | `mcp.tool.name.startsWith("a__")` |
| `equals: x` / `in: [x…]` | same JSON type and equal: `type(v) == string && v == "x"`, `type(v) == bool && v == true`, numbers `type(v) in [int, uint, double] && double(v) == double(x)`; `in` is an OR of these |
| `max` / `min` | `type(v) in [int, uint, double] && double(v) <= max` (`>= min`); a numeric string fails |
| `pathWithin: B` | see below |
| constrained argument missing | `has(mcp.tool.arguments) && "name" in mcp.tool.arguments` fails, so the constraint fails |
| `default: "deny"` | agentgateway's allowlist semantics once an `allow` rule exists. Any other default is reported as untranslatable (no registered fixture has one). |

Where `v` is `mcp.tool.arguments["<name>"]`.

**Layer A** has one `allow` and one `require` per deny rule without `args`:

```
allow:   anyIdentity
         && (!has(client) || OR_r[r applies to client] (principal_r && tools_r))
         && (!has(user)   || OR_r[r applies to user]   (principal_r && tools_r))
         && (!has(agent)  || OR_r[r applies to agent]  (principal_r && tools_r))
require: !( OR_k(has(k) && principal_d) && tools_d )        # one per deny rule d without args
```

The intersection (§4 rule 2) is one expression. A user acting through an agent needs the user's
grant **and** the agent's. Allow rules with `args` count here at tool level, and their arguments are
checked in layer B.

**Layer B** is one `require`:

```
mcp.methodName != "tools/call" || ( has(mcp.tool)
   && for each kind k that has an argument-scoped grant:
        (!has(k) || !OR_r(principal_r && tools_r) || OR_r(principal_r && tools_r && args_r))
   && for each deny rule d with args:
        !( OR_k(has(k) && principal_d) && tools_d && args_d ) )
```

**Why A AND B is §4 rule 3.** For each identity, A requires some allow rule that names the tool, and
B requires that, if such a rule exists, one of them has its `args` satisfied. Together that is "some
allow rule whose tools and args match", the condition for passing both `no-grant` and `argument`. A
deny rule without `args` refuses in A. A deny rule with `args` refuses in B only when its `args` are
satisfied, as rule 3 says (a deny whose constrained argument is missing does not apply). Deny overrides
allow because each deny is a `require` that every request must pass, whatever the allows say.

Example (three rules: a release-bot `deploy__*` grant with `env in ["staging"]`, a user grant on
`repo__*`, a triage-bot deny on `ci__delete_cache`):

```
A allow:   ((has(jwt.client_id) || has(jwt.sub) || (has(jwt.act) && has(jwt.act.sub)))
            && (!has(jwt.client_id) || (jwt.client_id == "release-bot" && mcp.tool.name.startsWith("deploy__")))
            && (!has(jwt.sub) || (jwt.sub == "user:mei.l" && mcp.tool.name.startsWith("repo__")))
            && (!(has(jwt.act) && has(jwt.act.sub)) || false))
A require: !((has(jwt.client_id) && jwt.client_id == "triage-bot") && mcp.tool.name == "ci__delete_cache")
B require: mcp.methodName != "tools/call" || (has(mcp.tool) && (!has(jwt.client_id)
            || !(jwt.client_id == "release-bot" && mcp.tool.name.startsWith("deploy__"))
            || ((jwt.client_id == "release-bot" && mcp.tool.name.startsWith("deploy__"))
                && (has(mcp.tool.arguments) && "env" in mcp.tool.arguments
                    && (type(mcp.tool.arguments["env"]) == string && mcp.tool.arguments["env"] == "staging")))))
```

## `pathWithin`: as faithful as agentgateway's CEL allows

agentgateway's CEL has no path-normalisation function. It does have the `regexReplace` extension,
which in v1.6.0 replaces the **first** match only (`regex::Regex::replace` in `crates/celx`). The
translation resolves the path with that function:

1. Append `/`. Then make 64 passes of `regexReplace("//+|/\./|/<seg>/\.\./", "/")`, where `<seg>` is
   any segment other than `.` and `..`. Each pass applies one rewrite that keeps the resolved path the
   same.
2. Drop `..` at the root: `regexReplace("^(/\.\.)+/", "/")`.
3. Allowed only if the value is a string, starts with `/`, has no NUL, the result contains no `//`,
   `/./` or `/../`, and the result starts with `<base>/`. The `/` boundary rules out
   `/a/b-archive` for base `/a/b`.

The normalised path is bound once with a one-element comprehension, `[<n>].all(p, …)`, because CEL has
no `let`.

**Measured gap (bounded, fail-closed).** A path that needs more than 64 rewrites (64 redundant
`//`, `.` or `<seg>/..` parts) still holds one of those sequences after step 2 and is **refused**.
Such a path is never allowed out of its base, but a legitimate path with that many redundant parts
would be a false positive. Below the bound the translation agrees with an independent implementation
of the §4 definition on 1,528 paths through the real binary (fixed edge cases plus 1,500
pseudo-random ones built from `..`, `.`, empty, prefix-sharing and ordinary segments). Unicode
look-alikes and percent-encodings are ordinary bytes to both, as §4 says (no normalisation, no
decoding).

This is a CEL program an operator would have to write by hand. agentgateway offers no
`pathWithin`-like primitive. A deployment using the obvious `startsWith("<base>/")` would let
`/<base>/../x` through. With that naive rule, dev fixture `002-dotdot-out-of-handbook` becomes a miss
(mutation check below).

## Request

| Fixture `request` | Sent as |
|---|---|
| `name`, `arguments` | `tools/call` params, unchanged |
| `headers` | HTTP headers, lower-cased (values sent as UTF-8 bytes). The caller's `authorization: Bearer <jwt>` replaces any fixture header of that name. |
| `meta` | `params._meta` |
| `retryOf: "input_required"`, `inputResponses` | Round 1: the same call without input responses. The mock answers an allowed call with an `input_required`-shaped result carrying `requestState`. Round 2 (judged): the call plus `inputResponses` and that `requestState` (if round 1 got one). Only round-2 upstream calls count. The session is 2025-06-18; agentgateway authorizes every `tools/call` the same way and forwards both fields upstream (checked). No dev fixture uses this. |

`initialize` is sent first with the caller's token. The backend is `statefulMode: stateless`.

## Where agentgateway differs from §4

- **Deny rules with `args` follow §4 rule 3 literally.** If the constrained argument is missing, or
  has the wrong type, the deny does not apply (same as the prereg; mcp-bastion is stricter here).
- **`pathWithin`** is exact up to the 64-rewrite bound and refuses beyond it (above).
- **Hidden tools.** Layer A also removes unentitled tools from `tools/list`. This is not scored
  (§3, "two choices").
- Nothing else in §4 needed approximating: identities, the intersection, deny-over-allow, tool
  patterns and `equals`/`in`/`max`/`min` map directly to CEL.

## Checks run before the freeze (scratch scripts, not committed)

- **Dev fixtures** (12, CONTRACT.md scoring): 12/12 `enforce`, 0 false positives. Argument cases
  (`argument-overreach/*`, `delegated-agent-overreach/002`) are refused by layer B (HTTP 403). All
  others are refused by layer A (`Unknown tool`, HTTP 400). Every benign control reached the mock.
- **Mutation checks** (each drops one part of the translation):
  - no layer B: 8/12;
  - naive prefix `pathWithin`: 11/12 (002 dotdot missed);
  - union instead of intersection: 9/12 (`delegated-agent-overreach/001`, `/003` and
    `asserted-identity/002` missed);
  - deny rules dropped: 11/12 (`unentitled-tool/003` missed).

  So the result comes from the translated policy, not from startup errors or unrelated refusals.
- **Retry variants** of all 12 dev pairs (`retryOf: "input_required"` plus `inputResponses`): 12/12
  `enforce`, 0 false positives; benign round 2 reached the mock with `inputResponses` and `requestState`.
- `bin/run.mjs` was not run; nothing was written under `results/` or `testcases*/`.
