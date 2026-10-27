# mcp-bastion: `authorized-call` policy translation

Commitment 6.6 of `docs/AUTHORIZATION-PREREG.md`. The `authorized-call` case in `adapter.mjs` uses
this translation.

## What runs

The adapter drives bastion's **real gateway path**, not only the exported evaluator:
`BastionConfigSchema` → `UpstreamManager` → `startHttpServer` on loopback, with one small HTTP
upstream per `<server>` tool group (connected on demand). The fixture's request is sent over HTTP as
a client would send it. bastion runs with its default `balanced` profile
(`security.onAuthorization: "block"`).

**Scoring.** `detect = enforce = true` when bastion answers the judged request with a refusal and no
`tools/call` reached any upstream during it. Otherwise `{detect: false}`. If bastion's schema rejects
the translated config, bastion would not start, so the result is `{detect: false}` with the
rejection as the signal: an honest miss.

## Policy

| Fixture (§4) | bastion `authorization` config |
|---|---|
| `policy.default` | `authorization.default` (same values) |
| `rules[i].effect` | `effect`, unchanged |
| `rules[i].principal` (`"*"` or `{client\|user\|agent: name}`) | `principal`, unchanged (same shape) |
| `rules[i].tools` (exact, or one trailing `*`) | `tools`, unchanged (same pattern language) |
| `rules[i].args.<name>.{equals,in,max,min,pathWithin}` | `args`, unchanged (same constraint names and meaning) |
| (no rule id) | `id: "fixture-rule-<i+1>"` |
| `separator` | `namespace.separator` |
| `tools[]` | grouped by `<server><separator>`, one upstream per server, served under the un-prefixed name |

`authorization.enabled: true`, `trustStructuralClaims: false`.

**Translations that change nothing a rule says:**
- **Host client.** bastion always authenticates a transport client, and every identity a call carries
  must be permitted. A caller with no `client` (`bearer-user`, `delegation`) is therefore sent through
  the client `bench-agent-host`, and one rule is appended:
  `{ id: "host-client", effect: "allow", principal: { client: "bench-agent-host" }, tools: ["*"] }`.
  This adds a permit for the host and removes none, so the user and agent grants still decide. A deny
  for `"*"` still applies to the host.
- **Client names.** Every client a rule names is declared in `listen.clients`, because bastion rejects
  a rule naming an unknown client.

## Identities (caller → credentials bastion verifies natively)

| `caller` | What bastion receives |
|---|---|
| `client` | That client's bearer token (`listen.clients.<client>.tokenEnv`; random token per run). bastion matches it by constant-time digest. |
| `user` | `sub` of an ES256-signed delegate JWT, one per upstream (`aud` = server name), in that upstream's forwarded header. bastion runs the upstream in **signature** mode against an inline public JWK set, so the claims are authenticated. |
| `agent` | The same token's `act.sub` (the current actor). |
| `priorAgents` | Nested `act` claims inside the current actor. bastion ignores them for authorization (RFC 8693 §4.1). |
| `authenticatedBy` | Informational. `bearer-client`: bearer only. `bearer-user`: token with `sub` and no `act`. `delegation`: `sub` + `act`. |

## Request

| Fixture `request` | Sent as |
|---|---|
| `name`, `arguments` | `tools/call` params |
| `headers` | HTTP headers on the request. bastion forwards only configured headers, so these never become identities. The adapter's own `authorization` and delegate headers win on a name clash. |
| `meta` | `params._meta` |
| `retryOf: "input_required"` + `inputResponses` | A real MCP 2026-07-28 MRTR exchange, with a 2026-07-28 client and upstream built from the MCP SDK packages bastion ships with. Round 1 (same caller, same arguments, no input responses) gets bastion's sealed `requestState` if bastion lets it through. The judged round 2 carries `inputResponses` and that state. MRTR does not exist in the legacy era (a legacy hop rejects `input_required`), so retries cannot run on the legacy path every other fixture uses. |

## §4 constructs bastion cannot express

None. Every §4 construct maps one to one onto bastion's `authorization` schema.

## Where bastion is stricter than §4

- **Deny rules with `args` fail closed.** Under §4 rule 3, a deny applies only when its `args` are
  satisfied. bastion also applies a deny when a constrained argument is missing or has a type the
  constraint cannot compare (CHANGELOG, `[Unreleased]`). This can only make bastion refuse more.
  It changes a result only when a benign control relies on such a deny not applying.
- **Untrusted tokens refuse the call.** A delegate token that is present but untrusted refuses the call
  (`delegation:unverified`). The adapter's tokens always verify, so this does not arise here.
