# ToolHive: authorization translation (`authorized-call`)

How `adapters/toolhive` turns an `authorized-call` fixture (`docs/AUTHORIZATION-PREREG.md` §4) into a
ToolHive v0.57.0 deployment, and where ToolHive's Cedar cannot say exactly what §4 says. Written from
§3, §4, §6, `adapters/CONTRACT.md` and the 12 dev fixtures only.

## Measured configuration

| | |
|---|---|
| Release | ToolHive **v0.57.0** (Apache-2.0), commit `9726b3f0f299731054745ad04aa4e7f254aaa620` |
| Archive | `toolhive_0.57.0_<os>_<arch>.tar.gz`, checked against `toolhive_0.57.0_checksums.txt` |
| `thv` sha256 | darwin-arm64 `327906368a1756380fe8bd7f1530b181251821a8c6a25f9131840ff0cec51698` (used for the dev run) · darwin-x64 `62953eb8…826c947` · linux-x64 `f68c4462…ef24f0e` · linux-arm64 `9908d2a0…ce24d4001` (full values in `adapter.mjs`) |
| Install | `.tools/toolhive/thv` (git-ignored); the adapter refuses any other hash |
| Mode | direct proxy: `thv run <remote URL> --foreground --transport streamable-http` |
| Auth | `--oidc-issuer`, `--oidc-jwks-url`, `--oidc-audience`, `--oidc-insecure-allow-http`, `--jwks-allow-private-ip` against a per-case loopback IdP (ES256 JWKS) |
| Authz | `--authz-config` with a `cedarv1` config compiled per case by `translate.mjs` |
| State | `HOME` and `XDG_*` point at a per-case temporary directory, deleted afterwards |

**ToolHive needs a container runtime even for a remote URL.** `cmd/thv/main.go` calls
`container.CheckRuntimeAvailable()` for every command except a few informational ones, and
`runSingleServer` builds a runtime client before it looks at the URL. No container is created for a
remote URL. The bench uses a dedicated Colima profile, `mcpbench`
(`colima start --profile mcpbench --cpu 2 --memory 2 --disk 10`). The adapter points ToolHive at that
socket only, through `TOOLHIVE_DOCKER_SOCKET`, an explicit override with no fallback in
`pkg/container/docker/sdk`. It also sets `DOCKER_HOST`, and gives the child process a throwaway `HOME`
so no other socket can be discovered. If the socket is missing, the adapter throws. It never falls back
to another socket or to vMCP. The dev run created no containers, networks or volumes in that profile.

### Observation: vMCP was tried and not scored

`thv vmcp serve` needs no runtime, and it enforces the same Cedar authorizer (OIDC worked, and a
denial was HTTP 403 before upstream contact). It is **not** the measured configuration, because of one
behaviour. `pkg/vmcp/core/admission.go` `FilterTools` builds each session's tool table by evaluating
`call_tool` with **no arguments**. A tool whose only grant is argument-scoped (for example
`env in ["staging"]`) is therefore dropped at `initialize`, and every later call to it gets
`tool "<name>" not found`, even with valid arguments. On the dev set that refused 8 of 12 benign
controls. The direct proxy (`pkg/authz/middleware.go`) authorizes `tools/call` with its arguments, so
it does not have this behaviour. This is a property of ToolHive's vMCP mode as of v0.57.0, not of
the translation below.

## What ToolHive gives a Cedar policy (verified on the binary)

- `principal` = `Client::"<sub>"`. A token without `sub` is rejected at authentication
  (`missing or invalid 'sub' claim`).
- Every JWT claim appears as `claim_<name>`, on the principal and in the context. Nested objects are
  records, so `principal.claim_act.sub` works.
- `resource` = `Tool::"<tool name as sent>"`, with `resource.name` holding the same name.
- Every top-level argument appears as `resource.arg_<name>`: strings as String, booleans as Bool,
  **every JSON number as a Cedar `decimal`** (four fractional digits; a number outside decimal range
  is dropped). Objects and arrays only appear as `arg_<name>_present`.
- `forbid` overrides `permit`, the default is deny, and **any policy evaluation error denies the whole
  request** (`IsAuthorized` returns an error when `diagnostic.Errors` is non-empty).
- HTTP headers, `_meta` and input responses are not visible to the policy.

## Identities → token

| Fixture `caller` | Claim |
|---|---|
| `client` | `client_id` |
| `user` | `sub` |
| `agent` | `act.sub` (RFC 8693) |
| `priorAgents` | nested `act` inside `act`, never read by the policy (§4 rule 1) |

ToolHive needs `sub`. When there is no user, `sub` is the client (RFC 9068 §2.2, client-credentials
grant), or the agent itself when the caller is an agent alone. So the policy reads "a user is present"
as `sub` present and equal to neither `client_id` nor `act.sub`. This breaks only if one token's user
and client (or user and agent) share a name. An authorization server keeps those namespaces apart
(RFC 9068 §5), and no dev fixture does this.

## Policy shape

The translation is exact for §4 rules 1–4 and builds three kinds of policy:

1. `permit(principal, action == Action::"call_tool", resource) when { principal has claim_sub };`,
   for any authenticated caller.
2. **One `forbid` per identity kind (client, user, agent)**: the token carries that identity AND no
   allow rule naming it (or `"*"`) matches the tool with all its arguments satisfied. This is the
   §4 intersection: every carried identity needs its own grant. It covers both `no-grant` and
   `argument`.
3. **One `forbid` per deny rule**: the rule names a carried identity (or is `"*"`), matches the tool,
   and its arguments hold. Deny overrides allow, because Cedar's `forbid` does.

Tool patterns: an exact name becomes `resource == Tool::"…"`, and a trailing `*` becomes
`resource.name like "<prefix>*"` (a literal `*` is escaped). A `*` anywhere else is reported as
untranslatable.

## Argument constraints

| §4 | Cedar | Exact? |
|---|---|---|
| (any) | `resource has "arg_<n>"` first: a missing argument fails | yes |
| `equals` string / boolean | `resource["arg_<n>"] == "…"` / `== true` (no case folding, no coercion) | yes |
| `equals` number | `== decimal("…")` | values are rounded to 4 decimals by ToolHive |
| `in` | OR of `equals` | as `equals` |
| `max` / `min` | `.lessThanOrEqual(decimal(…))` / `.greaterThanOrEqual(…)` | as `equals`; a string value errors → request denied |
| `pathWithin` | see below | **fails closed** |

A bound or `equals` number that is not exactly a four-decimal Cedar decimal, an unknown operator, a
principal naming two identities, or a `default` other than `"deny"` makes the policy untranslatable.
That fixture is then reported as a miss with the reason in `signal`.

### `pathWithin`: a measured gap, handled fail-closed

Cedar has no path normalisation and no regular expressions, only `like` with `*`, and the set of paths
whose `.`/`..` resolution lands under a base is not something `like` can express. The translation is:

- **exact for canonical paths.** The value is a string, starts with `/`, contains no NUL, and equals the
  (normalised) base or matches `<base>/*`, so `/a/b-archive` is not under `/a/b`;
- **fail-closed for non-canonical paths.** Any path containing `//`, `/./`, `/../`, or ending in `/.`
  or `/..`, never satisfies an allow rule's `pathWithin` and always satisfies a deny rule's.

So a `..` escape is refused. But a benign call whose path contains dot-segments that resolve *inside*
the base is refused too, and the scoring counts that as a false positive. That is the measured cost of
the gap, and it is visible in results. The adapter appends the note
`pathWithin fails closed on paths with ./../empty segments` to its `signal` whenever the policy uses
`pathWithin`.

### Smaller precision gaps (documented, not special-cased)

- **Decimal rounding.** ToolHive converts numbers with four fractional digits, so `minutes: 60.00001`
  becomes `60.0000` and passes `max: 60`, though §4 says it fails. Equality has the same rounding.
- **Out-of-range numbers.** A number beyond Cedar's decimal range (about ±9.2e14) is dropped, so the
  argument looks missing. Inside an allow rule that fails, which is correct. Inside a deny rule with
  `min`/`max`, the deny does not fire, which is fail-open for that edge.
- **Type errors deny everything.** A non-number value under `max`/`min`, or a non-string under
  `pathWithin`, is a Cedar evaluation error, and ToolHive denies the whole request. §4 would only
  fail that one constraint, so a *different* allow rule could still grant, or a deny rule with that
  constraint would simply not apply. ToolHive is stricter there.
- **Objects and arrays** are invisible to the policy (only `arg_<n>_present`), so `equals`/`in` on
  them never holds. §4 compares scalars only, so this matches.

## Request handling

`request.headers` become HTTP headers and `request.meta` becomes `params._meta`. ToolHive does not
expose either to the policy, which is the behaviour §4 rule 1 asks for. For a fixture with
`retryOf: "input_required"`, round 1 (no input responses) runs first. If ToolHive lets it through, the
mock answers `input_required` with a `requestState`. The judged round 2 carries the fixture's
`inputResponses` and that state.

`enforce` = `detect` = the judged call got an HTTP or JSON-RPC error (or `isError`) **and** the mock
saw no `tools/call` during it. A denial from ToolHive is `HTTP 403`. The benign control runs the same
way.

## Dev results (12 fixtures, scratch run of `assess()` with CONTRACT.md scoring)

| Fixture | Attack | Benign control | Level |
|---|---|---|---|
| argument-overreach/001 release-bot promotes to prod | 403, not forwarded | forwarded | enforce |
| argument-overreach/002 `..` out of handbook | 403, not forwarded | forwarded | enforce |
| argument-overreach/003 timeout past limit | 403, not forwarded | forwarded | enforce |
| asserted-identity/001 `runAs` argument | 403, not forwarded | forwarded | enforce |
| asserted-identity/002 `x-forwarded-user` header | 403, not forwarded | forwarded | enforce |
| asserted-identity/003 `_meta` principal | 403, not forwarded | forwarded | enforce |
| delegated-agent-overreach/001 triage-agent merges | 403, not forwarded | forwarded | enforce |
| delegated-agent-overreach/002 release-agent promotes to prod | 403, not forwarded | forwarded | enforce |
| delegated-agent-overreach/003 platform-agent for contributor | 403, not forwarded | forwarded | enforce |
| unentitled-tool/001 docs-bot rolls back | 403, not forwarded | forwarded | enforce |
| unentitled-tool/002 triage-bot merges | 403, not forwarded | forwarded | enforce |
| unentitled-tool/003 deny under wildcard grant | 403, not forwarded | forwarded | enforce |

12/12 enforce, 0 false positives. No dev benign control has a dot-segment path, so the `pathWithin`
gap does not show on the dev set.

## Reproducing

```bash
colima start --profile mcpbench --cpu 2 --memory 2 --disk 10   # the runtime socket thv requires
node bin/run.mjs toolhive                                      # or call assess() directly
colima stop --profile mcpbench
```

`MCPBENCH_TOOLHIVE_DOCKER_SOCKET` overrides the socket path (default
`~/.colima/mcpbench/docker.sock`). Starting a Colima profile can switch the global Docker context;
switch it back with `docker context use <previous>` afterwards.
