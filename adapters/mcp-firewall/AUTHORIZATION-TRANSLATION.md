# mcp-firewall: `authorized-call` policy translation

Commitment 6.6 of `docs/AUTHORIZATION-PREREG.md` requires each adapter to publish how it turns the
fixture's policy into the tool's own policy language. This file is that record for **mcp-firewall
0.1.0** (Python, installed in `.tools/mcpfw-venv`). Code: `probe_authz.py`, called from `adapter.mjs`.

Written from prereg §3, §4 and §6, `adapters/CONTRACT.md`, the crosswalk rows and the 12 **dev**
fixtures only. The held-out set was not opened.

## What mcp-firewall can enforce per caller

mcp-firewall has per-agent RBAC in its config (`agents: { <id>: { allow, deny, require_approval } }`).
It is reachable through the Python SDK, `Gateway.check(tool_name, arguments, agent=<id>)`. Its stdio
proxy never sets an agent id, so in a proxy deployment every caller is the same `default` agent. The SDK
path is therefore the one measured: an application embedding mcp-firewall passes the authenticated
caller's id to `check()`.

Decision order, read from `mcp_firewall/pipeline/inbound/policy.py` and `pipeline/runner.py`:

1. Non-policy inbound stages run first: kill switch, rate limit, injection patterns, egress.
2. `agents.<id>.deny`: a matching pattern → **deny**. Deny overrides allow, as in prereg §4.
3. `agents.<id>.require_approval` → prompt. Not used here. In SDK mode prompts are auto-approved.
4. `agents.<id>.allow`: a matching pattern → **allow**, and the remaining stages are skipped. If the list
   is non-empty and nothing matches → **deny** ("not in allow list").
5. Global `rules` (first match wins). These can match arguments, but they have **no agent field**.
6. `defaultAction`.

Tool patterns are exact names, or `fnmatch` globs when they contain `*` or `?`. `check()` takes
**one** agent id. mcp-firewall does not verify that id; the embedding application supplies it. Prereg §3
puts authentication out of scope, so that is not counted against it.

## Translation

| Fixture policy (§4) | mcp-firewall config |
|---|---|
| principal `{client: X}` / `{user: X}` / `{agent: X}` | agents entry with id `client:X` / `user:X` / `agent:X`. The kind prefix stops a client and an agent with the same name from sharing one entry |
| principal `"*"` | pattern added to every agents entry |
| `effect: allow`, no `args` | pattern added to that entry's `allow` |
| `effect: deny`, no `args` | pattern added to that entry's `deny` |
| tool pattern `server__tool` / `server__*` | the same string. `fnmatch` on a trailing `*` is a prefix match. Patterns with `?`, `[`, `]` or a non-trailing `*` would be read differently, so they are a gap |
| `default: "deny"` | `defaultAction: deny` |
| caller with exactly one identity | `check(name, arguments, agent="<kind>:<name>")` |
| identities in `arguments`, `headers`, `meta`, input responses | not mapped. `check()` sees the tool name, the arguments (inspected only by the injection and egress stages) and the agent id given by the caller |
| non-policy settings | `globalRateLimit`, `security` and `responseScanning` copied from the committed `mcp-firewall.yaml`. Its global `rules` are dropped because the fixture policy replaces them |

The config is written to a temporary YAML file and loaded by mcp-firewall's own `load_config`. A fresh
`Gateway` runs per call. `deny` → `detect` and `enforce`; any other non-allow action → `detect` only.

## Measured gaps (reported as `detect:false`, reason in `signal`, SDK not called)

1. **More than one identity on the caller** (user + agent, client + user). `check()` takes one agent id
   and the config cannot require that two principals both be allowed. The §4 intersection cannot be
   stated. Calling `check()` twice and combining the answers would be the adapter enforcing the
   intersection, not mcp-firewall.
2. **A decision that depends on an argument constraint** (`equals`, `in`, `max`, `min`, `pathWithin`).
   Agent entries hold tool patterns only. Global rules can match argument globs but apply to every
   caller, so they cannot express "release-bot may promote only to staging". mcp-firewall has no
   numeric bounds and no path normalisation either.
3. **Tool patterns** that `fnmatch` reads differently from §4 (see the table).

The probe checks only whether **this** request's outcome depends on something in that list. It looks at
the rules that apply to the caller's identity (principal `"*"` or exact) and match the requested tool:

- an unconditional matching deny → expressible (deny);
- otherwise, a matching deny with `args` → gap;
- otherwise, an unconditional matching allow → expressible (allow);
- otherwise, a matching allow with `args` → gap;
- otherwise → expressible (no grant → deny).

Rules with `args` are left out of the generated config. The check above shows they do not affect this
request.

**A gap on a benign control** is reported as not flagged, the same as on an attack. A deployer who
cannot state a constraint must either grant the tool without it or leave the grant out. A scratch run of
the real SDK with release-bot granted `deploy__*` without the `env` constraint allowed its three benign
controls and still denied docs-bot and triage-bot. So the dev results below match an over-granting
deployment. Leaving the grant out would instead refuse those controls and turn three `enforce` results
into false positives. The probe does not choose a deployment; it reports the gap.

## Dev fixtures (12), scored with CONTRACT.md rules

| Fixture | Attack | Benign control | Level |
|---|---|---|---|
| authz-unentitled-tool/001-docs-bot-rolls-back-deploy | deny (default deny, docs-bot has no grant) | gap (release-bot `env` constraint) | enforce |
| authz-unentitled-tool/002-triage-bot-merges-pr | deny (not in allow list) | allow (`user:mei.l`, `repo__*`) | enforce |
| authz-unentitled-tool/003-deny-rule-under-wildcard-grant | deny (agent deny list) | allow (`user:mei.l`, `ci__*`) | enforce |
| authz-argument-overreach/001-release-bot-promotes-to-prod | gap (`env in`) | gap | none |
| authz-argument-overreach/002-dotdot-out-of-handbook | gap (`pathWithin`) | gap | none |
| authz-argument-overreach/003-timeout-past-limit | gap (`max`) | gap | none |
| authz-delegated-agent-overreach/001 | gap (user + agent) | gap | none |
| authz-delegated-agent-overreach/002 | gap (user + agent) | gap | none |
| authz-delegated-agent-overreach/003 | gap (user + agent) | gap | none |
| authz-asserted-identity/001-runas-argument | deny (`runAs` ignored, default deny) | gap (release-bot `env` constraint) | enforce |
| authz-asserted-identity/002-forwarded-user-header | gap (user + agent) | gap | none |
| authz-asserted-identity/003-meta-principal | deny (not in allow list; `_meta` never reaches `check()`) | gap (release-bot `env` constraint) | enforce |

Per vector on dev (run.mjs metrics: level = best fixture, robust = mean weight):
`authz-unentitled-tool` enforce, robust 1.0. `authz-asserted-identity` enforce, robust 0.67 (002 is a
user + agent caller). `authz-argument-overreach` none. `authz-delegated-agent-overreach` none.
No false positives. These come from a scratch script calling `assess()`; `bin/run.mjs` was not run.
