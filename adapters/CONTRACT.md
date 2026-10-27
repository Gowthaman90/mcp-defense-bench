# Adapter contract

Each scored tool provides `adapters/<tool>/adapter.mjs` exporting:

```js
export const meta = { tool, class, reproducible };
export async function assess(input, testcase) { /* … */ return { detect, enforce, signal }; }
```

`assess()` is called **twice per test case** by `bin/run.mjs`: once with the malicious `fixture`,
once with the `benignControl`. `input` is whichever object was passed (both carry `.type` + payload).

Return:
- `detect` — did the tool surface a signal on this input?
- `enforce` — can/does the tool block or short-circuit it (not merely warn)?
- `signal` — short human string for the results log (optional).

Optional `meta` fields:
- `fixtureTypes` — the fixture `type`s the adapter is wired for. Cases of any other type are not run:
  their vectors stay `unknown` (not a miss), and they do not count toward the benign-corpus denominator.
  For a peer measured on one family only.

- `unwiredFixtureTypes` — the opposite: fixture `type`s the adapter is not wired for yet. Same effect
  (vectors stay `unknown`, not a miss). Used when a peer may support a family but no adapter drives
  that code yet.

A test case may carry `"scoreCap": "detect"`: its level is capped at **detect** even when the tool
blocks (used where an RFC says the property must not drive access control, e.g. prior actors in an
RFC 8693 delegation chain; `docs/DELEGATION-PREREG.md` §6.4). The cap applies on every corpus.

## The integrity rule that makes scores honest

> An adapter must report only what its tool **actually inspects at runtime** — never what its
> regexes *could* catch if pointed at data the tool never sees.

Example: mcp-bastion inspects tool **definitions** and definition **hashes**, but not tool **results**
or transport. So its adapter returns `{detect:false}` for result-borne and transport fixtures, even
though its text rules would "match" if misapplied. That honesty is the whole point — the benchmark
measures deployed behavior, not theoretical capability.

## Scoring (in `bin/run.mjs`)

Per vector, from the malicious vs benign results:
- missed the attack (`!detect`) → **none**
- caught the attack **and** a false positive on the benign control → **none** + `falsePositive` flag
- caught **and** clean on benign, warn-only → **detect**
- caught **and** clean on benign, can block → **enforce**

A vector only reaches `verified: true` when a test case actually exercised it. `unknown` = the adapter
has no implementation for that fixture type yet (peer tools not wired) — scored 0, flagged, not
counted as a real miss.

## `authorized-call` (authorization family, `docs/AUTHORIZATION-PREREG.md`)

The fixture states a deployment policy, an already-authenticated caller (`client`, `user`, `agent`) and
one `tools/call` request. Intended semantics are §4 of the prereg. An adapter:

- **translates the fixture's `policy` into the tool's own policy language** and maps the caller's
  identities to credentials or context the tool verifies natively (commitment 6.6). The translation is
  published with the adapter. A rule the tool cannot express is a measured gap: that fixture is a miss,
  and the reason is in `signal`, never silently approximated;
- reports `enforce` only if the tool refuses the call **before any upstream contact** in its default
  enforcing configuration, and `detect` if it at least flags it;
- runs the benign control the same way: refusing it is a false positive. Because each control differs
  from its attack in one thing (usually the caller), refusing by tool name alone fails the control.

No case in this family carries `scoreCap`.

