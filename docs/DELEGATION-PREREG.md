# Delegation family: pre-registration

**Registered:** 2026-10-15, as git tag `delegation-prereg-2026-10-15`, **before any measured defender
implements delegation checks.** This file is the commitment; `staging/delegation/` is the registered
material. Reviewers should compare the two, and compare every fixture with the sha256 recorded in
`staging/delegation/MANIFEST.json`.

Status: **staged, unscored.** Nothing here changes the published v0.8.0 numbers. The family is
promoted into the scored rubric only by the procedure in §8.

## 1. Why this family exists

When one agent delegates to several sub-agent MCP servers for a signed-in user, it typically sends one
short-lived token per sub-agent through a relay or gateway. Some ways this goes wrong can be seen by
the sub-agent alone (an expired token). Others can only be seen by a component that sees the **whole
request**, for example two delegate tokens in one request that name different users. The benchmark
has no vector for any of these today. `credential-token-theft` covers the agent being tricked into
leaking a token; it does not cover a relay presenting a token to a party it was not issued for.

## 2. The objection this design answers

The AISec 2026 review objected that the benchmark and its strongest measured tool share an author.
`docs/HELD-OUT-PROTOCOL.md` answered with a held-out set written after the defender freeze. For this
family the order is stronger: **the vector definitions, the development fixtures and the held-out
fixtures are registered before any measured defender has delegation-checking code at all.**

## 3. Vectors (5)

| id | What goes wrong | Gateway-only? | Grounding |
|---|---|---|---|
| `delegation-audience-confusion` | Token presented to a party it was not issued for: a sibling sub-agent's token (lateral), or a token for the relay itself / with no audience (passthrough) | no (an upstream that checks `aud` also catches it) | MCP Security Best Practices, Token Passthrough; RFC 8707; RFC 8725 §3.9 |
| `delegation-subject-mixing` | Delegate tokens in one request name different users (`iss`+`sub`) | **yes** | OWASP ASI03; RFC 7519 §4.1.1–4.1.2 |
| `delegation-stale-relay` | Expired, not-yet-valid, expiry-less, or over-long-lived token relayed | no | RFC 7519 §4.1.4–4.1.5; RFC 8725 |
| `delegation-chain-laundering` | Unauthorized current actor; deep or cyclic prior-actor chain | mostly (policy lives at the deployment) | RFC 8693 §4.1 |
| `delegation-signature-forgery` | `alg` none / casing, attacker key, HS/asymmetric confusion, header key URL, post-signing tamper | no; scoreable only for tools that verify signatures | RFC 7515; RFC 8725 §2.1–2.2, §3.1–3.2, §3.10 |

Crosswalk rows (Rater A, pre-adjudication): `staging/delegation/crosswalk-rows.json`.

**Two choices made while authoring, recorded here:**
- *Passthrough is folded into audience confusion,* not a sixth vector, so it cannot read as
  double-counting the existing `credential-token-theft` (whose aliases include "token passthrough").
- *"The gateway holds long-lived credentials" is deliberately not a vector.* It is an architectural
  property that would favour the benchmark author's own tool by definition; it belongs in prose.

## 4. Fixture type `delegated-request` and its intended semantics

```jsonc
{
  "type": "delegated-request",
  "now": 1791936000,                       // fixed clock (2026-10-14T00:00:00Z) for every fixture
  "gateway":   { "audiences": ["…"] },     // audiences that identify the relay itself
  "upstreams": { "<name>": { "audience": "…", "incomingHeader": "…", "upstreamHeader": "…", "upstreamScheme?": "Bearer" } },
  "trust":     { "mode": "structural" } | { "mode": "signature", "jwks": {…}, "issuer": "…", "algorithms": ["ES256"|"EdDSA"] },
  "policy":    { "maxLifetimeSeconds": n, "clockSkewSeconds": n, "allowedActors": ["…"], "maxChainDepth": n },
  "request":   { "method": "tools/call"|"tools/list", "target": "<name>", "headers": { "<incomingHeader>": "<JWS>" } }
}
```

What each fixture's `intent.violates` means (encoded in `scripts/delegation/tokens.mjs#violations`,
used only to reject malformed fixtures at generation time, never run against a defender):

- `malformed`: the target's token is not a strict JWS compact serialization (three base64url segments,
  no padding, JSON objects).
- `audience-passthrough`: the target's token has no `aud`, or any `aud` value is a gateway audience.
- `audience-lateral`: otherwise, no `aud` value equals the target's audience (exact, case-sensitive).
- `subject-mixing`: the decodable tokens in the request carry more than one distinct (`iss`, `sub`) pair.
- `time`: `exp` missing or not a JSON number, or `now > exp + skew`, or `nbf > now + skew` (or non-number).
- `lifetime`: `exp − iat > maxLifetimeSeconds`.
- `actor`: the current actor (`act.sub`, else `act.client_id`) is not in `allowedActors`.
- `chain-depth` / `chain-cycle`: the nested `act` chain is longer than `maxChainDepth` / repeats an actor.
- `signature` (signature mode only): `alg` not in the allow-list (case-sensitive), `kid` not in the
  configured JWKS (header `jku` / `x5u` / `jwk` never followed), the signature does not verify, or `iss`
  differs from the configured issuer.

Each attack fixture has a near-identical benign control (same target and method, compliant tokens).
Structural-mode tokens are HS256 with a random secret that was never written down, so **no tool can
verify their signatures**, exactly as in an HS256 deployment where only issuer and upstream hold the
secret. Signature-mode fixtures embed only **public** JWKs; the private keys existed only in memory
during generation, so the fixtures can never be re-signed.

## 5. Held-out families (adapted from HELD-OUT-PROTOCOL §3)

- **D:** different domains (claims processing, freight logistics); the dev domain is travel booking.
- **L:** claim shape: bare-string and URN audiences, opaque subjects, actor named by `client_id`, no `exp`, `alg` casing.
- **S:** surface: `tools/list` instead of `tools/call`; upstream `Authorization: Bearer`; a key URL in the JWS header.
- **E:** encoding: standard-base64 payload, numeric-string `exp`, case-variant subject, payload swapped after signing.

The generator enforces ≥ 3 dev and ≥ 2 held-out fixtures per vector, at least one held-out D or L per
vector, and that no development artefact (domain, hosts, header names, subjects, actor names) appears
in a held-out fixture, including inside decoded token payloads. Registered: **15 dev + 15 held-out**
(families D 5, L 3, S 4, E 3).

## 6. Commitments

1. **Implementer blindness.** Whoever implements a measured defender's delegation checks works from
   §3–§4 of this file, the crosswalk rows and the **dev** fixtures only. They do not open
   `scripts/delegation/heldout-cases.mjs` or `staging/delegation/heldout/` until the held-out numbers
   are published.
2. **Defender freeze.** Before the first held-out run, each defender's version/commit is written to
   `staging/delegation/MANIFEST.json → defenderFreeze`. No defender changes between that run and publication.
3. **One run.** Held-out results are published as first measured. A malformed fixture is removed and the
   removal logged in `MANIFEST.json → removals`; no fixture is ever edited or regenerated
   (`scripts/gen-delegation.mjs` refuses to overwrite a registered set).
4. **RFC-conforming score cap.** Fixtures marked `"scoreCap": "detect"` (prior-actor depth/cycle) are
   scored at most `detect` even if a tool blocks, because RFC 8693 §4.1 says prior actors are
   informational and must not drive access control. `bin/run.mjs` gains this rule at promotion,
   **before** any run that includes the family.
5. **Peers.** Measured: `null-baseline`, `mcp-bastion`, `mcp-firewall`, `pipelock` (each wired as
   `detect:false` only after confirming it never parses delegate tokens, otherwise `unknown`), plus an
   adapter for the identity adapter in `vaquarkhan/MCP-Bastion`, a different project of the same name
   that validates JWT audiences. It drives its real code at a pinned commit. The adapter integrity rule
   (`adapters/CONTRACT.md`) applies to all of them.
6. **Two totals.** Results after promotion are reported over both the 32 published vectors and the 37
   vectors including this family, with a `docs/CHANGELOG-scoring.md` entry, so the change in the
   denominator cannot read as inflation.

## 7. Crosswalk agreement

Rater A (primary) rows and a blind Rater B pass (an LLM, from the codebook and vector descriptions
only) are registered in `staging/delegation/ratings/`. Pre-adjudication agreement over these 5 vectors:
mcpLayer sets 5/5 exact; STRIDE primary κ 0.29; 12 disagreements listed in
`staging/delegation/ratings/AGREEMENT-pre-adjudication.md`. Five vectors is too few for stable κ;
adjudication happens openly at promotion (`rubric/ratings/ADJUDICATION.md`). A human Rater C remains an
open invitation.

## 8. Promotion procedure

1. Implement and freeze defenders (commitments 1–2). Wire the `scoreCap` rule (commitment 4).
2. Verify every staged file still matches its MANIFEST hash.
3. Adjudicate the crosswalk rows; merge them into `rubric/crosswalk.json` (version bump).
4. Move dev fixtures into the development corpus (`testcases/`) and held-out fixtures into the held-out
   corpus, byte-identical (checked against the hashes), via the corpus generators.
5. Run dev, then held-out once, for every peer; regenerate the leaderboard from `results/`.

## 9. Limits, stated plainly

- The same author wrote these fixtures and a private design note for the benchmark author's own tool
  (mcp-bastion) listing the checks it would add. Blindness is therefore to **code**, not to intent: no
  defender's delegation code existed when the fixtures were registered, but the author knew which
  properties a defender should check. An externally authored set would be stronger and is invited.
- The intended semantics in §4 are one reasonable reading of the cited RFCs; where a tool's reading
  differs on a borderline case (for example the case-variant subject), that is reported, not hidden.
- Structural-mode fixtures test claims a relay can check without keys. They say nothing about
  authenticating a token; that is what the signature-mode fixtures are for.

## 10. Deviations from registration (logged after the fact)

§1–§9 above are the registered text and are not edited. Deviations are recorded here and in
`staging/delegation/MANIFEST.json → deviations`.

**D1 (2026-10-16): one peer removed before publication.** Commitment 6.5 named a peer adapter for the
identity adapter in `vaquarkhan/MCP-Bastion`. It was built, frozen and measured as registered, then
removed before any result was published. Its adapter and results were deleted, not published.
- **Why:** licence caution. That project's licence grants non-commercial use only, and the benchmark
  author chose not to rely on an interpretation of that clause for a published comparison. The decision
  was about the licence, not about the peer's result.
- **Effect:** none on anything else. No fixture, scoring rule or other tool changed. Every other tool's
  dev, held-out and benign results are the files from the single registered run, unchanged. Each peer is scored
  independently, so removing one cannot move another's numbers.
- **History:** the commits that built and measured the peer had not been pushed. Before publication
  they were rebuilt so the peer's adapter and results never appear in the public history. Commit dates,
  order and every other file are unchanged. The freeze record (`defenderFreeze.bench.commit`) now points
  at the rebuilt adapter commit `52fde33`, which differs from the original only by the removed peer.
