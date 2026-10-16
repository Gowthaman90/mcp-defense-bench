/**
 * DEVELOPMENT fixtures for the delegation family (staged, unscored until promotion).
 * Domain: a travel-booking orchestrator delegating to flights / hotels / payments sub-agents.
 * Imported by scripts/gen-delegation.mjs; do not run directly.
 *
 * Each case: { vector, slug, severity, description, violates, fixture, benignControl, expected,
 * scoreCap?, provenance }. `violates` is asserted against tokens.mjs#violations at generation time.
 */
import { mintAsym, mintHS, mintUnsigned } from "./tokens.mjs";
import { createHmac } from "node:crypto";

export function devCases({ now, keys }) {
  const ISS = "https://idp.travel.test";
  const GW = "https://gw.travel.test/mcp";
  const AUD = {
    flights: "https://flights.travel.test/mcp",
    hotels: "https://hotels.travel.test/mcp",
    payments: "https://payments.travel.test/mcp",
  };
  const upstreams = Object.fromEntries(
    Object.entries(AUD).map(([n, audience]) => [
      n,
      { audience, incomingHeader: `x-delegate-${n}`, upstreamHeader: "x-user-assertion" },
    ]),
  );
  const ANA = "user:ana.k";
  const RAVI = "user:ravi.m";
  const ACTOR = "trip-orchestrator";
  const policy = { maxLifetimeSeconds: 300, clockSkewSeconds: 30, allowedActors: [ACTOR], maxChainDepth: 3 };
  const claims = (aud, over = {}) => ({
    iss: ISS,
    sub: ANA,
    aud,
    iat: now - 30,
    exp: now + 90,
    jti: `dev-${Math.abs(hash(JSON.stringify([aud, over]))).toString(36)}`,
    act: { sub: ACTOR },
    ...over,
  });
  const tok = (aud, over) => mintHS({}, claims(aud, over));
  const base = (headers, extra = {}) => ({
    type: "delegated-request",
    now,
    gateway: { audiences: [GW] },
    upstreams,
    trust: { mode: "structural" },
    policy,
    request: { method: "tools/call", target: "flights", headers },
    ...extra,
  });
  const good = () => ({ "x-delegate-flights": tok(AUD.flights) });

  // signature-mode trust: one ES256 key in the deployment's JWKS
  const sigTrust = { mode: "signature", jwks: { keys: [keys.travel.jwk] }, issuer: ISS, algorithms: ["ES256"] };
  const signed = (over = {}) =>
    mintAsym({ alg: "ES256", kid: keys.travel.jwk.kid }, claims(AUD.flights, over), keys.travel.privateKey);
  const sigBase = (token) => base({ "x-delegate-flights": token }, { trust: sigTrust });

  const DEF = { detect: true, enforce: true };
  return [
    // ── delegation-audience-confusion ─────────────────────────────────────────────────────────
    {
      vector: "delegation-audience-confusion", slug: "hotels-token-routed-to-flights", severity: "high",
      description: "The orchestrator's call to the flights sub-agent carries the token the platform issued for the hotels sub-agent. A relay that does not check the audience lets one service's grant act at another.",
      violates: ["audience-lateral"],
      fixture: base({ "x-delegate-flights": tok(AUD.hotels) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "delegate token audience (hotels) does not match the target upstream (flights)" },
      provenance: "Synthetic. RFC 8707 resource indicators; RFC 8725 §3.9.",
    },
    {
      vector: "delegation-audience-confusion", slug: "gateway-token-passed-through", severity: "high",
      description: "The token in the flights delegate header was issued for the gateway itself (its audience is the gateway's URL) and would be passed on unchanged to the flights sub-agent: the token passthrough the MCP security guidance forbids.",
      violates: ["audience-passthrough"],
      fixture: base({ "x-delegate-flights": tok(GW) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "token issued for the gateway relayed downstream (passthrough)" },
      provenance: "Synthetic. MCP Security Best Practices, Token Passthrough (MUST NOT accept tokens not explicitly issued for the server).",
    },
    {
      vector: "delegation-audience-confusion", slug: "unscoped-token-passed-through", severity: "high",
      description: "The delegate token carries no audience claim at all, so it is not bound to any one sub-agent and could be replayed at every service that trusts the issuer.",
      violates: ["audience-passthrough"],
      fixture: base({ "x-delegate-flights": tok(undefined) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "delegate token has no audience" },
      provenance: "Synthetic. RFC 8725 §3.9; MCP authorization audience binding.",
    },

    // ── delegation-subject-mixing ─────────────────────────────────────────────────────────────
    {
      vector: "delegation-subject-mixing", slug: "two-users-two-subagents", severity: "high",
      description: "One booking request carries a flights token for Ana and a hotels token for Ravi. Each sub-agent sees a valid token, so the booking runs partly as each user.",
      violates: ["subject-mixing"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels, { sub: RAVI }) }),
      benignControl: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels) }),
      expected: { ...DEF, signal: "delegate tokens in one request name different subjects" },
      provenance: "Synthetic. OWASP ASI03; RFC 7519 §4.1.2.",
    },
    {
      vector: "delegation-subject-mixing", slug: "same-subject-foreign-issuer", severity: "high",
      description: "Both tokens name 'user:ana.k', but the hotels token comes from a different identity provider. A subject is only unique within its issuer, so these may be two different people.",
      violates: ["subject-mixing"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels, { iss: "https://partner-idp.travel.test" }) }),
      benignControl: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels) }),
      expected: { ...DEF, signal: "same subject string from different issuers" },
      provenance: "Synthetic. RFC 7519 §4.1.1–4.1.2 (sub unique within iss).",
    },
    {
      vector: "delegation-subject-mixing", slug: "odd-one-out-of-three", severity: "high",
      description: "Three delegate tokens travel together: flights and hotels for Ana, payments for Ravi. The call targets flights, whose own token is fine; the mix is visible only across the whole request.",
      violates: ["subject-mixing"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels), "x-delegate-payments": tok(AUD.payments, { sub: RAVI }) }),
      benignControl: base({ "x-delegate-flights": tok(AUD.flights), "x-delegate-hotels": tok(AUD.hotels), "x-delegate-payments": tok(AUD.payments) }),
      expected: { ...DEF, signal: "one of three delegate tokens names a different subject" },
      provenance: "Synthetic.",
    },

    // ── delegation-stale-relay ────────────────────────────────────────────────────────────────
    {
      vector: "delegation-stale-relay", slug: "expired-ten-minutes", severity: "high",
      description: "A captured flights token that expired ten minutes ago is relayed again.",
      violates: ["time"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { iat: now - 720, exp: now - 600 }) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "delegate token expired" },
      provenance: "Synthetic. RFC 7519 §4.1.4.",
    },
    {
      vector: "delegation-stale-relay", slug: "not-yet-valid", severity: "medium",
      description: "The token's not-before time is four minutes in the future (beyond clock skew); it is being used before the issuer allowed.",
      violates: ["time"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { iat: now, nbf: now + 240, exp: now + 290 }) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "delegate token not yet valid (nbf)" },
      provenance: "Synthetic. RFC 7519 §4.1.5.",
    },
    {
      vector: "delegation-stale-relay", slug: "thirty-day-lifetime", severity: "medium",
      description: "The token is inside its validity window but was issued for thirty days, far beyond the deployment's five-minute delegation policy.",
      violates: ["lifetime"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { iat: now - 60, exp: now + 30 * 86400 }) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "delegate token lifetime exceeds policy" },
      provenance: "Synthetic. RFC 8725; NSA MCP guidance (least-privilege, short-lived tokens).",
    },

    // ── delegation-chain-laundering ───────────────────────────────────────────────────────────
    {
      vector: "delegation-chain-laundering", slug: "unlisted-current-actor", severity: "high",
      description: "The token's current actor is 'bulk-export-agent', an agent the deployment never authorized to act for users; only 'trip-orchestrator' is allowed.",
      violates: ["actor"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { act: { sub: "bulk-export-agent" } }) }),
      benignControl: base(good()),
      expected: { ...DEF, signal: "current actor not on the allowed-actor list" },
      provenance: "Synthetic. RFC 8693 §4.1 (current actor may drive access control).",
    },
    {
      vector: "delegation-chain-laundering", slug: "deep-act-chain", severity: "medium",
      description: "The current actor is allowed, but the prior-actor chain is four agents deep (policy: three), so authority passed through more intermediaries than the deployment expects.",
      violates: ["chain-depth"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { act: { sub: ACTOR, act: { sub: "itinerary-planner", act: { sub: "fare-scraper", act: { sub: "helper-7" } } } } }) }),
      benignControl: base({ "x-delegate-flights": tok(AUD.flights, { act: { sub: ACTOR, act: { sub: "itinerary-planner" } } }) }),
      expected: { detect: true, enforce: false, signal: "delegation chain deeper than policy (prior actors are informational: detect + audit)" },
      scoreCap: "detect",
      provenance: "Synthetic. RFC 8693 §4.1: prior actors are informational only and MUST NOT drive access control, so detection is the conforming response.",
    },
    {
      vector: "delegation-chain-laundering", slug: "cyclic-act-chain", severity: "medium",
      description: "The chain runs trip-orchestrator → itinerary-planner → trip-orchestrator: the same agent appears twice, a loop that obscures who actually originated the action.",
      violates: ["chain-cycle"],
      fixture: base({ "x-delegate-flights": tok(AUD.flights, { act: { sub: ACTOR, act: { sub: "itinerary-planner", act: { sub: ACTOR } } } }) }),
      benignControl: base({ "x-delegate-flights": tok(AUD.flights, { act: { sub: ACTOR, act: { sub: "itinerary-planner" } } }) }),
      expected: { detect: true, enforce: false, signal: "cycle in the delegation chain" },
      scoreCap: "detect",
      provenance: "Synthetic. RFC 8693 §4.1 (prior actors informational).",
    },

    // ── delegation-signature-forgery (signature trust mode) ───────────────────────────────────
    {
      vector: "delegation-signature-forgery", slug: "alg-none", severity: "high",
      description: "An unsigned token (alg 'none', empty signature) with plausible claims is presented to a deployment that trusts one ES256 key.",
      violates: ["signature"],
      fixture: sigBase(mintUnsigned({ alg: "none" }, claims(AUD.flights))),
      benignControl: sigBase(signed()),
      expected: { ...DEF, signal: "unsigned token (alg none)" },
      provenance: "Synthetic. RFC 8725 §2.1, §3.1.",
    },
    {
      vector: "delegation-signature-forgery", slug: "attacker-key-same-kid", severity: "high",
      description: "The token claims the deployment's key id but is signed with a different (attacker) ES256 key.",
      violates: ["signature"],
      fixture: sigBase(mintAsym({ alg: "ES256", kid: keys.travel.jwk.kid }, claims(AUD.flights), keys.attacker.privateKey)),
      benignControl: sigBase(signed()),
      expected: { ...DEF, signal: "signature does not verify under the trusted key" },
      provenance: "Synthetic. RFC 7515; RFC 8725 §3.2.",
    },
    {
      vector: "delegation-signature-forgery", slug: "hs256-public-key-confusion", severity: "high",
      description: "Algorithm confusion: the header switches to HS256 and the token is MAC'd with the deployment's PUBLIC key (PEM) as the HMAC secret, hoping a verifier uses the key bytes for whatever algorithm the header names.",
      violates: ["signature"],
      fixture: sigBase(
        mintHS({ alg: "HS256", kid: keys.travel.jwk.kid }, claims(AUD.flights), Buffer.from(keys.travel.publicKey.export({ type: "spki", format: "pem" }))),
      ),
      benignControl: sigBase(signed()),
      expected: { ...DEF, signal: "algorithm not allowed for this key (HS256 with an asymmetric key)" },
      provenance: "Synthetic. RFC 8725 §2.1, §3.1 (key/algorithm binding).",
    },
  ];
}

/** Small deterministic string hash for readable jti values. */
function hash(s) {
  return [...createHmac("sha256", "jti").update(s).digest()].slice(0, 4).reduce((a, b) => (a << 8) | b, 0);
}
