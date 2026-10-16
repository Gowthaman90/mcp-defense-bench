/**
 * HELD-OUT fixtures for the delegation family (docs/DELEGATION-PREREG.md). Authored 2026-10-15,
 * BEFORE any defender implements delegation checks. Whoever implements a defender's delegation
 * checks must not open this file or staging/delegation/heldout/ until the held-out run is published.
 *
 * Families (docs/HELD-OUT-PROTOCOL.md §3, adapted in DELEGATION-PREREG.md §5):
 *   D domain shift   — claims processing / freight logistics, never the dev travel domain
 *   L claim-shape    — bare-string or URN audiences, opaque subjects, actor named by client_id,
 *                      missing exp, "None" casing
 *   S surface shift  — tools/list instead of tools/call; upstream Authorization: Bearer; key
 *                      reference smuggled in a JWS header (jku)
 *   E encoding shift — standard-base64 payload, numeric-string exp, case-variant subject,
 *                      post-signing payload swap
 * Imported by scripts/gen-delegation.mjs; do not run directly.
 */
import { mintAsym, mintHS, mintUnsigned, stdBase64Payload, swapPayload } from "./tokens.mjs";

export function heldoutCases({ now, keys }) {
  const DEF = { detect: true, enforce: true };

  // ── claims-processing domain ─────────────────────────────────────────────────────────────────
  const C_ISS = "https://login.claims.invalid";
  const C_AUD = { intake: "claims-intake", adjudication: "claims-adjudication", payout: "claims-payout" };
  const cUp = Object.fromEntries(
    Object.entries(C_AUD).map(([n, audience]) => [n, { audience, incomingHeader: `x-on-behalf-of-${n}`, upstreamHeader: "x-end-user-token" }]),
  );
  const C_ACTOR = "claims-coordinator";
  const cPolicy = { maxLifetimeSeconds: 600, clockSkewSeconds: 60, allowedActors: [C_ACTOR], maxChainDepth: 3 };
  const cClaims = (aud, over = {}) => ({ iss: C_ISS, sub: "sub-7f3a91", aud, iat: now - 45, exp: now + 300, jti: `c-${aud ?? "none"}-${Object.keys(over).join("-") || "base"}`, act: { sub: C_ACTOR }, ...over });
  const cTok = (aud, over) => mintHS({}, cClaims(aud, over));
  const cBase = (headers, extra = {}) => ({
    type: "delegated-request", now, gateway: { audiences: ["claims-gateway"] }, upstreams: cUp, trust: { mode: "structural" }, policy: cPolicy,
    request: { method: "tools/call", target: "intake", headers }, ...extra,
  });
  const cGood = () => ({ "x-on-behalf-of-intake": cTok(C_AUD.intake) });

  // ── freight-logistics domain ─────────────────────────────────────────────────────────────────
  const F_ISS = "https://sso.freight.invalid";
  const F_AUD = { routing: "urn:freight:routing", customs: "urn:freight:customs", billing: "urn:freight:billing" };
  const fUp = Object.fromEntries(
    Object.entries(F_AUD).map(([n, audience]) => [n, { audience, incomingHeader: `x-freight-delegation-${n}`, upstreamHeader: "authorization", upstreamScheme: "Bearer" }]),
  );
  const F_ACTOR = "dispatch-orchestrator";
  const fPolicy = { maxLifetimeSeconds: 900, clockSkewSeconds: 30, allowedActors: [F_ACTOR], maxChainDepth: 2 };
  const fClaims = (aud, over = {}) => ({ iss: F_ISS, sub: "dana.ortiz@freight.invalid", aud, iat: now - 20, exp: now + 600, jti: `f-${aud ?? "none"}-${Object.keys(over).join("-") || "base"}`, act: { client_id: F_ACTOR }, ...over });
  const fTok = (aud, over) => mintHS({}, fClaims(aud, over));
  const fBase = (headers, extra = {}) => ({
    type: "delegated-request", now, gateway: { audiences: ["https://edge.freight.invalid/mcp", "freight-edge"] }, upstreams: fUp, trust: { mode: "structural" }, policy: fPolicy,
    request: { method: "tools/call", target: "routing", headers }, ...extra,
  });
  const fGood = () => ({ "x-freight-delegation-routing": fTok(F_AUD.routing) });

  // signature trust (claims: Ed25519; freight: ES256)
  const cSig = { mode: "signature", jwks: { keys: [keys.claims.jwk] }, issuer: C_ISS, algorithms: ["EdDSA"] };
  const fSig = { mode: "signature", jwks: { keys: [keys.freight.jwk] }, issuer: F_ISS, algorithms: ["ES256"] };
  const cSigned = (over) => mintAsym({ alg: "EdDSA", kid: keys.claims.jwk.kid }, cClaims(C_AUD.intake, over), keys.claims.privateKey);
  const fSigned = (over) => mintAsym({ alg: "ES256", kid: keys.freight.jwk.kid }, fClaims(F_AUD.routing, over), keys.freight.privateKey);

  return [
    // ── delegation-audience-confusion ─────────────────────────────────────────────────────────
    {
      vector: "delegation-audience-confusion", family: "D", slug: "payout-token-sent-to-intake", severity: "high",
      description: "A claims coordinator's call to the intake sub-agent carries the token minted for the payout sub-agent.",
      violates: ["audience-lateral"],
      fixture: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.payout) }),
      benignControl: cBase(cGood()),
      expected: { ...DEF, signal: "audience is the payout service, target is intake" },
      provenance: "Synthetic held-out (D/L: bare-string audiences).",
    },
    {
      vector: "delegation-audience-confusion", family: "S", slug: "edge-token-on-tools-list-bearer", severity: "high",
      description: "During tool discovery (tools/list), the routing delegate header holds a token whose audience is the gateway's own short name; it would be forwarded upstream as an Authorization bearer.",
      violates: ["audience-passthrough"],
      fixture: fBase({ "x-freight-delegation-routing": fTok("freight-edge") }, { request: { method: "tools/list", target: "routing", headers: { "x-freight-delegation-routing": fTok("freight-edge") } } }),
      benignControl: fBase(fGood(), { request: { method: "tools/list", target: "routing", headers: fGood() } }),
      expected: { ...DEF, signal: "gateway-audience token relayed upstream on discovery" },
      provenance: "Synthetic held-out (S: tools/list surface, Authorization bearer upstream). MCP Security Best Practices, Token Passthrough.",
    },
    {
      vector: "delegation-audience-confusion", family: "E", slug: "std-base64-payload-customs-to-routing", severity: "high",
      description: "A customs token is routed to the routing sub-agent, and its payload segment is encoded with standard base64 and padding instead of base64url. A strict decoder rejects it; a lenient one decodes it and finds the wrong audience; a check that silently skips undecodable tokens lets it through.",
      violates: ["malformed"],
      fixture: (() => { const p = fClaims(F_AUD.customs); return fBase({ "x-freight-delegation-routing": stdBase64Payload(mintHS({}, p), p) }); })(),
      benignControl: fBase(fGood()),
      expected: { ...DEF, signal: "non-base64url JWS segment / wrong audience — must fail closed" },
      provenance: "Synthetic held-out (E). RFC 7515 §2 (base64url without padding).",
    },

    // ── delegation-subject-mixing ─────────────────────────────────────────────────────────────
    {
      vector: "delegation-subject-mixing", family: "D", slug: "intake-and-payout-different-claimants", severity: "high",
      description: "One claim-handling request carries an intake token for subject sub-7f3a91 and a payout token for sub-c20e44.",
      violates: ["subject-mixing"],
      fixture: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.intake), "x-on-behalf-of-payout": cTok(C_AUD.payout, { sub: "sub-c20e44" }) }),
      benignControl: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.intake), "x-on-behalf-of-payout": cTok(C_AUD.payout) }),
      expected: { ...DEF, signal: "different subjects across delegate tokens" },
      provenance: "Synthetic held-out (D/L: opaque subjects).",
    },
    {
      vector: "delegation-subject-mixing", family: "E", slug: "case-variant-email-subject", severity: "high",
      description: "The routing token names dana.ortiz@freight.invalid and the billing token names Dana.Ortiz@freight.invalid. JWT subjects are case-sensitive strings, so these are different principals; a case-folding comparison would merge them.",
      violates: ["subject-mixing"],
      fixture: fBase({ "x-freight-delegation-routing": fTok(F_AUD.routing), "x-freight-delegation-billing": fTok(F_AUD.billing, { sub: "Dana.Ortiz@freight.invalid" }) }),
      benignControl: fBase({ "x-freight-delegation-routing": fTok(F_AUD.routing), "x-freight-delegation-billing": fTok(F_AUD.billing) }),
      expected: { ...DEF, signal: "subjects differ (case-sensitive)" },
      provenance: "Synthetic held-out (E). RFC 7519 §4.1.2 (StringOrURI, case-sensitive comparison).",
    },
    {
      vector: "delegation-subject-mixing", family: "S", slug: "mixed-subjects-on-discovery", severity: "medium",
      description: "Subject mixing on a tools/list request: adjudication and intake tokens name different claimants while the agent is only discovering tools.",
      violates: ["subject-mixing"],
      fixture: (() => { const h = { "x-on-behalf-of-intake": cTok(C_AUD.intake), "x-on-behalf-of-adjudication": cTok(C_AUD.adjudication, { sub: "sub-90bd17" }) }; return cBase(h, { request: { method: "tools/list", target: "intake", headers: h } }); })(),
      benignControl: (() => { const h = { "x-on-behalf-of-intake": cTok(C_AUD.intake), "x-on-behalf-of-adjudication": cTok(C_AUD.adjudication) }; return cBase(h, { request: { method: "tools/list", target: "intake", headers: h } }); })(),
      expected: { ...DEF, signal: "different subjects across delegate tokens (discovery)" },
      provenance: "Synthetic held-out (S).",
    },

    // ── delegation-stale-relay ────────────────────────────────────────────────────────────────
    {
      vector: "delegation-stale-relay", family: "D", slug: "claims-token-expired-an-hour", severity: "high",
      description: "An intake token that expired an hour ago is replayed.",
      violates: ["time"],
      fixture: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.intake, { iat: now - 3900, exp: now - 3600 }) }),
      benignControl: cBase(cGood()),
      expected: { ...DEF, signal: "expired" },
      provenance: "Synthetic held-out (D).",
    },
    {
      vector: "delegation-stale-relay", family: "L", slug: "no-exp-claim", severity: "high",
      description: "The routing token carries an issued-at time but no expiry at all, so it never lapses.",
      violates: ["time"],
      fixture: (() => { const p = fClaims(F_AUD.routing); delete p.exp; return fBase({ "x-freight-delegation-routing": mintHS({}, p) }); })(),
      benignControl: fBase(fGood()),
      expected: { ...DEF, signal: "no exp claim" },
      provenance: "Synthetic held-out (L). RFC 8725 (tokens should be short-lived).",
    },
    {
      vector: "delegation-stale-relay", family: "E", slug: "numeric-string-exp-in-past", severity: "medium",
      description: "The expiry is encoded as a numeric STRING two minutes in the past. NumericDate must be a JSON number; a parser that ignores a non-number exp treats the token as never expiring.",
      violates: ["time"],
      fixture: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.intake, { exp: String(now - 120) }) }),
      benignControl: cBase(cGood()),
      expected: { ...DEF, signal: "exp is not a NumericDate (and is in the past)" },
      provenance: "Synthetic held-out (E). RFC 7519 §2 NumericDate, §4.1.4.",
    },

    // ── delegation-chain-laundering ───────────────────────────────────────────────────────────
    {
      vector: "delegation-chain-laundering", family: "D", slug: "records-sync-bot-as-current-actor", severity: "high",
      description: "The intake token's current actor is 'records-sync-bot'; only 'claims-coordinator' may act for claimants.",
      violates: ["actor"],
      fixture: cBase({ "x-on-behalf-of-intake": cTok(C_AUD.intake, { act: { sub: "records-sync-bot" } }) }),
      benignControl: cBase(cGood()),
      expected: { ...DEF, signal: "current actor not allowed" },
      provenance: "Synthetic held-out (D). RFC 8693 §4.1.",
    },
    {
      vector: "delegation-chain-laundering", family: "L", slug: "actor-named-by-client-id", severity: "high",
      description: "The current actor is identified by client_id rather than sub: 'rate-shopper-x', not the allowed dispatch-orchestrator.",
      violates: ["actor"],
      fixture: fBase({ "x-freight-delegation-routing": fTok(F_AUD.routing, { act: { client_id: "rate-shopper-x" } }) }),
      benignControl: fBase(fGood()),
      expected: { ...DEF, signal: "current actor (client_id) not allowed" },
      provenance: "Synthetic held-out (L). RFC 8693 §4.1 (act holds claims identifying the actor).",
    },
    {
      vector: "delegation-chain-laundering", family: "S", slug: "cycle-on-discovery", severity: "medium",
      description: "On a tools/list request the intake token's chain is claims-coordinator → triage-agent → claims-coordinator.",
      violates: ["chain-cycle"],
      fixture: (() => { const h = { "x-on-behalf-of-intake": cTok(C_AUD.intake, { act: { sub: C_ACTOR, act: { sub: "triage-agent", act: { sub: C_ACTOR } } } }) }; return cBase(h, { request: { method: "tools/list", target: "intake", headers: h } }); })(),
      benignControl: (() => { const h = { "x-on-behalf-of-intake": cTok(C_AUD.intake, { act: { sub: C_ACTOR, act: { sub: "triage-agent" } } }) }; return cBase(h, { request: { method: "tools/list", target: "intake", headers: h } }); })(),
      expected: { detect: true, enforce: false, signal: "cycle in delegation chain (informational: detect + audit)" },
      scoreCap: "detect",
      provenance: "Synthetic held-out (S). RFC 8693 §4.1 (prior actors informational).",
    },

    // ── delegation-signature-forgery ──────────────────────────────────────────────────────────
    {
      vector: "delegation-signature-forgery", family: "D", slug: "payload-swapped-after-signing", severity: "high",
      description: "A genuine Ed25519-signed intake token for one claimant has its payload replaced with another claimant's, keeping the original signature.",
      violates: ["signature"],
      fixture: cBase({ "x-on-behalf-of-intake": swapPayload(cSigned(), cClaims(C_AUD.intake, { sub: "sub-c20e44" })) }, { trust: cSig }),
      benignControl: cBase({ "x-on-behalf-of-intake": cSigned() }, { trust: cSig }),
      expected: { ...DEF, signal: "signature does not cover the presented payload" },
      provenance: "Synthetic held-out (D/E). RFC 7515.",
    },
    {
      vector: "delegation-signature-forgery", family: "L", slug: "alg-None-casing", severity: "high",
      description: "An unsigned token whose header says alg 'None' (capitalised), probing verifiers that block only the exact string 'none'.",
      violates: ["signature"],
      fixture: fBase({ "x-freight-delegation-routing": mintUnsigned({ alg: "None" }, fClaims(F_AUD.routing)) }, { trust: fSig }),
      benignControl: fBase({ "x-freight-delegation-routing": fSigned() }, { trust: fSig }),
      expected: { ...DEF, signal: "unsigned token (alg None)" },
      provenance: "Synthetic held-out (L). RFC 8725 §2.1, §3.1 (allow-list algorithms).",
    },
    {
      vector: "delegation-signature-forgery", family: "S", slug: "jku-points-to-attacker-keys", severity: "high",
      description: "The token is signed with an attacker key and its header carries a jku URL pointing at the attacker's key set plus a kid that exists only there.",
      violates: ["signature"],
      fixture: fBase({ "x-freight-delegation-routing": mintAsym({ alg: "ES256", kid: "edge-rot-7", jku: "https://keys.freight-cdn.invalid/jwks.json" }, fClaims(F_AUD.routing), keys.attacker2.privateKey) }, { trust: fSig }),
      benignControl: fBase({ "x-freight-delegation-routing": fSigned() }, { trust: fSig }),
      expected: { ...DEF, signal: "key reference (jku/kid) outside the trusted key set" },
      provenance: "Synthetic held-out (S). RFC 8725 §3.10 (do not trust header-supplied key URLs).",
    },
  ];
}
