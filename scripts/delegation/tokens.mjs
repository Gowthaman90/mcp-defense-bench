/**
 * Token minting + fixture-intent checking for the delegation family (docs/DELEGATION-PREREG.md).
 *
 * Minting: real JWS tokens. Structural-mode tokens are HS256-signed with a random secret that is
 * generated per run and never written anywhere (no defender can verify them, exactly like an HS256
 * deployment where only the issuer and the upstream hold the secret). Signature-mode tokens are
 * signed with ES256 / Ed25519 keys generated in memory; only PUBLIC keys are emitted (as JWKS), the
 * private keys are discarded when the process exits, so no fixture can be re-signed after
 * pre-registration.
 *
 * Intent checking (`violations`): computes, for a fixture, which delegation properties it violates
 * under the semantics written in docs/DELEGATION-PREREG.md §4. The generator uses it ONLY to assert
 * that every attack fixture violates what it claims to and every benign control violates nothing
 * (catching malformed fixtures before registration). It is never run against a defender and is not
 * a scored tool.
 */
import { createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";

export const b64u = (buf) => Buffer.from(buf).toString("base64url");
const seg = (obj) => b64u(JSON.stringify(obj));

/** Never persisted: tokens signed with it are verifiable by nobody. */
const DISCARDED_SECRET = randomBytes(32);

export function mintHS(header, payload, secret = DISCARDED_SECRET) {
  const h = seg({ typ: "JWT", ...header, alg: header.alg ?? "HS256" });
  const p = seg(payload);
  const s = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${s}`;
}

/** Sign with an asymmetric private key (ES256 → P-256/SHA-256 in IEEE-P1363 form; EdDSA → Ed25519). */
export function mintAsym(header, payload, privateKey) {
  const h = seg({ typ: "JWT", ...header });
  const p = seg(payload);
  const data = Buffer.from(`${h}.${p}`);
  const sig =
    header.alg === "EdDSA"
      ? sign(null, data, privateKey)
      : sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${h}.${p}.${b64u(sig)}`;
}

/** An unsigned token (`alg` as given, e.g. "none" / "None"), empty signature segment. */
export function mintUnsigned(header, payload) {
  return `${seg({ typ: "JWT", ...header })}.${seg(payload)}.`;
}

/** Generate a key pair in memory and return { privateKey, jwk } (public JWK with kid/alg/use). */
export function newKey(kind, kid) {
  const { privateKey, publicKey } =
    kind === "EdDSA" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: kind, use: "sig" };
  return { privateKey, publicKey, jwk };
}

/** Replace a token's payload segment while keeping its original signature (post-signing tamper). */
export function swapPayload(token, payload) {
  const [h, , s] = token.split(".");
  return `${h}.${seg(payload)}.${s}`;
}

/** Re-encode a token's payload with the STANDARD base64 alphabet and padding (not base64url). */
export function stdBase64Payload(token, payload) {
  const [h, , s] = token.split(".");
  let json = JSON.stringify(payload);
  // Guarantee at least one character outside the base64url alphabet ('=' padding).
  while (Buffer.byteLength(json) % 3 === 0) json = json.replace(/}$/, " }");
  return `${h}.${Buffer.from(json).toString("base64")}.${s}`;
}

// ── intent checking ─────────────────────────────────────────────────────────────────────────────

const B64U = /^[A-Za-z0-9_-]*$/;

/** Strict JWS compact decode. Returns { header, payload, signingInput, signature } or null if malformed. */
export function strictDecode(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => B64U.test(p)) || !parts[0] || !parts[1]) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object") return null;
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], "base64url") };
  } catch {
    return null;
  }
}

/** The ordered actor chain of a token: [current, prior1, prior2, ...] (RFC 8693 §4.1). */
export function actorChain(payload) {
  const chain = [];
  let act = payload.act;
  while (act && typeof act === "object") {
    chain.push(act.sub ?? act.client_id ?? null);
    act = act.act;
  }
  return chain;
}

function signatureOk(dec, trust) {
  const alg = dec.header.alg;
  if (typeof alg !== "string" || !trust.algorithms.includes(alg)) return false; // allow-list, case-sensitive
  // Keys come ONLY from the configured JWKS; jku / x5u / embedded jwk headers are never followed.
  const jwk = (trust.jwks.keys ?? []).find((k) => k.kid === dec.header.kid);
  if (!jwk || (jwk.alg && jwk.alg !== alg)) return false;
  const key = createPublicKey({ key: jwk, format: "jwk" });
  const data = Buffer.from(dec.signingInput);
  const ok =
    alg === "EdDSA"
      ? verify(null, data, key, dec.signature)
      : verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, dec.signature);
  return ok && dec.payload.iss === trust.issuer;
}

/**
 * Which properties a `delegated-request` fixture violates. Property names:
 *   malformed, audience-lateral, audience-passthrough, subject-mixing, time, lifetime,
 *   actor, chain-depth, chain-cycle, signature
 */
export function violations(fx) {
  const out = new Set();
  const skew = fx.policy?.clockSkewSeconds ?? 0;
  const subjects = new Set();
  for (const [name, up] of Object.entries(fx.upstreams)) {
    const raw = fx.request.headers[up.incomingHeader];
    if (raw === undefined) continue;
    const dec = strictDecode(raw);
    const isTarget = name === fx.request.target;
    if (!dec) {
      if (isTarget) out.add("malformed");
      continue;
    }
    const p = dec.payload;
    if (typeof p.sub === "string") subjects.add(`${p.iss}\u0000${p.sub}`);
    if (!isTarget) continue;
    // audience
    const auds = p.aud === undefined ? [] : Array.isArray(p.aud) ? p.aud : [p.aud];
    if (auds.length === 0 || auds.some((a) => fx.gateway.audiences.includes(a))) out.add("audience-passthrough");
    else if (!auds.includes(up.audience)) out.add("audience-lateral");
    // validity window + lifetime
    if (typeof p.exp !== "number") out.add("time");
    else if (fx.now > p.exp + skew) out.add("time");
    if (p.nbf !== undefined && (typeof p.nbf !== "number" || p.nbf > fx.now + skew)) out.add("time");
    if (typeof p.exp === "number" && typeof p.iat === "number" && fx.policy?.maxLifetimeSeconds !== undefined) {
      if (p.exp - p.iat > fx.policy.maxLifetimeSeconds) out.add("lifetime");
    }
    // actor chain
    const chain = actorChain(p);
    if (chain.length && fx.policy?.allowedActors && !fx.policy.allowedActors.includes(chain[0])) out.add("actor");
    if (fx.policy?.maxChainDepth !== undefined && chain.length > fx.policy.maxChainDepth) out.add("chain-depth");
    if (new Set(chain).size !== chain.length) out.add("chain-cycle");
    // signature (only when the fixture's trust mode gives a key set)
    if (fx.trust?.mode === "signature" && !signatureOk(dec, fx.trust)) out.add("signature");
  }
  if (subjects.size > 1) out.add("subject-mixing");
  return [...out].sort();
}
