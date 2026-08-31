# Spec verification — MCP 2026-07-28

**Purpose.** Every claim in [`ROADMAP-2026H2.md`](ROADMAP-2026H2.md) that originated in a vendor blog
post is checked here against **primary sources**: the specification text, the deprecated-features
registry, and the extension repositories. Nothing sourced only from a blog may enter a fixture, the
rubric, or a paper. Verified 2026-08-30.

**Primary sources used**

| Source | What it settles |
|---|---|
| `modelcontextprotocol.io/specification/2026-07-28/basic/transports` | Header mirroring; body is source of truth |
| `…/basic/transports/streamable-http` | Required headers, `-32020`, Base64 sentinel, intermediary rule, backward compatibility |
| `…/basic/patterns` and `…/basic/patterns/mrtr` | MRTR, `InputRequiredResult`, `requestState` security requirements |
| `…/server/tools` | `x-mcp-header`, tool result shapes, non-normative "Stateful Tools" guidance |
| `…/server/utilities/caching` | `ttlMs` / `cacheScope` semantics and security considerations |
| `…/deprecated` | The deprecation registry (Roots, Sampling, Logging, DCR, HTTP+SSE) |
| `github.com/modelcontextprotocol/ext-tasks` — `specification/2026-07-28/tasks.md` | Tasks methods, routing headers, Security Considerations |
| `github.com/modelcontextprotocol/ext-apps` + SEP-1865 | MCP Apps security model |

---

## Verdicts

### ✅ CONFIRMED — header/body validation and `-32020`

Verbatim: *"Servers that process the request body **MUST** reject requests where the values specified
in the headers do not match the corresponding values in the request body. This prevents potential
security vulnerabilities when different components in the network rely on different sources of truth
(e.g., a load balancer routing on the header value while the MCP server executes based on the body
value)."* Rejection is `400 Bad Request` + JSON-RPC error `-32020` (`HeaderMismatch`).

Required headers: `MCP-Protocol-Version` (every POST), `Mcp-Method` (all requests), `Mcp-Name`
(`tools/call`, `resources/read`, `prompts/get`). `MCP-Protocol-Version` MUST match
`_meta["io.modelcontextprotocol/protocolVersion"]` in the body.

Three details the blogs missed, all of which strengthen the vector:

1. **Base64 sentinel.** `Mcp-Name` and `Mcp-Param-{Name}` values that are not header-safe are carried
   as `=?base64?{value}?=`. Servers *"**MUST** decode an encoded `Mcp-Name` or `Mcp-Param-{Name}`
   value before comparing it to the corresponding request body value."* A defender that string-compares
   raw header to raw body **misses any mismatch hidden behind the sentinel** — a spec-defined evasion path.
2. **The intermediary rule — this is the gateway's rule, and it is the bastion thesis in the spec's own words.**
   *"Intermediaries that enforce policy based on mirrored headers (e.g., routing or rate-limiting by
   tenant) **SHOULD** verify that the `MCP-Protocol-Version` header indicates a version that requires
   header–body validation. If the version is older or the header is absent, the intermediary **SHOULD**
   reject the request rather than trusting unvalidated header values."*
3. **`x-mcp-header` constraints are normative and testable**: non-empty, RFC 9110 token syntax, no CR/LF,
   case-insensitively unique, primitive types only (`number` forbidden), statically reachable via
   `properties` chains only. Clients **MUST** exclude a tool whose annotation violates these.

> Cross-reference: the Tasks extension requires `Mcp-Name` to equal `params.taskId` on `tasks/get`,
> `tasks/update`, `tasks/cancel`. A header/body desync on a task request therefore routes or authorizes
> one task while the server operates on another — vector 1 and vector 5 are the same mechanism.

### ✅ CONFIRMED, and stronger than claimed — `requestState`

The spec does not merely permit protection, it requires it. Verbatim: *"servers **MUST** treat
`requestState` as an attacker-controlled input. If `requestState` influences authorization, resource
access, or business logic, servers **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST**
reject state that fails verification."* Anti-replay is a **SHOULD**: bind the authenticated principal,
a short TTL, and an identifier for the originating request (method + digest of salient params). A
Warning adds that these bound the replay window but do not guarantee single use.

Clients **MUST NOT** inspect, parse, or modify `requestState`, and **MUST** echo it back exactly.
`inputRequests` values are restricted to `ElicitRequest`, `CreateMessageRequest`, `ListRootsRequest`,
and a server **MUST NOT** send a request type the client did not declare support for.
`InputRequiredResult` is permitted only on `prompts/get`, `resources/read`, `tools/call`.

### ⚠️ CORRECTION 1 — "handles" and `requestState` are two different things

The roadmap and the plain-language briefing used "handle" loosely for both. They are distinct:

- **`requestState`** — protocol-level, with the **MUST**s quoted above.
- **Tool state handles** (a `basket_id` returned by one tool and passed to the next) — covered by the
  `server/tools` section titled *Stateful Tools*, which is explicitly marked **non-normative**:
  *"The protocol has no concept of a state handle; from the wire's perspective a handle is an ordinary
  string in a tool result and an ordinary argument to subsequent tool calls."* Its advice (validate
  authorization on every call, keep handles opaque, bound their lifetime) is guidance, not a requirement.

**Consequence for the corpus:** the vector splits. `requeststate-forgery` tests a normative MUST and
carries high confidence. Handle hygiene is guidance-only and is folded in as a secondary,
lower-severity fixture rather than its own scored vector.

### ⚠️ CORRECTION 2 — `tasks/list` does not exist

The roadmap listed `tasks/list` as an enumeration surface. **It was deliberately removed**, and the
spec calls that out as a security improvement: *"Because there is no `tasks/list`, a server cannot
inadvertently leak the existence of one caller's tasks to another. This is an improvement over the
`2025-11-25` tasks specification, in which a poorly-scoped list could expose unrelated task IDs."*

The methods are `tasks/get`, `tasks/update`, `tasks/cancel`. The genuine, spec-backed requirements are:
*"A server **MAY** use task IDs as bearer tokens… Servers **MUST** generate them with sufficient entropy
that a third party cannot enumerate or guess them"* and *"Servers **MUST** perform authentication and
authorization checks on each task-related request."*

**Consequence:** `task-hijack` survives, but as a **conformance** vector — ID entropy and per-request
authorization — not as list-enumeration. Any draft text mentioning `tasks/list` is wrong and is fixed.

### ⚠️ CORRECTION 3 — MCP Apps is sandboxed by specification

Backslash presents server-shipped HTML as an open XSS/credential-capture surface. SEP-1865 (Final,
2026-01-26, `modelcontextprotocol/ext-apps`) defines a security model: UI resources use the `ui://`
scheme, content type `text/html;profile=mcp-app`, rendering happens in a **sandboxed iframe under a
strict Content-Security-Policy that blocks external network requests**, host↔iframe communication runs
over ordinary MCP JSON-RPC and is auditable, and the extension is **opt-in**, negotiated through
extension capabilities.

**Consequence:** the risk is real but it is a **conformance** question — does the host actually enforce
the sandbox and CSP? — not an inherent protocol hole. Severity drops from high to medium, confidence is
labelled *medium (vendor-sourced framing corrected against SEP-1865)*, and the fixture tests enforcement
rather than asserting the feature is unsafe. **Do not repeat the blog framing in a paper.**

### ✅ CONFIRMED — caching, with one gap worth more than the original claim

`ttlMs` is an integer in milliseconds; servers **MUST** provide a value `>= 0`; negative values are
ignored as `0`; absent means `0`. **The spec sets no maximum.** So an arbitrarily long TTL is
spec-legal, and clamping it is exactly the kind of policy only an intermediary can apply — the gap is
real and it is the gateway's to fill.

`cacheScope` is `"public"` or `"private"`. The Security Considerations are explicit: *"Servers MUST be
aware that responses with a `"public"` `cacheScope` may be shared between callers even if the Result is
coming from an authenticated endpoint… (i.e. different access tokens can leverage the same cache),"* and
implementors *"MUST apply appropriate per-primitive access controls, and MUST NOT rely on `cacheScope`
alone to prevent unauthorized access."* Cache-scope confusion is therefore spec-acknowledged, not speculative.

Two further rules the fixtures use: results carrying `inputResponses` or `requestState` (MRTR retries)
**MUST NOT** be cached; and a `notifications/tools/list_changed` **invalidates** a still-fresh cached
response. A defender that keeps serving a pinned list across an invalidation signal is measurably wrong.

### ✅ CONFIRMED — deprecations, with exact dates

From the deprecated-features registry: **Roots**, **Sampling**, **Logging** (all SEP-2577) and **Dynamic
Client Registration** (PR #2858) were deprecated in `2026-07-28`, each with earliest removal *"first
revision released on or after 2027-07-28"*. **HTTP+SSE** has been deprecated since `2025-03-26`. Nothing
has been removed yet. Roots' migration path is *"pass directories or files via tool parameters, resource
URIs, or server configuration"* — i.e. the boundary really does move into implementation code, as claimed.

### ✅ CONFIRMED — statelessness and legacy handling

`initialize` and protocol-level sessions are gone; the GET stream endpoint is removed; servers do not
initiate JSON-RPC requests. A server speaking only this revision **SHOULD** answer GET/DELETE on the MCP
endpoint with `405`, **ignore** any `Mcp-Session-Id` without minting or echoing one, and ignore
`Last-Event-ID`. `Origin` validation with **403** on an invalid Origin remains a **MUST** — bastion's
existing DNS-rebinding defence stays correct under the new revision.

---

## Net effect on the plan

| Roadmap item | Status after verification |
|---|---|
| `header-body-desync` | **Strengthened.** Add a Base64-sentinel evasion variant and the intermediary version-check rule. |
| `handle-forgery-replay` | **Split and renamed** → `requeststate-forgery` (normative) + handle hygiene (guidance, secondary fixture). |
| `list-cache-poisoning` / `cache-scope-confusion` | **Confirmed.** Sharpened: no spec maximum on `ttlMs`; MRTR results uncacheable; invalidation on `list_changed`. |
| `mrtr-input-phishing` | **Confirmed.** Constrain fixtures to the three permitted request types and the three permitted methods. |
| `task-hijack` | **Rescoped.** No `tasks/list`. Tests ID entropy + per-request authorization. |
| `extension-capability-smuggling` | **Downgraded** to medium; reframed as sandbox/CSP conformance per SEP-1865. |
| `roots-scope-gap` | **Confirmed**, including the migration path and the 2027-07-28 removal horizon. |
| `transport-downgrade` | **Confirmed**, with the exact legacy-handling behaviors to assert. |

Two of the eight vectors changed materially under verification, and one blog-sourced framing would have
been an overclaim in a paper. That is the reason this step exists.
