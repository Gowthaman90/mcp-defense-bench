#!/usr/bin/env python3
"""
Authorization probe for the mcp-firewall adapter (fixture type `authorized-call`).

Reads ONE fixture JSON from stdin and writes ONE verdict line:
{"detect": bool, "enforce": bool, "signal": str|null}.

What it drives: mcp-firewall 0.1.0's REAL SDK, `Gateway(config_path=...).check(tool, arguments, agent=...)`,
whose policy stage (pipeline/inbound/policy.py) applies per-agent RBAC in this order:
  1. agents.<id>.deny        (glob or exact)      -> deny        (deny overrides allow)
  2. agents.<id>.require_approval                -> prompt      (not used here)
  3. agents.<id>.allow       non-empty, no match  -> deny        ("not in allow list")
  4. global `rules` (no agent field, first match wins)
  5. defaultAction
The non-policy inbound stages (kill switch, rate limit, injection, egress, chain) run first, unchanged
from the committed mcp-firewall.yaml.

How the fixture's policy becomes mcp-firewall config (published in AUTHORIZATION-TRANSLATION.md):
  - each principal {client|user|agent: name} -> one agents entry with id "<kind>:<name>";
  - allow/deny rules WITHOUT `args` -> that entry's allow/deny tool patterns;
    principal "*" rules are added to every entry;
  - policy.default "deny" -> defaultAction: deny; no global `rules` (the fixture policy replaces them);
  - the caller's single identity -> the `agent=` argument of check().
What mcp-firewall cannot express is a measured gap, reported as detect:false with the reason, and the
SDK is not called (no approximation):
  - a caller carrying more than one identity (client+user, user+agent): check() takes one agent id,
    so the §4 intersection cannot be stated;
  - a decision that depends on an argument constraint (`args`): agent entries hold tool patterns only,
    and global rules that can match arguments are not scoped to an agent;
  - a tool pattern that fnmatch would read differently from §4 (contains ? [ ] or a non-trailing *).
"""
import json
import os
import sys
import tempfile

import yaml
from mcp_firewall.sdk import Gateway

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_CFG = os.path.join(HERE, "mcp-firewall.yaml")
KINDS = ("client", "user", "agent")
# Non-policy sections kept from the committed config so the rest of the pipeline runs as configured.
KEEP = ("version", "globalRateLimit", "security", "responseScanning")


def gap(reason):
    return {"detect": False, "enforce": False, "signal": f"gap: {reason}"[:200]}


def expressible_pattern(p):
    # §4: exact name, or one trailing '*' as a prefix match. mcp-firewall uses fnmatch when the
    # pattern contains '*' or '?', so the two agree only when no other glob syntax is present.
    if not isinstance(p, str) or not p:
        return False
    body = p[:-1] if p.endswith("*") else p
    return not any(ch in body for ch in "*?[]")


def pattern_matches(name, p):
    # §4 tool-pattern semantics; used only to decide which rules bear on this request (gap check).
    return name.startswith(p[:-1]) if p.endswith("*") else name == p


def principal_key(principal):
    if principal == "*":
        return "*"
    if isinstance(principal, dict) and len(principal) == 1:
        (kind, name), = principal.items()
        if kind in KINDS and isinstance(name, str):
            return f"{kind}:{name}"
    return None


def translate(fx):
    """Return (config_dict, agent_id) or a gap verdict dict."""
    caller = fx.get("caller") or {}
    req = fx.get("request") or {}
    policy = fx.get("policy") or {}
    tool = req.get("name")
    if not isinstance(tool, str):
        return gap("request has no tool name")

    ids = [(k, caller[k]) for k in KINDS if caller.get(k)]
    if len(ids) != 1:
        kinds = "+".join(k for k, _ in ids) or "none"
        return gap(f"caller carries {kinds}; check() takes one agent id, so the identity intersection is not expressible")
    kind, name = ids[0]
    agent_id = f"{kind}:{name}"

    if policy.get("default") != "deny":
        return gap(f"policy.default={policy.get('default')!r} not translated (registered fixtures use deny)")

    rules = policy.get("rules") or []
    parsed = []
    for i, r in enumerate(rules):
        key = principal_key(r.get("principal"))
        eff = r.get("effect")
        pats = r.get("tools") or []
        if key is None or eff not in ("allow", "deny") or not isinstance(pats, list):
            return gap(f"rule {i} has a principal/effect/tools shape with no mcp-firewall equivalent")
        parsed.append((i, key, eff, pats, bool(r.get("args"))))

    # Which rules bear on THIS request for THIS identity (§4 step 3), and does the outcome hinge on args?
    relevant = [p for p in parsed if p[1] in ("*", agent_id) and any(pattern_matches(tool, t) for t in p[3])]
    for i, _, _, pats, _ in relevant:
        bad = [t for t in pats if not expressible_pattern(t)]
        if bad:
            return gap(f"rule {i} tool pattern {bad[0]!r} has no fnmatch equivalent")
    if any(e == "deny" and not a for _, _, e, _, a in relevant):
        pass  # an unconditional deny decides it: expressible whatever else applies
    elif any(e == "deny" and a for _, _, e, _, a in relevant):
        return gap(f"deny rule for {agent_id} on {tool} has argument constraints; agent entries hold tool patterns only")
    elif any(e == "allow" and not a for _, _, e, _, a in relevant):
        pass  # an unconditional allow decides it
    elif any(e == "allow" and a for _, _, e, _, a in relevant):
        return gap(f"grant for {agent_id} on {tool} has argument constraints; agent entries hold tool patterns only")
    # else: no rule applies -> no grant, expressible

    # Build agents: every principal named in the policy plus the caller, from rules without args.
    agents = {}
    keys = {p[1] for p in parsed if p[1] != "*"} | {agent_id}
    for k in sorted(keys):
        agents[k] = {"allow": [], "deny": []}
    for _, key, eff, pats, has_args in parsed:
        if has_args:
            continue  # cannot be expressed; shown above not to bear on this request
        ok = [t for t in pats if expressible_pattern(t)]
        targets = agents.keys() if key == "*" else [key]
        for k in targets:
            lst = agents[k][eff]
            lst.extend(t for t in ok if t not in lst)

    with open(BASE_CFG) as f:
        base = yaml.safe_load(f) or {}
    cfg = {k: base[k] for k in KEEP if k in base}
    cfg["defaultAction"] = "deny"
    cfg["agents"] = agents
    cfg["rules"] = []
    cfg["audit"] = {"enabled": False}
    return cfg, agent_id


def assess(fx):
    out = translate(fx)
    if isinstance(out, dict):
        return out
    cfg, agent_id = out
    req = fx.get("request") or {}
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "mcp-firewall.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(cfg, f, sort_keys=False)
        gw = Gateway(config_path=path)  # real loader, real pipeline; SDK mode (no interactive prompt)
        r = gw.check(req.get("name"), req.get("arguments") or {}, agent=agent_id)
    detect = r.action != "allow"
    enforce = r.action == "deny"
    sig = f"{r.action} [{r.stage}] {r.reason}"[:200] if detect else f"allow as {agent_id}"
    return {"detect": detect, "enforce": enforce, "signal": sig}


def main():
    raw = sys.stdin.read()
    try:
        out = assess(json.loads(raw))
    except Exception as exc:  # noqa: BLE001
        out = {"detect": False, "enforce": False, "signal": None, "error": str(exc)[:160]}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
