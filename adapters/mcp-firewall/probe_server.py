#!/usr/bin/env python3
"""
Persistent probe for the mcp-firewall adapter.

Reads one fixture JSON per line on stdin, maps it to mcp-firewall's REAL SDK
(Gateway.check for inbound tool calls, Gateway.scan_response for outbound results),
and writes one verdict JSON per line: {"detect":bool,"enforce":bool,"signal":str|null}.

Integrity rule (adapters/CONTRACT.md): only report what mcp-firewall actually inspects.
Its runtime SDK inspects tool-call ARGUMENTS (inbound) and response TEXT (outbound) — not tool
DEFINITIONS, registry entries, transport, or consent flows. Those return detect=false honestly.
"""
import sys
import json
import os
from mcp_firewall.sdk import Gateway

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-firewall.yaml")
gw = Gateway(config_path=CFG)


def from_check(r):
    detect = r.action != "allow"
    enforce = r.action == "deny"
    sig = f"{r.action}: {r.reason}"[:80] if detect else None
    return detect, enforce, sig


def response_text(inp):
    res = inp.get("result", {}) or {}
    return " ".join(p.get("text", "") for p in res.get("content", []) if isinstance(p, dict))


def assess(inp):
    t = inp.get("type")
    if t == "tool-call":
        c = inp.get("call", {})
        return from_check(gw.check(c.get("name", "tool"), c.get("arguments", {})))
    if t == "tool-call-sequence":
        best = (False, False, None)
        for c in inp.get("calls", []):
            d, e, s = from_check(gw.check(c.get("name", "tool"), c.get("arguments", {})))
            if d and (not best[0] or e):
                best = (d, e, s)
        return best
    if t == "scenario" and isinstance(inp.get("action"), dict):
        a = inp["action"]
        return from_check(gw.check(a.get("name", "tool"), a.get("arguments", {})))
    if t in ("malicious-tool-result", "benign-tool-result"):
        s = gw.scan_response(response_text(inp))
        detect = len(s.findings) > 0
        enforce = bool(s.modified) or any(f.get("action") in ("deny", "redact") for f in s.findings)
        sig = s.findings[0].get("reason", "")[:80] if s.findings else None
        return detect, enforce, sig
    # tool definitions, registry, config-diff, consent, capability-grant, network scenarios:
    # not consumed by mcp-firewall's runtime SDK -> honest miss.
    return False, False, None


def main():
    # NB: use readline(), not `for line in sys.stdin` — the latter read-ahead-buffers and deadlocks
    # on a pipe (waits for EOF/full buffer instead of yielding per line).
    while True:
        raw = sys.stdin.readline()
        if raw == "":  # EOF
            break
        line = raw.strip()
        if not line:
            continue
        try:
            inp = json.loads(line)
            d, e, s = assess(inp)
            out = {"detect": bool(d), "enforce": bool(e), "signal": s}
        except Exception as exc:  # noqa: BLE001
            out = {"detect": False, "enforce": False, "signal": None, "error": str(exc)[:120]}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
