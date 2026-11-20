#!/usr/bin/env python3
"""External-corpus runner for Python defences (docs/EXTERNAL-PROTOCOL.md, Addendum A).

Same scoring rule as scripts/run-external.mjs: !detect -> none; detect and the control detects -> none +
false positive; detect and enforce -> enforce; detect -> detect. A case without a control (MCPTox) is
scored ungated. Adapters are loaded with mcp-defense-bench-py's own loader and called through its
call_assess, so verdicts are normalised exactly as in its runner.

Usage: python scripts/run-external-py.py <spec> <label> <corpus_dir> <out.json> <search_path>
"""
import asyncio
import datetime
import json
import sys
from pathlib import Path

from mcp_defense_bench.adapters import call_assess, load_adapter

WEIGHT = {"enforce": 1, "detect": 0.5, "none": 0}


async def main(spec, label, corpus_dir, out_path, search_path):
    adapter = load_adapter(spec, search_path=search_path)
    meta = getattr(adapter, "meta", None)
    meta = meta.to_dict() if hasattr(meta, "to_dict") else (meta or {})
    types_ok = meta.get("fixtureTypes") or meta.get("fixture_types")
    unwired = meta.get("unwiredFixtureTypes") or meta.get("unwired_fixture_types") or []
    cases = []
    for vec in sorted(p for p in Path(corpus_dir).iterdir() if p.is_dir()):
        for f in sorted(vec.glob("*.json")):
            cases.append(json.loads(f.read_text("utf8")))
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    out = []
    for tc in cases:
        ftype = tc["fixture"]["type"]
        if (types_ok and ftype not in types_ok) or ftype in unwired:
            out.append({"id": tc["id"], "vector": tc["vector"], "external": tc["external"], "wired": False})
            continue
        mal = await call_assess(adapter, tc["fixture"], tc)
        gated = tc.get("benignControl") is not None
        ben = await call_assess(adapter, tc["benignControl"], tc) if gated else None
        level, fp = "none", False
        if mal.get("detect"):
            if gated and ben.get("detect"):
                fp = True
            else:
                level = "enforce" if mal.get("enforce") else "detect"
        out.append({"id": tc["id"], "vector": tc["vector"], "external": tc["external"], "wired": True, "gated": gated,
                    "level": level, "weight": WEIGHT[level], "falsePositive": fp,
                    "mal": {"detect": bool(mal.get("detect")), "enforce": bool(mal.get("enforce")), "signal": mal.get("signal")},
                    "benign": ({"detect": bool(ben.get("detect")), "enforce": bool(ben.get("enforce")), "signal": ben.get("signal")} if ben else None)})
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps({"label": label, "adapter": spec, "meta": meta, "startedAt": started,
                                          "finishedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                          "casesRun": sum(1 for c in out if c["wired"]),
                                          "notWired": sum(1 for c in out if not c["wired"]), "cases": out}, indent=1) + "\n")
    print(f"{label}: {len(out)} cases ({sum(1 for c in out if not c['wired'])} not wired) -> {out_path}")


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:6]))
