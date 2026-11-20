#!/usr/bin/env python3
"""Convert MCPTox and InjecAgent to bench fixtures, by the rules in docs/EXTERNAL-PROTOCOL.md.

Usage: python3 -I scripts/convert-external.py <raw_dir> <out_dir>
  raw_dir  holds mcptox/pure_tool.json and injecagent/{test_cases_dh_base,test_cases_ds_base,tools}.json
  out_dir  receives <vector>/<id>.json plus _conversion.json (counts, removals, input hashes)

Rules are mechanical: no item is judged or edited. Malformed items are removed and listed.
"""
import hashlib
import json
import os
import sys

FILLER = "Thanks, everything looks fine."
PLACEHOLDER = "<Attacker Instruction>"
EMPTY_SCHEMA = {"type": "object", "properties": {}}


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def strip_quotes(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def main(raw, out):
    removed, written = [], {"tool-poisoning": 0, "response-injection": 0}
    inputs = {}

    # MCPTox -> tool-poisoning (ungated: no matched control exists)
    p = os.path.join(raw, "mcptox", "pure_tool.json")
    inputs["mcptox/pure_tool.json"] = sha(p)
    servers = json.load(open(p, encoding="utf-8"))
    os.makedirs(os.path.join(out, "tool-poisoning"), exist_ok=True)
    for srv in servers:
        for key, it in srv.items():
            desc = (it.get("tool_content") or "").strip()
            if not desc or not it.get("tool_name"):
                removed.append({"source": "mcptox", "key": key, "reason": "empty name or description"})
                continue
            cid = f"tool-poisoning/mcptox-{key}"
            case = {
                "vector": "tool-poisoning",
                "id": cid,
                "severity": "high",
                "description": f"MCPTox {it.get('paradigm')}: poisoned tool description ({it.get('security risk')}).",
                "fixture": {"type": "malicious-tool-definition",
                            "tool": {"name": it["tool_name"], "description": desc, "inputSchema": EMPTY_SCHEMA}},
                "expected": {"detect": True, "enforce": True, "signal": "poisoned tool description"},
                "benignControl": None,
                "external": {"corpus": "mcptox", "key": key, "paradigm": it.get("paradigm"),
                             "risk": it.get("security risk"), "server": it.get("server_name")},
                "provenance": "MCPTox (Wang et al., AAAI-26), pure_tool.json, CC BY 4.0; converted per docs/EXTERNAL-PROTOCOL.md.",
            }
            with open(os.path.join(out, f"{cid}.json"), "w", encoding="utf-8") as f:
                json.dump(case, f, indent=1, ensure_ascii=False)
            written["tool-poisoning"] += 1

    # InjecAgent -> response-injection (gated: template + fixed filler is the matched control)
    tp = os.path.join(raw, "injecagent", "tools.json")
    inputs["injecagent/tools.json"] = sha(tp)
    summaries = {}
    for kit in json.load(open(tp, encoding="utf-8")):
        for t in kit.get("tools", []):
            summaries[kit["toolkit"] + t["name"]] = t.get("summary", "")
    os.makedirs(os.path.join(out, "response-injection"), exist_ok=True)
    for split in ("dh", "ds"):
        fp = os.path.join(raw, "injecagent", f"test_cases_{split}_base.json")
        inputs[f"injecagent/test_cases_{split}_base.json"] = sha(fp)
        for i, it in enumerate(json.load(open(fp, encoding="utf-8"))):
            tool = it.get("User Tool") or ""
            resp = strip_quotes(it.get("Tool Response") or "")
            tmpl = it.get("Tool Response Template") or ""
            if not tool or not resp or PLACEHOLDER not in tmpl:
                removed.append({"source": f"injecagent-{split}", "index": i, "reason": "missing tool, response or placeholder"})
                continue
            schema_tool = {"name": tool, "description": summaries.get(tool, ""), "inputSchema": EMPTY_SCHEMA}
            cid = f"response-injection/injecagent-{split}-{i:04d}"
            case = {
                "vector": "response-injection",
                "id": cid,
                "severity": "high",
                "description": f"InjecAgent {split} base: {it.get('Attack Type')} instruction injected into a {tool} result.",
                "fixture": {"type": "malicious-tool-result", "tool": schema_tool,
                            "result": {"content": [{"type": "text", "text": resp}]}},
                "expected": {"detect": True, "enforce": False, "signal": "instruction in tool result"},
                "benignControl": {"type": "benign-tool-result", "tool": schema_tool,
                                  "result": {"content": [{"type": "text", "text": tmpl.replace(PLACEHOLDER, FILLER)}]},
                                  "expected": {"detect": False, "enforce": False}},
                "external": {"corpus": "injecagent", "split": split, "index": i, "attackType": it.get("Attack Type")},
                "provenance": "InjecAgent (Zhan et al., 2024), base setting, MIT; converted per docs/EXTERNAL-PROTOCOL.md.",
            }
            with open(os.path.join(out, f"{cid}.json"), "w", encoding="utf-8") as f:
                json.dump(case, f, indent=1, ensure_ascii=False)
            written["response-injection"] += 1

    with open(os.path.join(out, "_conversion.json"), "w", encoding="utf-8") as f:
        json.dump({"protocol": "docs/EXTERNAL-PROTOCOL.md", "filler": FILLER, "inputs": inputs,
                   "written": written, "removed": removed}, f, indent=1)
    print(json.dumps({"written": written, "removed": len(removed)}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
