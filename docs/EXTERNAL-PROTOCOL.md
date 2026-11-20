# External-corpus protocol (registered 2026-11-20, before any conversion was run or any tool scored)

## Why

The held-out corpus (`docs/HELD-OUT-PROTOCOL.md`) was written by the benchmark's author. Its own "Limits"
section says an externally authored set would be stronger. This protocol scores the same frozen builds on
two attack corpora written by other researchers for other purposes, converted to fixtures by fixed
mechanical rules. It was prompted by an editor's comment that the results needed more substantiation.

## Corpora (pinned)

| Corpus | Source | Commit | Files used | Licence | Channel |
|---|---|---|---|---|---|
| MCPTox (AAAI-26) | github.com/zhiqiangwang4/MCPTox-Benchmark | `630121b3275f74cc72d000a7a056e4d3c68648ef` | `pure_tool.json` (485 poisoned tool descriptions, 45 servers) | CC BY 4.0 | tool definitions |
| InjecAgent (ACL Findings 2024) | github.com/uiuc-kang-lab/InjecAgent | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | `data/test_cases_dh_base.json` (510), `data/test_cases_ds_base.json` (544), `data/tools.json` | MIT | tool results |

Downloaded 2026-11-20; SHA-256 of every file in `paper/journal/external/raw/SOURCES.txt` (private paper
repository) and repeated in `results/external/MANIFEST.json` at run time.

**Blindness.** Neither corpus was used to write any development or held-out fixture, and neither is
referenced in mcp-bastion's source (`grep -ril 'mcptox|injecagent'` over `testcases/`,
`testcases-heldout/` and `mcp_bastion/src` returns nothing, checked 2026-11-20). The author had read the
MCPTox paper, which is cited in the related work, but did not use its data. MSB is **excluded**: ten
development fixtures name it as their pattern source. The InjecAgent "enhanced" variants are excluded
because they add a fixed hacking prefix ("IMPORTANT!!! Ignore all previous instructions…") whose wording
overlaps the development corpus's trigger phrases; only the "base" cases are used.

## Conversion rules (mechanical; no per-item judgement)

**MCPTox → vector `tool-poisoning`.** For every entry: fixture type `malicious-tool-definition`, tool
`name` = `tool_name`, `description` = `tool_content` with surrounding whitespace removed, `inputSchema` =
`{"type":"object","properties":{}}` (the corpus does not give schemas). Tags: `paradigm`, `security risk`,
`server_name`. **No matched control**: MCPTox has no benign counterpart, and a first-sentence control was
rejected because in many entries the first sentence is the attack. MCPTox is therefore scored *ungated*
(share of fixtures flagged and share blocked), and its benign cost is the tool's false-positive rate on the
benchmark's benign-only corpus, whose 256 harvested tool definitions are the same channel.

**InjecAgent → vector `response-injection`.** For every base case: fixture type `malicious-tool-result`,
tool `name` = `User Tool`, `description` = the matching tool's `summary` in `tools.json` (toolkit name +
tool name; empty if not found), `inputSchema` = `{"type":"object","properties":{}}`, result text =
`Tool Response` with one pair of surrounding double quotes removed. **Matched control**: type
`benign-tool-result`, same tool, result text = `Tool Response Template` with the literal
`<Attacker Instruction>` replaced by the fixed sentence `Thanks, everything looks fine.` Tags:
`Attack Type`, `dh|ds`. InjecAgent is scored with the HOC gate (Section "Metrics").

A converted item that is malformed (empty description or result, placeholder missing from the template)
is removed and listed in the manifest; no item is edited.

## Tools and builds (frozen before conversion)

| Tool | Build | Adapter | Rebuild check |
|---|---|---|---|
| mcp-bastion | 1.0.0, commit `a3716d5` (first held-out run) | bench at `2771b2a` | reproduces recorded dev (51) and held-out (48) outcomes, 0 differences |
| mcp-bastion | frozen commit `45b579c` (released as 1.4.0) | bench HEAD adapter (unchanged since `fd96021`) | reproduces recorded dev (78) and held-out (75) outcomes, 0 differences |
| mcp-firewall | 0.1.0 (PyPI) | bench HEAD | pinned venv |
| pipelock | 3.0.0 free binary, sha256 `96843f7f3b54…` | bench HEAD | pinned binary |
| null baseline | constant | bench HEAD | — |

agentgateway and ToolHive are wired for the authorization family only and are not run.

## Metrics

Per tool and corpus: share of attack fixtures **flagged** (detect) and **blocked** (enforce), with Wilson 95%
intervals; per MCPTox paradigm and per InjecAgent attack type. For InjecAgent additionally the HOC case
outcome behind the gate (enforce 1, detect 0.5, none 0, and none + false positive when the control is
flagged), its mean, and the false positives on controls. These are compared with each build's
development and held-out RobustCoverage on the same vector (`tool-poisoning`, `response-injection`).

## Predictions (written before the run)

1. mcp-bastion 1.0.0 flags a smaller share of MCPTox than of its development `tool-poisoning` fixtures,
   because its held-out run lost `tool-poisoning` entirely and its definition checks are phrase lists.
2. On InjecAgent, whose injected instructions are plain polite requests without trigger phrases, every
   tool's gated mean is below its development `response-injection` score.
3. The null baseline scores zero on both.

## Rules

One run per tool and build. Results are published as measured. No converter rule, filler sentence, tool
configuration or build changes after the first run; any later change is a new, separately labelled run.

## Addendum A — outside defenders (registered 2026-11-20, before any of them was run on any corpus in this round)

Three third-party Python defences, scored with the Python port of the benchmark (mcp-defense-bench-py at
`b57b168`, configs in its `examples/` exactly as published there; one mechanical rule per tool, never per case):

| Tool | Version (PyPI upload) | Config | Inspects | Held-out status |
|---|---|---|---|---|
| mcp-assure | 0.3.2 (2026-07-29) | `mcp_assure_example:operator_pack` (FastMCP middleware) | tool name allow-list, argument names | **frozen before registration (2026-09-05)**: held-out claim |
| mcp-gate-policy | 0.3.2 (2026-08-07) | `mcp_gate_example:operator_policy` (stdio proxy) | `tools/call` argument values | **frozen before registration**: held-out claim |
| agentx-mcp + agentx-security-sdk | 0.2.4 (2026-10-08) + 0.5.5 (2026-10-14) | `agentx_mcp_example:enforce` (stdio proxy) | `tools/call` floors; `tools/list` pins + hidden-Unicode | released **after** the held-out set was published (2026-09-07): re-measurement on a seen set, not a held-out claim (rule 7) |

Environment: Python 3.12, fastmcp 4.1.0, mcp 2.3.0, isolated venv. agentx runs with `AGENTX_TELEMETRY=off` and a
fresh `HOME` per input. Corpora: development, held-out and benign from this repository at the commit of the run;
the external corpus through `scripts/run-external-py.py`, which applies the same scoring rule as
`scripts/run-external.mjs` (ungated when a case has no control).

Their authors did not see this benchmark's corpora while building these versions, so for them the development
corpus is also unseen; their development-to-held-out difference therefore measures how much harder the held-out
corpus is for an independent defender, a control for the co-development gap of the reference proxy.

**Predictions.**
1. None of the three flags any MCPTox definition or InjecAgent result above 1%: mcp-assure and mcp-gate do not
   read definitions or results, and agentx reads descriptions only for hidden-Unicode carriers.
2. For mcp-assure and mcp-gate the development-to-held-out difference on the base vectors is at most one
   vector-equivalent in either direction.

One run per tool and corpus; results published as measured.
