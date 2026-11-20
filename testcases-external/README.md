# External corpora (converted)

Fixtures converted mechanically by `scripts/convert-external.py` under `docs/EXTERNAL-PROTOCOL.md`.
They are derived works of third-party datasets and keep those datasets' licences:

- `tool-poisoning/mcptox-*.json` — from **MCPTox** (Wang et al., "MCPTox: A Benchmark for Tool Poisoning on
  Real-World MCP Servers", AAAI-26), https://github.com/zhiqiangwang4/MCPTox-Benchmark at commit
  `630121b3275f74cc72d000a7a056e4d3c68648ef`, file `pure_tool.json`. Licence: **CC BY 4.0**. Changes: each
  entry wrapped as a `malicious-tool-definition` fixture; text unchanged.
- `response-injection/injecagent-*.json` — from **InjecAgent** (Zhan et al., 2024),
  https://github.com/uiuc-kang-lab/InjecAgent at commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, base-setting
  test cases and `tools.json`. Licence: **MIT** (Copyright (c) 2023 Qiusi Zhan). Changes: each case wrapped as a
  `malicious-tool-result` fixture with a control built from its own template.

These are not development or held-out fixtures and are never used to change a defender.
