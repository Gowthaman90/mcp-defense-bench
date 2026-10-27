# Evasion-robustness report

4 evasion fixtures · 6 tools measured

| Attack (encoding) | agentgateway | mcp-bastion | mcp-firewall | null-baseline | pipelock | toolhive |
|---|--|--|--|--|--|--|
| header-body-desync — *base64-sentinel* | ? | 🟢 | · | · | · | ? |
| response-injection — *homoglyph substitution* | ? | 🟡 | · | · | 🟡 | ? |
| response-injection — *base64-wrapped payload* | ? | 🟡 | · | · | 🟡 | ? |
| tool-poisoning — *zero-width / bidi-control characters* | ? | 🟡 | · | · | · | ? |

**Robustness (evasion fixtures detected):**
- agentgateway: not wired for these fixtures
- mcp-bastion: 4/4
- mcp-firewall: 0/4
- null-baseline: 0/4
- pipelock: 2/4
- toolhive: not wired for these fixtures

🟢 enforce · 🟡 detect · · missed · ? not wired
