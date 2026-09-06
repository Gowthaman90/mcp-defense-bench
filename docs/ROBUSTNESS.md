# Evasion-robustness report

4 evasion fixtures · 4 tools measured

| Attack (encoding) | mcp-bastion | mcp-firewall | null-baseline | pipelock |
|---|--|--|--|--|
| header-body-desync — *base64-sentinel* | 🟢 | · | · | · |
| response-injection — *homoglyph substitution* | 🟡 | · | · | 🟡 |
| response-injection — *base64-wrapped payload* | 🟡 | · | · | 🟡 |
| tool-poisoning — *zero-width / bidi-control characters* | 🟡 | · | · | · |

**Robustness (evasion fixtures detected):**
- mcp-bastion: 4/4
- mcp-firewall: 0/4
- null-baseline: 0/4
- pipelock: 2/4

🟢 enforce · 🟡 detect · · missed
