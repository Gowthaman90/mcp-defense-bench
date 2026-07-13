# Evasion-robustness report

3 evasion fixtures · 4 tools measured

| Attack (encoding) | mcp-bastion | mcp-firewall | null-baseline | pipelock |
|---|--|--|--|--|
| response-injection — *homoglyph substitution* | · | · | · | 🟡 |
| response-injection — *base64-wrapped payload* | · | · | · | 🟡 |
| tool-poisoning — *zero-width / bidi-control characters* | 🟡 | · | · | · |

**Robustness (evasion fixtures detected):**
- mcp-bastion: 1/3
- mcp-firewall: 0/3
- null-baseline: 0/3
- pipelock: 2/3

🟢 enforce · 🟡 detect · · missed
