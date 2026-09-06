# Held-out evaluation protocol (pre-registered)

**Registered:** 2026-09-05, before any held-out fixture was written and before any defender was run
against one. This file is the commitment; `testcases-heldout/` is the execution. Reviewers should
compare the two.

## Why this exists

The AISec 2026 review of *Measuring the Defenders* raised the right objection: the benchmark and its
strongest measured tool (mcp-bastion) were developed together. The development corpus was used to
find gaps, fix them, and re-measure. A coverage number produced that way is evidence that the
benchmark *guides* development; it is weaker evidence that the tool *generalises*. The remedy is a
held-out set of attack fixtures that the defender's authors never saw while building it.

## The commitment

1. **Defender freeze.** Every defender is evaluated at a version whose detection code was finalised
   before this protocol was registered. The exact versions/commits are recorded in
   `results/heldout/MANIFEST.json` at run time. No defender may be modified between the first
   held-out run and publication of the held-out numbers.
2. **Fixture authorship is blind to detector source.** Held-out fixtures are authored from the
   *vector descriptions in the rubric* and the *published attack literature* only. The author does
   not consult any defender's detection rules, pattern lists, or test suites while writing them.
3. **Transformation families.** For each of the 24 original vectors, the held-out set contains
   fixtures drawn from these families, each fixture tagged with the family it belongs to:
   - **D — domain shift.** A different tool domain from every development fixture for that vector
     (no `get_weather`, `ping_host`, `fetch_url`, `read_file`/`http_post` pairs, `connect_service`,
     `set_role`, `list_tickets`, `formatters`).
   - **L — lexical shift.** No reuse of a development fixture's trigger phrasing. In particular the
     held-out set does not use `<IMPORTANT>`, `ignore previous instructions`, `SYSTEM:`,
     `attacker.example`, or `AKIAIOSFODNN7EXAMPLE`. Reserved hosts come from other RFC 2606/5737/6761
     ranges (`*.invalid`, `*.test`, `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`).
   - **S — surface shift.** Where the vector admits it, the attack is expressed through a different
     fixture type than the development fixture (e.g. a definition-borne attack re-expressed as a
     result-borne one, or a single call re-expressed as a call sequence).
   - **E — encoding shift.** One additional realistic obfuscation not present in the development
     corpus (e.g. markdown-link hiding, HTML entities, JSON-in-string nesting, URL-encoding,
     mixed-case/spacing). Zero-width, homoglyph and base64 are *development* encodings and are
     therefore excluded from E.
4. **Matched controls, as always.** Every held-out fixture carries a near-identical benign control.
5. **Minimum size.** At least two held-out fixtures per original vector (≥ 48), at least one of
   which is family D or L.
6. **No iteration.** Held-out results are published as measured on the first run. If a fixture is
   found to be malformed (schema error, contradiction with its own control), it is *removed and the
   removal logged* in `results/heldout/MANIFEST.json`; it is never edited to change an outcome.
7. **Rolling retirement.** Once published, a held-out set is retired into the development corpus of
   the next benchmark version. Any later coverage claim requires a fresh held-out set under this
   protocol.

## What is reported

For every measured tool: development-corpus coverage and held-out coverage, side by side, per
vector, with the **generalisation gap** (dev − held-out). A large gap is a finding about the tool,
not a defect of the benchmark; it is exactly what this protocol exists to expose.

## Limits, stated plainly

The held-out fixtures are still written by the benchmark's author. Blindness to detector source and
the constraint to the four transformation families are the controls on that; an externally authored
red-team set would be stronger and remains an open invitation (see `CONTRIBUTING` in the README).
The protocol is strict about *when* fixtures were written and *what they may reuse*, not about *who*
wrote them.
