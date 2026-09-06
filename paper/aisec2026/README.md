# AISec 2026 submission packet — mcp-defense-bench (Benchmark paper)

**Deadline: July 24, 2026 (firm).** Notification Sept 3 · Camera-ready Sept 16 (firm).
Venue: 19th ACM Workshop on AI and Security (AISec '26), co-located with ACM CCS 2026.
Category: **Benchmark paper** (new in 2026) — **requires a functional artifact link + mandatory artifact sharing at submission.**
Format: `acmart` **sigconf**, **10 pages** (excl. bibliography & appendix) **+ up to 2 appendix pages** = 12 max.

## Files
- `main.tex` — normal version (author visible). Use if AISec is **not** double-blind.
- `main-anon.tex` — **anonymized version** (name/email/personal links removed). Use if AISec **is** double-blind.
- `refs.bib` — bibliography (shared by both).
- Build: **Overleaf** (upload the files; grab the ACM template's `ACM-Reference-Format.bst`), or locally: `pdflatex <file> && bibtex <file> && pdflatex <file> && pdflatex <file>`.

## Tool names — real names KEPT (per chair guidance)
Originally renamed to placeholders for max compliance, then **reverted** after the chair confirmed the
4open.science mirror is the accepted anonymization. The paper now keeps the real tool names
(mcp-bastion, mcp-defense-bench) and hides only the *author*; this stays consistent with the mirror URL
(which contains the real repo name). Normal, accepted good-faith double-blind.

## Anonymous artifact mirror — DONE
Created at `https://anonymous.4open.science/r/mcp-defense-bench-2D7D/` and already wired into the
Availability section of `main-anon.tex`. Delete the mirror after the review period ends.
_(Optional nicety: the mirror's files still contain the author name in `CITATION.cff` / `README`; the
chairs accept this, but you may scrub those two lines in the mirror source if you want it cleaner.)_

## ⚠️ DECIDE / VERIFY BEFORE SUBMITTING (in priority order)

1. **Double-blind? — CONFIRMED YES, and RESOLVED with the chairs (2026-07-17).** CFP requires anonymization. **Chair Giovanni Apruzzese confirmed by email that using anonymous.4open.science for the artifact is the accepted approach.** → **submit `main-anon.tex`** (author anonymized; real tool names kept, per the chair's guidance, for consistency with the mirror). Artifact mirror is live and already wired into the Availability section: `https://anonymous.4open.science/r/mcp-defense-bench-2D7D/`. Submission site: **https://aisec26.hotcrp.com/**.
   - If **single-blind / non-anonymous**: submit as-is (author + tool names visible; conflict disclosed in Acknowledgements).
   - If **double-blind**: this paper is hard to anonymize because the artifact is a public repo under the author's name. You must (a) change the class to `\documentclass[sigconf,review,anonymous]{acmart}`, (b) replace the author block + the `\acks` "the author develops mcp-bastion" with a neutral "one evaluated tool is developed by the authors," (c) replace the GitHub/Zenodo links with an **anonymized artifact mirror** (e.g. `anonymous.4open.science`), and (d) confirm AISec's policy on public-artifact benchmark papers — some venues grant an exception. **Resolve this first; it changes the whole packet.**

2. **Page fit** — compile on Overleaf and check it lands ≤10 pages. The content is close but may run slightly over in double-column. If over, trim: the Setup section (§5) prose, the Discussion sub-paragraphs, and the Limitations list are the safest cuts. Tables 1–3 should stay.

3. **Artifact link works** — the Benchmark category *requires* a functional link. Confirm `https://github.com/Gowthaman90/mcp-defense-bench` + the Zenodo DOI resolve and that the leaderboard/README render. (If double-blind, this becomes the anonymized mirror in item 1.)

4. **ACM metadata** — `\acmConference`/`\acmDOI`/copyright are placeholders; AISec/ACM supply real values at camera-ready. Leave as-is for submission (`\setcopyright{none}`, `printacmref=false`).

5. **CCS concepts / keywords** — sanity-check the two `\ccsdesc` lines against the ACM CCS tool if you want a tighter match.

## Content changes already folded in (vs. the arXiv/Figshare whitepaper)
- Reformatted to ACM sigconf; abstract/sections/tables ported; references → BibTeX `\cite`.
- **AgentDefense-Bench differentiation sharpened** in Related Work (coverage vs. detection-accuracy) — matches the corrected PRIOR-ART framing.
- Conflict-of-interest + ethics moved into `\acks` (ACM convention).
- Trimmed a few long enumerations for double-column density; no results changed.

## Status
- [x] ACM sigconf manuscript drafted (`main.tex`)
- [x] Bibliography (`refs.bib`)
- [ ] **Double-blind decision (item 1)** ← do this first
- [ ] Compile on Overleaf; confirm ≤10 pages
- [ ] Confirm artifact link (or build anonymized mirror)
- [ ] Final proofread pass
- [ ] Submit via the AISec 2026 submission site before Jul 24 (AoE)

_This packet is local/uncommitted, consistent with the rest of the paper-2 work. The mcp-defense-bench
artifact itself is already public, so submitting the paper does not expose anything new._
