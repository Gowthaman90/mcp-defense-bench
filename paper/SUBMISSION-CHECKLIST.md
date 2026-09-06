# Submission checklist — double-blind venues

The AISec 2026 submission (#34) was **desk-rejected for breaking anonymity**: the anonymised artifact
mirror still contained the author's name. Everything else about the review was survivable; that was
not. This checklist exists so it cannot happen again. Run it in order; do not skip the greps.

## A. Artifact anonymity (the thing that failed)

- [ ] Build the mirror **from the script, never by hand**: `node scripts/make-anon-mirror.mjs /tmp/anon-mirror`.
      It exits non-zero and lists residual hits if any identity string survives. Do not upload until it prints `leak scan clean`.
- [ ] Upload the **output directory** (a `git archive` — no `.git/`), never a clone. Git history carries author
      name/e-mail in every commit and the chairs look.
- [ ] Open the uploaded mirror in a **private browser window** and grep the rendered README, `package.json`,
      any `CITATION`/`zenodo` file, `docs/index.html`, and the LICENSE for: surname, first name, GitHub handle,
      e-mail, DOIs, personal domains, the real tool names.
- [ ] Search the web for each **placeholder-free unique string** in the artifact (a distinctive metric name, a
      fixture id, the leaderboard title). If the first result is your public repo, the string de-anonymises you:
      rename it in the mirror or accept the risk consciously.
- [ ] Real tool names: the paper and the mirror must agree. If the paper says OurProxy, the mirror must not say
      mcp-bastion anywhere (the script handles this) — and the *public* repo must not have a release note titled
      with the paper's title before decisions are out.
- [ ] Zenodo / Figshare: do **not** mint a real-name DOI for the paper before the decision. A preprint under
      your name is discoverable by title.

## B. Paper anonymity

- [ ] `\documentclass[conference]{IEEEtran}` (SaTML) with author block `Anonymous Author(s)`; ACM venues use
      `anonymous` class option.
- [ ] Own prior work cited in the third person; no "our previous paper", no self-citation to the arXiv/Figshare
      whitepaper with your name in the bib entry (`author = {Anonymous}` or cite the anonymised mirror).
- [ ] Acknowledgements removed; funding removed; no "we thank Massimiliano Brighindi" (an independent
      reviewer's name is a search key to your public issue tracker) — say "an independent reviewer".
- [ ] PDF metadata stripped: `exiftool -all= paper.pdf` or check `pdfinfo paper.pdf` shows no Author.
- [ ] LaTeX comments removed from the submitted source if source is uploaded (`%%` lines carry names).

## C. Venue-specific (SaTML 2027)

- [ ] Abstract registration **Sep 22, 2026 AoE**; paper **Sep 29, 2026 AoE**; ORCID + certification at abstract time.
- [ ] Up to 12 pages IEEEtran, references/appendix unlimited.
- [ ] **Prior reviews must be appended** with a statement of how each point was addressed — use
      `paper/REVIEWS-AND-RESPONSE.md`, anonymised (it mentions no names).
- [ ] Anonymised artifact shared **within 3 days of submission** (open-science policy; violation = desk reject).
- [ ] LLM-usage disclosure section present.
- [ ] Not under submission elsewhere.

## D. Content sanity (what the AISec reviewer actually asked for)

- [ ] Held-out results reported beside development results, per vector, with the gap (`docs/LEADERBOARD.md`).
- [ ] Benign-corpus FP rate with a confidence interval, per input kind, including the by-design cost rows.
- [ ] Inter-rater agreement table with the pre-adjudication numbers as headline; adjudication log linked.
- [ ] Every number in the paper generated from `results/` by `paper/v2/gen-tables.mjs`, not typed.
- [ ] Limitations say plainly: fixtures still single-author; Rater B is an LLM; Rater C open.
