# Staged delegation family (unscored)

Pre-registered in [`../../docs/DELEGATION-PREREG.md`](../../docs/DELEGATION-PREREG.md) (tag `delegation-prereg-2026-10-15`).

- `crosswalk-rows.json`: Rater A rows for the 5 vectors (pre-adjudication).
- `dev/`: 15 development fixtures. Defender authors may read these.
- `heldout/`: 15 held-out fixtures. **Defender authors must not open these** until held-out results are published.
- `ratings/`: blind Rater B sheet and the pre-adjudication agreement report.
- `MANIFEST.json`: sha256 of every fixture and generator file, public keys, counts, freeze and removal log.

Fixtures are frozen: never edit or regenerate them. A malformed fixture is removed and the removal logged in the manifest.
