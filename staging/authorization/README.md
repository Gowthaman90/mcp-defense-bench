# Staged authorization family (unscored)

Pre-registered in [`../../docs/AUTHORIZATION-PREREG.md`](../../docs/AUTHORIZATION-PREREG.md) (tag `authorization-prereg-2026-10-26`).

- `crosswalk-rows.json`: Rater A rows for the 4 vectors (pre-adjudication).
- `dev/`: 12 development fixtures. Defender authors may read these.
- `heldout/`: 12 held-out fixtures. **Defender authors must not open these** until held-out results are published.
- `ratings/`: the blind rating input, the blind Rater B sheet and the pre-adjudication agreement report.
- `MANIFEST.json`: sha256 of every fixture and generator file, counts, freeze, removal and deviation logs.

Fixtures are frozen: never edit or regenerate them. A malformed fixture is removed and the removal logged in the manifest.
