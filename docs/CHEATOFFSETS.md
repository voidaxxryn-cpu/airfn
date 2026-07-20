# cheatoffsets.com integration

Owner: viru (script) + airproductions (CI wiring).

## What it does

`scripts/gen_offsets.mjs` polls `https://www.cheatoffsets.com/api/games/fortnite/current`, ETag-conditional. Parses the returned JSON's `offsets` tree; if empty (Fortnite's SDK dump format doesn't feed their parser cleanly), falls back to regex-parsing the fenced cpp blocks inside `payload.markdown`. Writes `airfn/offsets/offsets.h`.

## Files touched

- `airfn/offsets/offsets.h`       — regenerated
- `airfn/offsets/.etag`           — cached ETag, checked in so CI knows what "unchanged" means

## Not touched

- `airfn/offsets/offsets_manual.hpp` — anything viru wants to keep across regens lives here.

## Cadence

- Manual: `node scripts/gen_offsets.mjs` — run before every code-review.
- CI: `.github/workflows/offsets.yml` — cron `*/30 * * * *`. If the header changes, bot commits and pushes to the branch.

## Failure modes

| Symptom                                 | Cause                              | Fix                                              |
| --------------------------------------- | ---------------------------------- | ------------------------------------------------ |
| Script exits 1 "both trees empty"       | Upstream markdown format changed   | Look at raw JSON; extend `parseMarkdown()` regex |
| `304 unchanged` on every run            | Working as intended                | —                                                |
| Bot never commits despite new game patch| ETag cache stale in the runner     | Delete `.etag`, re-run workflow                  |
