# Plan: display names and location removal (Rowanholt)

Branch `feat/display-names`, from main `9af6b5d`. Planned 12 November 2026; not implemented yet.

## Names

| Code name (stays) | Display name | Module |
|---|---|---|
| Gandalf | Custodian | Acquisition |
| Elrond | Ledger | Analysis |
| Smith | Smith | AI analyst |
| Pippin | Lookout | Threat intel |
| Aragorn | Steward | Administration |
| Andúril | Quartermaster | Docker manager |
| Mordor | Crucible | Lab and recorded attack telemetry |

Bare names, no "The". A one-for-one word swap, possessives included ("Elrond's" -> "Ledger's").

## What changes (anything a user reads)

1. **Web UI** (`src/web/frontend/src`): the nav in `App.js`, the Home cards (`Home.js`), `PageHero` titles (Aragorn, Pippin and the rest), the `HelpPage.js` sections, the `who:` labels and diagram labels, `guide/content.js`, tooltips (`CaseBrowser.js`, `MordorTelemetry.js`, `NewAnalysis.js` "Gandalf Acquisition Jobs"), and the old analysis UI's `OptionsPanel.js` label plus its e2e spec.
2. **CLI and log output:** `help=` text (13), messages printed to users, errors and progress text in `.py`, `.sh`, the `rowanholt` script and `.ps1` (e.g. `anduril_cli.py` "Anduril" -> "Quartermaster"). Log message text changes too, since analysts read it in the audit logs.
3. **Smith's answers and MCP tool descriptions:** `smith_offline.py` strings such as "Elrond's analysis (--Analysis)" and the smith-mcp tool descriptions (text only, never tool names).
4. **Docs:** `README.md`, `docs/`, `desktop/README.md`, the `src/*/README.md` files, and the guide. Each gets a mapping table near the top (display name -> code name -> paths) so developers can find the code.
5. **Desktop apps:** the macOS app, `desktop/linux/rowanholt-app.sh`, `desktop/windows/Rowanholt.ps1`, and the installer text in `rowanholt.wxs`.
6. **Architecture diagrams:** the generators in `scripts/docs/architecture/` (`build_map.py`, `build_gandalf_flow.py` and the rest), then a regeneration of `public/architecture/*.html` and the preview JPGs. "The realm ... map of Middle-earth" becomes a plain architecture map.
7. **`.claude/CLAUDE.md`:** the naming rule becomes "code names stay in identifiers; display names in anything user-facing", with the table.

## Locations removed

| File | Change |
|---|---|
| `src/common/startup_progress.py` + `tests/unit/test_startup_progress.py` | Drop the places list; progress is phase plus ETA, as Windows already does |
| `desktop/macos/journey.html`, `desktop/macos/build.sh`, `desktop/linux/rowanholt-app.sh` | The same: phase plus ETA |
| `public/architecture/rowanholt-journey.html` | Remove, or rebuild as a plain startup-stage diagram (decision 4) |
| `desktop/windows/Rowanholt.ps1` | Phase texts: "Waking Docker" -> "Starting Docker", "Forging the images" -> "Building images", "Raising the halls" -> "Starting services", "Opening the doors" -> "Opening Rowanholt" (same on macOS and Linux) |
| `App.css` | The Shire-to-Mordor path styles (dead or tied to the journey: check) |
| `README.md`, `docs/ARCHITECTURE.md`, `src/analysis/README.md`, `src/analysis/elrond.py`, `HelpPage.js`, `guide/content.js` | Delete the place references from the text |

Skip: `cyberchef.py` (minified vendor code, false positives).

## ASCII art and quotes

| File | What's there |
|---|---|
| `src/analysis/elrond.py` (`asciitext`, line 541; `quotes`, line 480) | 4 ASCII scenes ("Welcome to Minas Tirith", "Welcome to Bag End", two more) and 49 Tolkien quotes, printed at start and at stage changes (`asciitext` used at lines 764, 861, 934, 1034, 1195; also imported in `rowanholt/main.py:120`) |
| `src/acquisition/python/gandalf.py` (line ~212) | The same 49 quotes |
| `src/acquisition/windows/Invoke-Gandalf.ps1` (line 54) | The same 49 quotes |
| `src/acquisition/python/passkey_decrypt.py` | The same 49 quotes |
| `desktop/windows/rowanholt.wxs`, `desktop/macos/journey.html`, `scripts/docs/architecture/build_gandalf_flow.py` | One quote each |
| `src/acquisition/bash/gandalf.sh`, `collect_artefacts-py`, the desktop scripts | Possible banners: check each during the change (the grep for art also matches separator lines) |

The quotes are verbatim text from the books and films, both still in copyright, which is a bigger exposure than any name. The plan:

- **Scenes:** delete all four and the `asciitext` list, with no replacement. Remove the uses in `elrond.py` (lines 764, 861, 934, 1034, 1195) and the import in `rowanholt/main.py:120`. If an existing banner line still prints a title at those points, keep that line; nothing new is added.
- **Quotes:** remove them, or replace them with original lines (decision 6). The collectors run on target hosts, so whatever replaces them should be short, ASCII-only and in one shared list per language, not four copies.
- **Check the output that's asserted:** if any tests or the guide capture (`scripts/docs/guide/capture.py`) expect the banner, update them.

## What stays (explicitly out of scope)

- Python and JS identifiers, module and directory paths (`src/mordor`, `src/common/anduril`), component file names (`Aragorn.js`)
- URL routes (`/gandalf`, `/pippin`), API paths and JSON fields, database values (no Alembic migration needed)
- CLI subcommands and flags (`rowanholt anduril enable`, `--Mordor`), env vars, container and network names (`rowanholt-anduril`)
- Evidence-format names written into cases: `gandalf_integrity.jsonl`, the `log.meta` fields, and the collector scripts' output on target hosts. Changing these breaks reading older cases.
- Code comments and docstrings: they're for developers, and the mapping table covers them
- Third-party names: "OTRF Security-Datasets (Mordor)" is that project's own name (also in Shikari)
- Image filenames (the art itself is decision 1)

## Order

1. Merge `feat/msi-wizard` to main (decision 5), because it rewrote the text in `Rowanholt.ps1` and `rowanholt.wxs`, then rebase this branch onto it.
2. Locations and phase texts: the smallest step; it settles the startup flow on all three platforms.
2b. ASCII scenes and quotes (elrond.py, the three collectors, passkey_decrypt.py, the installer).
2d. CLI aliases (decision 2), with unit tests for the old and new spellings.
3. Web UI.
4. CLI, log and Smith strings, plus test updates.
5. Docs, CLAUDE.md, the mapping table.
6. Diagram generators, then regeneration.
7. Desktop apps and installer text, then a Windows MSI rebuild for the VM test.
8. Other repos as their own branches: `homelab` (`README.md`, `rowanholt/rowanholt-orb-server.sh`, `rowanholt-orb-smoke.py`: check whether the smoke test matches UI text) and FlightDeck card text. Shikari: no change (OTRF's name only).

One commit per step, so any step can be reverted alone.

## Verification

- Unit tests from `tests/unit` with `~/.cache/rivendell-tests` (strings asserted in tests get updated, not deleted)
- Frontend `npm run build`, plus the analysis UI's Playwright `options-panel.spec.js`
- An audit grep: no capitalised code name left in user-facing files (UI text, help, docs, desktop), with the allowed exceptions listed above
- Screenshots of Home, the nav, the Help page and Steward on the dev stack, and retaken guide photographs (`public/guide/aragorn*.jpg` and any others that show the old names)
- homelab smoke test against the dev server

## Decisions (settled 12 November 2026)

1. **Images:** out of scope. The portraits (`gandalf.png`, `elrond.png`, `pippin.png`, `aragorn.png`, `smith.png`), `middle_earth.png` and `mordor_open/closed.jpg` stay as they are, including the character portraits on the Home page: no replacement and no new art. Only the text beside them changes (card names, alt text, captions). Retake the guide photographs afterwards for the new text.
2. **CLI aliases:** add `rowanholt quartermaster ...` beside `rowanholt anduril ...`, and the flags `--Custodian` / `--Crucible` beside `--Gandalf` / `--Mordor` (argparse aliases into the same dest), with help text showing the new names first. The old ones keep working with no deprecation warning yet.
3. **URL routes:** keep `/gandalf`, `/elrond`, `/pippin`, `/aragorn`, `/mordor`. Only the link text changes.
4. **`rowanholt-journey.html`:** rebuild it as a plain diagram of the startup stages (Docker, images, services, open), with the same ETA wording as the apps. The Help page links to it under its new title.
5. **`feat/msi-wizard`:** merge it to main as step 1 (Ben approved this through the recommendation, 12 November 2026), then rebase `feat/display-names` onto it. `feat/rename-smith` is never merged.
6. **Quotes:** replace them with original DFIR one-liners in the same dry tone. One shared list per language: `src/common/quips.py` for elrond.py, gandalf.py and passkey_decrypt.py (check that the collector copies on target hosts can import it; if a script has to stay standalone, it gets an inline copy produced by the build, not edited by hand), and a PowerShell array in `Invoke-Gandalf.ps1`. The installer, the macOS journey and the diagram generator use one line each from the list. ASCII only, no attributions. Draft list below for Ben to edit.

### Draft one-liners

```
Hash it before you trust it.
Volatile first. The disk will wait; the RAM won't.
If it isn't in the timeline, it didn't happen. If it is, prove it.
Every artefact is innocent until correlated.
The attacker cleared the logs. The logs about the logs are still here.
Absence of evidence is a finding. Write it down.
Time zones: the oldest adversary.
Never analyse the original. Not even once. Especially not once.
Prefetch remembers what the user would rather forget.
The registry keeps secrets badly and grudges well.
A clean system is either clean or very well cleaned.
Your hypothesis is not your conclusion. Yet.
Write the report as if the defence will read it. They will.
Chain of custody: boring until the day it isn't.
Correlation is a lead. Causation needs a second source.
Timestamps lie. Four of them lie less.
The first alert is rarely the first event.
Living off the land still leaves footprints in the mud.
Assume the clock is wrong until it proves otherwise.
Scope creep is also an incident.
Read the ShimCache, then distrust it accordingly.
If the binary is signed, ask who signed it and why.
Every persistence mechanism was somebody's convenience feature.
The quietest host is worth a second look.
Collect broadly. Conclude narrowly.
No IOC survives contact with a competent adversary.
Lateral movement leaves logons. Logons leave 4624s.
Deleted is a state of mind. The MFT disagrees.
Document now. Your memory is not evidence.
The answer is in the data. The question is usually the problem.
```

30 lines, to replace 49 quotes. The order is random per run, as now.

## Size

About 150 to 200 files touched, almost all text. Roughly a day of changes, plus regenerating the diagrams, retaking the guide photographs and one round of Windows/macOS checks.
