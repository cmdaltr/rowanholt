# The YouTube walkthrough

Rivendell's narrated walkthrough is filmed with Playwright against a running stack, narrated by
Piper and put together with ffmpeg. `regenerate.sh` also retakes the in-app guide's photographs,
because both show the same pages.

The scripts here are kept locally and never committed: `.gitignore` excludes everything in this
folder except this README.

## Regenerating

With Rivendell running (`rivendell start`):

```bash
scripts/docs/video/regenerate.sh               # guide photographs, then the video
scripts/docs/video/regenerate.sh --refilm      # after a change to the web UI
scripts/docs/video/regenerate.sh --video-only  # or --guide-only
```

It asks for the admin password in a dialog, unless `RIVENDELL_PASSWORD` is already set. A
full render takes about 25 minutes.

Any other options are passed to `make_video.py`:

```bash
scripts/docs/video/regenerate.sh --video-only --only eru         # just the Eru section
scripts/docs/video/regenerate.sh --video-only --preview          # silent, to check the filming
```

The guide's photographs (`src/web/frontend/public/guide/`) are part of the app, so commit them
when they change. The script reminds you.

To retake only some of the guide's pages, run the capture directly. Page IDs come from
`src/web/frontend/src/guide/content.js`:

```bash
~/.cache/rivendell-video/bin/python scripts/docs/guide/capture.py --only case intel
```

Add `--username admin` (with `RIVENDELL_PASSWORD` set) for pages that need an admin: Account,
Aragorn and Aragorn's settings.

## What it needs

| What | Where |
|---|---|
| Playwright and Chromium | `~/.cache/rivendell-video` (created on the first run if missing) |
| Piper and the `en_GB-alan-medium` voice | `~/.local/share/piper` (install steps at the top of `make_video.py`) |
| ffmpeg | `brew install ffmpeg` |
| A finished demo case | see below |

## Settings

These are set as environment variables. The defaults are what the current video uses.

| Variable | Default | What |
|---|---|---|
| `CASE_DIR` | `/Volumes/Portable6TB/Data/rivendell/claude_testing/threatintel_demo` | The finished Elrond case shown in the video |
| `CASE_ID` | `THREATINTEL-DEMO-01` | Its case ID in the web UI. Eru and the Job page use this case's newest job |
| `INTEGRITY` | `…/volatility_order_win3/elrond_intake/LAB-WIN11/gandalf_integrity.csv` | A `gandalf_integrity.csv`, used when the case has none |
| `OUT` | `scripts/docs/video/output` | Where the video goes (git-ignored with the rest of this folder) |

The narration expects the lab's Windows machine: the techniques **T1070.006**, **T1564.004**
and **T1546.003**, and IOCs under `rivendell-lab.test`.

The Jobs scene films the real job list, so delete or archive any test jobs first.

## What comes out

In `OUT`:

| File | What |
|---|---|
| `rivendell-walkthrough.mp4` | The video, with chapters |
| `rivendell-walkthrough.srt` | Captions |
| `chapters.txt` | The chapter list for the YouTube description |
| `thumbnail.jpg` | 1280×720 |
| `scenes/` | The render cache. Keep it so later renders only redo what changed |

## Adding or reordering sections

`scenes.py` holds a list called `SECTIONS`, one section per feature or component. Each section
is a YouTube chapter, fades in from black and fades out to black. To add a feature, add a
section wherever it belongs; to reorder, move the blocks. Nothing outside a section refers to
it.

```python
{
    "id": "pippin",                      # unique: it names the files in scenes/
    "chapter": "Pippin: threat intelligence",
    "scenes": [
        {
            "id": "pippin",
            "visual": {"kind": "page", "url": "/intel", "actions": [("wait", 2)]},
            "text": "What's said while the page is on screen.",
        },
    ],
},
```

A scene's visual is a title card (`card`), a page of the web UI (`page`) or a terminal
(`terminal`). The docstring at the top of `scenes.py` lists the actions a page scene can take.
`SPOKEN` in `scenes.py` sets how Piper pronounces terms the captions spell out
(for example ATT&CK, JSON).

## Caching

- **Scenes** are cached by section and scene ID. A scene is only filmed and narrated again
  when its narration or visual changes.
- **Sections** are only joined again when one of their scenes changes.
- **The final video** is joined from the sections without re-encoding them.

The cache can't see a change to the web UI itself, such as a new nav icon or a restyled page.
After one of those, run with `--refilm`, which films the web UI scenes again. Cards and
terminals come from the cache.

## When something looks wrong

- **A scene logs `… not found, skipped`:** a selector in `scenes.py` no longer matches the UI.
  Fix the selector, then re-run with `--only <section>`.
- **The welcome covers the pages:** the render marks the welcome as already shown, using the
  key the app reads (`rivendell.offeredAt` in localStorage, `OFFERED` in `make_video.py`). If
  the app's key changes, change `OFFERED` to match.
- **Eru's answers don't appear:** without Ollama, Eru shows its offline questions, which are
  the ones `scenes.py` clicks. With a model running, the buttons are different.
- **The log stays empty until the end:** that's normal when the output isn't going to a
  terminal. Progress shows in `scenes/` as each scene is written.
