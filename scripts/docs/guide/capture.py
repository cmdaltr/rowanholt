"""
Photographs every page the in-app guide covers, and records where each of its sections
sits, for components/Guide.js. Run it against a running stack after changing a page's
layout:

    pip install playwright && python3 -m playwright install chromium
    python3 scripts/docs/guide/capture.py [--url http://localhost:5687] [--api http://localhost:5688]

Pages and their sections come from src/web/frontend/src/guide/content.js; a section is
found by its data-guide attribute. Each photograph is cropped to the part of the page its
sections cover. Writes src/web/frontend/public/guide/<page>.jpg and boxes.json.

Sign in as an admin (--username, with RIVENDELL_PASSWORD in the environment) so Account
and Aragorn are photographed too. The Job page uses the most recent job, so have one.

A page that now shows fewer of its sections than its last photograph did (no jobs on this
install, the lab agent not running) keeps that photograph; --fresh replaces them all. --only
retakes just the named pages (python3 scripts/docs/guide/capture.py --only case intel).
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FRONTEND = REPO / "src" / "web" / "frontend"
CONTENT = FRONTEND / "src" / "guide" / "content.js"
OUT = FRONTEND / "public" / "guide"

# The app scrolls inside its own container, not the document, so a full-page screenshot
# only ever holds one window's worth: the window is made tall enough for every page instead
WIDTH, HEIGHT = 1440, 2400
MARGIN = 24  # around the sections, in pixels
MAX_HEIGHT = 1500  # a photograph taller than this is unreadable in the guide
# Pages whose sections can't be brought closer: Home's four portrait cards put Mordor at about
# 1,650px. The guide scrolls the photograph to the selected section, so these stay readable
PAGE_MAX_HEIGHT = {"home": 2300}


def guide_pages() -> list:
    """(page id, route, [section ids]) from content.js, in order."""
    text = CONTENT.read_text()
    pages = []
    for match in re.finditer(r"\{\s*id: '([\w-]+)',\s*route: '([^']+)',(.*?)\n  \},", text, re.S):
        sections = re.findall(r"id: '([\w.-]+)',\s*title:", match.group(3))
        pages.append((match.group(1), match.group(2), sections))
    if not pages:
        sys.exit(f"No pages found in {CONTENT}")
    return pages


def sign_in(api: str, username: str, password: str) -> tuple:
    """(token, user) from the API's sign-in, as the web app stores them."""
    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    with urllib.request.urlopen(urllib.request.Request(f"{api}/api/auth/login", data=body), timeout=20) as response:
        signed_in = json.load(response)
    return signed_in["access_token"], signed_in["user"]


def latest_job(api: str, token: str, case: str = "") -> str:
    """The most recent job's ID (of that case, when one is named), for the Job page."""
    request = urllib.request.Request(f"{api}/api/jobs?limit={100 if case else 1}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=20) as response:
        jobs = json.load(response).get("jobs", [])
    if case:
        jobs = [job for job in jobs if job.get("case_number") == case]
    return jobs[0]["id"] if jobs else ""


def prepare(page, page_id: str) -> None:
    """Bring out sections that only appear after a choice."""
    if page_id == "elrond":
        page.fill("#caseNumber", "GUIDE-0001")
        page.wait_for_timeout(1500)  # the case number is checked against existing cases
        page.check("input[name=analysisMode][value=local]")
        page.wait_for_timeout(800)
    elif page_id == "case":
        # A table open, and the host list held to the height of a laptop screen: in the tall window
        # it would otherwise run to 80vh and push Findings, Notes and Activity out of the photograph
        table = page.locator("[data-guide='case.hosts'] button:text-is('wbem.json')")
        if table.count():
            table.first.click()
            page.wait_for_timeout(1500)
        page.evaluate("(el => { el.style.maxHeight = '520px'; el.scrollTop = 0; })"
                      "(document.querySelector(\"[data-guide='case.hosts']\"))")


TEAM = [{"username": "admin"}, {"username": "alice", "full_name": "Alice Brandybuck"},
        {"username": "bob", "full_name": "Bob Took"}]


def as_team_server(page, job_id: str, on: bool) -> None:
    """Show the Job page as a team server would, with its Access panel.

    The panel only appears in server mode, so the auth config, the job's sharing and the user
    directory are answered here rather than restarting the backend with invented users.
    """
    routes = {
        "**/api/auth/config": lambda route: route.fulfill(json={**route.fetch().json(), "server_mode": True}),
        f"**/api/jobs/{job_id}/sharing": lambda route: route.fulfill(
            json={"owner": "admin", "shared_with": ["alice"], "can_manage": True}),
        "**/api/auth/directory": lambda route: route.fulfill(json=TEAM),
    }
    for pattern, handler in routes.items():
        page.route(pattern, handler) if on else page.unroute(pattern)


def capture(args: argparse.Namespace) -> None:
    from playwright.sync_api import sync_playwright

    token, user = args.token or os.environ.get("RIVENDELL_TOKEN", ""), None
    if args.username:
        token, user = sign_in(args.api, args.username, os.environ.get("RIVENDELL_PASSWORD", ""))
    job_id = ""
    try:
        job_id = latest_job(args.api, token)
    except OSError as exc:
        print(f"  Couldn't list jobs ({exc}): the Job page is skipped")

    known = [page_id for page_id, _, _ in guide_pages()]
    if args.only and set(args.only) - set(known):
        sys.exit(f"No guide page {', '.join(sorted(set(args.only) - set(known)))}: pick from {', '.join(known)}")
    OUT.mkdir(parents=True, exist_ok=True)
    earlier = {}
    if not args.fresh and (OUT / "boxes.json").exists():
        earlier = json.loads((OUT / "boxes.json").read_text())
    boxes = dict(earlier)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT})
        # No start-up offer over the pages, and the token where the app keeps it
        context.add_init_script(
            "localStorage.setItem('rivendell.offeredAt', String(Date.now()));"
            + (f"localStorage.setItem('access_token', {json.dumps(token)});" if token else "")
            + (f"localStorage.setItem('user', {json.dumps(json.dumps(user))});" if user else ""))
        page = context.new_page()
        for page_id, route, sections in guide_pages():
            if args.only and page_id not in args.only:
                continue
            if ":first" in route:
                if not job_id:
                    print(f"  {page_id}: no jobs yet, skipped")
                    continue
                route = route.replace(":first", job_id)
            if page_id == "job":
                as_team_server(page, job_id, True)
            page.goto(f"{args.url}{route}", wait_until="networkidle")
            page.wait_for_timeout(1500)
            prepare(page, page_id)
            found = page.evaluate("""(ids) => {
                const out = {};
                for (const id of ids) {
                    const el = document.querySelector(`[data-guide="${id}"]`);
                    if (!el) continue;
                    const r = el.getBoundingClientRect();
                    if (r.width < 4 || r.height < 4) continue;
                    out[id] = [r.left + scrollX, r.top + scrollY, r.width, r.height];
                }
                return out;
            }""", sections)
            if page_id == "job":
                as_team_server(page, job_id, False)
            if not found or len(found) < len(earlier.get(page_id, {}).get("boxes", {})):
                print(f"  {page_id}: {len(found)} sections on the page now, fewer than before: kept the earlier photograph")
                continue
            top = max(0, min(b[1] for b in found.values()) - MARGIN)
            bottom = max(b[1] + b[3] for b in found.values()) + MARGIN
            bottom = min(bottom, top + PAGE_MAX_HEIGHT.get(page_id, MAX_HEIGHT))
            clip = {"x": 0, "y": top, "width": WIDTH, "height": min(bottom, HEIGHT) - top}
            image = f"{page_id}.jpg"
            page.screenshot(path=str(OUT / image), clip=clip, type="jpeg", quality=82)
            boxes[page_id] = {
                "image": image, "width": WIDTH, "height": round(clip["height"]),
                "boxes": {sid: [round(x), round(y - top), round(w), round(h)]
                          for sid, (x, y, w, h) in found.items() if y - top < clip["height"]},
            }
            missing = sorted(set(sections) - set(boxes[page_id]["boxes"]))
            print(f"  {page_id}: {len(boxes[page_id]['boxes'])} sections" + (f" (not shown: {', '.join(missing)})" if missing else ""))
        browser.close()
    (OUT / "boxes.json").write_text(json.dumps(boxes, indent=1) + "\n")
    print(f"Wrote {len(boxes)} pages to {OUT}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default="http://localhost:5687", help="the web UI")
    parser.add_argument("--api", default="http://localhost:5688", help="the API, for the latest job")
    parser.add_argument("--token", help="an API token (or RIVENDELL_TOKEN)")
    parser.add_argument("--username", help="sign in as this user (password in RIVENDELL_PASSWORD)")
    parser.add_argument("--fresh", action="store_true", help="replace every photograph, even with fewer sections")
    parser.add_argument("--only", nargs="+", metavar="PAGE",
                        help="retake just these pages (ids from guide/content.js: case, intel, home, ...); the rest are kept")
    capture(parser.parse_args())


if __name__ == "__main__":
    main()
