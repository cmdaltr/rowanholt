# Licensing model

ostraka, Shikari and Rowanholt share one licensing model (Ben, 11 November 2026). The first part of
this file is that shared specification, kept identical in each product's `docs/LICENSING_MODEL.md`;
the second is Rowanholt's own split. The reference implementation of the licence line is
`samarkand.licence`, in the samarkand package all three products depend on. The canonical copy of
the shared part, the issued licences and the prompts for applying it are in the private
`cmdaltr/licensing` repo.

## Shared across ostraka, Shikari and Rowanholt

### Code licence and notices

- **Elastic License 2.0** for all three (`LICENSE`: the ELv2 text, after a line naming the licensor,
  Ben Smith (cmdaltr)). Free to use, copy and change; no providing it to others as a hosted or
  managed service; no getting around the licence key. Not open core: the key's protection is in the
  code licence itself, not goodwill.
- **`COMMERCIAL-LICENSE.md`** adds the Pro and Services terms, governed by the law of England and
  Wales, marked for legal review. Services is where ELv2's managed-service restriction is lifted for
  work done for the licensee's own clients.
- Copyright **cmdaltr**; a ™ notice for each product's name and logo; outside contributions need a
  contributor licence agreement.
- Releases already published under another licence (Rowanholt's MIT, Shikari's AGPL) keep it; ELv2
  applies from the first release that ships it.

### Editions

| Edition | For | Seats | Always includes |
|---|---|---|---|
| **Free** | Individuals and small teams | The product's own free number | The whole core product: reports in the product's own style, no automation |
| **Pro** | Organisations using it for themselves | As the licence states, or unlimited | Free, plus `report-branding` and `automation` |
| **Services** | MSSPs and consultancies working for clients | As the licence states, or unlimited | Pro, plus `brand-library` and the `managed-service` right |

The features are the same in every product (Ben, 11 November 2026); only the free seat number
differs:

| Feature | Edition | What it is |
|---|---|---|
| `report-branding` | Pro | One brand (colours and logos) for the installation's reports, in place of the product's own style |
| `brand-library` | Services | A brand per client, chosen for each piece of work the report comes from |
| `automation` | Pro | Signed webhooks: the product calls the customer's systems when something happens. Checked when a webhook is sent, so one configured on Free is kept but doesn't fire |
| `managed-service` | Services | The right in `COMMERCIAL-LICENSE.md` section 3 to run the product for clients. Not a switch |

Webhooks work the same everywhere, sent by `samarkand.webhooks` (the reference for them): an
admin registers a URL and the events it wants; each delivery is a POST of
`{"event", "sent_at", "data"}` (`sent_at` ISO 8601 in UTC) with `X-<Product>-Event` and, when the webhook has a secret,
`X-<Product>-Signature: sha256=<hex HMAC-SHA256 of the raw body>`; three tries with backoff; the last
20 deliveries kept per webhook for the admin page. Webhook bodies pass the same masking as the
product's other outward messages.

### The licence

One line: `<product>-licence-1.<payload>.<signature>`.

- `payload` is base64url (no padding) of canonical JSON: sorted keys, compact separators.
- `signature` is Ed25519, base64url, over the ASCII bytes of `<product>-licence-1.<payload>`, so
  the product and format version are signed too.
- Payload fields: `licence_id`, `product`, `licensee`, `edition` (`pro` or `services`), `seats` (a
  number, or `null` for unlimited), `issued`, `expires` (a date, or `null` for perpetual), and
  optionally `email`, `features` (extra feature ids, or `*` for all) and `not_before`. Dates are
  `YYYY-MM-DD`.
- A licence for another product, another format version, or with a bad signature is refused with a
  reason an admin can act on.

### Terms and accepting them

- `COMMERCIAL-LICENSE.md` states its version on the line after its title (`**Version 1.0**, date`).
  The licensor is "Ben Smith, trading as cmdaltr (cmdaltr.com)" until there's a company. An order
  wins over the terms, the terms over ELv2.
- The product ships a copy of the terms where its server can read them (ostraka:
  `backend/ostraka/legal/`), and a test keeps the copy identical to the root file.
- **Installing a licence needs an admin to accept the current terms on the licensee's behalf.** The
  admin page checks the licence first (showing the licensee, edition, seats and dates), shows the
  terms, and installs only once "I accept the <product> Commercial Licence, version x.y, on behalf
  of <licensee>, and I have authority to do so" is ticked. The API refuses an install without
  `accept_terms` (422) or with a `terms_version` that isn't current (409).
- The installed licence keeps the terms version, who accepted (the account, and "Name <email>" as
  written) and when; the admin page shows it, and the install's audit entry carries the version.
  The CLI needs `--accept-terms "Name <email>"`.
- Every version a customer has accepted is filed in the licensing repo under
  `terms/<product>/COMMERCIAL-LICENSE-v<version>.md`. A new version applies from the next key a
  customer installs.

### Keys and tooling

- **One signing key per product**, so a leak affects one product only. Only the public half ships,
  as hex in `PUBLIC_KEYS` (a tuple, so a key can be rotated by adding the new one). Licences are
  checked offline; nothing calls home.
- `scripts/admin/sign_licence.py` with `keygen PATH`, `public` and `sign`, reading the private key
  from `<PRODUCT>_LICENCE_KEY` (a file path or the key itself; PEM, or the seed as hex).
- `scripts/admin/issue-licence.sh "Licensee" <pro|services> <seats|unlimited> [email|-]
  [YYYY-MM-DD|perpetual] [features]`.
- **The ledger:** with `LICENCE_LEDGER_DIR` set to the licensing repo, `sign` writes the licence to
  `issued/<product>/<licence_id>.licence` and appends a row to `ledger.csv` (licence_id, product,
  licensee, email, edition, seats, features, issued, not_before, expires, terms_version, order,
  file, notes). Without it, the licence goes to a git-ignored `licences/`. The signed order form for
  a sale goes in the licensing repo's `orders/`.
- `.gitignore` covers `licences/`, `*licence-signing-key*`, `*licence-signing.key`, `*.lic.key` and
  `*.licence`. Never commit a private key or an issued licence.

### Behaviour

- **Entitlements:** the edition's own features, plus any the licence lists; `*` grants every
  feature. Code asks `has(feature)`, never the edition name.
- **Check at the point of use**, never at configuration time, so editing stored settings can't get
  around it.
- **Seats** count accounts that can sign in plus open invitations that would add one, and are
  checked only when someone is added (invited, re-enabled, given access). Never retroactively.
- **Validity:** from the start of `not_before` (if any) to the end of `expires`. Before
  `not_before`: Free, shown as pending. After `expires`: the edition carries on for **30 days'
  grace** with a warning to admins, then the installation is Free again.
- **Nobody is ever locked out.** A licence ending, being removed or failing to verify never
  deactivates anyone or deletes anything; it only stops new additions past the free limit and turns
  paid features off.
- **Admin surface:** an admin-only page to see the edition, places taken and who accepted the terms,
  and to check, accept and install or remove a licence; `<product> licence show|install FILE
  --accept-terms NAME|remove`. Installs and removals are recorded where the
  product keeps its security log.
- **Tests** sign with a throwaway key (patching `PUBLIC_KEYS`) and cover: valid, tampered, another
  key, another product, not-yet-valid, grace then lapse, perpetual, wildcard, edition features, the
  seat limit, install refused without acceptance or with a stale terms version, acceptance recorded,
  and the shipped terms identical to `COMMERCIAL-LICENSE.md`.

### Individual to each product

Where the licence is stored (ostraka: its database; a product without one: a file); the free seat
number; what a client's brand attaches to (ostraka: an incident); which events send webhooks; how
"an admin" is spotted for the seat rule.

## Rowanholt's split

Decided by Ben, 11 November 2026: the features are the shared table's, the same in every product.
Ben also confirmed that nobody else contributed code to the original Elrond and Gandalf repositories,
so Rowanholt moves from MIT to ELv2 from the next release.

| | Free | Pro | Services |
|---|---|---|---|
| Local mode (one analyst, no sign-in) | The Free edition: needs no licence | With a Pro licence installed | With a Services licence installed |
| Accounts that can sign in to a team server | 4 (`FREE_SEATS`) | The licence's `seats` | The licence's `seats` |
| The product | All of it: acquisition, analysis, the case browser, single sign-on, Aulë | The same | The same |
| The Word case report | Rowanholt's own style | The installation's brand (`report-branding`) | The case's brand, else the installation's (`brand-library`) |
| The Markdown report and the Navigator layer | Rowanholt's own | The same | The same |
| Webhooks (`automation`) | Kept, not sent | Sent | Sent |
| `managed-service` | — | — | Yes: a right in COMMERCIAL-LICENSE.md section 3, not a switch |

Single sign-on stays free because gating it would sign people out, which the shared model never does.

### How it's built

- **Modes.** Local mode is the Free edition: it runs with no licence and behaves as before, but its
  analyst (the admin there, `access.LOCAL_USER`) can install a Pro or Services licence for branding
  and webhooks, from the Licence page or `rowanholt server licence`, accepting the terms as on a
  server. Seats apply only in server mode (`rowanholt_server_mode`).
- **Mechanism.** `src/web/backend/licence.py` binds Rowanholt's own (its id, `PUBLIC_KEYS`, four
  free seats) to `samarkand.licence`, which reads the `rowanholt-licence-1` line and gives the
  standing (pending, active, grace, lapsed), `EDITION_FEATURES` (`report-branding`, `brand-library`,
  `automation`, `managed-service`) and `has()`. Where the licence is kept and the seat rule stay here.
- **Storage.** Rowanholt keeps its accounts in a JSON file, not the database, so everything the
  licence governs sits beside it in `/app/data` (on the host `src/web/backend/data/`): `licence.json`
  (the licence line and the acceptance of the terms: `{"licence", "terms_version", "accepted_by",
  "accepted_by_name", "accepted_at"}`, or `ROWANHOLT_LICENCE`), `brands.json` with each brand's
  cleaned logos in `brands/<id>/` (or `ROWANHOLT_BRANDS`), and `webhooks.json` with their secrets (or
  `ROWANHOLT_WEBHOOKS`). The backend and the worker both mount it. All gitignored, kept out of the
  image, written mode 600, and in `rowanholt server backup`.
- **Terms.** The server reads `src/web/backend/legal/COMMERCIAL-LICENSE.md` (the Docker build
  context is the backend folder, so it can't see the repository root); a test keeps it identical to
  the root file.
- **Seats** count enabled accounts in users.json (Rowanholt has no invitations), checked only when
  someone is added: an account created through the API (`/api/auth/register` and `/api/auth/users`
  on a server), re-enabled (`PATCH /api/auth/users/{id}`), provisioned on a first single sign-on
  (`auth/oidc.py`), or added or enabled with `rowanholt server users`. A refusal is 402 with the
  reason; nobody already in is ever disabled.
- **Report branding.** A brand is a name, a primary and optional secondary colour, "Prepared for",
  and up to three logos (cover, header, client), managed by admins on the Branding page
  (`/api/brands`, `branding_routes.py`). Uploads are cleaned as ostraka's: PNG or JPEG only, refused
  past 4096 × 4096 pixels before decoding, redrawn as a fresh PNG (`branding.clean_logo`, Pillow).
  The palette is derived as ostraka's: headings darkened to 4.5:1 on the page, the rest from the
  primary's hue (`src/analysis/rowanholt/report/theme.py`, stdlib, as the report package must be).
  Which brand a report gets is decided when the Word report is built (`case_routes.full_report`,
  `branding.brand_for`): the case's brand under `has("brand-library")`, else the installation's under
  `has("report-branding")`, else Rowanholt's own. Saving a brand or a choice is open on every edition
  and kept when the licence changes; only what's rendered changes. Markdown and the Navigator layer
  aren't branded.
- **A client's brand** attaches to a case number (every job of the case; a case is a client
  engagement), chosen by an admin from the case browser (`/api/jobs/{job_id}/case/brand`).
- **Webhooks** (`webhooks.py`, `webhook_routes.py`), sent by `samarkand.webhooks` with the prefix
  `X-Rowanholt`: `X-Rowanholt-Event`, `X-Rowanholt-Signature: sha256=<HMAC>`, three tries with
  backoff, redirects not followed, the last 20 deliveries kept. URLs are https, or http for
  localhost, loopback and RFC 1918 addresses (a homelab SOAR); never a link-local address (cloud
  metadata) whatever the scheme, nor credentials in the URL, and one that breaks these rules (say,
  edited by hand in `webhooks.json`) isn't sent. Events:
  `job.completed` and `job.failed` (sent from `JobStorage.save_job` when a job's status becomes one
  of them, whichever path ended it), `finding.confirmed` and `report.ready` (the case routes). Bodies
  carry ids, the case number, a host and counts, never artefact contents; a failed job's error has its
  file paths removed. Rowanholt has no other outward messages to share a masking step with, so that
  is the masking. Sending is checked with `has("automation")` when an event is sent: registering,
  listing and editing stay open, a Free installation keeps its webhooks, and the Webhooks page says
  they aren't sending and why. The test button is a delivery, so it's refused (402) when they aren't.
- **Admins.** An account with the `admin` role, or the analyst in local mode. The API is
  `/api/licence` (GET; POST `/check`; GET `/terms`; PUT with `accept_terms` and `terms_version`,
  422 / 409; DELETE), `/api/brands` and `/api/webhooks`, all admin-only. The Licence, Branding and
  Webhooks pages are linked for admins beside Aragorn; the Licence page shows "Commercial licence vX
  accepted by NAME on DATE"; during grace every page warns admins.
- **Command line.** `rowanholt server licence show|install FILE --accept-terms "Name <email>"|remove`
  (`scripts/server/server-licence.sh`, running `manage_licence.py` in the backend container), in
  either mode.
- **Audit.** Licence installs and removals, brand changes and webhook changes go in the `audit_logs`
  table (`storage.AuditLogModel`, migration `d5a2e8f1c693`), the licence's with the terms version.
  `models/database.py`'s AuditLog is the dormant schema's (its foreign key points at a users table
  Rowanholt doesn't use), so it isn't the one written.
- **Tooling and tests.** `scripts/admin/sign_licence.py` (it signs `samarkand.licence.head_of`'s
  text and joins the line with `line_of`; samarkand itself never signs) and `issue-licence.sh` (key in
  `ROWANHOLT_LICENCE_KEY`, ledger with `LICENCE_LEDGER_DIR`); `tests/unit/test_licence_units.py`,
  `tests/unit/test_licence.py`, `tests/unit/test_branding.py`, `tests/unit/test_webhooks.py`, and the
  frontend's `Licence.test.js`, `Webhooks.test.js` and `Branding.test.js`.
