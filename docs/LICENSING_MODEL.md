# Licensing model

ostraka, Shikari and Rowanholt share one licensing model (Ben, 11 November 2026). The first part of
this file is that shared specification, kept identical in each product's `docs/LICENSING_MODEL.md`;
the second is Rowanholt's own split. ostraka is the reference implementation. The canonical copy of
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
| **Free** | Individuals and small teams | The product's own free number | The whole core product, unbranded |
| **Pro** | Organisations using it for themselves | As the licence states, or unlimited | The product's Pro features |
| **Services** | MSSPs and consultancies working for clients | As the licence states, or unlimited | Pro's features, the product's Services features, and the `managed-service` right |

What each edition unlocks is decided per product (below, for ostraka).

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
number; feature ids and what each edition unlocks; how "an admin" is spotted for the seat rule.

## Rowanholt's split

Decided by Ben, 11 November 2026. Ben also confirmed that nobody else contributed code to the
original Elrond and Gandalf repositories, so Rowanholt moves from MIT to ELv2 from the next release.

| | Free | Pro | Services |
|---|---|---|---|
| Local mode (one analyst, no sign-in) | Everything, no licence | Everything | Everything |
| Accounts that can sign in to a team server | 4 (`FREE_SEATS`) | The licence's `seats` | The licence's `seats` |
| Features | The whole product, single sign-on included | The same | The same |
| `managed-service` | — | — | Yes: a right in COMMERCIAL-LICENSE.md section 3, not a switch |

No feature is gated: the editions differ in seats only. Single sign-on stays free because gating it
would sign people out, which the shared model never does.

### How it's built

- **Modes.** The licence and seats apply only in server mode (`rowanholt_server_mode`). Local mode
  needs no licence, shows no Licence page or terms, and behaves exactly as before.
- **Mechanism.** `src/web/backend/licence.py`: the `rowanholt-licence-1` line, `PUBLIC_KEYS`
  (Rowanholt's own key), standing (pending, active, grace, lapsed), `EDITION_FEATURES` and `has()`.
- **Storage.** Rowanholt keeps its accounts in a JSON file, not the database, so the installed
  licence sits beside it: `licence.json` next to `USERS_FILE` (`/app/data/licence.json`, on the host
  `src/web/backend/data/licence.json`), or the path in `ROWANHOLT_LICENCE`. It holds
  `{"licence", "terms_version", "accepted_by", "accepted_by_name", "accepted_at"}`: the licence line
  and the acceptance of the terms together. Read through an mtime cache; gitignored, kept out of the
  image, and in `rowanholt server backup`.
- **Terms.** The server reads `src/web/backend/legal/COMMERCIAL-LICENSE.md` (the Docker build
  context is the backend folder, so it can't see the repository root); a test keeps it identical to
  the root file.
- **Seats** count enabled accounts in users.json (Rowanholt has no invitations), checked only when
  someone is added: an account created through the API (`/api/auth/register` and `/api/auth/users`
  on a server), re-enabled (`PATCH /api/auth/users/{id}`), provisioned on a first single sign-on
  (`auth/oidc.py`), or added or enabled with `rowanholt server users`. A refusal is 402 with the
  reason; nobody already in is ever disabled.
- **Admins.** An account with the `admin` role. The API is `/api/licence` (GET; POST `/check`; GET
  `/terms`; PUT with `accept_terms` and `terms_version`, 422 / 409; DELETE), admin-only and 404 in
  local mode. The Licence page (`/licence`, linked beside Aragorn for admins on a server) checks a
  licence, shows the terms, installs once the acceptance is ticked, and shows "Commercial licence vX
  accepted by NAME on DATE"; during grace every page warns admins.
- **Command line.** `rowanholt server licence show|install FILE --accept-terms "Name <email>"|remove`
  (`scripts/server/server-licence.sh`, running `manage_licence.py` in the backend container).
- **Audit.** Installs and removals go in the `audit_logs` table (`storage.AuditLogModel`, migration
  `d5a2e8f1c693`), with the terms version. `models/database.py`'s AuditLog is the dormant schema's
  (its foreign key points at a users table Rowanholt doesn't use), so it isn't the one written.
- **Tooling and tests.** `scripts/admin/sign_licence.py` and `issue-licence.sh` (key in
  `ROWANHOLT_LICENCE_KEY`, ledger with `LICENCE_LEDGER_DIR`); `tests/unit/test_licence_units.py`,
  `tests/unit/test_licence.py` and `src/web/frontend/src/components/Licence.test.js`.
