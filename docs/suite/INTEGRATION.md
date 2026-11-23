# How the suite connects

This is the contract between Ostraka, Rowanholt and Shikari (Ben, 23 November 2026). It's the same file in all
three repositories (`docs/suite/INTEGRATION.md`): change it here first, then in the code of each, then copy it to
the other two.

Ostraka is the client. It holds one connection to a Rowanholt server and one to a Shikari server: a URL, an API
token, and the secret their webhooks to Ostraka are signed with. Rowanholt and Shikari never call each other.

Three things cross between them:

- **Pairing** sets a connection up in one step.
- **Starting work:** Ostraka starts a Rowanholt job or a Shikari hunt for a record.
- **Webhooks** tell Ostraka when that work finishes.

Nothing here carries an incident's content to a sibling. A request carries the sibling's own identifiers, ATT&CK
technique ids, the hunt's target, evidence paths already on the sibling, and the Ostraka reference (`OST-26-014`,
`HNT-26-003`) that work is done for.

Ostraka's TLP guard still applies: a TLP:RED or TLP:AMBER+STRICT record only exchanges anything with a sibling on
the organisation's own network.

## Pairing

A Rowanholt or Shikari admin makes a **pairing link** in their own product (Settings, or `POST /api/pairing`). An
Ostraka admin pastes it into Ostraka (Settings → Integrations). Ostraka claims it, and the claim creates the token
and the webhook together.

### The link

```
https://rowanholt.example.org/pair#pair_Xb3…   (the sibling's public origin, then the code after #)
```

- The code is `pair_` followed by `secrets.token_urlsafe(32)`.
- It works once, within 10 minutes.
- Only its SHA-256 is stored, as with account links.
- An admin may have any number of codes open.

**Making codes (admin only, audited):**

```
POST   /api/pairing            {"note": "Ostraka on the homelab"}  → 201 {"id", "link", "expires_at"}
GET    /api/pairing            → [{"id", "note", "created_by", "created_at", "expires_at", "claimed_at", "claimed_by_name"}]
DELETE /api/pairing/{id}       → 204 (withdraws an unclaimed code)
```

The link is shown once, when it's made. In a sibling's UI, the admin copies it from the same panel that lists the
open codes.

### Claiming a code

The claim needs no sign-in, because the code is the credential:

```
POST /api/pairing/claim
{"code": "pair_…", "product": "ostraka", "name": "Ostraka", "version": "0.3.0",
 "webhook_url": "https://ostraka.example.org/api/integrations/rowanholt/webhook"}
```

**How the sibling handles a claim:**

1. Claims the code with one conditional update. Only one of two claims at once can succeed.
2. Refuses the claim if:
   - the code doesn't exist, has been claimed or was withdrawn: 404 `{"detail": "This pairing link isn't valid. Ask for a new one."}`
   - the code has expired: 410 `{"detail": "This pairing link has expired. Ask for a new one."}`
   - the admin who made it is deactivated or no longer an admin: 404, with the same message
   - `webhook_url` fails `samarkand.webhooks.url_problem`: 422 with its message
3. Creates an API token with the **`ostraka` scope**:
   - owned by the admin who made the code
   - named `Ostraka (paired)`
   - valid for 365 days
4. Creates a webhook to `webhook_url`:
   - for the events listed below
   - with a new secret
   - described as `Ostraka (paired)`
   - It's created even on a Free installation, where it won't fire until a licence with `automation` is installed.
5. Audits `pairing_claimed`: who made the code, the IP the claim came from, the token's prefix and the webhook's id. A
   refused claim is audited as `pairing_claim_refused`.

**The response:**

```
200 {"product": "rowanholt", "version": "2.2.0", "token": "rvt_…", "token_expires_at": "…",
     "webhook_id": "…", "webhook_secret": "…", "events": ["job.completed", "job.failed", "finding.confirmed"]}
```

The token and secret are in this response and nowhere else.

**Ostraka's side of the claim:**

- It stores the sibling's URL (the link's origin), the token and the webhook secret, all encrypted.
- It records `integration_paired` in its own security log.
- It runs the connection test.
- Pairing again replaces both.
- In the sibling, removing the token or the webhook undoes the pairing.

## Rowanholt

### The `ostraka` token scope

The scope lets Ostraka read cases and start jobs, and nothing else. It allows:

- `GET` and `HEAD` on `/api/health`, `/api/auth/me`, `/api/jobs` and everything under `/api/jobs/{id}` (a case, its
  rows, its findings), `/api/validate/case-id/{case}` and `/api/fs/browse`.
- `POST /api/jobs`.

Everything else gets 403, including admin paths and writing findings or notes. Jobs started with it belong to the
token's owner, the admin who made the pairing code.

### Starting a job

`POST /api/jobs` takes an optional `external_ref`: an Ostraka reference that matches
`^(OST|HNT)-\d{2}(\d{2})?-\d{3,}$`. Anything else gets 422.

- The job stores it.
- `GET /api/jobs/{id}` returns it.
- Every webhook about the job carries it.

Evidence is never uploaded. `source_paths` must already be under Rowanholt's allowed folders, as for any job.

### Webhooks Ostraka subscribes to

| Event | `data` |
|---|---|
| `job.completed` | `{job_id, case_number, status, images, external_ref}` |
| `job.failed` | `{job_id, case_number, status, images, error, external_ref}` |
| `finding.confirmed` | `{job_id, case_number, finding_id, host, technique, external_ref}` |

`external_ref` is `null` for a job that wasn't started from Ostraka.

## Shikari

### The `ostraka` token scope

Shikari's API tokens gain a scope:

- `full` is what every existing token is: anything its owner may do.
- `ostraka` allows:
  - `GET /health`, `GET /api/coverage`, `GET /api/runs` and `GET /api/runs/{id}`, `GET /api/results/{group}` and
    `GET /progress_status`
  - `POST /api/runs`

Everything else gets 403.

### Hunt runs

A **hunt run** is one request to hunt a target. It has a stable id that a later run of the same group doesn't
overwrite. It may also carry an Ostraka reference, and it may run its detections' queries against Shikari's SIEM
connections, keeping only how many results each one found.

```
POST /api/runs
{"kind": "group" | "cve" | "techniques", "target": "APT29" | "CVE-2024-3400" | "T1059.001,T1003.001",
 "external_ref": "HNT-26-003", "execute": true, "window_days": 7}
→ 202 {"id", "status": "queued", "group_name", "status_url"}
```

- `kind` and `target` start generation, as `/generate`, `/generate/cve` and `/hunt/technique` do.
- `execute` (default false) runs each generated query once generation has finished:
  - It uses Shikari's SIEM connections (`samarkand.siem`) for each platform that has one.
  - The search covers the last `window_days` days (1–90, default 7).
  - A platform without a connection is skipped, and the skip is recorded.

`GET /api/runs?external_ref=HNT-26-003` lists runs. `GET /api/runs/{id}` returns one:

```
{"id", "kind", "target", "external_ref", "execute", "window_days",
 "status": "queued" | "generating" | "generated" | "executing" | "executed" | "failed",
 "group_name", "created_at", "completed_at", "executed_at", "error",
 "detections": [{"file", "name", "techniques", "platforms", "queries": [{"platform", "query"}]}],
 "counts": [{"file", "technique", "platform", "query_index", "hits": 12 | null, "error": "" | "…", "skipped": false}],
 "totals": {"queries": 40, "run": 31, "hits": 57, "errors": 2, "skipped": 7}}
```

**Results are counted, never kept.** Shikari doesn't store, log or return any result row from a hunt run, only the
count. This is the same rule as Ostraka's SIEM queries.

### Webhooks Ostraka subscribes to

| Event | `data` |
|---|---|
| `run.completed` | as before, plus `run_id` and `external_ref` when the run came from `/api/runs` (otherwise `null`) |
| `run.failed` | as before, plus `run_id` and `external_ref` |
| `run.executed` | `{run_id, external_ref, group_name, totals}` once a run's queries have been executed |

## Ostraka

**Receiving webhooks.** Ostraka receives Rowanholt's webhooks at `/api/integrations/rowanholt/webhook` and
Shikari's at `/api/integrations/shikari/webhook`. Each must carry a signature that checks out. Like every webhook
Ostraka acts on, they need Ostraka's `automation` feature.

**When a Rowanholt job finishes** (`job.completed`, `job.failed`):

- The record named by `external_ref` gets an activity entry.
- So does any record linked to that job.
- Live viewers are told.

**When a finding is confirmed in Rowanholt** (`finding.confirmed`), it comes into the record as a **lead**. It
never arrives as a confirmed finding: only an analyst in Ostraka confirms.

**When a Shikari run changes** (`run.*`), Ostraka:

- fetches `GET /api/runs/{id}`
- updates the hunt run it holds
- writes an activity entry
- re-checks open detection gaps on `run.completed`, as before

**Starting work from a record:**

- **A Rowanholt job:** the case number, evidence paths on the Rowanholt server, and the analysis switches. The job
  is linked to the record.
- **A Shikari hunt run:** the kind, target, `execute` and window. The hunt shows each run's detections and its
  counts, never result rows.
- Both need the edit right on the record. Both are refused by the TLP guard as other exchanges are.
