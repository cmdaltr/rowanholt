# Rowanholt Web API Reference

**Version:** 2.1.0
**Base URL:** `http://127.0.0.1:5688/api` on a local stack; `https://<server>/api` on a team server, through its proxy
**Protocol:** REST, and two WebSockets (the case browser's live feed and the lab's VM consoles)
**Authentication:** none on a local stack; on a team server a session cookie, a sign-in's JWT, or an API token (see [Authentication Status](#authentication-status))

Paths below are given in full (`/api/...`), except under Authentication, where they're relative to the base URL (`/auth/login` is `/api/auth/login`). FastAPI's own schema is at `/openapi.json` and `/docs` on a running backend.

---

## Table of Contents

1. [Authentication Status](#authentication-status)
2. [Authentication](#authentication)
3. [API Tokens](#api-tokens)
4. [Users](#users)
5. [Job Management](#job-management)
6. [File System](#file-system)
7. [Administration (Aragorn)](#administration-aragorn)
8. [Docker Administration (Anduril)](#docker-administration-anduril)
9. [Mordor: Recorded Attack Telemetry](#mordor-recorded-attack-telemetry) (and datasets)
10. [Threat Intelligence](#threat-intelligence)
11. [Case Browser and Collaboration](#case-browser-and-collaboration)
12. [Smith (AI Analyst)](#smith-ai-analyst)
13. [Lab](#lab)
14. [Health Check](#health-check) (and Busy)
15. [Request/Response Formats](#requestresponse-formats)
16. [Error Handling](#error-handling)
17. [Code Examples](#code-examples)

---

## Authentication Status

What a caller may do depends on the mode the backend runs in. Every request goes through one middleware (`src/web/backend/auth/access.py`), which works out who is calling and, in server mode, turns away what they may not do, so a route added later is covered without remembering to protect it.

**Local mode** (the default: a stack on an analyst's own machine). Nothing needs a sign-in. A request without a token acts as the local analyst (`local`, role `admin`) and sees every job and case. The stack publishes the API on `127.0.0.1:5688` only, as it does every other port (Postgres, Redis, the web app, Splunk, Elastic, Kibana, the Navigator), so the open API is the machine's own. Signing in still works (login, guest and register are open), and a signed-in caller is that account: a non-admin one gets `403` from the admin-only routes (licence, brands, webhooks, users, symbol tables, sample data), which an anonymous request passes. A guest's token names no account, so a guest acts as the local analyst. Two areas want a signed-in admin even locally, since they drive the host: the lab (`/api/lab`, the Mordor lab and the Mordor telemetry Update) and Andúril (`/api/anduril`). Both are off (`503`) while the backend uses the default `SECRET_KEY`.

**Server mode** (`ROWANHOLT_SERVER_MODE`, set by `deploy/server/docker-compose.server.yml`; see [SERVER.md](SERVER.md)). Every `/api` route needs a signed-in user (`401 Sign in required`) except `/api/health`, `/api/busy`, `/api/auth/config`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/oidc/login`, `/api/auth/oidc/callback` and `/api/auth/verify`. There are no guests and no open sign-up. On top of that:

| Who | What |
|---|---|
| Admins only (`403`) | Everything under `/api/lab`, `/api/anduril` (and its old name `/api/aragorn`), `/api/auth/users`, `/api/symbols`, `/api/samples`, `/api/licence`, `/api/brands` and `/api/webhooks`, and a case's brand; anything but GET under `/api/mordor` and `/api/threat-intel`, apart from `POST /api/threat-intel/lookup` |
| Whoever can see the job (`404` otherwise, so job IDs can't be probed) | Everything under `/api/jobs/{job_id}`: its owner, the users it's shared with, and admins. A job from before server mode has no owner, so only admins see it until one shares it |
| Whoever can see the case (`404`) | `/api/ai/cases/{case_id}/…`: a case number behind a job they can see. A case folder in Smith's data directory with no job behind it is for admins |
| The job's owner or an admin (`403`) | Cancel, pause, resume, delete, archive, restart with fresh output, add a note (`PATCH`), change its sharing, confirm or give up a failed removal; the bulk actions check each job the same way |

A job's `can_manage` says which side of the last row the caller is on ([List Jobs](#list-jobs)).

**Credentials.** The backend reads the `Authorization: Bearer` header first, then the `session_token` cookie, so a stale header doesn't hide a good cookie.

- A sign-in ([Login](#login), or single sign-on) returns a JWT and sets it as the `session_token` cookie: `httpOnly`, `SameSite=Lax`, `Secure` in server mode, valid for 24 hours (`access_token_expire_minutes`). Each request checks the account in the user store, so disabling someone stops their next request.
- An API token (`rvt_…`, [API Tokens](#api-tokens)) goes in the bearer header. Its scope limits it: `full` is whatever its user may do, `smith-mcp` only what Smith's MCP server needs. Tokens are made on a team server only.

The lab and Andúril check a sign-in's JWT against the user store themselves, so an API token doesn't open them (`401`), even an admin's `full` one.

---

## Authentication

The routes under `/api/auth` (`src/web/backend/auth/routes_simple.py`). Accounts are kept in a JSON file (`USERS_FILE`, default `/app/data/users.json`; on a team server `src/web/backend/data/users.json` through the backend's bind mount), not the database. The first sign-in on an empty store creates `admin`: locally with the built-in password, on a server with `ROWANHOLT_ADMIN_PASSWORD` (`503` without it).

There is no MFA, no password reset by email and no `/auth/admin/*` route in this build: those endpoints, which this reference used to list, are in `auth/routes.py`, which the backend doesn't mount. Admins manage accounts through [Users](#users) or `rowanholt server users`.

#### Cross-site requests: the `X-Rowanholt` header

A state-changing request (anything but GET, HEAD and OPTIONS) under `/api` that the session cookie signs in must send `X-Rowanholt: 1`, or it's refused with `403`, in either mode (logout included). The web app's API client sends it on every request. The cookie is `SameSite=Lax`, which stops other sites but not the same site, and `ts.net` is a public suffix: every app on one tailnet (`*.<tailnet>.ts.net`) is the same site, and its pages' requests carry Rowanholt's cookie. A page on another origin can't add a custom header without the API's CORS allowing it, so the header proves the request came from Rowanholt's own pages. A request with a bearer token doesn't need it (a browser never sends one by itself): API tokens, the MCP server and scripts are unaffected, and so are requests with no credentials at all (a local stack's scripts).

### Sign-in Options

**Endpoint:** `GET /auth/config`

**Description:** How this Rowanholt signs people in, for the login page. No sign-in needed.

**Response:** `200 OK`
```json
{
  "server_mode": true,
  "local_login": true,
  "guest": false,
  "register": false,
  "sso": {"enabled": true, "name": "Entra ID"}
}
```

---

### Register New User

**Endpoint:** `POST /auth/register`

**Description:** Create an account. Locally anyone may, and the account is always a `user`. On a team server only an admin may (as with `POST /api/auth/users`), and `role` is honoured.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "a long passphrase",
  "full_name": "John Doe",
  "role": "user"
}
```

`full_name` is optional; `role` is `user` or `admin`, read in server mode only.

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "username",
  "full_name": "John Doe",
  "role": "user"
}
```

**Validation:**
- Username: 2–64 letters, digits, `.`, `_`, `@` or `-`
- Password: at least 12 characters on a team server; no minimum locally
- Email: not checked beyond being unique

**Errors:**
- `400 Bad Request`: email or username taken, or an invalid username or role
- `401`/`403`: on a team server, not signed in, or not an admin
- `402 Payment Required`: on a team server, the licence has no free place
- `503 Service Unavailable`: no accounts yet and no `ROWANHOLT_ADMIN_PASSWORD`

---

### Login

**Endpoint:** `POST /auth/login`

**Description:** Sign in with a password: returns a JWT and sets it as the session cookie.

**Request Body:** OAuth2 form data (`application/x-www-form-urlencoded`), not JSON. `username` accepts the username or the email address.

```bash
curl -X POST http://127.0.0.1:5688/api/auth/login \
  -d "username=user@example.com" --data-urlencode "password=<password>"
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "full_name": "John Doe",
    "role": "user",
    "is_active": true,
    "auth": "password",
    "last_login": "2026-11-12T10:00:00"
  }
}
```

`auth` is `password` or `sso`. There is no MFA step.

**Errors:**
- `401 Unauthorized`: wrong username or password
- `403 Forbidden`: account disabled, or single sign-on is the only way in and the account isn't an admin's (admins keep a password, to break glass)
- `429 Too Many Requests`: locked out. Five failures from one address lock that username from that address for 15 minutes; fifty across all addresses lock it everywhere (`max_login_attempts`, `lockout_duration_minutes`; [SERVER.md](SERVER.md#how-sign-in-lockouts-work))
- `503 Service Unavailable`: no accounts yet and no `ROWANHOLT_ADMIN_PASSWORD`

---

### Login as Guest

**Endpoint:** `POST /auth/guest`

**Description:** A one-hour guest token and cookie, locally only (`403` on a team server). The token names no account, so requests made with it act as the local analyst.

**Request Body:** None

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "guest",
    "email": "guest@rowanholt.app",
    "username": "guest",
    "full_name": "Guest User",
    "role": "guest"
  }
}
```

---

### Logout

**Endpoint:** `POST /auth/logout`

**Description:** Clear the session cookie. The JWT itself isn't revoked: it works until it expires. No sign-in needed (but a request carrying the cookie needs `X-Rowanholt: 1`, as above).

**Response:** `200 OK`
```json
{"message": "Logged out successfully"}
```

---

### Get Current User

**Endpoint:** `GET /auth/me`

**Description:** The caller, with the same fields as `user` in [Login](#login). Locally without a sign-in, the local analyst (`"username": "local"`, `"role": "admin"`, `"auth": "local"`). For an API token there's also `token`: its `id`, `name` and `scope`.

**Errors:**
- `401 Unauthorized`: on a team server, not signed in

---

### Session from the Cookie

**Endpoint:** `POST /auth/session`

**Description:** A fresh JWT for whoever the session cookie signs in, set again as the cookie, with the [Login](#login) response. The web app uses it after single sign-on, which leaves only the cookie. Refused to API tokens (`403`).

---

### Change Password

**Endpoint:** `POST /auth/change-password`

**Request Body:** `{"current_password": "...", "new_password": "..."}`

**Response:** `200 OK`, `{"message": "Password changed"}`

**Errors:**
- `400 Bad Request`: the account signs in with single sign-on, the current password is wrong, or (on a team server) the new one is under 12 characters
- `403 Forbidden`: made with an API token

---

### Forgot Password

> **Stub.** Always returns the message; nothing is sent.

**Endpoint:** `POST /auth/forgot-password?email=user@example.com`

`email` is a query parameter, not a JSON body.

**Response:** `200 OK`
```json
{"message": "If the email exists, a password reset link has been sent"}
```

---

### Proxy Check

**Endpoint:** `GET /auth/verify`

**Description:** The team server's proxy (Caddy's `forward_auth`) asks this before passing a request to Kibana, Splunk or the ATT&CK Navigator. `200` with `{"username"}` and an `X-Rowanholt-User` header for a signed-in user, `401` otherwise. No sign-in needed to ask.

**Query Parameters:**
- `login_redirect` (bool): answer a caller who isn't signed in with a `302` to the sign-in page instead of `401`
- `service`: `navigator` also checks the case behind a layer, from the URI in `X-Forwarded-Uri`; someone who can't see that case gets `403`

---

### Single Sign-On

**Endpoints:** `GET /auth/oidc/login`, `GET /auth/oidc/callback`

**Description:** OpenID Connect, when configured ([SERVER.md](SERVER.md#single-sign-on)). `login` redirects to the identity provider (`404` when single sign-on isn't set up); the provider returns to `callback`, which sets the session cookie and redirects to `/login/sso`. A failure redirects to `/login?sso_error=<reason>`.

---

## API Tokens

Long-lived, revocable tokens for scripts and Smith's MCP server, in place of a sign-in's 24-hour JWT (`auth/tokens.py`, table `api_tokens`). Team server only: locally these return `400`, since the API there needs none. A token is managed from a sign-in, never with a token: `/api/auth/tokens`, `/api/auth/session`, `/api/auth/users` and `/api/auth/change-password` refuse one (`403`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/auth/tokens?all=` | The caller's tokens, `{"tokens": [...]}`; with `all=true`, everyone's (admins; `403` otherwise) |
| `POST` | `/api/auth/tokens` | `{"name": "...", "scope": "full", "days": 90}`: a new token for the caller. The response is the record plus `token`, shown this once (only its SHA-256 is kept). `name` 1–100 characters, `scope` `full` or `smith-mcp`, `days` 1–365 (`400` otherwise) |
| `DELETE` | `/api/auth/tokens/{token_id}` | Revoke one of the caller's tokens (an admin, anyone's). Returns the record; `404` if there's no such token |

A record has `id`, `user_id`, `username`, `name`, `prefix` (the first characters, to recognise it), `scope`, `created_at`, `expires_at`, `last_used_at` (written at most once a minute) and `revoked_at`. A token stops working when it's revoked, when it expires, or when its user is disabled or removed.

**The `smith-mcp` scope** allows reads (GET, HEAD, OPTIONS), flagging leads and adding notes (`POST /api/jobs/{job_id}/case/findings` and `/notes`), and Smith's questions, which are POSTs that only read (`/api/ai/offline/answer`, `/api/ai/cases/{case_id}/query`, `/summary`, `/suggestions`); anything else is `403`, and so are the admin areas, even for an admin's token. Everything it writes is recorded as "Smith (for <user>)". The scope's names from before the analyst was renamed, `aule-mcp` and `eru-mcp`, are still accepted when a token is made (stored as `smith-mcp`) and read as `smith-mcp` wherever a scope is checked.

A caller that sends `X-Rowanholt-Agent: smith-mcp` (or `aule-mcp`, `eru-mcp`, or the old header `X-Rivendell-Agent`) is treated as Smith on the case routes without such a token: its findings are leads only, and it can't change or remove findings or assign hosts (`403`). Online threat intelligence lookups are refused to both.

---

## Users

| Method | Endpoint | Who | Description |
|---|---|---|---|
| `GET` | `/api/auth/directory` | Anyone signed in | Active users' `username` and `full_name`, for sharing a job |
| `GET` | `/api/auth/users` | Admins | Every account, with the fields in [Login](#login) |
| `POST` | `/api/auth/users` | Admins | `{"username", "email", "password", "full_name", "role"}`, validated as [Register](#register-new-user). `400` when the username or email is taken, `402` when the licence has no free place |
| `PATCH` | `/api/auth/users/{user_id}` | Admins | Any of `role` (`admin` or `user`), `is_active`, `password`, `full_name`. The last active admin can't be demoted or disabled (`400`); re-enabling an account needs a free place (`402`); `404` for no such user |

The same can be done from the host with `rowanholt server users` ([SERVER.md](SERVER.md#users)), which works when nobody can sign in.

---

## Job Management

### Create Job

**Endpoint:** `POST /api/jobs`

**Description:** Create and queue a new forensic analysis job.

**Authentication:** In server mode, anyone signed in; the caller becomes the job's owner.

**Request Body:**
```json
{
  "case_number": "CASE-2025-001",
  "source_paths": [
    "/evidence/disk.E01",
    "/evidence/memory.dmp"
  ],
  "destination_path": "/output/CASE-2025-001",
  "options": {
    "analysis": true,
    "memory": true,
    "timeline": true,
    "extract_iocs": true,
    "force_overwrite": false
  }
}
```

`destination_path` is optional. `backup_password` (optional, Mobile jobs only) is an encrypted phone backup's password: it goes to the worker through Redis, expiring, and is never stored with the job.

`options` maps onto Elrond's command line (`build_elrond_command` in `tasks_docker.py`). All are optional booleans unless shown otherwise:

| Group | Fields |
|---|---|
| Source | `local` (default `true`; collect from images), `gandalf` (pre-collected Gandalf archives), `network` (PCAPs, Zeek logs, NetFlow exports), `mobile` (phone backups and extractions) |
| Modes | `brisk`, `mordor` |
| Phases | `analysis`, `memory`, `memory_timeline`, `timeline` |
| Collection | `vss`, `userprofiles`, `collectFiles` + `collectFiles_filter`, `collect_files_all`, `collect_files_archive`, `collect_files_bin`, `collect_files_docs`, `collect_files_hidden`, `collect_files_lnk`, `collect_files_mail`, `collect_files_scripts`, `collect_files_unalloc` (carving), `collect_files_virtual`, `collect_files_web` |
| Detection | `extract_iocs` + `iocs_file` and `ioc_system_volume` (a macOS image's sealed system volume too: `--iocsSystemVolume` in [CLI.md](CLI.md)), `keywords` + `keywords_file`, `yara` + `yara_dir`, `misplaced_binaries`, `masquerading`, `clamav` |
| Hashing | `hash_collected`, `hash_all`, `nsrl` |
| Output | `splunk`, `elastic`, `opensearch`, `timesketch`, `navigator`, `threat_intel` (match the stored [threat intelligence](#threat-intelligence)), `archive`, `delete`, `save_template` |
| Job control | `force_overwrite` (replace an existing output folder: see below), `debug` (verbose job log) |

`replaces_output_of` and `output_marker` are the API's own: whatever a request sends is replaced.

Paths are passed to the worker unchanged, except `/host/tmp/rowanholt/…`, which becomes `/tmp/elrond/output/…`. Host paths under `/Volumes` work because both containers mount `/Volumes` at the same path.

**Paths.** Every source and the destination must be inside one of the allowed folders (this OS's defaults and `ROWANHOLT_EVIDENCE_PATHS`): a folder boundary, not a prefix (`/tmp/rowanholtX` isn't inside `/tmp/rowanholt`), with no `..` and no symbolic link below the allowed folder (`403` otherwise). A source may be a whole allowed folder, and must exist (`400`); the destination may be neither an allowed folder nor above one. Without `destination_path`, the output goes beside the first source as before (`<folder>/<case>` for a folder, `<parent>/<case>` for a file or a Gandalf acquisitions folder), and that's checked the same way; with no sources either, it's `OUTPUT_DIR/<case>`. The destination is refused (`409`) when it would hold evidence (any job's source), is where Elrond mounts images (`/mnt/elrond_mount*` and the like), or is at, in or around the output of a job that's still going.

**An output folder that's already there.** Without `force_overwrite`: `400` with `[Errno 17] File exists: '<path>'` (the web app then offers to overwrite). With it, the folder is replaced only if it's Rowanholt's output: the `.rowanholt-output` marker the worker writes when it creates a job's output folder, or, for output from before the marker (12 November 2026), the recorded output of an older job with its `rowanholt_job.log` in it. That job must be one the caller owns (or the caller an admin; only an admin for a job since deleted) and must not still be going. Anything else is never removed: `409` (not Rowanholt's, or still going) or `403` (someone else's), and the request is recorded in the audit log (`output.removal_requested`). The removal itself happens in the worker, which checks it all again first: see [Removing a job's old output](#removing-a-jobs-old-output).

**Response:** `200 OK`, the job as in [Get Job Details](#get-job-details) (`"status": "pending"`, `"owner"` the caller, `"can_manage": true`).

**Validation:**
- `case_number`: required; `/` and `\` become `_` and `..` is dropped, then it must be 6–30 characters (`400`)
- `source_paths`: required list; each inside the allowed folders (`403`) and existing (`400`)
- `destination_path`: optional, checked as above
- `backup_password`: only with `options.mobile` (`400`)

**Errors:**
- `400 Bad Request`: as above, or the output folder exists without `force_overwrite`
- `403 Forbidden`: a path outside the allowed folders, or an output folder the caller may not replace
- `409 Conflict`: the destination would hold evidence, is a mount point, or is around a job that's still going; or the folder isn't Rowanholt's output
- `500 Internal Server Error`: anything else, including a task that couldn't be queued (the job is failed with `Not queued: <error>`)

---

### List Jobs

**Endpoint:** `GET /api/jobs`

**Description:** The jobs the caller can see: in server mode their own, the ones shared with them, and every job for an admin; every job in local mode.

**Query Parameters:**
- `status` (optional): one of pending, running, paused, awaiting_confirmation, removing, completed, failed, cancelled, archived
- `limit` (optional): 1–100, default 50
- `offset` (optional): default 0
- `log_limit` (optional): log lines kept per job, the newest (default 10; 0 for all)

**Response:** `200 OK`
```json
{
  "jobs": [
    {
      "id": "uuid",
      "case_number": "CASE-2025-001",
      "status": "completed",
      "progress": 100,
      "created_at": "2025-01-15T12:00:00",
      "completed_at": "2025-01-15T13:00:00",
      "owner": "alice",
      "shared_with": ["bob"],
      "can_manage": true
    }
  ],
  "total": 150
}
```

Each job has every field in [Get Job Details](#get-job-details) (shortened here). `total` counts the caller's jobs with that status.

`owner` and `shared_with` come from the job's sharing (server mode). `can_manage` says whether the caller may do the owner's things to the job: cancel, pause, resume, delete, archive, unarchive, restart with fresh output, add a note, change its sharing, and confirm or give up a failed removal. It's `true` for the owner and for admins, `false` for the people the job is only shared with (who may see it, restart it with `fresh=false`, export it and ask Smith), and always `true` in local mode. It's per caller and never stored. The web app uses it to offer only the actions the server would allow; the server still refuses the rest with `403`. `GET /api/jobs/{job_id}`, `PATCH /api/jobs/{job_id}` and `GET /api/jobs/{job_id}/sharing` return it too.

---

### Get Job Details

**Endpoint:** `GET /api/jobs/{job_id}`

**Description:** Retrieve detailed information about a specific job.

**Authentication:** Whoever can see the job (see [Authentication Status](#authentication-status)).

**Path Parameters:**
- `job_id`: UUID of the job

**Query Parameters:**
- `log_limit` (optional): log lines returned, the newest (default 100; 0 for all). A long job's log runs to tens of thousands of lines

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "case_number": "CASE-2025-001",
  "source_paths": ["/evidence/disk.E01"],
  "destination_path": "/output/CASE-2025-001",
  "options": {},
  "status": "running",
  "progress": 45,
  "log": [
    "[2025-01-15T12:00:00] Job started",
    "[2025-01-15T12:15:00] Processing artefacts..."
  ],
  "result": null,
  "error": null,
  "celery_task_id": "task-uuid",
  "pending_action": null,
  "created_at": "2025-01-15T12:00:00",
  "started_at": "2025-01-15T12:00:01",
  "completed_at": null,
  "archived_at": null,
  "archived_from": null,
  "owner": "alice",
  "shared_with": ["bob"],
  "can_manage": true
}
```

`log` is a list of strings. `options` has every field listed under [Create Job](#create-job). `pending_action` is set only while the job is `awaiting_confirmation` ([Removing a job's old output](#removing-a-jobs-old-output)). `archived_at` and `archived_from` are set only while the job is `archived`: when, and the status [Unarchive](#unarchive-job) restores (both `null` for a job archived before 12 November 2026). `can_manage`: as in [List Jobs](#list-jobs).

**Errors:**
- `404 Not Found`: Job not found or unauthorized access

---

### Add a Note to a Job's Log

**Endpoint:** `PATCH /api/jobs/{job_id}`

**Description:** Add a note to the job's log, recorded as `Note from <username>: …` on one line, and in the audit log as `job.note_added`. Only the job's owner or an admin may; the people it's shared with get `403`. Nothing else can be changed here: `status`, `progress`, `result` and `error` are the worker's, and the job's status changes through its own routes (cancel, pause, resume, restart, archive, unarchive, confirm-removal, cancel-removal), which do what a status change needs. Until 12 November 2026 this route set any of them for anyone who could see the job.

**Request Body:**
```json
{"log_message": "Imaged from the second drive"}
```

**Response:** `200 OK` with the job

**Errors:**
- `403 Forbidden`: not the job's owner or an admin
- `404 Not Found`: Job not found
- `409 Conflict`: the job changed status while the note was added; try again
- `422 Unprocessable Entity`: no note, a note over 2,000 characters, or any other field

---

### Delete Job

**Endpoint:** `DELETE /api/jobs/{job_id}`

**Description:** Delete a job's record, with its owner and sharing and its case's findings, notes, host assignments and activity (`case_findings`, `case_notes`, `case_hosts`, `case_activity`), in one transaction. Nothing on disk is removed: its evidence and its output folder stay where they are. The audit log (`audit_logs`) is kept, and records the deletion: `job.deleted`, with the case number and how many rows went from each table. A pending, running, paused or removing job can't be deleted (cancel it first), and nor can one `awaiting_confirmation`: removing its old output failed, and it waits for its owner or an admin to try the removal again or give up ([confirm-removal or cancel-removal](#removing-a-jobs-old-output)) first.

**Authentication:** In server mode, the job's owner or an admin.

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK`
```json
{"message": "Job deleted successfully"}
```

**Errors:**
- `400 Bad Request`: the job is pending, running, paused or removing, or `awaiting_confirmation` (`Cannot delete a job awaiting confirmation: …`)
- `403 Forbidden`: not the job's owner or an admin
- `404 Not Found`: Job not found

---

### Cancel Job

**Endpoint:** `POST /api/jobs/{job_id}/cancel`

**Description:** Cancel a pending or running job. Revokes the Celery task with `SIGKILL` and releases the job's image locks. Child processes started by Elrond (foremost, yara, log2timeline) are not killed and keep the image mounted; see `tests/docs/TEST_RUNNER_GUIDE.md` for clean-up.

**Authentication:** In server mode, the job's owner or an admin; not the people it's shared with. The same goes for `POST /api/jobs/{job_id}/pause` and `/resume`.

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK` with the updated job object (`"status": "cancelled"`).

The job is marked cancelled first (the status, `completed_at` and a log line, in one conditional update from pending, running or paused), and only then stopped. A job that had already finished or failed is left as it is and nothing is killed. One that's marked stays cancelled: the worker's saves after the kill keep the cancel's status, `completed_at`, error and log line, and add the worker's own log lines and progress, so a killed run's "Process exited with code -9" doesn't turn it into a failure.

**Errors:**
- `400 Bad Request`: Job is not pending, running or paused. A job in `awaiting_confirmation` is given up with `cancel-removal`; one that's `removing` can't be cancelled (the worker finishes or fails it).
- `403 Forbidden`: Not the job's owner or an admin
- `404 Not Found`: Job not found
- `409 Conflict`: The job finished or failed before the cancel; `detail` says which (`The job is already completed: it ended before the cancel`)

---

### Pause and Resume Job

**Endpoints:** `POST /api/jobs/{job_id}/pause`, `POST /api/jobs/{job_id}/resume`

**Description:** `pause` sends `SIGSTOP` to a running job's Elrond process group and sets it `paused`; `resume` sends `SIGCONT` and sets it `running` again. Image mounts and the image lock stay held while it's paused, and Elrond's wall-clock timeouts keep counting, so a tool call paused for longer than its timeout fails on resume. The worker writes the event to the job's log.

**Authentication:** In server mode, the job's owner or an admin.

**Response:** `200 OK` with the job.

**Errors:**
- `400 Bad Request`: the job isn't running (pause) or paused (resume)
- `403 Forbidden`: Not the job's owner or an admin
- `404 Not Found`: Job not found
- `409 Conflict`: the signal couldn't be sent (`Could not pause job: <reason>`)

---

### Removing a job's old output

A fresh run (`force_overwrite` on a new job, a restart with `fresh=true`, a completed job's restart by default) removes the job's output folder before Elrond runs. The worker does it, in its own container, and only after checking (`src/web/backend/output_removal.py`):

- the folder comes from the job record (its recorded destination), never from a request or the pending action, and is inside the allowed folders as above, and not one of them;
- it's this job's output: its `.rowanholt-output` marker names the job (or the job the API checked it may replace), or, from before the marker, it's the job's own recorded destination with a `rowanholt_job.log`;
- nothing in it is evidence (any job's source), an allowed folder, another job's output or a mount point (an image Elrond mounted, a bind mount, another device), compared by path and again by device and inode, so a hard link or another spelling of the same folder doesn't hide one;
- no job that's still going writes at, in or around it.

It's deleted without following symbolic links or crossing onto another device, and must be gone afterwards. Each removal is recorded in the audit log (`audit_logs`, as licence and brand changes are): `output.removed` with the files and bytes, `output.removal_refused` or `output.removal_failed` with the reason. The job's own log is in the folder being removed, so the audit log is the record that lasts. A refusal fails the job with the reason (trying again can't help); a removal that fails part way (a busy file, permissions) stops the job in `awaiting_confirmation`, with `pending_action` (`action_type` `remove_output`, `target_path`, `message`).

### Confirm Removing the Old Output Again

**Endpoint:** `POST /api/jobs/{job_id}/confirm-removal` (`confirm-sudo`, its name until 12 November 2026, still answers; nothing was ever escalated)

**Description:** Try the failed removal again. The job moves from `awaiting_confirmation` to `removing` in one conditional update, the confirmation is recorded in the audit log (`output.removal_confirmed`: who, from which address, which folder), and the worker's `remove_output` task is queued. The worker checks and removes the folder as above; removed, the job is `pending` again and its run queued; not, the job fails with the reason (no second confirmation).

**Authentication:** In server mode, the job's owner or an admin; not the people it's shared with.

**Response:** `202 Accepted` with the job, `"status": "removing"`. Follow it with `GET /api/jobs/{job_id}`.

**Errors:**
- `403 Forbidden`: Not the job's owner or an admin
- `404 Not Found`: Job not found
- `409 Conflict`: Job is not awaiting confirmation (another confirmation got there first, or it moved on)
- `503 Service Unavailable`: The task couldn't be queued; the job is failed with `Not queued: <error>`

---

### Give Up Removing the Old Output

**Endpoint:** `POST /api/jobs/{job_id}/cancel-removal` (`cancel-sudo` still answers)

**Description:** Give up the removal for a job in `awaiting_confirmation`: the job fails, its old output stays as it is, and it's recorded in the audit log (`output.removal_cancelled`). This is the only way to end a job in that state.

**Authentication:** In server mode, the job's owner or an admin.

**Response:** `200 OK` with the updated job object (`"status": "failed"`).

**Errors:**
- `403 Forbidden`: Not the job's owner or an admin
- `404 Not Found`: Job not found
- `409 Conflict`: Job is not awaiting confirmation

---

### Restart Job

**Endpoint:** `POST /api/jobs/{job_id}/restart`

**Description:** Restart a failed, cancelled or completed job. Creates new Celery task. A job with findings is refused unless the request confirms, since the re-run rewrites the rows they point at.

**Authentication:** Whoever can see the job. With fresh output (`fresh=true`, the default for a completed job), only the job's owner or an admin, since it removes their output.

**Path Parameters:**
- `job_id`: UUID of the job

**Query Parameters:**
- `confirm` (bool, default `false`): restart even though the job has findings
- `fresh` (bool, default `true` for a completed job, `false` for a failed or cancelled one): remove the job's output first. Elrond skips any artefact whose cooked file is already there, so a completed job re-run into its old output comes out unchanged. The worker never removes an output directory that holds one of the job's sources

**Response:** `200 OK` with the job, `"status": "pending"` and its new `celery_task_id`.

**Errors:**
- `400 Bad Request`: Job not in failed/cancelled/completed state
- `403 Forbidden`: a fresh restart by someone who isn't the job's owner or an admin, or a job whose recorded output folder is no longer inside the allowed folders
- `404 Not Found`: Job not found
- `409 Conflict`: The job has findings and `confirm` wasn't set; `detail` is `{"findings": 3, "message": "..."}`
- `500 Internal Server Error`: the task couldn't be queued (the job is failed with `Not queued: <error>`)

---

### Archive Job

**Endpoint:** `POST /api/jobs/{job_id}/archive`

**Description:** Set a job `archived`, with a line in its log, and keep when (`archived_at`, in the job's responses) and the status it had (`archived_from`), which [Unarchive](#unarchive-job) restores.

**Authentication:** In server mode, the job's owner or an admin.

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK` with the job, `"status": "archived"` and `archived_at` set.

**Errors:**
- `400 Bad Request`: the job is pending, running, paused or removing, or already archived; or it's `awaiting_confirmation` (`Cannot archive a job awaiting confirmation: …`), waiting for its owner or an admin to try removing its old output again or give up first
- `403 Forbidden`: Not the job's owner or an admin
- `404 Not Found`: Job not found

---

### Unarchive Job

**Endpoint:** `POST /api/jobs/{job_id}/unarchive`

**Description:** Restore an archived job to the status it had when it was archived (`archived_from`), and clear `archived_at` and `archived_from`. A job archived before these were kept (migration `a6d3f9b2c418`, 12 November 2026) has no `archived_from`, and goes back to `failed` if it has an error, `completed` if it has a completion time, `cancelled` if it has neither (so a cancelled one comes back `completed`, since a cancel sets a completion time).

**Authentication:** In server mode, the job's owner or an admin.

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK` with the job (with `owner`, `shared_with` and `can_manage`).

**Errors:**
- `400 Bad Request`: Job is not archived
- `403 Forbidden`: `Only the job's owner or an admin can restore it from the archive`
- `404 Not Found`: Job not found

---

### Bulk Restart Jobs

**Endpoint:** `POST /api/jobs/bulk/restart`

**Description:** Restart failed, cancelled or completed jobs. Takes a bare JSON array of job IDs and returns `{"results": [...]}`, one `{"job_id", "success", "error"}` per job. Without `confirm=true`, a job with findings is skipped: its result has `success: false`, the reason in `error` and the count in `findings`. A fresh restart is the owner's or an admin's, job by job, as for a single restart; a job the caller can't see comes back `Job not found`.

**Query Parameters:**
- `fresh` (bool, default `true` for completed jobs, `false` for failed or cancelled ones): remove each job's previous output before it runs again
- `confirm` (bool, default `false`): restart jobs that have findings too

---

### Export Job to SIEM

**Endpoints:** `POST /api/jobs/{job_id}/export-siem`, `GET /api/jobs/{job_id}/export-siem`

**Description:** Index a completed job's output, again or for the first time, into the SIEMs its options name (`splunk`, `elastic`, `opensearch`, `timesketch`, `navigator`). The `POST` queues a task in the worker and answers at once; the worker runs Elrond's own `--Index` of the job's output folder (`python3 $ELROND_HOME/elrond.py <case> <output> --Index --Splunk ...`, the code a run with those options ends with), so the export uses the worker's `SPLUNK_*`, `ELASTICSEARCH_*`, `OPENSEARCH_*` and `TIMESKETCH_*` settings and its network. Each SIEM's index for the case is replaced, as `--Index` does (`docs/CLI.md`). The `GET` answers the job's last export: poll it while `state` is `queued` or `running`.

The export's notable lines (each target's phase, warnings and errors, and the outcome) are appended to the job's log one at a time, each a conditional update of a still-completed job, so the job's other fields are never rewritten; Elrond's full output goes to `rowanholt_siem_export.log` in the job's output folder. While an export is queued or running, nothing replaces or removes the output it reads: restarting, archiving or deleting the job answers `409` ("A SIEM export is running for this job; wait for it to finish", or `queued`), and the bulk forms skip it with that reason as its `error`. If Redis can't be read, those actions go ahead rather than be refused. Should the job still move on mid-export (Redis was unreadable), the export notices on its next log line, stops Elrond and fails. Its state is kept in Redis for 30 days, not in the job.

**`POST` response:** `202 Accepted`, the export's record:
```json
{"task_id": "uuid", "state": "queued", "targets": ["Splunk", "Elastic"], "requested_by": "alice",
 "queued_at": "2026-11-12T10:00:00", "phase": null, "hosts": [], "results": {}, "error": null}
```

**`GET` response:** `200 OK`, `{"state": "none"}` before any export, else the record, whose `state` is one of:
- `queued`: waiting for a worker
- `running`: with `started_at`, `hosts` and `phase`, `step` and `steps` (the target being indexed: `{"phase": "Elastic", "step": 2, "steps": 2}`)
- `succeeded` or `failed`: with `finished_at`, `returncode` and `results`, one per target: `{"ok": true}` or `{"ok": false, "error": "..."}`, plus `total` (Elastic's document count from `_count` after the run; OpenSearch's records and Timesketch's events, with `by_host`), `techniques` (Navigator), or for Splunk a `note`: Splunk is given monitors on the case's files and restarted, and reads them itself afterwards, so it has no count at the end of the export. `error` is set when Elrond stopped before indexing (a SIEM unreachable, no processed hosts), which fails every target
- `interrupted`: its worker died (no heartbeat), or it left the queue with no worker taking it; `error` says which. Export again

**Errors:**
- `400 Bad Request`: the job isn't completed, has no SIEM option, or its output folder is unknown or gone
- `404 Not Found`: Job not found
- `409 Conflict`: an export of this job is already queued or running
- `503 Service Unavailable`: Redis (the export's state, the queue) can't be reached; nothing is queued

**Who:** whoever can see the job (its owner, the people it's shared with, admins); a `smith-mcp` token is refused (`403`). Each `POST` is recorded in the audit log (`job.siem_export`).

**Busy:** a running export counts for [`/api/busy`](#busy) as `siem-exports` (its worker's heartbeat in Redis, refreshed every 15 seconds, expiring after 60). A queued one doesn't, as a pending job doesn't: its message waits out a rebuild in Redis's queue.

**What the server needs:** the SIEMs running and reachable from the worker: on one machine `docker compose --profile siem up -d` (Splunk, Elasticsearch and Kibana, the Navigator, on `rowanholt-network`), and the worker's `SPLUNK_PASSWORD` and `ELASTIC_PASSWORD` the same as the SIEMs' (both from `.env`; the defaults match). Splunk also reads the case's files itself, so the output folder must be mounted in Splunk's container where the worker has it (`docker-compose.yml` mounts `/tmp/rowanholt` and `/Volumes`). OpenSearch and Timesketch are elsewhere and need their `OPENSEARCH_*` and `TIMESKETCH_*` settings (`docs/CLI.md`).

---

### Get Navigator Layer

**Endpoint:** `GET /api/jobs/{job_id}/navigator?domain=`

**Description:** Download the job's MITRE ATT&CK Navigator layer, found in its output: `domain` is `enterprise-attack` (`<case>_navigator.json`) or `mobile-attack` (`<case>_mobile_navigator.json`); without it, Enterprise when the case has one, else Mobile. `404` when there's no output folder or no layer. The layer of confirmed findings only is [`/case/layer`](#case-browser-and-collaboration).

---

### Validate Case ID

**Endpoint:** `GET /api/validate/case-id/{case_id}`

**Description:** Check whether a case ID is already in use. Case numbers name output folders, so `exists` counts every job's, whoever owns it; `jobs` lists only the ones the caller can see.

**Response:** `200 OK`
```json
{"exists": true, "case_id": "CASE-001", "jobs": [{"id": "uuid1", "status": "completed", "created_at": "2025-01-15T12:00:00"}]}
```

---

### Check and Upload Required Files

**Endpoints:** `POST /api/check-required-files`, `POST /api/upload-required-files`

**Description:** Keyword, YARA and collect-files options read their input from fixed files in `/tmp/rowanholt` (`%TEMP%\rowanholt` on Windows): `keywords.txt`, `yara.yar` and `files.txt`. `check-required-files` takes `{"options": ["keywords", "yara", "collectFiles"]}` and returns `{"missing": [...], "found": [...], "directory": "/tmp/rowanholt"}` (a file counts when it isn't empty). `upload-required-files` takes multipart fields `keywords`, `yara` and `collectFiles`, overwrites those files, and returns `{"success": true, "uploaded": [{"option", "filename", "path", "size"}], "directory"}`. In server mode, anyone signed in.

---

### Job Sharing

**Endpoints:** `GET /api/jobs/{job_id}/sharing`, `PUT /api/jobs/{job_id}/sharing`

**Description:** Who owns a job and who it's shared with. `GET` (whoever can see the job) returns `{"owner", "shared_with", "can_manage"}`. `PUT` (the owner or an admin; `403` otherwise) takes `{"usernames": ["bob", "carol"]}`, which replaces the list, and returns the same shape; `400` names any that isn't an active user. The people a job is shared with can see it and work on its case; see [SERVER.md](SERVER.md#sharing-jobs).

---

### Bulk Actions

**Endpoints:** `POST /api/jobs/bulk/cancel`, `/bulk/delete`, `/bulk/archive`, `/bulk/unarchive` (and [`/bulk/restart`](#bulk-restart-jobs))

**Description:** The single-job action for each of several jobs, with the same rules job by job. The body is a bare JSON array of job IDs:

```json
["uuid1", "uuid2", "uuid3"]
```

**Response:** `200 OK`, a result per job:
```json
{
  "results": [
    {"job_id": "uuid1", "success": true},
    {"job_id": "uuid2", "success": false, "error": "Only the job's owner or an admin can cancel it"},
    {"job_id": "uuid3", "success": false, "error": "Job already completed: it ended before the cancel"}
  ]
}
```

A job the caller can't see comes back `Job not found`; one they see but don't manage, with the owner-or-admin refusal (for unarchive, `Only the job's owner or an admin can restore it from the archive`). Otherwise:

- **cancel**: as the single cancel, marked first, then stopped; a job that had already finished or failed is left alone, not stopped, and reported with `success: false`
- **delete**: as the single delete (the case's rows go with the job, nothing on disk is removed, the audit log records each); `Cannot delete running job` for a pending, running, paused or removing one, `Cannot delete a job awaiting confirmation: …` for one `awaiting_confirmation`
- **archive**: `Cannot archive running job` for a pending, running, paused or removing one; `Cannot archive a job awaiting confirmation: …` for one `awaiting_confirmation`; `Already archived`
- **unarchive**: `Job is not archived`; on success the result's `status` is the status restored, as the single unarchive restores it

---

## File System

### Browse File System

**Endpoint:** `GET /api/fs/browse`

**Description:** List a folder on the backend, for choosing images. The path must be one of the allowed folders or inside one, checked as job paths are: a folder boundary, not a prefix (`/tmp/rowanholtX` isn't inside `/tmp/rowanholt`), with no `..` and no symbolic link below the allowed folder (`403` otherwise). macOS metadata files (`._*`, `.DS_Store`) are left out; entries that can't be read are skipped and counted.

**Authentication:** In server mode, anyone signed in.

**Query Parameters:**
- `path` (optional): folder to list (default `/`, which is refused unless it's an allowed folder)

**Response:** `200 OK`
```json
{
  "items": [
    {"name": "..", "path": "/evidence", "is_directory": true, "size": null, "modified": null, "is_image": false},
    {"name": "cases", "path": "/evidence/cases", "is_directory": true, "size": null, "modified": "2025-01-15T10:00:00", "is_image": false},
    {"name": "disk.E01", "path": "/evidence/disk.E01", "is_directory": false, "size": 10737418240, "modified": "2025-01-15T09:00:00", "is_image": true}
  ],
  "current_path": "/evidence",
  "permission_warning": null,
  "skipped_count": 0
}
```

Folders come first, then files, by name; `..` leads when there's a parent. `is_image` marks `.e01`, `.ex01`, `.raw`, `.dd`, `.img`, `.bin`, `.vmdk`, `.vhd`, `.vhdx`, `.mem`, `.dmp` and `.lime`. `permission_warning` explains macOS's Full Disk Access when Docker couldn't read something.

**Errors:**
- `400 Bad Request`: not a folder
- `403 Forbidden`: outside the allowed folders, a `..` or a symbolic link in the path, or permission denied
- `404 Not Found`: Path does not exist

---

## Administration (Aragorn)

**Role Required:** `ADMIN` (the local analyst on a local stack). These back Aragorn's pages in the web app.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/licence` | The edition, `state` (`free`, `pending`, `active`, `grace`, `lapsed`), licensee, seats, features, `places_held`, `free_seats`, dates, the terms version an install accepts now, and who accepted the installed one |
| `GET` | `/api/licence/terms` | The commercial terms: `{"version", "text"}` |
| `POST` | `/api/licence/check` | `{"text"}`: what a licence says, installing nothing. `422` for one that doesn't verify or has run out |
| `PUT` | `/api/licence` | `{"text", "accept_terms": true, "terms_version"}`: install it. `422` without acceptance, `409` when the terms have changed since the admin read them |
| `DELETE` | `/api/licence` | Back to the Free edition (nobody is deactivated) |
| `GET` `POST` | `/api/brands` | Report brands, the installation's and each case's choice, and what the licence does with them; `POST` `{"name", "primary": "#RRGGBB", "secondary", "prepared_for"}` |
| `PATCH` `DELETE` | `/api/brands/{brand_id}` | Change or remove a brand (`404` for none) |
| `PUT` `GET` `DELETE` | `/api/brands/{brand_id}/logos/{slot}` | A logo for `cover`, `header` or `client`: multipart `file`, cleaned and redrawn as PNG; `GET` returns that PNG |
| `PUT` | `/api/brands/installation` | `{"brand_id"}` (or `null`): the installation's brand |
| `GET` `PUT` | `/api/jobs/{job_id}/case/brand` | The brand of a job's case number, `{"brand_id"}` |
| `GET` `POST` | `/api/webhooks` | `events`, the webhooks (`has_secret`, never the secret), and `sending` with `reason`; `POST` `{"url", "events", "secret", "description"}`, the secret generated when not given and returned this once. `422` for a URL or event refused |
| `PATCH` `DELETE` | `/api/webhooks/{hook_id}` | Change `url`, `events`, `enabled` or `description`, or remove it |
| `POST` | `/api/webhooks/{hook_id}/test` | Send a test `job.completed` now and return the delivery; `402` when this edition doesn't send webhooks |
| `GET` | `/api/symbols` | Volatility symbol tables for Linux and macOS, with their kernel banners and the folders' audit log |
| `POST` | `/api/symbols/add` | Multipart `kind` (`package`, `table`, `vmlinux` or `kdk`), `file`, and `system_map` or `dwarf` where the kind needs one; built in the worker. Returns `{"task_id"}` |
| `GET` | `/api/symbols/tasks/{task_id}` | `{"state": "pending"}`, then `done` with the build's output |
| `GET` | `/api/samples` | The sample cases (public forensic images): their files' state and, once there, the job to start |
| `POST` | `/api/samples/{sample_id}/fetch` | Download, check and unpack one in the worker: `{"task_id"}`. `409` for a sample that's built locally, not downloaded |
| `GET` | `/api/samples/tasks/{task_id}` | `running` with progress, then `done` |
| `POST` | `/api/samples/{sample_id}/import` | The job request for a fetched sample (backup password included), for the caller to `POST` to `/api/jobs` so the job is theirs. `409` until it's fetched or built |

Every licence, brand and webhook change goes in the audit log. Editions, events, signing and the URL rules are in [LICENSING_MODEL.md](LICENSING_MODEL.md#rowanholts-split). `/api/symbols` and `/api/samples` answer `503` when Elrond's package isn't mounted in the backend, or the worker's queue isn't available.

---

## Docker Administration (Anduril)

**Role Required:** `ADMIN`, signed in with a password or single sign-on (a sign-in's JWT, by cookie or bearer; not an API token), locally as well as on a team server. `/status` needs nothing locally and an admin on a team server. `/api/aragorn/…`, the name before the rename, answers the same.

Anduril manages Rowanholt's own containers and images. The backend doesn't hold the Docker socket: these endpoints proxy to the `anduril` service over the internal `rowanholt-anduril` network. Anduril only acts on containers that carry the `com.docker.compose.project=rowanholt` label and are named `rowanholt-*`, and on the images those containers use; anything else returns `403`. The API is off (`503`) until Anduril is enabled on the host with `rowanholt anduril enable`, and it stays off while the backend uses the default `SECRET_KEY`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/anduril/status` | Whether Anduril is usable: `enabled`, `secret_configured`, `token_present`, `reachable`, `reason` (`secret_key`, `not_enabled`, `unreachable`, `error`) and `enable_command` |
| `GET` | `/api/anduril/containers` | Rowanholt containers: name, service, image, state, health, upstream or built image |
| `GET` | `/api/anduril/images` | Rowanholt images: tags, size, whether built locally, which containers use them |
| `GET` | `/api/anduril/containers/{name}/logs?tail=200` | Last `tail` log lines (1–5000) |
| `GET` | `/api/anduril/containers/{name}/stats` | One CPU, memory, network and block I/O sample |
| `POST` | `/api/anduril/containers/{name}/{action}` | `start`, `stop`, `restart`, `update` (pull the upstream image and recreate if newer) or `recreate`. Body: `{"force": false}` |
| `POST` | `/api/anduril/images/pull` | Pull a newer version of an upstream image Rowanholt uses. Body: `{"ref": "redis:7-alpine"}` |
| `POST` | `/api/anduril/images/remove` | Remove an unused Rowanholt image (never forced). Body: `{"id": "sha256:..."}` |
| `POST` | `/api/anduril/images/prune` | Remove dangling images built for Rowanholt |
| `GET` | `/api/anduril/ops` | The last 50 operations |
| `GET` | `/api/anduril/ops/{id}` | One operation: `status` (`queued`, `running`, `succeeded`, `failed`), `log`, `result` |

Mutating calls return `202 Accepted` with an operation; poll `/ops/{id}` for the outcome. Operations run one at a time.

Stopping, restarting, updating or recreating `celery-worker`, `postgres` or `redis` interrupts analysis jobs, so these return `409 Conflict` while a job is running or an `elrond.py` process is alive. Send `"force": true` to go ahead anyway:

```json
{
  "detail": {
    "message": "Refusing to restart celery-worker while jobs are running: 7c1e...",
    "busy": true
  }
}
```

Anduril won't stop, restart or recreate its own container from the API. Use `rowanholt anduril disable` on the host.

---

## Mordor: Recorded Attack Telemetry

**Authentication:** locally, none, apart from Update and the lab, which need a signed-in admin (as [Lab](#lab)). On a team server, anyone signed in may read (GET); everything else under `/api/mordor` is admin-only, `/check` and `/noisy` included, as are dataset downloads and deletion

Which logs record each ATT&CK technique, from attacks emulated in labs, and whether a detection's indicators appear in the recorded events. The engine is `src/mordor/telemetry`, ported from Archer. It ships with 1,632 recordings covering 354 techniques: OTRF Security-Datasets (Mordor), Splunk attack_data and EVTX-to-MITRE-Attack. Your own recordings from `./lab.sh mordor-record` or the Mordor page show up as the source `lab`, and Microsoft GUIDE adds Defender XDR's alerting per technique. Reading touches no network. A rebuild from the CLI (`python -m src.mordor.telemetry --build`) or the lab is picked up on the next request.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/mordor/telemetry/status` | Sources built, recordings per source, technique count, whether field values are present, the lab's runs, Microsoft GUIDE's summary, and the state and log of an Update |
| `POST` | `/api/mordor/telemetry/build` | Update (admin): fetch what Splunk attack_data and OTRF changed and rebuild, in the background (`409` while one runs). EVTX-to-MITRE-Attack is included only when the backend has the `evtx` package, since without it a rebuild would drop those recordings |
| `GET` | `/api/mordor/telemetry/techniques` | Every recorded technique, one row each |
| `GET` | `/api/mordor/telemetry/technique/{technique_id}` | A technique's recordings (exact, else its sub-techniques or parent), their event types, the Defender XDR tables and Chronicle UDM types they need, and `defender`: GUIDE's alert count, organisations and true-positive rate, or `null` |
| `GET` | `/api/mordor/telemetry/data-sources` | For each Defender table and UDM event type, the techniques it records |
| `GET` | `/api/mordor/telemetry/search?q=` | `{technique: [logs]}` whose events hold a field value containing `q` (3–200 characters; `…` matches a variable span, as in `C:\Users\…\AppData`) |
| `POST` | `/api/mordor/telemetry/check` | One detection's indicators against its technique's recordings and everyone else's: seen, not seen or noisy per indicator |
| `POST` | `/api/mordor/telemetry/noisy` | Which indicators also appear while many unrelated techniques ran. Body: `{"indicators": [...]}`, or `{"technique_id": "T1053.005"}` to derive candidates from that technique's own recordings |

The GET endpoints take `collections` (`native`, `sysmon`, `edr`, `osquery`, `cloud`) and `platforms` (`windows`, `linux`, `macos`, `esxi`, `cloud`), comma-separated; both default to all.

A detection for `/check`:

```json
{
  "technique_id": "T1053.005",
  "name": "Scheduled task created from the command line",
  "indicators": {"cmd": ["schtasks /create"], "file": ["schtasks.exe"]}
}
```

Indicator kinds are `cmd`, `file`, `sw`, `path`, `reg`, `network`, `domain`, `ip`, `port`, `service`, `acct`, `evt`, `api` and `op`/`operation`.

### Mordor Datasets

OTRF Security-Datasets (Mordor) to download as evidence (`mordor_routes.py`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/mordor/catalog?platform=&tactic=&technique=&search=&limit=&offset=` | The OTRF catalogue (`limit` up to 200), each with `status` `available` or `downloaded`: `{"datasets", "total", "platforms", "tactics"}` |
| `POST` | `/api/mordor/catalog/refresh?force=` | Re-read the catalogue from OTRF's GitHub repository |
| `GET` | `/api/mordor/datasets?status=&limit=&offset=` | The datasets downloaded here, in the same shape |
| `GET` | `/api/mordor/datasets/{dataset_id}` | One dataset, its files and where it's stored |
| `POST` | `/api/mordor/datasets/{dataset_id}/download` | `{"output_dir": null}`: download in the background (`status` `downloading`, or `downloaded` when it's there already). Counts as busy for `/api/busy` while it runs |
| `DELETE` | `/api/mordor/datasets/{dataset_id}` | Remove a downloaded dataset |
| `GET` | `/api/mordor/datasets/{dataset_id}/verify` | Check its files: `valid`, `files_checked`, `total_files`, `errors` |

### Mordor Lab

**Role Required:** `ADMIN`, signed in (a sign-in's JWT, not an API token), locally as well as on a team server

The machines recordings run on (`src/mordor/lab`, ported from Archer). Docker, Tart and UTM are on the host, so these proxy to the lab agent (`./lab.sh agent start`) and return `503` without it. Machine and snapshot names are 1–64 letters, digits, `.`, `-` or `_`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/mordor/lab/overview` | The host and its engines, the templates it can create, every machine (`lab` for the lab's own, `deletable` only for ones created here), the names already taken, and any running job |
| `GET` | `/api/mordor/lab/logs?engine=&name=` | A container's log, or a VM's address |
| `GET` | `/api/mordor/lab/provision-steps?os=` | The set-up steps for `windows`, `linux` or `macos` |
| `POST` | `/api/mordor/lab/create` | `{"template": "ubuntu-container", "name": "..."}`. Starts a job |
| `POST` | `/api/mordor/lab/action` | `{"engine", "name", "action"}`: `start`, `stop`, `snapshot`, `revert` (a job) or `delete`, with `snapshot` for the last three. Delete is refused for the lab's machines and anything not created here |
| `POST` | `/api/mordor/lab/adopt` | Set a UTM VM's OS: `{"engine": "utm", "name", "os"}` |
| `POST` | `/api/mordor/lab/clone` | `{"engine": "utm", "name", "new_name"}`. Starts a job |
| `POST` | `/api/mordor/lab/verify-iso` | `{"path"}`: whether the file is a Windows ARM64 installer (reads the ISO9660 directory only) |
| `POST` | `/api/mordor/lab/provision` | `{"engine", "name", "os", "step"}`. On the lab's Windows VM it runs `mordor-sensor`. Starts a job |
| `POST` | `/api/mordor/lab/record` | `{"engine", "name", "os", "techniques", "revert_to", "execute"}`. With `execute: false` it returns the plan and warnings and runs nothing; with `true` it runs Atomic Red Team in the machine and imports the recording. Starts a job |

A job returns `202` with a lab run (`id`, `label`, `status`); poll `/api/lab/runs/{id}?offset=` for its output. One job runs at a time across the whole lab (`409` otherwise).

---

## Threat Intelligence

**Authentication:** none locally. On a team server, anyone signed in may read and make an online lookup; importing, pulling, changing expiry and deleting are admin-only

The indicators in `threat_intel_indicators`, in the fixed ten-column schema (Evidential Element, Threat Group, Procedure Example, Technique ID, Technique Name, Tactic, Contextual Evidence, Reference URL, Navigation Layer URL, Source Type). Parsing and matching are Elrond's (`src/analysis/rowanholt/threat_intel/`); the backend mounts that package. A job with `"threat_intel": true` exports them for Elrond's `--threatIntel`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threat-intel` | `total`, `groups`, `expired` (past their `valid_until`, left out of matching) and `sources`: `[{source, count}]` |
| `GET` | `/api/threat-intel/indicators?q=&source=&limit=&offset=` | Indicators whose element, group or technique ID contains `q`; `limit` up to 500. Each has `valid_until` (null: no expiry), `confidence`, `first_seen` and `expired` |
| `POST` | `/api/threat-intel/import` | Multipart `file`: the Iran APT workbook (XLSX), a STIX 2.1 bundle (JSON), Rowanholt's or MITRESaw's CSV, or a `.txt` watchlist. Up to 200 MB. Returns `read`, `added`, `duplicates` and `sources`; indicators already stored under the same element, group, technique and source are skipped, but their expiry is renewed. A STIX indicator keeps its own `valid_until` and `confidence`; IPs and domains from other sources hold for 90 days from import, everything else doesn't expire |
| `POST` | `/api/threat-intel/taxii` | `{"url", "username", "password", "added_after"}`: every object in a TAXII 2.1 collection (read by `samarkand.taxii`). Redirects aren't followed, so the credentials go only to the URL given: use the collection's final URL (https, say, not an http address that redirects). `502` when the collection can't be read, with the reason (credentials refused, the HTTP status, not JSON, unreachable) |
| `PUT` | `/api/threat-intel/indicators/{id}/validity` | `{"valid_until": "2027-01-01"}` extends one indicator, `{"valid_until": null}` clears its expiry; admins only on a team server. `400` for a date that isn't ISO, `404` for no such indicator |
| `DELETE` | `/api/threat-intel/sources/{source}` | Every indicator from one source |
| `GET` | `/api/threat-intel/lookup` | `{"enabled", "provider"}`: whether online lookups are on (`ROWANHOLT_ONLINE_LOOKUPS=virustotal` and `VIRUSTOTAL_API_KEY` in `.env`) |
| `POST` | `/api/threat-intel/lookup` | `{"value"}`: one IP, domain or MD5/SHA-1/SHA-256 sent to VirusTotal. Returns `kind`, `found`, `malicious`, `suspicious`, `harmless`, `undetected`, `reputation`, `last_analysis`, `tags`, `link` and `cached` (answers are kept an hour). Any signed-in analyst; `403` to a smith-mcp token or Smith's agent header, `400` for anything else or a value that mustn't leave (a private, reserved or documentation address, an internal-looking name such as `.local` or `.corp`), `404` when lookups are off, `429` when VirusTotal's quota is spent, `502` when it can't be reached. Each lookup is logged with who asked |
| `GET` | `/api/threat-intel/enrich?value=` | What the indicators say about one process name, command line, path, IP, domain or hash: per element, its `kind`, `breadth` (groups using it), `common` (more than 15), `groups`, `techniques` and `sources` |

`503` means the package isn't mounted in the backend (`docker compose up -d backend` after pulling).

---

## Case Browser and Collaboration

**Authentication:** whoever can see the job (its owner, the people it's shared with, admins); everyone in local mode. Smith (a `smith-mcp` token, or the `X-Rowanholt-Agent` header: [API Tokens](#api-tokens)) may read, flag leads and add notes, recorded as "Smith (for <user>)"; it can't confirm or dismiss, change or remove a finding, or assign a host (`403`)

A job's output, read-only, and the team's findings, notes, host assignments and activity on it (`case_routes.py`, `case_files.py`). Only `<host>/artefacts/cooked/`, `<host>/analysis/` and the case's top-level CSVs are readable; `raw/` never is, and nothing writes to the case directory. Findings reference a row by file, row (`2` onwards for a CSV line, `#0` onwards for a JSON record) and the SHA-256 of the row, so a re-run that changes it shows up.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/jobs/{job_id}/case` | `hosts` (each with `files`, `assignee`, `status`), `case_files`, and `findings` counted by status. `404` until the job has output |
| `GET` | `/api/jobs/{job_id}/case/rows?host=&path=&q=&offset=&limit=` | Rows of one table containing `q` in any field: `columns`, `rows` (`ref`, `hash`, `cells`), `total`, and `exact` (false when the count stopped early). `host` is `(case)` for the case's own files |
| `GET` | `/api/jobs/{job_id}/case/rows.csv?host=&path=&q=` | The same table (its rows containing `q`) as a CSV download, named after the host and table |
| `GET` | `/api/jobs/{job_id}/case/findings?status=&verify=` | Findings; with `verify=true`, `intact` says whether each row still hashes the same |
| `POST` | `/api/jobs/{job_id}/case/findings` | `{"host", "artefact", "row_ref", "title", "technique", "status"}`; the row is read server-side for its hash and excerpt. `status` is `lead` (default), `confirmed` or `benign`; `technique` an ATT&CK ID. `409` if the row is already flagged |
| `PATCH` | `/api/jobs/{job_id}/case/findings/{id}` | Change `title`, `technique` or `status`; pass the `updated_at` you loaded and a change someone else made first returns `409` instead of being overwritten |
| `DELETE` | `/api/jobs/{job_id}/case/findings/{id}` | Remove a finding and its notes (anyone who can see the job, as for the other case routes) |
| `GET` `POST` | `/api/jobs/{job_id}/case/notes` | Notes, Markdown: `{"body", "finding_id"}`, `finding_id` null for the case |
| `PUT` | `/api/jobs/{job_id}/case/hosts/{host}` | `{"assignee", "status"}`; status is `to do`, `in progress` or `done`. In server mode the assignee must be an active user (username or email, stored as the username), otherwise `400`; `""` unassigns |
| `GET` | `/api/jobs/{job_id}/case/activity?since=` | Who did what, newest first; `since` (the highest `id` seen) for polling |
| `WS` | `/api/jobs/{job_id}/case/live` | Sends `{activity, status, progress}` when any of them changes (checked every 2 seconds): the newest activity id and the job's state, so a page knows when to reload; no case data. Authenticated like the routes above, by the session cookie or a bearer header (never a token in the URL), and checked again before each check, so signing out or losing the share closes it (code 1008); refused from a page on an origin the backend doesn't serve |
| `GET` | `/api/jobs/{job_id}/case/report` | Markdown: case notes, then confirmed findings by host with their notes (the case browser's **Findings**) |
| `GET` | `/api/jobs/{job_id}/case/full-report?format=docx\|markdown` | The case report as a download (DOCX by default): case notes and confirmed findings, each with its row and whether the row is unchanged; Appendix A, open leads and dismissed rows; Appendix B, Elrond's report from the case (hosts and timespan, techniques with their rows, indicators, Gandalf's integrity check, method; [CLI.md](CLI.md#case-report)). Read-only over the case; the case's reading is kept until its files change, since the first download of a large case reads all its tables. Recorded in the activity feed. `503` if Elrond's `rowanholt/report` isn't mounted |
| `GET` | `/api/jobs/{job_id}/case/layer?domain=` | An ATT&CK Navigator layer of confirmed findings' techniques only; `domain` `enterprise-attack` or `mobile-attack` |

A case's report brand (`/api/jobs/{job_id}/case/brand`) is an admin's: see [Administration](#administration-aragorn).

---

## Smith (AI Analyst)

**Authentication:** none locally. On a team server, anyone signed in, over the cases behind jobs they can see (`404` for another case); case folders in Smith's data directory with no job behind them are admins'. A `smith-mcp` token may call the GETs and the question POSTs (`/offline/answer`, `/query`, `/summary`, `/suggestions`), not `/chat`

Ask Smith's back end. Free-text answers come from Ollama at `OLLAMA_HOST` (default `http://host.docker.internal:11434`) with the model `ROWANHOLT_MODEL_NAME` (default `llama3.2:3b`) and a `ROWANHOLT_NUM_CTX`-token window (default 8192). Without them, `/status` says why and the offline endpoints answer fixed questions from Elrond's output.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/ai/status` | `llm_available`, `ollama_running`, `model_name`, `models`, `ollama_host`, `data_dir`, and `reason`: why free text won't work (empty when it will) |
| `GET` | `/api/ai/offline/questions` | The fixed questions: `id`, `question`, `needs_case` (including `threat_intel` and `findings`) |
| `POST` | `/api/ai/offline/answer` | `{"question_id": "techniques", "case_id": "CASE-001", "job_id": "..."}` (`case_id` only where `needs_case`; `job_id`, optional, reads that job's output, as for `/query`). Returns `{"answer", "rows", "job_id", "offline": true}`: `rows` are the rows the answer's shown lines came from (`host`, `file`, `row_ref`, `hash`, `line`), the reference a finding stores, so `POST /api/jobs/{job_id}/case/findings` can flag one; `job_id` is the job (one the caller can see) whose case was read, and `rows` is empty without one. Counts (hosts, IOCs, logins by user) cite nothing. `404` for an unknown question |
| `GET` | `/api/ai/cases` | Cases Smith can see: one entry per completed job (`job_id`; two jobs can share a case number), with `indexed` and `has_artifacts`, and, for admins only on a team server, case folders in Smith's data directory, which have no job |
| `POST` | `/api/ai/chat` | `{"message": "..."}` without case context. Returns `{"response", "model", "processing_time"}` |
| `GET` | `/api/ai/cases/{case_id}/info` | What is indexed for a case (`?job_id=` as for `/query`) |
| `POST` | `/api/ai/cases/{case_id}/query` | `{"question": "..."}` answered from the case's data. `?job_id=` reads that job's output (`404` if the caller can't see it or it isn't this case); without it, the first job with the case number the caller can see; `rows` are the rows the answer cites by tag (`host`, `file`, `row_ref`, `hash`, `line`, `tag`), only ones it was given, on `job_id` (empty without a job) |
| `POST` | `/api/ai/cases/{case_id}/suggestions` | Five investigation paths from the model, each with the `rows` its text cites; `rows` and `job_id` for all of them, as for `/query` |
| `POST` | `/api/ai/cases/{case_id}/summary` | An executive summary of the case, with the `rows` it cites and `job_id`, as for `/query` |

The LLM endpoints return `503` when Ollama or the model isn't available.

---

## Lab

**Role Required:** `ADMIN`, signed in with a password or single sign-on (a sign-in's JWT, by cookie or bearer; not an API token), locally as well as on a team server, since the lab drives the host. Off (`503`) while the backend uses the default `SECRET_KEY`. `/status` needs nothing locally and an admin on a team server.

The test lab (`lab/`) from the browser: Linux targets, Tart and UTM VMs, Gandalf against seeded hosts. Docker, Tart and UTM are on the host, so these proxy to the lab agent (`./lab.sh agent start`, loopback `:5691`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/lab/status` | Whether the agent is reachable: `available`, and `reason` and `start_command` when it isn't |
| `GET` | `/api/lab/state` | Host profile, lab settings, whether the lab password is stored, and any running command |
| `PUT` | `/api/lab/config` | `{"settings": {...}}`: change `lab.conf` on the host |
| `PUT` | `/api/lab/password` | `{"password": "..."}`: store the lab password in the host's keyring |
| `POST` | `/api/lab/run` | `{"command": "gandalf-collect", "args": ["bash"]}`: start a `lab.sh` command |
| `GET` | `/api/lab/runs` | Recent runs |
| `GET` | `/api/lab/runs/{id}?offset=` | A run's status and its output from byte `offset` on |
| `POST` | `/api/lab/runs/{id}/cancel` | Cancel a run |
| `GET` | `/api/lab/consoles` | The running VMs with a console (a VNC server on the host's loopback): `engine`, `name`, `port`, `auth`, never the password |
| `GET` | `/api/lab/consoles/{engine}/{name}` | One VM's console, with the VNC password noVNC answers with (Tart's, new each run). `404` when it has none |
| `WS` | `/api/lab/consoles/{engine}/{name}/ws` | The VM's VNC stream for noVNC, binary frames each way through the lab agent. Refused at the handshake (code 1008) unless the caller is a signed-in admin and the page is on an origin the backend serves; checked again while open, so a sign-out or demotion ends it ([SERVER.md](SERVER.md#lab-vm-consoles)) |

---

## Health Check

### Health Status

**Endpoint:** `GET /api/health`

**Description:** Check API health status. `GET /` returns the web app's build where the backend has one, else `{"name", "version", "status": "running"}`.

**Authentication:** None

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T12:00:00"
}
```

### Busy

**Endpoint:** `GET /api/busy`

**Description:** Whether Rowanholt is in the middle of work a restart (the backend, worker and frontend recreated, images rebuilt; Redis left running) would interrupt. The homelab's `homelab pull` and `homelab update` ask before rebuilding and hold off while it says `true`; anything else (an error, a timeout) they read as idle, so it answers in well under a second. It's busy while any of these is true:

| Check | Busy while |
|---|---|
| `jobs` | a job is running or paused and its worker's heartbeat is live, or lapsed less than 90 seconds ago (see [Jobs left by a crash](#jobs-left-by-a-crash)). Pending jobs never count |
| `requests` | a mutating `/api` request (not GET, HEAD or OPTIONS) from a caller the access checks let through is being handled: uploads |
| `downloads` | a Mordor dataset download is running in the background |
| `siem-exports` | a worker is running a job's SIEM export: its heartbeat key in Redis is live (refreshed every 15 seconds, expiring after 60). A queued export doesn't count, as a pending job doesn't (see [Export Job to SIEM](#export-job-to-siem)) |
| `side-tasks` | a sample fetch or symbol table build queued in the worker hasn't finished (forgotten after six hours with no result) |
| `telemetry-build` | the Mordor telemetry update is running |
| `removals` | the worker is removing a job's old output (`removing`), its task waiting in the queue or its heartbeat beating; a removal whose worker died is failed after the same grace, with its own reason (registered by `removal_routes.py`) |

A check that fails (the database unreachable, say) counts as busy. A pending job isn't busy (decided 12 November 2026): it's a message in Celery's queue, and the queue is in Redis, which a rebuild doesn't recreate (`rowanholt start` runs `docker compose up -d --build`, which leaves the unchanged Redis container alone, and its `redis_data` volume keeps the RDB snapshots if it is ever recreated). The job waits out the rebuild and runs on the new worker a few minutes later; counting it held updates for hours behind a long queue. A job awaiting confirmation isn't busy: it waits on a person, in the database. Lab runs aren't counted: they run on the host, through the lab agent, which a rebuild doesn't touch.

#### Jobs left by a crash

The jobs table only says what was last saved, so a worker killed mid-job (its container recreated, the host restarted, out of memory) would leave its job `running` for ever and every rebuild held, and a job whose queued message Redis lost would stay `pending` for ever. Each job therefore has a signal of life in Redis (`src/web/backend/job_liveness.py`); only running and paused jobs feed `/api/busy`, but pending ones are checked the same way so a lost one is failed:

| Status | Live while |
|---|---|
| `running`, `paused` | the worker's heartbeat key exists. A thread in the worker refreshes it every 15 seconds with a 60-second expiry, from the task's start to its final save, whatever Elrond is doing: a Volatility or Plaso step silent for hours, or a paused job, keeps it |
| `pending` | the same heartbeat (a job waiting for its images' locks is still pending), or its task's message is in Celery's queue (any priority) or delivered to a worker and not yet started, or it was queued in the last two minutes |

A job with none of these is given a further 90 seconds, during which a running or paused one still counts as busy (a Redis restart loses every key while the workers carry on; their next refresh puts them back), then it's failed: status `failed`, the reason in `error` and as the last line of its log, `completed_at` set, a `job.failed` webhook, and its image locks released. Its output so far is kept and nothing is deleted; restart it as any failed job. A dead job stops holding rebuilds within about three minutes of dying: up to 60 seconds for its heartbeat to expire, then the grace. The backend looks for such jobs at start-up and every 30 seconds, and on each busy check; a pass is one indexed query and one Redis round trip.

The two reasons a user sees:

- *Interrupted: the worker running this job stopped without finishing it (killed, or its container or the host restarted). Its output so far is kept; restart the job to run it again.*
- *Interrupted: this job was queued, but its task is no longer in the queue and no worker picked it up (the worker or Redis restarted first). Restart the job to run it.*

A job whose task can't be queued at all (Redis down when it's created or restarted) is failed there and then with `Not queued: <error>`, and the request returns `500`; a confirmed removal that can't be queued returns `503`, with the job failed the same way.

**Authentication:** None, in server mode too. The answer is the one bit; which checks said busy goes to the backend's log, never to the caller.

**Response:** `200 OK`
```json
{
  "busy": false
}
```

New work a restart would cut off registers a check in `src/web/backend/busy.py`.

---

## Request/Response Formats

A successful response is the resource itself (a job, a list, a finding), with no wrapper. Most job actions return the job.

### Error Response

```json
{"detail": "Only the job's owner or an admin can cancel it"}
```

`detail` is a string, except in a few places where it's an object: a restart refused for findings (`{"findings": 3, "message": "..."}`) and Andúril's busy refusal (`{"message", "busy"}`). There are no error codes beyond the HTTP status.

### Validation Error Response (422)

FastAPI's, for a body or parameter of the wrong shape:

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "case_number"],
      "msg": "Field required"
    }
  ]
}
```

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Successful request
- `202 Accepted`: queued: a confirmed removal, an Andúril operation, a lab job
- `400 Bad Request`: Invalid request, or not allowed in the job's state
- `401 Unauthorized`: not signed in (server mode), or a wrong password
- `402 Payment Required`: the licence has no free place for another account, or this edition doesn't send webhooks
- `403 Forbidden`: not allowed: an admin area, someone else's job, a token's scope, a path outside the allowed folders, or a cookie request without `X-Rowanholt: 1`
- `404 Not Found`: not found, including a job or case the caller can't see
- `409 Conflict`: the state moved on (a job that ended before the cancel, a finding changed since it was loaded) or the action would clash (a busy service, an output folder in use)
- `413 Payload Too Large`: a threat intelligence file over 200 MB
- `422 Unprocessable Entity`: Validation error
- `429 Too Many Requests`: sign-in locked out
- `500 Internal Server Error`: Server error
- `502 Bad Gateway`: a TAXII collection or VirusTotal couldn't be read
- `503 Service Unavailable`: a dependency is missing: Ollama, the lab agent, Andúril, an Elrond package not mounted, the worker's queue, or the default `SECRET_KEY`

---

## Code Examples

Locally the API needs no token, so the sign-in below only matters on a team server (use its `https://<server>/api` address). A script there is better off with an [API token](#api-tokens) than a password.

### Python

```python
import requests

BASE_URL = "http://127.0.0.1:5688/api"

# Login
response = requests.post(f"{BASE_URL}/auth/login", data={
    "username": "user@example.com",
    "password": "password"
})
data = response.json()
token = data["access_token"]

# Create job with authentication
headers = {"Authorization": f"Bearer {token}"}
job_response = requests.post(
    f"{BASE_URL}/jobs",
    headers=headers,
    json={
        "case_number": "CASE-001",
        "source_paths": ["/evidence/disk.E01"],
        "destination_path": "/output/CASE-001",
        "options": {"analysis": True}
    }
)
job = job_response.json()
print(f"Job created: {job['id']}")

# Check job status
job_id = job["id"]
status_response = requests.get(f"{BASE_URL}/jobs/{job_id}", headers=headers)
print(f"Job status: {status_response.json()['status']}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

const BASE_URL = 'http://127.0.0.1:5688/api';

async function main() {
  // Login
  const loginResponse = await axios.post(
    `${BASE_URL}/auth/login`,
    new URLSearchParams({ username: 'user@example.com', password: 'password' })
  );

  const token = loginResponse.data.access_token;

  // Create job
  const jobResponse = await axios.post(
    `${BASE_URL}/jobs`,
    {
      case_number: 'CASE-001',
      source_paths: ['/evidence/disk.E01'],
      destination_path: '/output/CASE-001',
      options: { analysis: true }
    },
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  console.log('Job created:', jobResponse.data.id);

  // Monitor job
  const jobId = jobResponse.data.id;
  const statusResponse = await axios.get(
    `${BASE_URL}/jobs/${jobId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );

  console.log('Job status:', statusResponse.data.status);
}

main();
```

### cURL

```bash
# Login
curl -s -X POST http://127.0.0.1:5688/api/auth/login \
  -d "username=user@example.com" -d "password=password" \
  | jq -r '.access_token' > token.txt

TOKEN=$(cat token.txt)

# Or, on a team server, an API token made from a sign-in (shown once)
curl -s -X POST https://rowanholt.example.org/api/auth/tokens \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "nightly export", "scope": "full", "days": 90}' | jq -r '.token'

# Create job
curl -X POST http://127.0.0.1:5688/api/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "case_number": "CASE-001",
    "source_paths": ["/evidence/disk.E01"],
    "destination_path": "/output/CASE-001",
    "options": {"analysis": true}
  }'

# List jobs
curl -X GET "http://127.0.0.1:5688/api/jobs?status=running" \
  -H "Authorization: Bearer $TOKEN"

# Cancel job
curl -X POST "http://127.0.0.1:5688/api/jobs/{job_id}/cancel" \
  -H "Authorization: Bearer $TOKEN"
```

A bearer request needs no `X-Rowanholt` header; one signed in by the cookie (`curl -b`) does.

---

## Security Notes

1. **Keep the local API local.** It's open to anyone who can reach it, so it's published on `127.0.0.1` only; anything shared belongs on a team server
2. **Use HTTPS on a team server.** Caddy terminates TLS and is the only thing published ([SERVER.md](SERVER.md))
3. **Prefer API tokens for scripts.** Give each a name and the shortest life that works, `smith-mcp` where reads, leads and notes are enough, and revoke it when it's done with
4. **Never log or share a token.** A JWT can't be revoked before it expires (24 hours); an API token can
5. **Set `SECRET_KEY`.** With the default, anyone could forge a JWT: the lab and Andúril refuse to run, and a team server won't start

---

## Rate Limiting

There's none, apart from sign-in lockouts: five failed passwords from one address lock that username from that address for 15 minutes, and fifty across all addresses lock it everywhere ([SERVER.md](SERVER.md#how-sign-in-lockouts-work)).

---

## Pagination

Lists that page take `limit` and `offset` and return a `total`:

| Endpoint | `limit` |
|---|---|
| `GET /api/jobs` | default 50, at most 100 |
| `GET /api/threat-intel/indicators` | default 100, at most 500 |
| `GET /api/mordor/catalog`, `/api/mordor/datasets` | default 50, at most 200 |
| `GET /api/jobs/{job_id}/case/rows` | default 100, at most 500 |

**Example:**
```
GET /api/jobs?limit=20&offset=40
```

---

## WebSocket Support

Two, both under `/api` and authenticated like the HTTP routes, by the session cookie or a bearer header, never a token in the URL, and refused (code 1008) from a page on an origin the backend doesn't serve:

- `/api/jobs/{job_id}/case/live`: when a case's activity, or its job's status or progress, changes, so a page knows to reload ([Case Browser](#case-browser-and-collaboration))
- `/api/lab/consoles/{engine}/{name}/ws`: a lab VM's VNC stream, admins only ([Lab](#lab))

Job progress has no socket of its own: poll `GET /api/jobs/{job_id}`.

---

**For additional support, see:**
- [SERVER.md](SERVER.md) - Running Rowanholt as a team server: sign-in, users, sharing
- [SECURITY.md](SECURITY.md) - Security implementation details
- [QUICKSTART.md](QUICKSTART.md) - Getting started guide
- [USAGE.md](USAGE.md) - Complete user documentation

---

**Version:** 2.1.0
**Last Updated:** 2026-11-12
**License:** See LICENSE file
