# Rivendell Web API Reference

**Version:** 2.1.0
**Base URL:** `http://localhost:5688/api`
**Protocol:** REST
**Authentication:** JWT Bearer Token or HTTP-only Cookie

---

## Table of Contents

1. [Authentication Status](#authentication-status)
2. [Authentication](#authentication)
3. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
4. [Admin Endpoints](#admin-endpoints)
5. [Job Management](#job-management)
6. [File System](#file-system)
7. [Docker Administration (Anduril)](#docker-administration-anduril)
8. [Mordor: Recorded Attack Telemetry](#mordor-recorded-attack-telemetry)
9. [Threat Intelligence](#threat-intelligence)
10. [Case Browser and Collaboration](#case-browser-and-collaboration)
11. [Eru (AI Analyst)](#eru-ai-analyst)
12. [Lab](#lab)
13. [Health Check](#health-check)
14. [Request/Response Formats](#requestresponse-formats)
15. [Error Handling](#error-handling)
16. [Code Examples](#code-examples)

---

## Authentication Status

The backend mounts the simple file-based auth router (`src/web/backend/auth/routes_simple.py`, users in `USERS_FILE`, default `/app/data/users.json`). It provides `register`, `login`, `guest`, `logout`, a stub `me` and a stub `forgot-password`. The MFA, password-reset and admin endpoints below are implemented in `auth/routes.py`, which is not mounted.

No job, file-system, AI or Mordor endpoint checks the token or cookie, so anyone who can reach port 5688 can submit, read, cancel and delete jobs. Keep the API on localhost or behind a reverse proxy that authenticates.

---

## Authentication

All authenticated endpoints require either:
- **Bearer Token** in `Authorization` header: `Authorization: Bearer <token>`
- **HTTP-only cookie** set during login

### Register New User

**Endpoint:** `POST /auth/register`

**Description:** Create a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "SecurePassword123!",
  "full_name": "John Doe"  // Optional
}
```

**Response:** `201 Created`
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "full_name": "John Doe",
    "role": "user",
    "is_active": true,
    "created_at": "2025-01-15T10:00:00Z",
    "last_login": null
  }
}
```

**Validation:**
- Email: Valid email format
- Username: Min 3 chars, alphanumeric + underscores only
- Password: Min 8 characters
- Full name: Optional, max 255 characters

**Errors:**
- `400 Bad Request`: Validation error or user already exists
- `500 Internal Server Error`: Server error

---

### Login

**Endpoint:** `POST /auth/login`

**Description:** Authenticate and receive an access token. Also sets an HTTP-only cookie.

**Request Body:** OAuth2 form data (`application/x-www-form-urlencoded`), not JSON. `username` accepts the username or the email address.

```bash
curl -X POST http://localhost:5688/api/auth/login \
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
    "role": "user"
  }
}
```

There is no MFA step in the mounted auth router.

**Errors:**
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account disabled
- `500 Internal Server Error`: Server error

---

### Login as Guest

**Endpoint:** `POST /auth/guest`

**Description:** Create temporary guest session (expires in 1 hour).

**Request Body:** None

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "uuid",
    "email": null,
    "username": "guest_abc123",
    "full_name": "Guest User",
    "role": "guest",
    "is_active": true,
    "created_at": "2025-01-15T12:00:00Z",
    "last_login": "2025-01-15T12:00:00Z"
  }
}
```

---

### Logout

**Endpoint:** `POST /auth/logout`

**Description:** End current session and invalidate token.

**Authentication:** Required

**Request Body:** None

**Response:** `200 OK`
```json
{
  "message": "Successfully logged out"
}
```

---

### Get Current User

> **Stub.** Returns a fixed guest user in the current build.

**Endpoint:** `GET /auth/me`

**Description:** Retrieve current authenticated user information.

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "full_name": "John Doe",
    "role": "user",
    "is_active": true,
    "mfa_enabled": false,
    "created_at": "2025-01-15T10:00:00Z",
    "last_login": "2025-01-15T12:00:00Z"
  }
}
```

---

### Forgot Password

> **Stub.** Always returns the success message; no email is sent.

**Endpoint:** `POST /auth/forgot-password`

**Description:** Request password reset email (development: token logged to console).

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset instructions sent to email",
  "reset_token": "abc123..."  // Only in development mode
}
```

**Note:** In production, token is sent via email only.

---

### Reset Password

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/reset-password`

**Description:** Reset password using token from forgot-password endpoint.

**Request Body:**
```json
{
  "token": "reset_token_here",
  "new_password": "NewSecurePassword123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset successful"
}
```

**Errors:**
- `400 Bad Request`: Invalid token, token expired, or password validation failed
- `500 Internal Server Error`: Server error

---

## Multi-Factor Authentication (MFA)

### Setup MFA

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/mfa/setup`

**Description:** Initialize MFA setup and generate TOTP secret with QR code URI.

**Authentication:** Required

**Response:** `200 OK`
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_uri": "otpauth://totp/Rivendell:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Rivendell",
  "backup_codes": [
    "1234-5678",
    "9012-3456",
    ...  // 10 codes total
  ]
}
```

**Note:** Save backup codes securely. They are shown only once.

---

### Enable MFA

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/mfa/enable`

**Description:** Enable MFA after verifying TOTP code.

**Authentication:** Required

**Request Body:**
```json
{
  "code": "123456"  // 6-digit TOTP code from authenticator app
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA enabled successfully"
}
```

**Errors:**
- `400 Bad Request`: Invalid TOTP code or MFA already enabled
- `401 Unauthorized`: Not authenticated

---

### Disable MFA

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/mfa/disable`

**Description:** Disable MFA for current user.

**Authentication:** Required

**Request Body:**
```json
{
  "code": "123456"  // Current TOTP code or backup code
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA disabled successfully"
}
```

---

### Verify MFA

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/mfa/verify`

**Description:** Complete login with MFA code.

**Request Body:**
```json
{
  "temp_token": "temporary_token_from_login",
  "code": "123456"  // TOTP code or backup code
}
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
    "role": "user",
    "mfa_enabled": true
  }
}
```

**Errors:**
- `401 Unauthorized`: Invalid code or temp token
- `400 Bad Request`: Backup code already used

---

### Regenerate Backup Codes

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/mfa/regenerate-backup-codes`

**Description:** Generate new set of backup codes (invalidates old ones).

**Authentication:** Required

**Request Body:**
```json
{
  "code": "123456"  // Current TOTP code for verification
}
```

**Response:** `200 OK`
```json
{
  "backup_codes": [
    "1234-5678",
    "9012-3456",
    ...  // 10 new codes
  ]
}
```

---

## Admin Endpoints

**Role Required:** `ADMIN`

### Reset User Password (Admin)

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/admin/reset-user-password`

**Description:** Admin can reset any user's password (except other admins). Invalidates all user sessions.

**Authentication:** Admin role required

**Request Body:**
```json
{
  "user_id": "uuid",
  "new_password": "NewPassword123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset successful for user username"
}
```

**Errors:**
- `403 Forbidden`: Cannot reset admin passwords or insufficient permissions
- `404 Not Found`: User not found

---

### Disable User MFA (Admin)

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/admin/disable-user-mfa`

**Description:** Emergency MFA disable for locked-out users.

**Authentication:** Admin role required

**Request Body:**
```json
{
  "user_id": "uuid"
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA disabled for user username"
}
```

**Errors:**
- `400 Bad Request`: MFA not enabled for user
- `404 Not Found`: User not found

---

### Toggle User Account Status (Admin)

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `POST /auth/admin/toggle-user-status`

**Description:** Enable or disable user account.

**Authentication:** Admin role required

**Request Body:**
```json
{
  "user_id": "uuid",
  "is_active": false  // true to enable, false to disable
}
```

**Response:** `200 OK`
```json
{
  "message": "User account disabled successfully"
}
```

**Errors:**
- `403 Forbidden`: Cannot disable admin accounts or insufficient permissions
- `404 Not Found`: User not found

---

### List All Users (Admin)

> **Not mounted.** Implemented in `auth/routes.py`; the backend mounts `auth/routes_simple.py`, which does not provide this endpoint.

**Endpoint:** `GET /auth/admin/users`

**Description:** Get list of all users with security status.

**Authentication:** Admin role required

**Query Parameters:**
- `role` (optional): Filter by role (user, admin, guest)
- `active_only` (optional): Boolean, show only active users

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "email": "user@example.com",
    "username": "username",
    "full_name": "John Doe",
    "role": "user",
    "is_active": true,
    "mfa_enabled": false,
    "created_at": "2025-01-15T10:00:00Z",
    "last_login": "2025-01-15T12:00:00Z"
  },
  ...
]
```

---

## Job Management

### Create Job

**Endpoint:** `POST /api/jobs`

**Description:** Create and queue a new forensic analysis job.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

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

`options` maps onto Elrond's command line (`build_elrond_command` in `tasks_docker.py`). All are optional booleans unless shown otherwise:

| Group | Fields |
|---|---|
| Source | `local` (default `true`; collect from images), `gandalf` (pre-collected Gandalf archives) |
| Modes | `brisk`, `mordor` |
| Phases | `analysis`, `memory`, `memory_timeline`, `timeline` |
| Collection | `vss`, `userprofiles`, `collectFiles` + `collectFiles_filter`, `collect_files_all`, `collect_files_archive`, `collect_files_bin`, `collect_files_docs`, `collect_files_hidden`, `collect_files_lnk`, `collect_files_mail`, `collect_files_scripts`, `collect_files_unalloc` (carving), `collect_files_virtual`, `collect_files_web` |
| Detection | `extract_iocs` + `iocs_file`, `keywords` + `keywords_file`, `yara` + `yara_dir`, `misplaced_binaries`, `masquerading` |
| Hashing | `hash_collected`, `hash_all`, `nsrl` |
| Output | `splunk`, `elastic`, `navigator`, `archive`, `delete`, `save_template` |
| Job control | `force_overwrite` (remove an existing `destination_path`), `debug` (verbose job log) |

Paths are passed to the worker unchanged, except `/host/tmp/rivendell/…`, which becomes `/tmp/elrond/output/…`. Host paths under `/Volumes` work because both containers mount `/Volumes` at the same path.

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "case_number": "CASE-2025-001",
  "source_paths": ["/evidence/disk.E01"],
  "destination_path": "/output/CASE-2025-001",
  "options": {},
  "status": "pending",
  "progress": 0,
  "log": [],
  "result": null,
  "error": null,
  "celery_task_id": "task-uuid",
  "created_at": "2025-01-15T12:00:00Z",
  "started_at": null,
  "completed_at": null
}
```

**Validation:**
- `case_number`: Required, sanitized (alphanumeric, hyphens, underscores)
- `source_paths`: Required, non-empty array, validated against allowed paths
- `destination_path`: Required, validated path
- `options`: Optional JSON object

**Errors:**
- `400 Bad Request`: Validation error or invalid paths
- `403 Forbidden`: Guest users cannot create jobs or access denied to path
- `500 Internal Server Error`: Server error

---

### List Jobs

**Endpoint:** `GET /api/jobs`

**Description:** List all jobs. Jobs are not filtered by user in the current build.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Query Parameters:**
- `status` (optional): Filter by status (pending, running, awaiting_confirmation, completed, failed, cancelled, archived)
- `limit` (optional): Number of results (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)
- `case_number` (optional): Filter by case number

**Response:** `200 OK`
```json
{
  "jobs": [
    {
      "id": "uuid",
      "case_number": "CASE-2025-001",
      "status": "completed",
      "progress": 100,
      "created_at": "2025-01-15T12:00:00Z",
      "completed_at": "2025-01-15T13:00:00Z"
    },
    ...
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

---

### Get Job Details

**Endpoint:** `GET /api/jobs/{job_id}`

**Description:** Retrieve detailed information about a specific job.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

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
    {"timestamp": "2025-01-15T12:00:00Z", "level": "INFO", "message": "Job started"},
    {"timestamp": "2025-01-15T12:15:00Z", "level": "INFO", "message": "Processing artifacts..."}
  ],
  "result": null,
  "error": null,
  "celery_task_id": "task-uuid",
  "created_at": "2025-01-15T12:00:00Z",
  "started_at": "2025-01-15T12:00:01Z",
  "completed_at": null
}
```

**Errors:**
- `404 Not Found`: Job not found or unauthorized access

---

### Delete Job

**Endpoint:** `DELETE /api/jobs/{job_id}`

**Description:** Permanently delete a job. Cannot delete pending or running jobs (cancel first).

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK`
```json
{"message": "Job deleted successfully"}
```

**Errors:**
- `400 Bad Request`: Cannot delete running job
- `404 Not Found`: Job not found

---

### Cancel Job

**Endpoint:** `POST /api/jobs/{job_id}/cancel`

**Description:** Cancel a pending or running job. Revokes the Celery task with `SIGKILL` and releases the job's image locks. Child processes started by Elrond (foremost, yara, log2timeline) are not killed and keep the image mounted; see `tests/docs/TEST_RUNNER_GUIDE.md` for clean-up.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK` with the updated job object (`"status": "cancelled"`).

**Errors:**
- `400 Bad Request`: Job is not pending or running. A job in `awaiting_confirmation` must be cancelled with `cancel-sudo`.
- `404 Not Found`: Job not found

---

### Confirm Directory Removal

**Endpoint:** `POST /api/jobs/{job_id}/confirm-sudo`

**Description:** When a job is submitted with `force_overwrite` and the worker cannot remove the existing destination directory (error or timeout), the job stops in `awaiting_confirmation`. Confirming removes the directory with sudo and starts the job again as a new Celery task.

**Response:** `200 OK` with the updated job object.

**Errors:**
- `400 Bad Request`: Job is not awaiting confirmation
- `404 Not Found`: Job not found

---

### Cancel Directory Removal

**Endpoint:** `POST /api/jobs/{job_id}/cancel-sudo`

**Description:** Decline the directory removal for a job in `awaiting_confirmation`. The job is marked failed with "Directory removal cancelled by user". This is the only way to cancel a job in that state.

**Response:** `200 OK` with the updated job object.

**Errors:**
- `400 Bad Request`: Job is not awaiting confirmation
- `404 Not Found`: Job not found

---

### Restart Job

**Endpoint:** `POST /api/jobs/{job_id}/restart`

**Description:** Restart a failed, cancelled or completed job. Creates new Celery task. A job with findings is refused unless the request confirms, since the re-run rewrites the rows they point at.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

**Query Parameters:**
- `confirm` (bool, default `false`): restart even though the job has findings

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "status": "pending",
  "celery_task_id": "new-task-uuid",
  "message": "Job restarted successfully"
}
```

**Errors:**
- `400 Bad Request`: Job not in failed/cancelled/completed state
- `404 Not Found`: Job not found
- `409 Conflict`: The job has findings and `confirm` wasn't set; `detail` is `{"findings": 3, "message": "..."}`

---

### Archive Job

**Endpoint:** `POST /api/jobs/{job_id}/archive`

**Description:** Archive a completed or failed job. Preserves original status for restoration.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "status": "archived",
  "archived_at": "2025-01-15T15:00:00Z",
  "message": "Job archived successfully"
}
```

**Errors:**
- `400 Bad Request`: Cannot archive running jobs
- `404 Not Found`: Job not found

---

### Unarchive Job

**Endpoint:** `POST /api/jobs/{job_id}/unarchive`

**Description:** Restore archived job to original status (completed/failed).

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Path Parameters:**
- `job_id`: UUID of the job

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "status": "completed",  // Restored to original status
  "archived_at": null,
  "message": "Job restored successfully"
}
```

**Errors:**
- `400 Bad Request`: Job not archived
- `404 Not Found`: Job not found

---

### Bulk Restart Jobs

**Endpoint:** `POST /api/jobs/bulk/restart`

**Description:** Restart failed, cancelled or completed jobs. Takes a bare JSON array of job IDs and returns a result per job. Without `confirm=true`, a job with findings is skipped: its result has `success: false`, the reason in `error` and the count in `findings`.

**Query Parameters:**
- `fresh` (bool, default `false`): remove each job's previous output before it runs again
- `confirm` (bool, default `false`): restart jobs that have findings too

---

### Export Job to SIEM

**Endpoint:** `POST /api/jobs/{job_id}/export-siem`

**Description:** Run, or re-run, the SIEM export for a completed job.

---

### Get Navigator Layer

**Endpoint:** `GET /api/jobs/{job_id}/navigator`

**Description:** Download the job's MITRE ATT&CK Navigator JSON layer.

---

### Validate Case ID

**Endpoint:** `GET /api/validate/case-id/{case_id}`

**Description:** Check whether a case ID is already in use.

**Response:** `200 OK`
```json
{"exists": true, "jobs": ["uuid1"]}
```

---

### Check and Upload Required Files

**Endpoints:** `POST /api/check-required-files`, `POST /api/upload-required-files`

**Description:** Keyword, YARA and collect-files options need input files. `check-required-files` takes `{"options": ["keywords", "yara", "collectFiles"]}` and returns `{"missing": [...], "found": [...]}`. `upload-required-files` takes multipart fields `keywords`, `yara` and `collectFiles`.

---

### Bulk Cancel Jobs

**Endpoint:** `POST /api/jobs/bulk/cancel`

**Description:** Cancel multiple jobs at once.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Request Body:**
A bare JSON array of job IDs:

```json
["uuid1", "uuid2", "uuid3"]
```

**Response:** `200 OK`
```json
{
  "cancelled": 3,
  "failed": 0,
  "errors": []
}
```

---

### Bulk Delete Jobs

**Endpoint:** `POST /api/jobs/bulk/delete`

**Description:** Delete multiple jobs at once.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Request Body:**
A bare JSON array of job IDs:

```json
["uuid1", "uuid2", "uuid3"]
```

**Response:** `200 OK`
```json
{
  "deleted": 3,
  "failed": 0,
  "errors": []
}
```

---

### Bulk Archive Jobs

**Endpoint:** `POST /api/jobs/bulk/archive`

**Description:** Archive multiple jobs at once.

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Request Body:**
A bare JSON array of job IDs:

```json
["uuid1", "uuid2", "uuid3"]
```

**Response:** `200 OK`
```json
{
  "archived": 3,
  "failed": 0,
  "errors": []
}
```

---

## File System

### Browse File System

**Endpoint:** `GET /api/fs/browse`

**Description:** Browse server filesystem (limited to configured allowed paths).

**Authentication:** Not enforced in the current build (see [Authentication Status](#authentication-status))

**Query Parameters:**
- `path` (optional): Path to browse (default: "/")

**Response:** `200 OK`
```json
[
  {
    "name": "evidence",
    "path": "/evidence",
    "type": "directory",
    "size": null,
    "modified": "2025-01-15T10:00:00Z"
  },
  {
    "name": "disk.E01",
    "path": "/evidence/disk.E01",
    "type": "file",
    "size": 10737418240,
    "modified": "2025-01-15T09:00:00Z"
  }
]
```

**Errors:**
- `403 Forbidden`: Access denied to path
- `404 Not Found`: Path does not exist

---

## Docker Administration (Anduril)

**Role Required:** `ADMIN` (except `/status`)

Anduril manages Rivendell's own containers and images. The backend doesn't hold the Docker socket: these endpoints proxy to the `anduril` service over the internal `rivendell-anduril` network. Anduril only acts on containers that carry the `com.docker.compose.project=rivendell` label and are named `rivendell-*`, and on the images those containers use; anything else returns `403`. The API is off (`503`) until Anduril is enabled on the host with `rivendell anduril enable`, and it stays off while the backend uses the default `SECRET_KEY`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/anduril/status` | Whether Anduril is usable. No authentication; returns `enabled`, `reason` (`secret_key`, `not_enabled`, `unreachable`) and `enable_command` |
| `GET` | `/api/anduril/containers` | Rivendell containers: name, service, image, state, health, upstream or built image |
| `GET` | `/api/anduril/images` | Rivendell images: tags, size, whether built locally, which containers use them |
| `GET` | `/api/anduril/containers/{name}/logs?tail=200` | Last `tail` log lines (1–5000) |
| `GET` | `/api/anduril/containers/{name}/stats` | One CPU, memory, network and block I/O sample |
| `POST` | `/api/anduril/containers/{name}/{action}` | `start`, `stop`, `restart`, `update` (pull the upstream image and recreate if newer) or `recreate`. Body: `{"force": false}` |
| `POST` | `/api/anduril/images/pull` | Pull a newer version of an upstream image Rivendell uses. Body: `{"ref": "redis:7-alpine"}` |
| `POST` | `/api/anduril/images/remove` | Remove an unused Rivendell image (never forced). Body: `{"id": "sha256:..."}` |
| `POST` | `/api/anduril/images/prune` | Remove dangling images built for Rivendell |
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

Anduril won't stop, restart or recreate its own container from the API. Use `rivendell anduril disable` on the host.

---

## Mordor: Recorded Attack Telemetry

**Authentication:** none to read; `ADMIN` for Update and the lab

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

### Mordor Lab

**Role Required:** `ADMIN`

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

**Authentication:** none to read; `ADMIN` to import, pull or delete on a team server

The indicators in `threat_intel_indicators`, in the fixed ten-column schema (Evidential Element, Threat Group, Procedure Example, Technique ID, Technique Name, Tactic, Contextual Evidence, Reference URL, Navigation Layer URL, Source Type). Parsing and matching are Elrond's (`src/analysis/rivendell/threat_intel/`); the backend mounts that package. A job with `"threat_intel": true` exports them for Elrond's `--threatIntel`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threat-intel` | `total`, `groups`, and `sources`: `[{source, count}]` |
| `GET` | `/api/threat-intel/indicators?q=&source=&limit=&offset=` | Indicators whose element, group or technique ID contains `q`; `limit` up to 500 |
| `POST` | `/api/threat-intel/import` | Multipart `file`: the Iran APT workbook (XLSX), a STIX 2.1 bundle (JSON), Rivendell's or MITRESaw's CSV, or a `.txt` watchlist. Up to 200 MB. Returns `read`, `added`, `duplicates` and `sources`; indicators already stored under the same element, group, technique and source are skipped |
| `POST` | `/api/threat-intel/taxii` | `{"url", "username", "password", "added_after"}`: every object in a TAXII 2.1 collection. `502` when the collection can't be read |
| `DELETE` | `/api/threat-intel/sources/{source}` | Every indicator from one source |
| `GET` | `/api/threat-intel/enrich?value=` | What the indicators say about one process name, command line, path, IP, domain or hash: per element, its `kind`, `breadth` (groups using it), `common` (more than 15), `groups`, `techniques` and `sources` |

`503` means the package isn't mounted in the backend (`docker compose up -d backend` after pulling).

---

## Case Browser and Collaboration

**Authentication:** whoever can see the job (its owner, the people it's shared with, admins); everyone in local mode

A job's output, read-only, and the team's findings, notes, host assignments and activity on it (`case_routes.py`, `case_files.py`). Only `<host>/artefacts/cooked/`, `<host>/analysis/` and the case's top-level CSVs are readable; `raw/` never is, and nothing writes to the case directory. Findings reference a row by file, row (`2` onwards for a CSV line, `#0` onwards for a JSON record) and the SHA-256 of the row, so a re-run that changes it shows up.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/jobs/{job_id}/case` | `hosts` (each with `files`, `assignee`, `status`), `case_files`, and `findings` counted by status. `404` until the job has output |
| `GET` | `/api/jobs/{job_id}/case/rows?host=&path=&q=&offset=&limit=` | Rows of one table containing `q` in any field: `columns`, `rows` (`ref`, `hash`, `cells`), `total`, and `exact` (false when the count stopped early). `host` is `(case)` for the case's own files |
| `GET` | `/api/jobs/{job_id}/case/findings?status=&verify=` | Findings; with `verify=true`, `intact` says whether each row still hashes the same |
| `POST` | `/api/jobs/{job_id}/case/findings` | `{"host", "artefact", "row_ref", "title", "technique", "status"}`; the row is read server-side for its hash and excerpt. `status` is `lead` (default), `confirmed` or `benign`; `technique` an ATT&CK ID. `409` if the row is already flagged |
| `PATCH` | `/api/jobs/{job_id}/case/findings/{id}` | Change `title`, `technique` or `status`; pass the `updated_at` you loaded and a change someone else made first returns `409` instead of being overwritten |
| `DELETE` | `/api/jobs/{job_id}/case/findings/{id}` | Remove a finding and its notes |
| `GET` `POST` | `/api/jobs/{job_id}/case/notes` | Notes, Markdown: `{"body", "finding_id"}`, `finding_id` null for the case |
| `PUT` | `/api/jobs/{job_id}/case/hosts/{host}` | `{"assignee", "status"}`; status is `to do`, `in progress` or `done`. In server mode the assignee must be an active user (username or email, stored as the username), otherwise `400`; `""` unassigns |
| `GET` | `/api/jobs/{job_id}/case/activity?since=` | Who did what, newest first; `since` (the highest `id` seen) for polling |
| `GET` | `/api/jobs/{job_id}/case/report` | Markdown: case notes, then confirmed findings by host with their notes |
| `GET` | `/api/jobs/{job_id}/case/layer` | An ATT&CK Navigator layer of confirmed findings' techniques only |

---

## Eru (AI Analyst)

**Authentication:** none

Ask Eru's back end. Free-text answers come from Ollama at `OLLAMA_HOST` (default `http://host.docker.internal:11434`) with the model `RIVENDELL_MODEL_NAME` (default `llama3.2:3b`) and a `RIVENDELL_NUM_CTX`-token window (default 8192). Without them, `/status` says why and the offline endpoints answer fixed questions from Elrond's output.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/ai/status` | `llm_available`, `ollama_running`, `model_name`, `models`, `ollama_host`, `data_dir`, and `reason`: why free text won't work (empty when it will) |
| `GET` | `/api/ai/offline/questions` | The fixed questions: `id`, `question`, `needs_case` (including `threat_intel` and `findings`) |
| `POST` | `/api/ai/offline/answer` | `{"question_id": "techniques", "case_id": "CASE-001"}` (`case_id` only where `needs_case`). Returns `{"answer", "rows", "job_id", "offline": true}`: `rows` are the rows the answer's shown lines came from (`host`, `file`, `row_ref`, `hash`, `line`), the reference a finding stores, so `POST /api/jobs/{job_id}/case/findings` can flag one; `job_id` is the job (one the caller can see) whose case was read, and `rows` is empty without one. Counts (hosts, IOCs, logins by user) cite nothing. `404` for an unknown question |
| `GET` | `/api/ai/cases` | Cases Eru can see: indexed vector stores and completed jobs, with `indexed` and `has_artifacts` |
| `POST` | `/api/ai/chat` | `{"message": "..."}` without case context. Returns `{"response", "model", "processing_time"}` |
| `GET` | `/api/ai/cases/{case_id}/info` | What is indexed for a case |
| `POST` | `/api/ai/cases/{case_id}/query` | `{"question": "..."}` answered from the case's data; `rows` are the rows the answer cites by tag (`host`, `file`, `row_ref`, `hash`, `line`, `tag`), only ones it was given, on `job_id` (empty without a job) |
| `POST` | `/api/ai/cases/{case_id}/suggestions` | Investigation paths to follow |
| `POST` | `/api/ai/cases/{case_id}/summary` | An executive summary of the case, with the `rows` it cites and `job_id`, as for `/query` |

The LLM endpoints return `503` when Ollama or the model isn't available.

---

## Lab

**Role Required:** `ADMIN` (except `/status`)

The test lab (`lab/`) from the browser: Linux targets, Tart and UTM VMs, Gandalf against seeded hosts. Docker, Tart and UTM are on the host, so these proxy to the lab agent (`./lab.sh agent start`, loopback `:5691`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/lab/status` | Whether the agent is reachable. No authentication; returns `available`, and `reason` and `start_command` when it isn't |
| `GET` | `/api/lab/state` | Host profile, lab settings, whether the lab password is stored, and any running command |
| `PUT` | `/api/lab/config` | `{"settings": {...}}`: change `lab.conf` on the host |
| `PUT` | `/api/lab/password` | `{"password": "..."}`: store the lab password in the host's keyring |
| `POST` | `/api/lab/run` | `{"command": "gandalf-collect", "args": ["bash"]}`: start a `lab.sh` command |
| `GET` | `/api/lab/runs` | Recent runs |
| `GET` | `/api/lab/runs/{id}?offset=` | A run's status and its output from byte `offset` on |
| `POST` | `/api/lab/runs/{id}/cancel` | Cancel a run |

---

## Health Check

### Health Status

**Endpoint:** `GET /api/health`

**Description:** Check API health status.

**Authentication:** None

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T12:00:00Z",
  "version": "2.1.0"
}
```

---

## Request/Response Formats

### Standard Success Response

```json
{
  "data": { ... },
  "message": "Operation successful"
}
```

### Standard Error Response

```json
{
  "detail": "Error description",
  "error_code": "ERR_001"  // Optional
}
```

### Validation Error Response (422)

```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "Invalid email format",
      "type": "value_error.email"
    }
  ]
}
```

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `204 No Content`: Successful deletion
- `400 Bad Request`: Invalid request or validation error
- `401 Unauthorized`: Authentication required or invalid credentials
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation error
- `500 Internal Server Error`: Server error

### Common Error Codes

- `ERR_AUTH_001`: Invalid credentials
- `ERR_AUTH_002`: Account disabled
- `ERR_AUTH_003`: MFA verification failed
- `ERR_JOB_001`: Job not found
- `ERR_JOB_002`: Invalid job state transition
- `ERR_PATH_001`: Path access denied

---

## Code Examples

### Python

```python
import requests

BASE_URL = "http://localhost:5688/api"

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

const BASE_URL = 'http://localhost:5688/api';

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
curl -s -X POST http://localhost:5688/api/auth/login \
  -d "username=user@example.com" -d "password=password" \
  | jq -r '.access_token' > token.txt

TOKEN=$(cat token.txt)

# Create job
curl -X POST http://localhost:5688/api/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "case_number": "CASE-001",
    "source_paths": ["/evidence/disk.E01"],
    "destination_path": "/output/CASE-001",
    "options": {"analysis": true}
  }'

# List jobs
curl -X GET "http://localhost:5688/api/jobs?status=running" \
  -H "Authorization: Bearer $TOKEN"

# Cancel job
curl -X POST "http://localhost:5688/api/jobs/{job_id}/cancel" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Security Best Practices

1. **Always use HTTPS in production** - Encrypt all API communication
2. **Store tokens securely** - Never log or expose JWT tokens
3. **Implement rate limiting** - Prevent brute force attacks
4. **Validate all inputs** - API performs sanitization, but client validation helps UX
5. **Use MFA for sensitive accounts** - Especially admin accounts
6. **Rotate tokens regularly** - Implement token refresh mechanism
7. **Monitor API usage** - Track suspicious activity
8. **Keep secrets secret** - Use environment variables, never hardcode

---

## Rate Limiting

**Status:** Planned for v2.2

Future rate limits (per user):
- Authentication endpoints: 10 requests/minute
- Job creation: 100 requests/hour
- Other endpoints: 1000 requests/hour

---

## Pagination

For list endpoints (e.g., `/api/jobs`):

**Query Parameters:**
- `limit`: Number of results per page (default: 50, max: 100)
- `offset`: Number of results to skip (default: 0)

**Response includes:**
- `total`: Total number of results
- `limit`: Applied limit
- `offset`: Applied offset

**Example:**
```
GET /api/jobs?limit=20&offset=40
```

---

## WebSocket Support

**Status:** Planned for v2.2

Real-time job progress updates via WebSocket:

```javascript
const ws = new WebSocket('ws://localhost:5688/ws/jobs/{job_id}');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  console.log(`Progress: ${update.progress}%`);
  console.log(`Status: ${update.status}`);
};
```

---

**For additional support, see:**
- [SECURITY.md](SECURITY.md) - Security implementation details
- [QUICKSTART.md](QUICKSTART.md) - Getting started guide
- [USAGE.md](USAGE.md) - Complete user documentation

---

**Version:** 2.1.0
**Last Updated:** 2026-10-22
**License:** See LICENSE file
