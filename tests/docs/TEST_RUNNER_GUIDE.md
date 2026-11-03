# Dernvale Test Runner Guide

How to run the E2E tests against the Docker stack, control jobs while they run, and read the results. All commands run from the repository root.

## Before You Start

Start the stack with the worker at concurrency 1. Higher concurrency lets jobs share `/mnt/elrond_mountNN` and unmount each other's images, so every long run should use an override that sets `--concurrency=1`:

```yaml
# docker-compose.concurrency1.yml
services:
  celery-worker:
    command: sh -c 'cd /app && PYTHONPATH=/app exec /usr/bin/python3 -m celery -A tasks_docker.celery_app worker --loglevel=info --concurrency=1'
```

```bash
docker compose -f docker-compose.yml -f docker-compose.concurrency1.yml up -d
# add the SIEM services for splunk/elastic/navigator tests
docker compose -f docker-compose.yml -f docker-compose.concurrency1.yml --profile siem up -d
```

Always pass both `-f` files. A plain `docker compose up` recreates the worker without the override.

Give Docker Desktop at least 16 GB of memory if the SIEM profile is up. Splunk under Rosetta, Elastic, Kibana and a running job together can exhaust 12 GB and crash the VM. The worker is capped at 8 GB in `docker-compose.yml`.

Don't rebuild the worker image while a heavy job and the SIEM profile are running. The build alone pushed the VM over during testing.

## Paths

| Variable | Default | Purpose |
|---|---|---|
| `TEST_IMAGES_PATH` | first match of `/Volumes/*/dernvale_imgs`, `/Volumes/*/dernvale`, `/Volumes/*/*/dernvale`, `/mnt/*/dernvale_imgs`, `/media/*/dernvale_imgs`, then `/tmp/dernvale` | Evidence images |
| `TEST_OUTPUT_PATH` | `$TEST_IMAGES_PATH/tests` | One output directory per test |
| `DERNVALE_API_URL` | `http://localhost:5688` | Backend API |

Keep `TEST_OUTPUT_PATH` outside the image folder if you can. Before 22 Oct 2026 `$I30` extraction walked the whole evidence directory, so every test output stored beside the images slowed every later Windows job.

```bash
TEST_OUTPUT_PATH=/Volumes/Portable6TB/Data/rivendell/claude_testing \
  python3 tests/scripts/run_test.py --validate
```

## Running Tests

`tests/scripts/run_test.py` submits tests to the API. It defines 120 test cases.

| Command | Does |
|---|---|
| `--list [--tags windows memory]` | List tests, optionally filtered by tag |
| `--show NAME` | Show a test's images, options and estimate |
| `--validate` | Check every test image exists |
| `--run NAME [--wait]` | Submit one test; `--wait` blocks until it finishes |
| `--queue NAME [NAME ...]` | Submit several tests; the worker runs them in order |
| `--run-tags TAG [TAG ...]` | Submit every test with the given tags |
| `--yes` | Overwrite an existing output directory without prompting |
| `--generate-jobs [-o DIR]` | Write job JSON files for the web UI |

```bash
python3 tests/scripts/run_test.py --yes --queue win_brisk linux_analysis
```

If a test's output directory already exists, `run_test.py` asks before overwriting it; `--yes` answers yes. The worker then runs `rm -rf` on the old directory. If that fails or times out, which happens with carving output (tens of thousands of files over VirtioFS), the job parks in `awaiting_confirmation` until someone confirms a sudo removal or cancels it (see Job Control). Rename large old outputs aside before re-running instead.

## Job Control

| Command | Does |
|---|---|
| `--status` | Running, pending, completed and failed jobs |
| `--cancel JOB_ID [JOB_ID ...]` | Cancel specific jobs. Falls back to `/cancel-sudo` for jobs in `awaiting_confirmation` |
| `--cancel-all` | Cancel every running and pending job |
| `--rerun-failed` | Restart all failed jobs |
| `--delete-all` | Delete all completed, failed and cancelled jobs |

`--cancel-all` and `--delete-all` act on every job, including other people's and ones queued for later. Use `--cancel` with IDs from `--status` when anything else is queued.

### Cleaning Up After a Cancel

Cancelling revokes the Celery task, but `elrond.py` and the tool it was running (foremost, yara, log2timeline) keep going inside the worker and keep the image mounted. Check and clean up before the next Linux job, or it can find its mount point busy:

```bash
docker exec dernvale-celery-worker ps -eo pid,etime,cmd | grep -E "elrond|foremost|yara|log2timeline|psort"
docker exec dernvale-celery-worker kill -9 <pid> ...
docker exec dernvale-celery-worker sh -c 'mount | grep elrond_mount'
docker exec dernvale-celery-worker umount /mnt/elrond_mount00
docker exec dernvale-celery-worker kpartx -d /dev/loopN
docker exec dernvale-celery-worker losetup -d /dev/loopN
docker exec dernvale-celery-worker losetup -a   # should be empty
```

Only release loop devices when no Linux job is running.

### Long Silent Stretches

Some steps write nothing to the audit log or job log, so a healthy job can look stalled:

| Step | Where | Seen |
|---|---|---|
| Empty-directory cleanup at the end of collection | `collect.py`, three `os.walk` passes | 32 min on `win_full` (7 shadow copies) |
| Result statistics after Elrond exits | `tasks_docker.py`, `rglob` + `stat` of the output tree | 33 min for 87k carved files |
| foremost | `carve.py` | 36–59 min on a 21 GB raw image |
| Plaso | `log2timeline` | 105 min on the Windows E01 |

Check the processes in the worker (`ps` above) before cancelling anything that has gone quiet.

## Wrapper Scripts

`tests/scripts/run_single_test.sh <test> [--no-restart]` runs one test with `--wait` and restarts `dernvale-backend` and `dernvale-celery-worker` afterwards. The batch scripts in `tests/scripts/batch/` group related tests; see [`tests/scripts/batch/README.md`](../scripts/batch/README.md) for the list.

Both wrappers restart or tear down containers between tests (`batch_common.sh` runs `docker-compose down`). That drops the concurrency override and kills anything else queued, so don't use them while another run is in progress; queue with `run_test.py` instead.

`scripts/jobs/jobs-status.sh` and `scripts/jobs/jobs-stop.sh` are shell equivalents of `--status` and `--cancel`.

## Output

```
$TEST_OUTPUT_PATH/<test>/
├── dernvale_audit.log          # one CSV row per finished piece of work
├── mitre_techniques.txt
├── TEST_<test>_navigator.json   # navigator tests only
└── <image>/
    ├── artefacts/
    │   ├── raw/                 # collected files
    │   └── cooked/              # parsed artefacts (CSV/JSON)
    ├── analysis/                # analysis.csv, iocs.csv, yara.csv
    └── carved/                  # carving tests; one folder per file type, plus foremost's audit.txt
```

## Timings

`tests/scripts/test_timings.py` reads every `dernvale_audit.log` under the output root and charges each stage the gap since the previous entry. The output tables feed [`docs/PERFORMANCE.md`](../../docs/PERFORMANCE.md).

```bash
python3 tests/scripts/test_timings.py \
  --output-root "$TEST_OUTPUT_PATH" --images-root "$TEST_IMAGES_PATH" \
  --markdown timings.md --csv timings.csv --json timings.json
```

Audit timestamps are UTC. Silent steps (above) are charged to whichever stage logs next, and work after the last entry (result statistics) is not counted, so compare the audit span with the job's wall-clock time.

## Troubleshooting

**Backend not responding.** `docker compose -f docker-compose.yml -f docker-compose.concurrency1.yml ps`, then `docker logs dernvale-backend --tail 50`. If Docker Desktop itself has died (`docker ps` returns a 500), restart it with `open -a Docker`. Any running job is lost and has to be re-queued.

**A job ran twice.** Redis re-delivers unacknowledged tasks after `visibility_timeout`. `tasks_docker.py` now sets it to 24 hours with `worker_prefetch_multiplier=1`. If you see repeats, check that the worker was restarted after that change.

**A Linux job finishes in 20 seconds with no output.** Loop devices leaked from earlier jobs. Run the `losetup -a` check above and release them.

**Test results.** Results for each run are tracked in the Notion "Dernvale — Test Plan" database. [`TEST_RESULTS.md`](TEST_RESULTS.md) holds a snapshot.
