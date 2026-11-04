# Rowanholt Web Interface - Quick Start

## Prerequisites

- Docker (OrbStack or Docker Desktop)
- OR Python 3.10+, Node.js 18+, Redis (for local dev)

## Quick Start (Docker)

From the repo root:

```bash
docker compose up -d
```

This starts the core stack: postgres, redis, backend (FastAPI), celery-worker, and frontend (React).

Access points:
- **Web Interface**: http://localhost:5688 (or http://rowanholt.lab via FlightDeck local proxy)
- **API docs**: http://localhost:5688/docs
- **Frontend (React)**: http://localhost:5687

### Optional: SIEM stack

Splunk, Elasticsearch, Kibana, and ATT&CK Navigator are profile-gated. Start them separately once the core stack is healthy:

```bash
docker compose --profile siem up -d
```

SIEM access points once running:
- **Splunk Web**: http://localhost:7755 (admin / rowanholt)
- **Kibana**: http://localhost:5601 (elastic / rowanholt)
- **Elasticsearch**: http://localhost:9200
- **ATT&CK Navigator**: http://localhost:5602

Stop only the SIEM containers without tearing down the core stack:

```bash
docker compose stop splunk elastic elastic-setup kibana kibana-setup navigator
```

### FlightDeck shortcuts

If you use [FlightDeck](https://github.com/cmdaltr/FlightDeck):

```bash
fd start rowanholt        # start core stack
fd start rowanholt-siem   # start SIEM stack (core must be running)
fd stop  rowanholt-siem   # stop SIEM stack only
fd stop  rowanholt        # stop core stack
```

## Common Commands

```bash
# View logs
docker compose logs -f

# View logs for a specific service
docker compose logs -f backend

# Restart services
docker compose restart

# Stop everything (core only)
docker compose down

# Rebuild after code changes
docker compose up --build -d
```

## Troubleshooting

### "Cannot access /mnt or /media directories"

The container needs access to where your disk images are stored. Edit `docker-compose.yml` and add a volume mount:

```yaml
volumes:
  - /path/to/your/images:/mnt/images:ro
```

Then restart:

```bash
docker compose down && docker compose up -d
```

### "Redis connection failed"

```bash
docker compose restart redis
```

### "Port already in use"

Change the host-side port in `docker-compose.yml`:

```yaml
ports:
  - "5689:5688"  # map to a different host port
```

## File Locations

- **Job output**: `/tmp/rowanholt/` (on host)
- **Uploaded images**: managed via `rowanholt_uploads` Docker volume
- **Backend config**: `src/web/backend/.env`

## Manual Installation (Without Docker)

```bash
cd src/web/backend
pip install -r requirements.txt
cp .env.example .env

# Terminal 1: Redis
redis-server

# Terminal 2: Backend
uvicorn main:app --host 0.0.0.0 --port 5688 --reload

# Terminal 3: Celery worker
celery -A tasks_docker.celery_app worker --loglevel=info
```

Frontend:

```bash
cd src/web/frontend
npm install
npm start
```

---

For full documentation see [README.md](../../README.md) or the [docs/](../../docs/) directory.
