# Elrond Web Interface - Quick Start Guide

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Dernvale no longer uses. Dernvale runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../docs/QUICKSTART.md) and the `dernvale` command.

Get up and running with the Elrond Web Interface in 5 minutes!

## Prerequisites

- **Docker Desktop** (Recommended) - [Download here](https://www.docker.com/products/docker-desktop)
- OR Python 3.10+, Node.js 18+, and Redis

## Quick Start with Docker (Easiest)

### 1. Navigate to the web directory
```bash
cd elrond/web
```

### 2. Run the startup script
```bash
./start.sh
```

That's it! The script will:
- ✅ Check prerequisites
- ✅ Create configuration files
- ✅ Build Docker containers
- ✅ Start all services
- ✅ Display access URLs

### 3. Open in your browser
- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs

## Using the Web Interface

### Start Your First Analysis

1. **Go to "New Analysis"** page
2. **Enter a Case Number**: e.g., "INC-2025-001"
3. **Select Images**:
   - Click through the file browser
   - Select disk images (.e01, .raw, .dd, .img, etc.)
   - Multiple selections supported
4. **Configure Options**:
   - Browse option categories (Operation, Analysis, Collection, etc.)
   - Check boxes for desired features
   - **Required**: Select at least one operation mode (Collect/Gandalf/Reorganise)
5. **Click "Start Analysis"**

### Monitor Progress

1. **Go to "Jobs"** page
2. View all running and completed analyses
3. Click on any job to see:
   - Real-time progress
   - Live log output
   - Enabled options
   - Results when complete

## Common Commands

```bash
# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Stop everything
docker-compose down

# Rebuild after code changes
docker-compose build
docker-compose up -d
```

## Troubleshooting

### "Cannot access /mnt or /media directories"
The Docker container needs access to where your disk images are stored.

**Solution**: Edit `docker-compose.yml` and add your image location:
```yaml
volumes:
  - /path/to/your/images:/mnt/images:ro
```

Then restart:
```bash
docker-compose down
docker-compose up -d
```

### "Redis connection failed"
**Solution**: Restart the Redis container:
```bash
docker-compose restart redis
```

### "Port 3000 or 8000 already in use"
**Solution**: Change ports in `docker-compose.yml`:
```yaml
ports:
  - "3001:3000"  # Change 3001 to any available port
```

## File Locations

- **Job Data**: `/tmp/elrond/output/jobs/`
- **Analysis Output**: `/tmp/elrond/output/`
- **Configuration**: `backend/.env`

## Manual Installation (Without Docker)

If you prefer not to use Docker:

### Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env

# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Backend
uvicorn main:app --reload

# Terminal 3: Start Celery Worker
celery -A tasks.celery_app worker --loglevel=info
```

### Frontend
```bash
cd frontend
npm install
npm start
```

## Next Steps

- 📖 Read the full [README.md](README.md) for detailed documentation
- 🔧 Customize options in `backend/.env`
- 🎨 Access API documentation at http://localhost:8000/docs
- 🐛 Report issues on GitHub

## Quick Tips

💡 **Tip**: Enable "Brisk" mode for balanced speed and analysis depth

💡 **Tip**: Use "Super Quick" mode for rapid initial triage

💡 **Tip**: Jobs auto-refresh, but you can manually refresh anytime

💡 **Tip**: Multiple analyses can run concurrently (default: 3)

---

**Need Help?** Check the full [README.md](README.md) or open an issue on GitHub.
