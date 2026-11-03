# Elrond Web Interface

A modern web application for the Elrond Digital Forensics Acceleration Suite. This interface provides an intuitive way to analyze disk and memory images with full control over all analysis options through an easy-to-use GUI.

## Features

### 🎯 Core Features
- **File Browser**: Browse and select disk/memory images from mounted directories
- **Visual Options Panel**: Configure all 30+ analysis options using organized checkboxes
- **Real-time Monitoring**: Track analysis progress with live updates
- **Job Management**: View, monitor, cancel, and manage multiple concurrent analyses
- **Detailed Logs**: Access complete analysis logs in real-time
- **RESTful API**: Programmatic access to all features

### 🔧 Analysis Options Supported
- **Operation Modes**: Collect, Gandalf, Process
- **Collection**: User profiles, VSS, files, symlinks
- **Analysis**: Automated analysis, IOC extraction, timelines
- **Memory**: Volatility analysis, memory timelines
- **Security**: ClamAV scanning, YARA signatures
- **Output**: Splunk, Elastic, MITRE ATT&CK Navigator
- **Modes**: Brisk, Threat Hunt, Exhaustive

## Architecture

```
elrond-web/
├── backend/           # FastAPI backend
│   ├── main.py       # API routes
│   ├── tasks.py      # Celery background tasks
│   ├── storage.py    # Job persistence
│   ├── config.py     # Configuration
│   └── models/       # Data models
├── frontend/         # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── App.js       # Main application
│   │   └── api.js       # API client
│   └── public/
└── docker-compose.yml
```

## Quick Start

### Prerequisites
- Docker and Docker Compose v2
- Or: Python 3.12, Node.js 18+, Redis, PostgreSQL

### Option 1: Docker Compose (Recommended)

1. **Work from the repository root.** The maintained stack is the root `docker-compose.yml` (backend, Celery worker, Postgres, Redis, frontend, plus the `siem` profile). `src/web/docker-compose.yml` is an older copy without Postgres and won't run the current backend.

2. **Configure environment** (optional):
   ```bash
   cp backend/.env.example backend/.env
   # Edit backend/.env with your settings
   ```

3. **Start all services**:
   ```bash
   docker compose up -d                     # core stack
   docker compose --profile siem up -d      # add Splunk, Elastic, Kibana, Navigator
   ```

4. **Access the application**:
   - Frontend: http://localhost:5687
   - Backend API: http://localhost:5688
   - API Docs: http://localhost:5688/docs
   - Splunk: http://localhost:7755 (username: admin, password: rivendell)
   - Kibana: http://localhost:5601
   - Elasticsearch: http://localhost:9200

5. **View logs**:
   ```bash
   docker compose logs -f
   ```

6. **Stop services**:
   ```bash
   docker compose down
   ```

### Option 2: Manual Setup

#### Backend Setup

1. **Install dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Start Redis**:
   ```bash
   # On macOS with Homebrew
   brew services start redis

   # On Linux
   sudo systemctl start redis
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Start the backend**:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 5688 --reload
   ```

5. **Start Celery worker** (in a new terminal):
   ```bash
   cd backend
   celery -A tasks_docker.celery_app worker --loglevel=info --concurrency=1
   ```

#### Frontend Setup

1. **Install dependencies**:
   ```bash
   cd frontend
   npm install
   ```

2. **Configure API URL** (optional):
   ```bash
   echo "REACT_APP_API_URL=http://localhost:5688" > .env
   ```

3. **Start the frontend**:
   ```bash
   npm start
   ```

4. **Access the application**:
   - Open http://localhost:3000 in your browser

## Usage Guide

### Starting a New Analysis

1. **Navigate to "New Analysis"** page
2. **Enter Case Number**: Required identifier for the investigation
3. **Select Images**:
   - Use the file browser to navigate to your disk/memory images
   - Click on image files to select them (multiple selections supported)
   - Supported formats: .e01, .ex01, .raw, .dd, .img, .vmdk, .vhd, .vhdx, .mem, .dmp, .lime
4. **Configure Options**:
   - Navigate through option categories using the tabs
   - Check/uncheck options as needed
   - Use "Enable All" or "Disable All" for quick configuration
   - **Important**: At least one operation mode (Collect or Gandalf) must be selected
5. **Optional**: Specify destination directory (defaults to output directory)
6. **Click "Start Analysis"**

### Monitoring Jobs

1. **Navigate to "Jobs"** page
2. **View all jobs** with status, progress, and timing information
3. **Filter by status**: Pending, Running, Completed, Failed, Cancelled
4. **Click on a job** to view detailed information
5. **Auto-refresh**: Job list updates every 5 seconds automatically

### Job Details

On the job details page, you can:
- View real-time progress bar
- Monitor live log output
- See enabled options
- View source images and destination path
- Cancel running jobs
- Delete completed jobs
- Auto-updates every 3 seconds

### SIEM Integration

When SIEM export options (Splunk, Elastic, Navigator) are enabled:

1. **Automatic Export**: After analysis completes, artifacts are automatically exported to selected SIEM platforms
2. **Quick Access Links**: Click vendor icons to access SIEM dashboards:
   - **Splunk**: Opens Splunk Web UI (http://localhost:7755)
   - **Elastic**: Opens Kibana dashboard (http://localhost:5601)
   - **Navigator**: Downloads MITRE ATT&CK Navigator JSON file for upload to the Navigator
3. **Job Logs**: View detailed SIEM export progress in the job log

**SIEM Credentials:**
- Splunk: username `admin`, password `rivendell`
- Elasticsearch/Kibana: username `elastic`, password `rivendell`

**Note**: Navigator JSON files can be uploaded to https://mitre-attack.github.io/attack-navigator/ for visualization

## API Documentation

### Interactive API Docs
Visit http://localhost:5688/docs for interactive Swagger UI documentation.

### Key Endpoints

#### File System
- `GET /api/fs/browse?path=/mnt` - Browse filesystem

#### Jobs
- `POST /api/jobs` - Create new analysis job
- `GET /api/jobs` - List all jobs
- `GET /api/jobs/{job_id}` - Get job details
- `POST /api/jobs/{job_id}/cancel` - Cancel job
- `DELETE /api/jobs/{job_id}` - Delete job

### Example: Create Job via API

```bash
curl -X POST http://localhost:5688/api/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "case_number": "INC-2025-001",
    "source_paths": ["/mnt/evidence/image.e01"],
    "options": {
      "analysis": true,
      "userprofiles": true,
      "brisk": true
    }
  }'
```

## Configuration

### Backend Configuration (.env)

Key settings in `backend/.env`:

```env
# Allow browsing these directories
ALLOWED_PATHS=["/mnt", "/media", "/tmp/elrond"]

# Output and upload directories
OUTPUT_DIR=/tmp/elrond/output
UPLOAD_DIR=/tmp/elrond/uploads

# Maximum concurrent analyses
MAX_CONCURRENT_ANALYSES=3

# Analysis timeout (seconds)
ANALYSIS_TIMEOUT=86400
```

### Security Considerations

⚠️ **Important Security Notes**:

1. **File System Access**: By default, the application can only browse directories listed in `ALLOWED_PATHS`
2. **Change Secret Key**: Update `SECRET_KEY` in `.env` for production
3. **Network Access**: Consider using a reverse proxy (nginx) for production
4. **Authentication**: This version has no authentication - add authentication middleware for production use
5. **CORS**: Update `CORS_ORIGINS` to include only trusted frontend URLs

## Troubleshooting

### Backend Issues

**Problem**: Cannot connect to Redis
```bash
# Check if Redis is running
redis-cli ping
# Should return: PONG

# Start Redis if needed
docker compose up -d redis
```

**Problem**: Cannot browse directories
- Check `ALLOWED_PATHS` in `.env`
- Ensure directories are mounted in Docker (see docker-compose.yml)
- Verify directory permissions

**Problem**: Jobs not processing
```bash
# Check Celery worker logs
docker compose logs celery-worker

# Restart worker
docker compose restart celery-worker
```

**Problem**: SIEM export not working
```bash
# Check if SIEM services are running
docker ps | grep -E "splunk|elastic|kibana"

# Restart SIEM services
docker compose restart splunk elastic kibana

# Check SIEM export logs
docker compose logs celery-worker | grep -i siem
```

**Problem**: Cannot access Splunk/Kibana
- Verify services are running: `docker ps`
- Check correct ports:
  - Splunk: http://localhost:7755
  - Kibana: http://localhost:5601
- Wait for services to fully start (can take 1-2 minutes)

### Frontend Issues

**Problem**: Cannot connect to backend
- Verify backend is running: `curl http://localhost:5688/api/health`
- Check `REACT_APP_API_URL` in frontend `.env`
- Review CORS settings in backend

**Problem**: File browser shows "Access Denied"
- Update `ALLOWED_PATHS` in backend configuration
- Ensure paths are mounted in Docker container

### Performance

**Slow Analysis**:
- Enable "Quick" or "Super Quick" modes
- Disable timeline creation (very slow)
- Reduce number of concurrent analyses
- Consider using "Brisk" mode for balanced performance

**High Memory Usage**:
- Limit `MAX_CONCURRENT_ANALYSES`
- Monitor with: `docker stats`
- Increase Docker memory limits if needed

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Hot Reload

Both frontend and backend support hot reload in development mode:
- Frontend: Changes to `.js` files auto-reload
- Backend: `--reload` flag enables auto-restart on changes

### Adding New Options

1. Add to `AnalysisOptions` in `backend/models/job.py`
2. Update `build_elrond_command()` in `backend/tasks.py`
3. Add to appropriate section in `frontend/src/components/OptionsPanel.js`

## Production Deployment

A shared, production install is Rivendell's server profile: Caddy with TLS in front, sign-in on every route, and nothing else published. See [docs/SERVER.md](../../docs/SERVER.md) (`rivendell server init <hostname>`, then `rivendell start`).

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/cyberg3cko/elrond/issues
- Documentation: https://github.com/cyberg3cko/elrond

## License

This project follows the same license as the main Elrond project.

## Acknowledgments

Built with:
- FastAPI - Modern Python web framework
- React - Frontend library
- Celery - Distributed task queue
- Redis - In-memory data store
- Docker - Containerization platform
