# Accessing Analysis Data from Docker Containers

This guide explains how to access analysis results and job data from Dernvale Docker containers on your local machine.

## Quick Access: Shared Directory (Recommended)

**All job outputs are now automatically accessible at:**
```
/tmp/dernvale/
```

This directory is mounted from the Docker containers and contains:
- Analysis results
- Extracted artifacts
- Job logs
- SIEM export files
- Navigator JSON files

### Example: Finding Your Job Output

```bash
# List all job outputs
ls -la /tmp/dernvale/

# Open output directory in Finder
open /tmp/dernvale/

# View a specific job's output
ls -la /tmp/dernvale/CASE-ID-HERE/

# Copy results to your desktop
cp -R /tmp/dernvale/CASE-ID-HERE ~/Desktop/
```

## Directory Structure

```
/tmp/dernvale/
├── CASE-ID-001_output/
│   ├── image.E01/
│   │   ├── artefacts/
│   │   │   ├── raw/          # Raw extracted artifacts
│   │   │   └── cooked/       # Processed artifacts
│   │   ├── analysis/         # Analysis results
│   │   └── navigator.json    # MITRE ATT&CK Navigator file (if enabled)
│   └── splunk/               # Splunk export files (if enabled)
└── CASE-ID-002_output/
    └── ...
```

## Method 1: Direct File Access (Easiest)

Since `/tmp/dernvale/` is mounted, you can:

### In Finder:
1. Press `Cmd + Shift + G`
2. Type `/tmp/dernvale`
3. Press Enter

### In Terminal:
```bash
# Navigate to output directory
cd /tmp/dernvale

# List all outputs
ls -la

# Open in Finder
open .

# Copy to your Documents folder
cp -R /tmp/dernvale ~/Documents/forensics-data/
```

## Method 2: Docker Copy Command

If you need to copy data from other container locations:

```bash
# Copy from backend container
docker cp dernvale-backend:/path/in/container ~/Desktop/

# Copy from Celery worker
docker cp dernvale-celery-worker:/path/in/container ~/Desktop/

# Examples:
docker cp dernvale-celery-worker:/tmp/elrond/output/CASE-ID ~/Desktop/
docker logs dernvale-backend > ~/Desktop/dernvale-backend.log 2>&1
```

## Method 3: Browse Container Filesystem

Explore what's available in containers:

```bash
# List files in backend container
docker exec dernvale-backend ls -la /tmp/elrond/output/

# List files in Celery worker
docker exec dernvale-celery-worker ls -la /tmp/elrond/output/

# Interactive shell (advanced)
docker exec -it dernvale-celery-worker bash
# Now you can navigate and use commands like ls, cat, find, etc.
# Type 'exit' to leave
```

## Method 4: Export as Archive

Create a compressed archive for easy transfer:

```bash
# Create tar.gz of all outputs
docker exec dernvale-celery-worker tar czf /tmp/dernvale-export.tar.gz /tmp/elrond/output/

# Copy to your machine
docker cp dernvale-celery-worker:/tmp/dernvale-export.tar.gz ~/Desktop/

# Extract on your machine
cd ~/Desktop
tar xzf dernvale-export.tar.gz
```

## SIEM Data Export Locations

### Splunk Data
- **Container Path**: `/tmp/elrond/output/CASE-ID/splunk/`
- **Local Path**: `/tmp/dernvale/CASE-ID_output/splunk/`
- **Access via Web**: http://localhost:7755 (username: admin, password: dernvale)

### Elasticsearch/Kibana Data
- **Container Path**: Docker volume `elasticsearch_data`
- **Access via Web**: http://localhost:5601
- **Export via Kibana**: Use Kibana's export features in the web UI

### MITRE ATT&CK Navigator
- **Container Path**: `/tmp/elrond/output/CASE-ID/*navigator*.json`
- **Local Path**: `/tmp/dernvale/CASE-ID_output/*navigator*.json`
- **Download via Web**: Click Navigator icon in job details page

## Troubleshooting

### "Permission Denied" when accessing /tmp/dernvale

```bash
# Fix permissions
sudo chmod -R 755 /tmp/dernvale

# Or change ownership to your user
sudo chown -R $(whoami) /tmp/dernvale
```

### Directory doesn't exist

```bash
# Create the directory
sudo mkdir -p /tmp/dernvale

# Set permissions
sudo chmod 755 /tmp/dernvale
```

### Can't find output files

```bash
# Check what's in the container
docker exec dernvale-celery-worker ls -la /tmp/elrond/output/

# Check running jobs
docker ps | grep dernvale

# Check job status in web UI
# Navigate to http://localhost:5687/jobs
```

### Files are not appearing in /tmp/dernvale

```bash
# Restart containers to apply volume mounts
docker restart dernvale-backend dernvale-celery-worker

# Or restart all services
cd /path/to/dernvale/src/web
docker compose restart
```

## Best Practices

1. **Regular Backups**: Copy completed analysis results to a permanent location
   ```bash
   cp -R /tmp/dernvale/CASE-ID-* ~/Documents/cases/
   ```

2. **Disk Space**: Monitor `/tmp/dernvale/` size - forensic data can be large
   ```bash
   du -sh /tmp/dernvale/*
   ```

3. **Clean Up**: Remove old job outputs when done
   ```bash
   rm -rf /tmp/dernvale/OLD-CASE-ID_output
   ```

4. **Archive Important Cases**: Create compressed archives for long-term storage
   ```bash
   tar czf ~/Archives/CASE-ID.tar.gz /tmp/dernvale/CASE-ID_output/
   ```

## Integration with External Tools

### Open results in forensic tools:
```bash
# Open artifacts in Autopsy, X-Ways, etc.
open -a "Autopsy" /tmp/dernvale/CASE-ID_output/artifacts/

# Open timeline in Excel
open -a "Microsoft Excel" /tmp/dernvale/CASE-ID_output/timeline.csv
```

### Process with scripts:
```bash
# Run custom analysis script on results
python analyze.py /tmp/dernvale/CASE-ID_output/

# Batch process multiple cases
for case in /tmp/dernvale/*_output/; do
    echo "Processing $case"
    ./process.sh "$case"
done
```

## Additional Resources

- **Docker Volumes Documentation**: https://docs.docker.com/storage/volumes/
- **Docker CP Command**: https://docs.docker.com/engine/reference/commandline/cp/
- **Dernvale API**: http://localhost:5688/docs

## Quick Reference Card

```bash
# View outputs in Finder
open /tmp/dernvale

# List all job outputs
ls -la /tmp/dernvale/

# Copy specific job to Desktop
cp -R /tmp/dernvale/CASE-ID ~/Desktop/

# Browse container files
docker exec dernvale-celery-worker ls -la /tmp/elrond/output/

# Copy from container
docker cp dernvale-celery-worker:/tmp/elrond/output/CASE-ID ~/Desktop/

# Check disk usage
du -sh /tmp/dernvale/*

# Clean up old data
rm -rf /tmp/dernvale/OLD-CASE-ID_output
```
