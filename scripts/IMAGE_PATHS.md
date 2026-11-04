# Rowanholt Image Path Manager

Interactive script to manage forensic image paths in Rowanholt without reinstalling.

## Usage

```bash
python3 scripts/image-paths.py
```

Or make it executable and run directly:
```bash
chmod +x scripts/image-paths.py
./scripts/image-paths.py
```

## Features

### 1. Show Current Paths

View all currently configured forensic image paths:

```
Current Forensic Image Paths
======================================================================

Configured paths:

  ✓ /Volumes/Media5TB/rowanholt_imgs
     → /data (in container)

  ✓ /home/user/backup-images
     → /data1 (in container)
```

- ✅ Shows host paths and container mount points
- ✅ Indicates if path exists (✓) or not (✗)
- ✅ Lists all paths from docker-compose.yml

### 2. Add Paths

Add new paths to existing configuration without removing current ones:

```
Add Forensic Image Paths
======================================================================

Add up to 3 new image paths

Enter path #1 (or Enter to finish): /mnt/external/forensics
✓ Valid path: /mnt/external/forensics

Enter path #2 (or Enter to finish): [Enter]
```

**Features:**
- ✅ Add up to 3 new paths at once
- ✅ Validates each path exists
- ✅ Offers to create missing directories
- ✅ Prevents duplicate paths
- ✅ Preserves existing paths
- ✅ Updates docker-compose.yml automatically

### 3. Remove Paths

Remove specific paths or all paths:

```
Remove Forensic Image Paths
======================================================================

Current paths:

  1. /Volumes/Media5TB/rowanholt_imgs → /data
  2. /home/user/backup-images → /data1
  3. /mnt/external/forensics → /data2

Enter path numbers to remove (comma-separated) or 'all' to remove all
Remove paths: 2,3
```

**Features:**
- ✅ Select specific paths by number
- ✅ Remove multiple paths at once (comma-separated)
- ✅ Remove all paths with 'all' command
- ✅ Requires confirmation for 'all'
- ✅ Updates docker-compose.yml automatically

### 4. Replace All Paths

Remove all existing paths and configure new ones from scratch:

```
Replace All Forensic Image Paths
======================================================================

Current paths will be replaced:

  ✗ /Volumes/Media5TB/rowanholt_imgs
  ✗ /home/user/backup-images

Replace all paths? (y/N): y

Configure up to 3 new paths

ℹ  PRIMARY image path (required)
Enter path to forensic images: /new/path/to/images
✓ Valid path: /new/path/to/images

ℹ  SECONDARY image path (optional - press Enter to skip)
Enter secondary path or press Enter to skip: [Enter]
```

**Features:**
- ✅ Removes all existing paths
- ✅ Prompts for new paths (primary required, secondary/tertiary optional)
- ✅ Validates all new paths
- ✅ Requires confirmation before replacing
- ✅ Updates docker-compose.yml automatically

### 5. Exit

Quit the path manager.

## How It Works

### Path Validation

The script validates paths by:
1. Expanding `~` (home directory) to full path
2. Checking if path exists and is a directory
3. Offering to create missing directories
4. Looping until valid path provided or skipped

### Docker Compose Updates

The script updates `docker-compose.yml` by:
1. Reading the current configuration
2. Finding backend and celery-worker services
3. Removing old forensic image volume mounts
4. Adding new volume mounts:
   - Backend: Read-only (`:ro`)
   - Celery-worker: Read-write (for output)
5. Mapping paths to container mount points:
   - First path → `/data`
   - Second path → `/data1`
   - Third path → `/data2`

### Container Mount Points

Paths are mounted inside containers as:

| Host Path | Container Mount | Access |
|-----------|----------------|--------|
| 1st path | `/data` | Backend: read-only<br>Celery: read-write |
| 2nd path | `/data1` | Backend: read-only<br>Celery: read-write |
| 3rd path | `/data2` | Backend: read-only<br>Celery: read-write |

**In test job configs**, reference images as:
```json
{
  "source_paths": [
    "/data/image1.E01",
    "/data1/image2.E01",
    "/data2/image3.E01"
  ]
}
```

## Example Session

```bash
$ python3 scripts/image-paths.py

======================================================================
  Rowanholt Image Path Manager
======================================================================

Options:

  1. Show current paths
     View currently configured forensic image paths

  2. Add paths
     Add new paths to existing configuration

  3. Remove paths
     Remove specific paths from configuration

  4. Replace all paths
     Remove all current paths and configure new ones

  5. Exit

Select option (1-5): 1

======================================================================
  Current Forensic Image Paths
======================================================================

Configured paths:

  ✓ /Volumes/Media5TB/rowanholt_imgs
     → /data (in container)

Press Enter to continue...

======================================================================
  Rowanholt Image Path Manager
======================================================================

Options:
  ...

Select option (1-5): 2

======================================================================
  Add Forensic Image Paths
======================================================================

Add up to 3 new image paths

Press Enter to skip a path

Enter path #1 (or Enter to finish): /home/user/new-images
✓ Valid path: /home/user/new-images

Enter path #2 (or Enter to finish):

✓ Updated docker-compose.yml

Configured paths:

  • /Volumes/Media5TB/rowanholt_imgs
    → /data (in container)
  • /home/user/new-images
    → /data1 (in container)

ℹ  Restart Rowanholt for changes to take effect:
  docker compose down
  ./scripts/start-testing-mode.sh

Press Enter to continue...
```

## After Updating Paths

After updating paths, you must restart Rowanholt:

```bash
# Stop Rowanholt
docker compose down

# Start in testing mode
./scripts/start-testing-mode.sh

# Or start full stack
docker compose up -d
```

## Common Use Cases

### Adding an External Drive

```bash
python3 scripts/image-paths.py
# Select: 2. Add paths
# Enter: /Volumes/ExternalDrive/forensics
```

### Switching to Different Location

```bash
python3 scripts/image-paths.py
# Select: 4. Replace all paths
# Enter new path(s)
```

### Removing Temporary Paths

```bash
python3 scripts/image-paths.py
# Select: 3. Remove paths
# Enter: 2,3 (to remove 2nd and 3rd paths)
```

### Checking Current Configuration

```bash
python3 scripts/image-paths.py
# Select: 1. Show current paths
```

## Troubleshooting

### "Path does not exist"

**Solution:**
- Let the script create the directory (answer 'y')
- Or manually create it: `mkdir -p /path/to/images`

### "Permission denied"

**Solution:**
- Ensure you have write access to the path
- Use `sudo` if needed to create directories
- Check parent directory permissions

### Changes don't take effect

**Solution:**
- Restart Rowanholt after updating paths:
  ```bash
  docker compose down
  ./scripts/start-testing-mode.sh
  ```

### Path shows ✗ but exists

**Solution:**
- Path might be a broken symlink
- Path might have permission issues
- Verify: `ls -la /path/to/images`

### docker-compose.yml not found

**Solution:**
- Run script from repo root or scripts directory
- Ensure you're in the correct repository

## Related Documentation

- [Installation Guide](../INSTALL.md) - Full installation instructions
- [Docker Installation](DOCKER_INSTALL.md) - Docker-specific setup
- [Quick Start](../tests/QUICK_START.md) - Running tests

## Technical Details

### Pattern Matching

The script identifies forensic image mounts using regex:
```regex
^\s*-\s+([^:]+):(/data\d*)(?::ro)?(?:\s+#.*)?$
```

This matches volume mounts like:
- `- /path:/data:ro  # Forensic images`
- `- /path:/data1`
- `- /path:/data2  # Comment`

### File Updates

The script performs surgical updates to `docker-compose.yml`:
1. Reads entire file
2. Identifies forensic image mount lines
3. Removes only those lines
4. Inserts new mounts in correct locations
5. Preserves all other configuration

### Safety

- ✅ Never modifies paths outside repo
- ✅ Validates all paths before updating
- ✅ Backs up current config in memory
- ✅ Atomic file writes (write-then-move)
- ✅ Clear success/failure messages

## Tips

1. **Use absolute paths** - Avoid relative paths for clarity
2. **Test paths** - Use option 1 to verify after changes
3. **Restart always** - Docker needs restart to mount new volumes
4. **Keep backups** - Git commit before major path changes
5. **Document paths** - Add comments in job configs

## Integration with Installer

This script uses the same path management logic as the main installer (`install-rowanholt.py`), ensuring consistency across:
- Initial installation
- Path updates
- Path validation
- Docker configuration

---

**Need help?** See [INSTALL.md](../INSTALL.md) or open an [issue](https://github.com/cmdaltr/rowanholt/issues)
