"""
Celery Tasks - Dockerized Version

Background tasks for running Elrond analysis in Docker containers.
This version runs Elrond directly in the same container environment.
"""

import subprocess
import sys
import os
import re
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from celery import Celery
from celery.utils.log import get_task_logger

# Import without relative imports for Celery compatibility
try:
    from .config import settings
    from .storage import JobStorage
    from .models.job import JobStatus
except ImportError:
    # Fallback for when running as standalone module (Celery worker)
    from config import settings
    from storage import JobStorage
    from models.job import JobStatus

# Initialize Celery
celery_app = Celery(
    "elrond",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

logger = get_task_logger(__name__)
job_storage = JobStorage()


def _resolve_destination(job) -> Path:
    """
    Resolve the destination directory using the same logic as job creation.

    Prefers the stored destination_path, otherwise derives from the first
    source path (image_name_output), and finally falls back to output_dir/case_number.

    IMPORTANT: Always ensures output is under settings.output_dir to remain accessible
    on the host filesystem (not in Docker volumes).
    """
    if job.destination_path:
        return Path(job.destination_path)

    if job.source_paths:
        first_source = Path(job.source_paths[0])
        # Always write output to settings.output_dir, not uploads directory
        output_name = f"{first_source.stem}_output"
        return Path(settings.output_dir) / output_name

    return Path(settings.output_dir) / job.case_number


def _sources_inside(job, dest_dir: Path) -> Optional[str]:
    """The first of the job's sources that is the output directory or lies inside it, if any:
    a fresh restart removes the output directory, and must never take evidence with it."""
    dest = Path(os.path.realpath(dest_dir))
    for source in job.source_paths or []:
        for candidate in {source, translate_path_for_worker(source)}:
            resolved = Path(os.path.realpath(candidate))
            if resolved == dest or dest in resolved.parents:
                return source
    return None


def run_siem_export(job, output_dir: Path, logger):
    """
    Run SIEM export (Splunk, Elasticsearch, Navigator) after analysis completes.

    Calls the appropriate ingest scripts and logs progress to the job log.

    Args:
        job: Job object
        output_dir: Analysis output directory
        logger: Logger instance
    """
    opts = job.options

    # Build allimgs structure from source paths
    # Format: {index: "image_path::image_type"}
    # We need to scan the output directory to find actual processed images
    allimgs = {}

    # Look for subdirectories in output_dir that match source paths
    if output_dir.exists():
        for idx, source_path in enumerate(job.source_paths):
            source_name = Path(source_path).name
            # Detect OS type from source name or from analysis output
            img_type = '::Windows'  # Default

            # Try to detect OS from output directory structure
            if (output_dir / source_name).exists():
                artefacts_path = output_dir / source_name / "artefacts"
                if artefacts_path.exists():
                    # Check for Windows artifacts
                    if (artefacts_path / "cooked" / "registry").exists() or \
                       (artefacts_path / "cooked" / "evt").exists():
                        img_type = '::Windows'
                    # Check for macOS artifacts
                    elif (artefacts_path / "cooked" / "plists").exists():
                        img_type = '::macOS'
                    # Check for Linux artifacts
                    elif (artefacts_path / "cooked" / "logs").exists():
                        img_type = '::Linux'

            allimgs[idx] = f"{source_name}{img_type}"

    # Splunk export
    if opts.splunk:
        job.log.append(f"[{datetime.now().isoformat()}] -> starting Splunk indexing...")
        job_storage.save_job(job)

        try:
            # First, ensure Splunk app directory exists
            # In Docker mode, we can't write directly to the Splunk container filesystem
            # So we create the app structure using docker exec
            job.log.append(f"[{datetime.now().isoformat()}] -> ensuring Splunk elrond app exists...")
            job_storage.save_job(job)

            try:
                # Check if elrond app already exists
                check_result = subprocess.run(
                    ['docker', 'exec', 'dernvale-splunk', 'test', '-d', '/opt/splunk/etc/apps/elrond'],
                    capture_output=True
                )

                if check_result.returncode != 0:
                    # App doesn't exist, create it
                    subprocess.run(
                        ['docker', 'exec', 'dernvale-splunk', 'mkdir', '-p', '/opt/splunk/etc/apps/elrond/default'],
                        check=True
                    )
                    subprocess.run(
                        ['docker', 'exec', 'dernvale-splunk', 'chown', '-R', 'splunk:splunk', '/opt/splunk/etc/apps/elrond'],
                        check=True
                    )
                    job.log.append(f"[{datetime.now().isoformat()}] -> created Splunk elrond app directory")
                else:
                    job.log.append(f"[{datetime.now().isoformat()}] -> Splunk elrond app already exists")

            except Exception as e:
                logger.warning(f"Could not create Splunk app directory: {e}")
                job.log.append(f"[{datetime.now().isoformat()}] -> continuing with existing Splunk configuration")

            job_storage.save_job(job)

            # Create Splunk index for this case if it doesn't exist
            try:
                job.log.append(f"[{datetime.now().isoformat()}] -> creating Splunk index '{job.case_number}'...")
                job_storage.save_job(job)

                # Use Splunk CLI to create index
                create_index_result = subprocess.run(
                    ['docker', 'exec', 'dernvale-splunk', '/opt/splunk/bin/splunk', 'add', 'index', job.case_number, '-auth', 'admin:dernvale'],
                    capture_output=True,
                    text=True
                )

                if create_index_result.returncode == 0 or 'already exists' in create_index_result.stderr:
                    job.log.append(f"[{datetime.now().isoformat()}] -> Splunk index '{job.case_number}' ready")
                else:
                    job.log.append(f"[{datetime.now().isoformat()}] -> note: could not create index (may already exist)")

                job_storage.save_job(job)

            except Exception as e:
                logger.warning(f"Could not create Splunk index: {e}")
                # Silently continue - index may already exist
                job_storage.save_job(job)

            # Now process each source image for ingestion
            for idx, (key, img_spec) in enumerate(allimgs.items()):
                source_name = img_spec.split("::")[0]

                # Count artifacts for this source
                artifact_count = 0
                artifacts_dir = output_dir / source_name / "artefacts" / "cooked"
                if artifacts_dir.exists():
                    artifact_count = sum(1 for _ in artifacts_dir.rglob("*.csv"))
                    artifact_count += sum(1 for _ in artifacts_dir.rglob("*.json"))

                if artifact_count > 0:
                    job.log.append(f"[{datetime.now().isoformat()}] -> configuring Splunk to monitor {artifact_count:,} artefacts for '{source_name}'")
                    job_storage.save_job(job)

                    # Configure Splunk inputs using docker exec to write to the container's filesystem
                    # This creates monitor stanzas in inputs.conf for each artifact directory
                    try:

                        # Path inside Splunk container
                        inputs_conf = '/opt/splunk/etc/apps/elrond/default/inputs.conf'

                        # Create inputs.conf content for this image
                        artifacts_path = f"/tmp/elrond/output/{source_name}/artefacts/cooked"
                        monitor_stanza = f"\n[monitor://{artifacts_path}]\ndisabled = false\nhost = {source_name}\nsourcetype = elrondCSV\nindex = {job.case_number}\nrecursive = true\n\n"

                        # Write to inputs.conf using docker exec
                        subprocess.run(
                            ['docker', 'exec', 'dernvale-splunk', 'sh', '-c', f'echo "{monitor_stanza}" >> {inputs_conf}'],
                            check=True,
                            capture_output=True
                        )

                        job.log.append(f"[{datetime.now().isoformat()}] -> Splunk configured to monitor {artifacts_path}")
                        job_storage.save_job(job)

                    except Exception as e:
                        logger.warning(f"Could not configure Splunk monitoring: {e}")
                        # Silently continue - artifacts still available for manual indexing
                        job_storage.save_job(job)

            # Reload Splunk to pick up new monitoring configuration
            try:
                job.log.append(f"[{datetime.now().isoformat()}] -> reloading Splunk configuration...")
                job_storage.save_job(job)

                subprocess.run(
                    ['docker', 'exec', 'dernvale-splunk', '/opt/splunk/bin/splunk', 'reload', 'deploy-server', '-auth', 'admin:dernvale'],
                    capture_output=True,
                    timeout=10
                )

                job.log.append(f"[{datetime.now().isoformat()}] -> Splunk configuration reloaded")
                job_storage.save_job(job)

            except Exception as e:
                logger.warning(f"Could not reload Splunk: {e}")
                # Silently continue - configuration will be picked up on next Splunk restart
                job_storage.save_job(job)

            # Don't log Splunk URL - user knows where to access it
            logger.info(f"Splunk indexing completed for job {job.id}")
            job_storage.save_job(job)

        except Exception as e:
            # Re-raise the exception to be caught by the main SIEM export error handler
            raise

    # Elasticsearch export
    if opts.elastic:
        job.log.append(f"[{datetime.now().isoformat()}] -> starting Elasticsearch ingestion...")
        job_storage.save_job(job)

        try:
            # Process each source image
            for idx, (key, img_spec) in enumerate(allimgs.items()):
                source_name = img_spec.split("::")[0]

                # Count artifacts for this source
                artifact_count = 0
                artifacts_dir = output_dir / source_name / "artefacts" / "cooked"
                if artifacts_dir.exists():
                    artifact_count = sum(1 for _ in artifacts_dir.rglob("*.csv"))
                    artifact_count += sum(1 for _ in artifacts_dir.rglob("*.json"))

                if artifact_count > 0:
                    job.log.append(f"[{datetime.now().isoformat()}] -> ingesting artefacts into Elasticsearch for '{source_name}'")
                    job_storage.save_job(job)

                    # Run Elasticsearch ingest using subprocess to call the Python module directly
                    elrond_path = os.environ.get('ELROND_HOME', '/app/src/analysis')
                    elastic_script = Path(elrond_path) / 'dernvale' / 'post' / 'elastic' / 'ingest.py'

                    if elastic_script.exists():
                        # Import and call the function
                        sys.path.insert(0, str(elrond_path))
                        from dernvale.post.elastic.ingest import ingest_elastic_data

                        ingest_elastic_data(
                            verbosity=2,
                            output_directory=str(output_dir) + "/",
                            case=job.case_number,
                            stage="Elasticsearch",
                            allimgs=allimgs,
                        )

                        job.log.append(f"[{datetime.now().isoformat()}] -> ingested {artifact_count:,} artefacts into Elasticsearch for '{source_name}'")
                        job.log.append(f"[{datetime.now().isoformat()}] -> Elasticsearch ingestion completed for '{source_name}'")
                        job_storage.save_job(job)
                    else:
                        raise FileNotFoundError(f"Elasticsearch ingest script not found at {elastic_script}")

            job.log.append(f"[{datetime.now().isoformat()}] -> access Kibana at http://localhost:5601 (index: {job.case_number.lower()})")
            logger.info(f"Elasticsearch ingestion completed for job {job.id}")
            job_storage.save_job(job)

        except Exception as e:
            # Re-raise the exception to be caught by the main SIEM export error handler
            raise

    # MITRE ATT&CK Navigator export
    if opts.navigator and (opts.splunk or opts.elastic):
        job.log.append(f"[{datetime.now().isoformat()}] -> checking for MITRE ATT&CK Navigator layer...")
        job_storage.save_job(job)

        # Check if Navigator file was generated during analysis
        navigator_files = list(output_dir.rglob("*navigator*.json"))

        if navigator_files:
            for nav_file in navigator_files:
                file_size = nav_file.stat().st_size
                job.log.append(f"[{datetime.now().isoformat()}] -> Navigator layer found: {nav_file.name} ({file_size} bytes)")
            job.log.append(f"[{datetime.now().isoformat()}] -> upload to https://mitre-attack.github.io/attack-navigator/ for visualization")
            logger.info(f"Navigator generation completed for job {job.id}")
        else:
            # Silently skip Navigator if no techniques detected - this is normal for many images
            pass
            logger.warning(f"Navigator file not found for job {job.id}")

        job_storage.save_job(job)


@celery_app.task(bind=True)
def start_analysis(self, job_id: str):
    """
    Start Elrond analysis task in dockerized environment.

    Runs the full forensics engine directly in the container.

    Args:
        job_id: Job ID
    """
    job = job_storage.get_job(job_id)

    if not job:
        logger.error(f"Job {job_id} not found")
        return

    try:
        # Update job status
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        job.log.append(f"[{datetime.now().isoformat()}] -> starting forensic analysis")
        job_storage.save_job(job)

        # Build elrond command
        cmd = build_elrond_command(job)

        logger.info(f"Running command: {' '.join(cmd)}")
        job.log.append(f"[{datetime.now().isoformat()}] -> command: {' '.join(cmd)}")
        job_storage.save_job(job)

        # Set destination directory - must match what's passed to elrond command
        dest_dir = _resolve_destination(job)
        dest_dir_str = str(dest_dir)

        # Check if force_overwrite is set and directory exists
        if getattr(job.options, 'force_overwrite', False):
            evidence_inside = _sources_inside(job, dest_dir)
            if evidence_inside:
                logger.warning(f"Not removing {dest_dir_str}: it holds the job's source {evidence_inside}")
                job.log.append(f"[{datetime.now().isoformat()}] -> not removing {dest_dir_str}: it holds this job's "
                               f"source {evidence_inside}; re-running into the existing output")
                job_storage.save_job(job)
            elif dest_dir.exists():
                logger.info(f"Force overwrite enabled, removing existing directory: {dest_dir_str}")

                # Estimate directory size for ETA calculation
                size_note = ""
                try:
                    # Quick estimate using du command
                    du_result = subprocess.run(
                        ['du', '-sb', dest_dir_str],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    dir_size_bytes = int(du_result.stdout.split()[0]) if du_result.returncode == 0 else 0
                    dir_size_gb = dir_size_bytes / (1024**3) if dir_size_bytes else 0

                    # Rough estimate: ~1GB per 10-15 seconds on modern systems
                    estimated_seconds = int(dir_size_gb * 12)
                    if dir_size_gb and estimated_seconds > 5:
                        size_note = f" ({dir_size_gb:.1f}GB - this will take ~{estimated_seconds}s)"
                    elif dir_size_gb:
                        size_note = f" ({dir_size_gb:.1f}GB)"
                except:
                    pass

                job.log.append(f"[{datetime.now().isoformat()}] -> removing existing directory: {dest_dir_str}{size_note}")
                job_storage.save_job(job)

                start_time = datetime.now()
                try:
                    # Use rm -rf in background with periodic progress updates
                    import threading
                    import time

                    # Start rm -rf in background
                    rm_process = subprocess.Popen(
                        ['rm', '-rf', dest_dir_str],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                    # Monitor with periodic updates every 10 seconds
                    last_update = datetime.now()
                    while rm_process.poll() is None:
                        time.sleep(1)
                        elapsed = (datetime.now() - start_time).total_seconds()

                        # Update every 10 seconds
                        if (datetime.now() - last_update).total_seconds() >= 10:
                            job.log.append(f"[{datetime.now().isoformat()}] -> still removing directory... ({int(elapsed)}s elapsed)")
                            job_storage.save_job(job)
                            last_update = datetime.now()

                        # Timeout after 5 minutes
                        if elapsed > 300:
                            rm_process.kill()
                            raise subprocess.TimeoutExpired(cmd=['rm', '-rf', dest_dir_str], timeout=300)

                    # Check exit code
                    if rm_process.returncode != 0:
                        raise subprocess.CalledProcessError(rm_process.returncode, ['rm', '-rf', dest_dir_str])

                    elapsed = (datetime.now() - start_time).total_seconds()
                    logger.info(f"Successfully removed directory: {dest_dir_str} in {elapsed:.1f}s")
                    job.log.append(f"[{datetime.now().isoformat()}] -> successfully removed directory in {elapsed:.1f}s")
                except subprocess.TimeoutExpired:
                    logger.error(f"Timeout removing directory: {dest_dir_str}")
                    job.log.append(f"[{datetime.now().isoformat()}] -> timeout removing directory (took more than 5 minutes)")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error removing directory (exit code {e.returncode})")
                    job.log.append(f"[{datetime.now().isoformat()}] -> error removing directory")
                except Exception as e:
                    logger.error(f"Error removing directory: {e}")
                    job.log.append(f"[{datetime.now().isoformat()}] -> error removing directory: {e}")
                job_storage.save_job(job)

        # Create the output directory if it doesn't exist
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Run elrond directly in container
        # Since we're already in the forensics container, we can run it directly
        elrond_path = os.environ.get('ELROND_HOME', '/opt/elrond')
        elrond_script = Path(elrond_path) / 'elrond.py'

        if not elrond_script.exists():
            # Elrond not installed - create placeholder error
            raise FileNotFoundError(
                f"Elrond script not found at {elrond_script}. "
                f"Please install Elrond or set ELROND_HOME environment variable to point to Elrond installation."
            )

        # Prepend python3 and elrond script path to command
        cmd.insert(0, str(elrond_script))
        cmd.insert(0, 'python3')

        logger.info(f"Executing: {' '.join(cmd)}")

        # Run elrond with proper environment
        env = os.environ.copy()
        env['PYTHONPATH'] = f"{elrond_path}:{env.get('PYTHONPATH', '')}"
        env['ELROND_HOME'] = elrond_path
        env['ELROND_OUTPUT'] = str(settings.output_dir)
        env['ELROND_NONINTERACTIVE'] = '1'  # Signal non-interactive mode

        # SIEM credentials are now set in docker-compose.yml environment
        # and will be automatically available via os.environ in the analysis scripts

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            cwd=str(dest_dir),
            env=env,
        )

        # Monitor progress with phase tracking
        current_phase = "initializing"
        phase_progress = {
            "initializing": 0,
            "mounting": 5,
            "collecting": 10,
            "scanning": 40,  # Scanning artefacts between collection and processing
            "processing": 45,
            "analyzing": 75,
            "siem_export": 90,  # SIEM export phase (Splunk/Elastic/Navigator)
            "finalizing": 95
        }

        # Track processing progress within the processing phase (45-75%)
        processing_artefact_count = 0
        processing_base_progress = 45
        processing_max_progress = 75

        line_count = 0
        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if line:
                # Clean line: remove ANSI color codes
                line = re.sub(r'\x1b\[[0-9;]*m', '', line)  # Remove ANSI codes like [1;36m, [1;m, etc.

                # STRICT filtering: Only show lines containing ' -> '
                # This ensures only properly formatted audit log entries are shown
                if " -> " not in line:
                    continue

                # Skip noisy internal processing messages even if they contain arrows
                line_lower = line.lower()
                skip_patterns = [
                    r'^mode:\s',  # "Mode: Collect", "Mode: Process", etc.
                    r'completed (collection|processing|analysis) phase',  # Skip standard phases but NOT SIEM phases
                    r"collecting .* for .*\.\.\.",  # "Collecting '$MFT' for 'image.E01'..."
                    r"^mounted .* successfully at .*$",  # "Mounted 'image.E01' successfully at '/mnt/elrond_mount00'"
                    r'^-+$',  # Lines with only dashes (e.g., "----------------------------------------")
                    r"^-> processing '.*' .*\.evtx.* event log for .*$",  # "-> processing 'X.evtx' event log for 'image.E01'"
                    r"^-> processing '.*' (ntuser\.dat|usrclass\.dat) registry hive (from|for) .*$",  # "-> processing 'X' NTUSER.DAT registry hive from 'image.E01'"
                    r"^-> processing registry hive '.*' from .*$",  # "-> processing registry hive 'SOFTWARE' from 'image.E01'"
                    r"^-> processing wmi .* for .*$",  # "-> processing WMI '#1Terminal-Services-Core.etl' for 'image.E01'"
                    r"^-> extracting metadata for .* for .*$",  # "-> extracting metadata for 'X' for 'image.E01'"
                    r"^initializing.*analysis\.\.\.$",  # "Initializing Elrond DFIR Analysis..."
                    r"^case:\s",  # "Case: 111111111"
                    r"^attempting to mount .*\.\.\.$",  # "Attempting to mount 'win7-64-nfury-c-drive.E01'..."
                    r"^-> processing completed for .*$",  # "-> processing completed for 'image.E01'"
                    r"^-> (analysis completed|elrond completed) for .*$",  # "-> analysis completed for 'image.E01'" - we add our own completion message
                    r"^\[.*\] -> elrond completed for .*$",  # "[timestamp] -> elrond completed for 'xxx'" - redundant when phased orchestration used
                    r"-> indexing artefacts for '/.*/$",  # Skip indexing messages that contain output directory paths
                    r"-> splunk configured successfully for case .* for '/.*/$",  # Skip splunk messages that contain output directory paths
                    r"-> cleaning up small files and empty directories",  # Internal cleanup message
                    r"^=+ Commencing Index(ing)? Phase =+$",  # "========== Commencing Indexing Phase ==========" - only skip Indexing, keep others
                ]

                # Check if this line should be skipped
                should_skip = False
                for pattern in skip_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        should_skip = True
                        break

                if should_skip:
                    # Even if skipped from log, still count for progress tracking during processing
                    if current_phase == "processing":
                        processing_artefact_count += 1
                        # Increment progress gradually during processing (45% to 75%)
                        # Assume ~100 artefacts per image on average, cap at 75%
                        incremental_progress = processing_base_progress + min(
                            (processing_artefact_count * 0.3),  # ~0.3% per artefact
                            processing_max_progress - processing_base_progress
                        )
                        if incremental_progress > job.progress:
                            job.progress = int(incremental_progress)
                            # Save progress update periodically
                            if processing_artefact_count % 20 == 0:
                                job_storage.save_job(job)
                    continue

                # Remove duplicate timestamp if present (e.g., "-> 2025-11-23 20:51:49.011749 -> ")
                line = re.sub(r'-> \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ -> ', '-> ', line)

                # Transform "Commencing X Phase..." to uppercase with asterisks for emphasis
                def uppercase_phase(match):
                    prefix = match.group(1) or ''
                    phase_name = match.group(2).upper()
                    return f'{prefix}******** COMMENCING {phase_name} PHASE ********'

                line = re.sub(r'^(-> )?Commencing (.*?) Phase\.\.\.', uppercase_phase, line, flags=re.IGNORECASE)

                # Update log
                log_entry = f"[{datetime.now().isoformat()}] {line}"
                job.log.append(log_entry)
                line_count += 1

                # Determine current phase based on log output
                # Order matters - check more specific patterns first!
                line_lower = line.lower()

                # Check for completion first
                if 'analysis completed successfully' in line_lower or 'analysis finished' in line_lower:
                    current_phase = "finalizing"
                # Check for SIEM export phase (Splunk, Elastic, Navigator)
                elif any(keyword in line_lower for keyword in ['splunk phase', 'elastic phase', 'elasticsearch phase',
                                                                'navigator phase', 'attack-navigator',
                                                                'completed splunk', 'completed elastic', 'completed navigator']):
                    current_phase = "siem_export"
                # Check for mounting
                elif any(keyword in line_lower for keyword in ['mounting', 'mounted']):
                    current_phase = "mounting"
                # Check for collection phase completion - transition to scanning
                elif 'completed collection phase' in line_lower:
                    current_phase = "scanning"
                # Check for scanning artefacts (between collection and processing)
                elif 'scanning for artefacts' in line_lower or 'scanned' in line_lower:
                    current_phase = "scanning"
                # Check for commencing processing phase
                elif 'commencing processing phase' in line_lower:
                    current_phase = "processing"
                # Check for collection activities (including VSS)
                # Must be checked before 'analyzing' since VSS logs might contain 'extracting'
                elif 'collecting' in line_lower or 'volume shadow copy' in line_lower or 'vss' in line_lower:
                    current_phase = "collecting"
                # Check for processing
                elif any(keyword in line_lower for keyword in ['processing', 'parsing', 'parsed']):
                    current_phase = "processing"
                # Check for analyzing - ONLY if specifically in the analysis stage (not during collection)
                # Look for patterns like "Analyze stage" or "analyzing <specific artifact>"
                # but exclude lines that are just describing collection activities
                elif ('analyze stage' in line_lower or 'analysis stage' in line_lower or
                      ('analyzing' in line_lower and 'collecting' not in line_lower and 'artefact' not in line_lower)):
                    current_phase = "analyzing"

                # Set progress based on current phase (don't let it go backwards)
                new_progress = phase_progress.get(current_phase, job.progress)
                if new_progress > job.progress:
                    job.progress = new_progress

                # Save periodically (every 10 lines)
                if line_count % 10 == 0:
                    job_storage.save_job(job)

                logger.info(line)

        # Wait for completion
        return_code = process.wait()

        if return_code == 0:
            # Success
            job.status = JobStatus.COMPLETED
            job.progress = 100

            # Collect results information
            result_info = {
                "output_directory": dest_dir_str,
                "return_code": return_code,
                "analysis_duration": str(datetime.now() - job.started_at),
            }

            # Check for generated files
            output_path = dest_dir
            if output_path.exists():
                try:
                    result_info["output_files"] = len(list(output_path.rglob("*")))
                    result_info["output_size"] = sum(f.stat().st_size for f in output_path.rglob("*") if f.is_file())
                except (FileNotFoundError, PermissionError, OSError) as e:
                    # Handle cases where paths don't exist or are inaccessible
                    # (e.g., symbolic links to unmounted volumes, permission issues)
                    logger.warning(f"Could not enumerate output files: {e}")
                    result_info["output_files"] = 0
                    result_info["output_size"] = 0

            job.result = result_info

            # Run SIEM export if enabled
            opts = job.options
            logger.info(f"Checking SIEM export options: splunk={opts.splunk}, elastic={opts.elastic}, navigator={opts.navigator}")
            if opts.splunk or opts.elastic or opts.navigator:
                try:
                    run_siem_export(job, dest_dir, logger)
                except Exception as e:
                    # SIEM export failed - this is a FATAL error
                    logger.error(f"SIEM export failed: {e}")

                    # Write full traceback to error.log
                    error_log_path = dest_dir / "error.log"
                    with open(error_log_path, "a") as error_log:
                        error_log.write(f"\n{'='*80}\n")
                        error_log.write(f"SIEM Export Error - {datetime.now().isoformat()}\n")
                        error_log.write(f"{'='*80}\n")
                        error_log.write(traceback.format_exc())
                        error_log.write(f"\n{'='*80}\n\n")

                    # Log error reference in job log (no traceback)
                    job.log.append(f"[{datetime.now().isoformat()}] -> SIEM export failed: {e}")
                    job.log.append(f"[{datetime.now().isoformat()}] -> full traceback written to error.log")

                    # Mark job as FAILED and exit
                    job.status = JobStatus.FAILED
                    job.error = f"SIEM export failed: {e}"
                    job_storage.save_job(job)
                    return

            # Don't add completion message here - elrond already logs this
            job_storage.save_job(job)

        else:
            # Failed
            job.status = JobStatus.FAILED
            job.error = f"Process exited with code {return_code}"
            job.log.append(f"[{datetime.now().isoformat()}] -> analysis failed: {job.error}")

    except Exception as e:
        logger.exception(f"Error running analysis for job {job_id}")
        job.status = JobStatus.FAILED
        job.error = str(e)

        # Capture full traceback in the log
        tb_str = traceback.format_exc()
        job.log.append(f"[{datetime.now().isoformat()}] -> ========== error ==========")
        job.log.append(f"[{datetime.now().isoformat()}] -> {str(e)}")
        job.log.append(f"[{datetime.now().isoformat()}] -> traceback:")
        for line in tb_str.split('\n'):
            if line.strip():
                job.log.append(f"[{datetime.now().isoformat()}] -> {line}")

    finally:
        job.completed_at = datetime.now()
        job_storage.save_job(job)


def translate_path_for_worker(path_str: str) -> str:
    """
    Translate paths from backend container perspective to celery-worker perspective.

    Both containers mount:
      - elrond_uploads volume -> /tmp/elrond/uploads (SAME in both containers)
      - /tmp/dernvale (host) -> /tmp/elrond/output (worker) or /host/tmp/dernvale (backend)

    Args:
        path_str: Path from backend perspective

    Returns:
        Path translated for celery worker
    """
    path_str = str(path_str)

    # Paths in /tmp/elrond/uploads are the SAME in both containers (shared volume)
    if path_str.startswith('/tmp/elrond/uploads/'):
        return path_str

    # Backend uses /host/tmp/dernvale for output, worker uses /tmp/elrond/output
    if path_str.startswith('/host/tmp/dernvale'):
        return path_str.replace('/host/tmp/dernvale', '/tmp/elrond/output')

    # Backend uses /tmp/elrond/output, worker uses same
    if path_str.startswith('/tmp/elrond/output'):
        return path_str

    # Default: return as-is
    return path_str


def build_elrond_command(job):
    """
    Build elrond command from job options.

    Args:
        job: Job object

    Returns:
        Command list for subprocess
    """
    cmd = []

    # Case number (positional argument - MUST be first)
    cmd.append(job.case_number)

    opts = job.options

    # Source paths (translate from backend to worker perspective)
    # Just translate the paths - don't extract directory, elrond handles file or directory paths
    translated_sources = [translate_path_for_worker(p) for p in job.source_paths]
    cmd.extend(translated_sources)

    # Destination path (mirror job creation logic and translate to worker perspective)
    dest_path = str(_resolve_destination(job))
    translated_dest = translate_path_for_worker(dest_path)
    cmd.append(translated_dest)

    # Primary mode flags
    # Process is ALWAYS invoked
    cmd.append("--Process")

    # Collection mode (mutually exclusive)
    if opts.gandalf:
        # Gandalf mode: process pre-collected artifacts (no collection)
        cmd.append("--Gandalf")
    else:
        # Default/Local mode: collect from disk image
        cmd.append("--Collect")

    # Analysis options
    analysis_requested = getattr(opts, "analysis", False)
    magic_bytes_requested = analysis_requested or getattr(opts, "magic_bytes", False)

    if analysis_requested:
        cmd.append("--Analysis")
    if magic_bytes_requested:
        cmd.append("--magicBytes")
    if opts.extract_iocs:
        cmd.append("--extractIocs")
    if opts.keywords_file:
        cmd.extend(["--Keywords", opts.keywords_file])
    if opts.yara_dir:
        cmd.extend(["--Yara", opts.yara_dir])

    # Collection options
    # Build collect_files filter from preset options
    collect_filters = []
    if opts.collect_files_sys:
        collect_filters.extend(["exe", "dll", "sys", "drv", "ocx", "scr", "cpl", "msi"])
    if opts.collect_files_docs:
        collect_filters.extend(["doc", "docx", "xls", "xlsx", "pdf", "ppt", "pptx", "rtf", "odt", "ods", "odp"])
    if opts.collect_files_scripts:
        collect_filters.extend(["ps1", "bat", "cmd", "vbs", "js", "py", "sh", "bash", "pl", "rb", "lua"])

    if collect_filters:
        # Enable userprofiles collection (collect_files_* are user profile focused)
        cmd.append("--Userprofiles")
        cmd.extend(["--collectFiles", ",".join(collect_filters)])
    elif opts.collectFiles:
        if opts.collectFiles_filter:
            cmd.extend(["--collectFiles", opts.collectFiles_filter])
        else:
            cmd.append("--collectFiles")

    if opts.vss:
        cmd.append("--vss")
    if opts.userprofiles:
        cmd.append("--Userprofiles")

    # Processing options
    if opts.timeline:
        cmd.append("--Timeline")
    if opts.memory:
        cmd.append("--Memory")
    if opts.memory_timeline:
        cmd.append("--memorytimeline")

    # Output options
    if opts.splunk:
        cmd.append("--Splunk")
    if opts.elastic:
        cmd.append("--Elastic")
    if opts.navigator:
        cmd.append("--Navigator")

    # Speed/Quality modes
    if opts.brisk:
        cmd.append("--Brisk")
    if opts.mordor:
        cmd.append("--Mordor")

    # Hash options
    if opts.nsrl:
        cmd.append("--nsrl")
    if opts.hash_collected:
        cmd.append("--hashCollected")
    if opts.hash_all:
        cmd.append("--hashAll")

    # Post-processing
    if opts.delete:
        cmd.append("--Delete")
    if opts.archive:
        cmd.append("--Ziparchive")

    return cmd
