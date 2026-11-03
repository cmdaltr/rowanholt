# Dernvale Progress Tracking

This document describes how progress percentage is calculated during forensic analysis jobs.

## Overview

Progress is tracked per-image and scaled to overall job progress:
- Each image gets a proportional share of 0-95% progress
- Final 5% (95-100%) is reserved for job completion
- Progress never goes backwards

## Phase Transitions

| Trigger Message | Internal Progress |
|-----------------|-------------------|
| Identification phase | 5% |
| Scanning for forensic images | 7% |
| Found forensic image | 8% |
| **Commencing Collection Phase** | **10%** |
| Identifying operating system | 12% |
| Identified platform | 15% |
| **Completed Collection Phase** | **35%** |
| Scanning for artefacts | 40% |
| **Commencing Processing Phase** | **45%** |
| **Completed Processing Phase** | **70%** |
| **Commencing Analysis Phase** | **75%** |
| **Completed Analysis Phase** | **95%** |
| Splunk/Elastic/Navigator phases | 97% |
| Dernvale completed | 95% (overall) |

## Collection Sub-Steps (Windows)

| Trigger Message | Progress Range |
|-----------------|----------------|
| Collecting artefacts for... | 12% → 25% |
| Copying full user profile | 25% → 33% |
| Completed copying profile | 26% → 34% |
| Collecting registry/WMI/WBEM | 30% → 34% |
| Collected event logs | 34% |
| Recovered ($I30 records) | 35% |

## Collection Sub-Steps (Linux)

| Trigger Message | Progress Range |
|-----------------|----------------|
| /etc/passwd, shadow, group, hosts | 18% → 24% |
| Configuration files | 20% → 28% |
| Crontab | 22% → 28% |
| Bash history/files | 24% → 30% |
| Service files (systemd) | 26% → 32% |
| Systemd journal | 28% → 34% |
| Keyrings | 30% → 34% |

## Collection Sub-Steps (macOS)

| Trigger Message | Progress Range |
|-----------------|----------------|
| /etc/passwd, shadow, group, hosts | 18% → 24% |
| Crontab | 22% → 28% |
| Plist files | 24% → 33% |
| LaunchAgents/LaunchDaemons | 26% → 32% |
| StartupItems | 28% → 33% |
| Trash files | 30% → 34% |

## Shared (Linux/macOS)

| Trigger Message | Progress Range |
|-----------------|----------------|
| Log files (/var/log, /Library/Logs) | 22% → 30% |
| Temp files (/tmp) | 32% → 34% |
| Memory files (sleepimage, swapfile) | 33% → 35% |

## Processing & Analysis

| Phase | Progress Range |
|-------|----------------|
| Processing/parsing | 45% → 65% |
| Analyzing | 75% → 93% |

## Generic Fallback

| Trigger Message | Progress Range |
|-----------------|----------------|
| General "collecting/mounting" | 15% → 32% |

## Multi-Image Scaling

Progress is dynamically scaled based on the total number of images being analyzed.

### How it works

1. **Initial estimate**: Progress starts with an estimate from `source_paths` count
2. **Dynamic adjustment**: When elrond reports "Processing image X of Y", the system uses Y as the actual image count
3. **Progress range**: 95% is divided equally among all images (5% reserved for completion)

### Example: 3 images

| Image | Progress Range |
|-------|----------------|
| Image 1 of 3 | 0% - 31.6% |
| Image 2 of 3 | 31.6% - 63.3% |
| Image 3 of 3 | 63.3% - 95% |

### Example: 2 images

| Image | Progress Range |
|-------|----------------|
| Image 1 of 2 | 0% - 47.5% |
| Image 2 of 2 | 47.5% - 95% |

### Example: 1 image

| Image | Progress Range |
|-------|----------------|
| Image 1 of 1 | 0% - 95% |

Each image's internal progress (0-100% scale) is mapped to its allocated range. For example, if Image 2 of 3 is at 50% internal progress, the overall job progress would be: `31.6% + (31.6% × 0.5) = 47.4%`

## Implementation

Progress tracking is implemented in `src/web/backend/tasks_docker.py` in the `start_analysis` task.

Key variables:
- `total_images`: Total number of images being analyzed (dynamically updated from elrond output)
- `image_progress_range`: Progress range allocated to each image (95 / total_images)
- `image_base_progress`: Starting progress for current image
- `image_internal_progress`: Progress within current image (0-100 scale)
- `actual_image_count_detected`: Flag indicating if elrond has reported the actual image count
- `progress_count`: Number of log lines processed

Progress is saved to the job storage every 10 log lines.

## DEBUG Messages

Debug messages (MITRE enrichment, verbose command output) are filtered out by default.
They only appear in the job log if the "Debug" option is enabled in the Web UI.
