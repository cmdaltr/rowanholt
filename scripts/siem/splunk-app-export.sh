#!/bin/bash
#
# Export Elrond Splunk App for Splunk Base Publishing
#
# This script exports the Elrond Splunk app from the Docker container
# in the correct format for Splunk Base publishing, ensuring no case-specific
# data is included.
#
# Usage: ./export-splunk-app.sh [version]
#   version: Optional version number (e.g., 1.3.0). If not provided, uses current version from app.conf
#
# Output: Creates elrond-<version>.tar.gz in the current directory
#

set -e

CONTAINER_NAME="rowanholt-splunk"
APP_NAME="elrond"
EXPORT_DIR="/tmp/splunk_app_export"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Elrond Splunk App Export Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if Docker container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}Error: Docker container '${CONTAINER_NAME}' is not running.${NC}"
    echo "Please start the container first with: docker start ${CONTAINER_NAME}"
    exit 1
fi

# Get version from argument or from app.conf
if [ -n "$1" ]; then
    VERSION="$1"
    echo -e "${YELLOW}Using provided version: ${VERSION}${NC}"
else
    VERSION=$(docker exec ${CONTAINER_NAME} grep "^version" /opt/splunk/etc/apps/${APP_NAME}/default/app.conf | cut -d'=' -f2 | tr -d ' ')
    if [ -z "$VERSION" ]; then
        VERSION="1.0.0"
    fi
    echo -e "${YELLOW}Using version from app.conf: ${VERSION}${NC}"
fi

# Clean up any previous export
rm -rf "${EXPORT_DIR}"
mkdir -p "${EXPORT_DIR}"

echo ""
echo "Step 1: Copying app from container..."
docker cp ${CONTAINER_NAME}:/opt/splunk/etc/apps/${APP_NAME} "${EXPORT_DIR}/"

echo "Step 2: Cleaning up case-specific data..."

# Remove inputs.conf (contains case-specific file paths)
rm -f "${EXPORT_DIR}/${APP_NAME}/default/inputs.conf"
echo "  - Removed inputs.conf"

# Remove any local directory (user-specific settings)
rm -rf "${EXPORT_DIR}/${APP_NAME}/local"
echo "  - Removed local/ directory"

# Remove any metadata/local.meta
rm -f "${EXPORT_DIR}/${APP_NAME}/metadata/local.meta"
echo "  - Removed metadata/local.meta"

# Remove lookups directory if it contains case data
if [ -d "${EXPORT_DIR}/${APP_NAME}/lookups" ]; then
    # Keep only template/empty lookups, remove any with actual data
    find "${EXPORT_DIR}/${APP_NAME}/lookups" -name "*.csv" -size +1k -delete 2>/dev/null || true
    echo "  - Cleaned lookups directory"
fi

# Remove any .pyc files
find "${EXPORT_DIR}/${APP_NAME}" -name "*.pyc" -delete 2>/dev/null || true
find "${EXPORT_DIR}/${APP_NAME}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "  - Removed Python cache files"

# Remove any .DS_Store files (macOS)
find "${EXPORT_DIR}/${APP_NAME}" -name ".DS_Store" -delete 2>/dev/null || true
echo "  - Removed .DS_Store files"

# Remove any .git directories
find "${EXPORT_DIR}/${APP_NAME}" -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true
echo "  - Removed .git directories"

echo "Step 3: Updating app.conf with version ${VERSION}..."

# Update app.conf with the new version and ensure proper Splunk Base metadata
cat > "${EXPORT_DIR}/${APP_NAME}/default/app.conf" << EOF
#
# Splunk app configuration file
#

[install]
is_configured = false
state = enabled
build = $(date +%Y%m%d)

[ui]
is_visible = true
label = Elrond DFIR
supported_themes = light,dark

[launcher]
author = cmdaltr
description = Digital Forensics and Incident Response (DFIR) analysis app for the Rowanholt DF Acceleration Suite. Provides MITRE ATT&CK technique mapping, artifact analysis dashboards, and IOC detection capabilities.
version = ${VERSION}

[package]
id = elrond
check_for_updates = true
EOF

echo "Step 4: Creating app.manifest for Splunk Cloud compatibility..."

cat > "${EXPORT_DIR}/${APP_NAME}/app.manifest" << EOF
{
  "schemaVersion": "2.0.0",
  "info": {
    "title": "Elrond DFIR",
    "id": {
      "group": null,
      "name": "elrond",
      "version": "${VERSION}"
    },
    "author": [
      {
        "name": "cmdaltr",
        "email": null,
        "company": null
      }
    ],
    "releaseDate": null,
    "description": "Digital Forensics and Incident Response (DFIR) analysis app for the Rowanholt DF Acceleration Suite. Provides MITRE ATT&CK technique mapping, artifact analysis dashboards, and IOC detection capabilities.",
    "classification": {
      "intendedAudience": "Security",
      "categories": ["Security, Fraud & Compliance"],
      "developmentStatus": "Production/Stable"
    },
    "commonInformationModels": null,
    "license": {
      "name": "MIT",
      "text": null,
      "uri": null
    },
    "privacyPolicy": {
      "name": null,
      "text": null,
      "uri": null
    },
    "releaseNotes": {
      "name": "Release Notes",
      "text": "See README for details",
      "uri": null
    }
  },
  "dependencies": null,
  "tasks": null,
  "inputGroups": null,
  "incompatibleApps": null,
  "platformRequirements": {
    "splunk": {
      "Enterprise": "*"
    }
  },
  "supportedDeployments": ["_standalone", "_distributed", "_search_head_clustering"],
  "targetWorkloads": ["_search_heads"]
}
EOF

echo "Step 5: Ensuring README.txt exists..."

if [ ! -f "${EXPORT_DIR}/${APP_NAME}/README.txt" ]; then
    cat > "${EXPORT_DIR}/${APP_NAME}/README.txt" << EOF
Elrond DFIR - Splunk App
========================

Version: ${VERSION}

Description
-----------
Elrond is a Digital Forensics and Incident Response (DFIR) analysis app
designed for the Rowanholt DF Acceleration Suite. It provides:

- MITRE ATT&CK technique mapping and visualization
- Artifact analysis dashboards
- IOC detection capabilities
- Timeline analysis
- Keyword and YARA rule matching

Requirements
------------
- Splunk Enterprise 8.0 or later
- Rowanholt DF Acceleration Suite (for data ingestion)

Installation
------------
1. Download and extract the app
2. Copy to \$SPLUNK_HOME/etc/apps/
3. Restart Splunk

Documentation
-------------
For full documentation, visit:
https://github.com/cmdaltr/rowanholt

Support
-------
For issues and feature requests, please use the GitHub issue tracker.

License
-------
MIT License

Author
------
cmdaltr
EOF
fi

echo "Step 6: Cleaning nav.xml of case-specific entries..."

# Create a clean nav.xml without case-specific views
NAV_FILE="${EXPORT_DIR}/${APP_NAME}/default/data/ui/nav/default.xml"
if [ -f "$NAV_FILE" ]; then
    # Remove case-specific views from Cases collection but keep the structure
    python3 << PYSCRIPT
import re

with open("${NAV_FILE}", "r") as f:
    content = f.read()

# Replace the Cases collection content with an empty placeholder
# This regex matches the Cases collection and replaces its contents
content = re.sub(
    r'(<collection label="Cases">).*?(</collection>)',
    r'\1\n\t\t<!-- Case views will be added dynamically -->\n\t\2',
    content,
    flags=re.DOTALL
)

with open("${NAV_FILE}", "w") as f:
    f.write(content)

print("  - Cleaned Cases collection in nav.xml")
PYSCRIPT
fi

echo "Step 7: Creating tarball..."

# Create the tarball in Splunk Base format (app folder at root level)
cd "${EXPORT_DIR}"
tar -czvf "${APP_NAME}-${VERSION}.tar.gz" ${APP_NAME}

# Move to output location
OUTPUT_FILE="${SCRIPT_DIR}/../${APP_NAME}-${VERSION}.tar.gz"
mv "${EXPORT_DIR}/${APP_NAME}-${VERSION}.tar.gz" "${OUTPUT_FILE}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Export Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Output file: ${YELLOW}${OUTPUT_FILE}${NC}"
echo ""
echo "File contents:"
tar -tzvf "${OUTPUT_FILE}" | head -20
echo "..."
echo ""
echo -e "Total files: $(tar -tzvf "${OUTPUT_FILE}" | wc -l)"
echo -e "File size: $(ls -lh "${OUTPUT_FILE}" | awk '{print $5}')"
echo ""
echo -e "${GREEN}Ready for Splunk Base submission!${NC}"
echo ""
echo "Next steps:"
echo "  1. Go to https://splunkbase.splunk.com"
echo "  2. Sign in and click 'Publish an App'"
echo "  3. Upload ${OUTPUT_FILE}"
echo "  4. Fill in the app details and submit for review"
echo ""

# Cleanup
rm -rf "${EXPORT_DIR}"
