#!/bin/bash
#
# NSRL Database Download Script for Rowanholt
# ============================================
#
# Downloads and prepares the NIST National Software Reference Library (NSRL)
# Reference Data Set (RDS) for use with Rowanholt's hash comparison feature.
#
# The NSRL contains cryptographic hashes of known software, helping to:
# - Identify known-good files quickly
# - Filter out common software to focus on unknowns
# - Reduce false positives in malware analysis
#
# Usage:
#   ./download-nsrl.sh [OPTIONS]
#
# Options:
#   -d, --directory DIR    Installation directory (default: /opt/nsrl)
#   -m, --minimal          Download minimal RDS (SHA-256 only, ~3GB)
#   -f, --full             Download full RDS (all hashes, ~30GB)
#   -u, --update           Update existing installation
#   -h, --help             Show this help message
#
# Requirements:
#   - curl or wget
#   - unzip
#   - ~35GB free disk space (full) or ~5GB (minimal)
#
# After installation, configure Rowanholt to use NSRL:
#   elrond.py -c -p -n --nsrl /opt/nsrl/NSRLFile.txt <image>
#
# Or via CLI:
#   elrond.py --nsrl /opt/nsrl/NSRLFile.txt <image>
#

set -e

# Default settings
NSRL_DIR="/opt/nsrl"
DOWNLOAD_TYPE="minimal"
UPDATE_MODE=false

# NSRL download URLs (NIST official)
# Note: These URLs may change - check https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
NSRL_MODERN_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_modern.iso"
NSRL_MINIMAL_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    head -40 "$0" | tail -35 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_requirements() {
    log_info "Checking requirements..."

    # Check for download tool
    if command -v curl &> /dev/null; then
        DOWNLOAD_CMD="curl -L -o"
    elif command -v wget &> /dev/null; then
        DOWNLOAD_CMD="wget -O"
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    # Check for unzip
    if ! command -v unzip &> /dev/null; then
        log_error "unzip not found. Please install it."
        exit 1
    fi

    # Check disk space
    AVAILABLE_SPACE=$(df -BG "$NSRL_DIR" 2>/dev/null | tail -1 | awk '{print $4}' | sed 's/G//' || echo "0")
    if [ "$DOWNLOAD_TYPE" = "full" ] && [ "$AVAILABLE_SPACE" -lt 35 ]; then
        log_warning "Less than 35GB available. Full download requires ~35GB."
    elif [ "$DOWNLOAD_TYPE" = "minimal" ] && [ "$AVAILABLE_SPACE" -lt 5 ]; then
        log_warning "Less than 5GB available. Minimal download requires ~5GB."
    fi

    log_success "Requirements check passed"
}

create_directory() {
    log_info "Creating NSRL directory: $NSRL_DIR"

    if [ -d "$NSRL_DIR" ] && [ "$UPDATE_MODE" = false ]; then
        log_warning "Directory already exists: $NSRL_DIR"
        read -p "Remove existing directory and continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Aborted."
            exit 0
        fi
        rm -rf "$NSRL_DIR"
    fi

    mkdir -p "$NSRL_DIR"
    log_success "Directory created"
}

download_minimal() {
    log_info "Downloading NSRL Minimal RDS (SHA-256 hashes only)..."
    log_info "This will download approximately 800MB compressed (~3GB extracted)"

    local TEMP_FILE="$NSRL_DIR/rds_modernm.zip"

    # Download
    $DOWNLOAD_CMD "$TEMP_FILE" "$NSRL_MINIMAL_URL"

    if [ ! -f "$TEMP_FILE" ]; then
        log_error "Download failed"
        exit 1
    fi

    log_info "Extracting archive..."
    unzip -o "$TEMP_FILE" -d "$NSRL_DIR"

    # Clean up
    rm -f "$TEMP_FILE"

    log_success "Minimal NSRL database downloaded and extracted"
}

download_full() {
    log_info "Downloading NSRL Full RDS (all hash types)..."
    log_info "This will download approximately 8GB compressed (~30GB extracted)"
    log_warning "This may take a long time depending on your connection speed"

    local TEMP_FILE="$NSRL_DIR/RDS_modern.iso"

    # Download
    $DOWNLOAD_CMD "$TEMP_FILE" "$NSRL_MODERN_URL"

    if [ ! -f "$TEMP_FILE" ]; then
        log_error "Download failed"
        exit 1
    fi

    log_info "Mounting and extracting ISO..."

    # Create mount point
    local MOUNT_POINT="$NSRL_DIR/mount"
    mkdir -p "$MOUNT_POINT"

    # Mount ISO (platform-specific)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        hdiutil attach "$TEMP_FILE" -mountpoint "$MOUNT_POINT" -nobrowse
        cp -r "$MOUNT_POINT"/* "$NSRL_DIR/"
        hdiutil detach "$MOUNT_POINT"
    else
        # Linux
        if command -v mount &> /dev/null; then
            sudo mount -o loop "$TEMP_FILE" "$MOUNT_POINT"
            cp -r "$MOUNT_POINT"/* "$NSRL_DIR/"
            sudo umount "$MOUNT_POINT"
        else
            log_error "Cannot mount ISO. Install mount or use 7z to extract."
            exit 1
        fi
    fi

    # Clean up
    rm -rf "$MOUNT_POINT"
    rm -f "$TEMP_FILE"

    log_success "Full NSRL database downloaded and extracted"
}

create_hash_index() {
    log_info "Creating optimized hash index for faster lookups..."

    # Find the main NSRL file
    local NSRL_FILE=""
    for f in "$NSRL_DIR/NSRLFile.txt" "$NSRL_DIR/rds_modernm/NSRLFile.txt" "$NSRL_DIR/RDS_*/NSRLFile.txt"; do
        if [ -f "$f" ]; then
            NSRL_FILE="$f"
            break
        fi
    done

    if [ -z "$NSRL_FILE" ]; then
        log_warning "NSRLFile.txt not found. Index creation skipped."
        return
    fi

    log_info "Found NSRL file: $NSRL_FILE"

    # Create SHA-256 only index for faster lookups
    local INDEX_FILE="$NSRL_DIR/nsrl_sha256.txt"
    log_info "Extracting SHA-256 hashes to: $INDEX_FILE"

    # Extract just the SHA-256 column (typically column 1) and sort for binary search
    # NSRL format: "SHA-256","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
    tail -n +2 "$NSRL_FILE" | cut -d',' -f1 | tr -d '"' | sort -u > "$INDEX_FILE"

    local HASH_COUNT=$(wc -l < "$INDEX_FILE" | tr -d ' ')
    log_success "Created index with $HASH_COUNT unique SHA-256 hashes"

    # Create symlink for Rowanholt
    ln -sf "$NSRL_FILE" "$NSRL_DIR/NSRLFile.txt" 2>/dev/null || true
}

show_usage() {
    echo ""
    log_success "NSRL database installation complete!"
    echo ""
    echo "Installation directory: $NSRL_DIR"
    echo ""
    echo "Files available:"
    ls -lh "$NSRL_DIR"/*.txt 2>/dev/null | head -5 || echo "  (check subdirectories)"
    echo ""
    echo "Usage with Rowanholt CLI:"
    echo "  elrond.py -c -p -n --nsrl $NSRL_DIR/NSRLFile.txt <image>"
    echo ""
    echo "Usage with standalone hash comparison:"
    echo "  # Compare a single hash"
    echo "  grep -i '<sha256_hash>' $NSRL_DIR/nsrl_sha256.txt"
    echo ""
    echo "  # Compare multiple hashes from a file"
    echo "  while read hash; do grep -qi \"\$hash\" $NSRL_DIR/nsrl_sha256.txt && echo \"\$hash: KNOWN\"; done < hashes.txt"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--directory)
            NSRL_DIR="$2"
            shift 2
            ;;
        -m|--minimal)
            DOWNLOAD_TYPE="minimal"
            shift
            ;;
        -f|--full)
            DOWNLOAD_TYPE="full"
            shift
            ;;
        -u|--update)
            UPDATE_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Main execution
echo ""
echo "=========================================="
echo "  NSRL Database Download for Rowanholt"
echo "=========================================="
echo ""
echo "Download type: $DOWNLOAD_TYPE"
echo "Install directory: $NSRL_DIR"
echo ""

check_requirements
create_directory

if [ "$DOWNLOAD_TYPE" = "minimal" ]; then
    download_minimal
else
    download_full
fi

create_hash_index
show_usage
