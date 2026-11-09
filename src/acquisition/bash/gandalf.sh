#!/usr/bin/env bash

#############################################################################
# Gandalf Bash - Remote Forensic Artifact Acquisition Tool
#
# A pure bash implementation for Linux and macOS forensic evidence collection
# Part of the Rowanholt DF Acceleration Suite
#
# Usage: sudo ./gandalf.sh [ENCRYPTION] [MODE] [OPTIONS]
#
# Encryption: Key, Password, None
# Mode: Local, Remote
# Options: -o OUTPUT_DIR, -m (memory), -a (access times), -c (collect files)
#
#############################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version
VERSION="2.1.0"

# Default values
ENCRYPTION_METHOD=""
ACQUISITION_MODE=""
OUTPUT_DIR="/tmp/gandalf/acquisitions"
MEMORY_DUMP=false
ACCESS_TIMES=false
COLLECT_FILES=false
LIVE_CONTAINERS=false
SHOW_PROGRESS=false
NO_PROMPT=false
HOSTS_FILE=""
REMOTE_USER=""
REMOTE_HOST=""
WORK_DIR="/tmp/gandalf"

is_macos() { [ "$(uname -s)" = "Darwin" ]; }

# Lowercase without bash 4's ${var,,} (macOS ships bash 3.2)
lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# SHA-256 of a file: sha256sum on Linux, shasum on macOS
sha256_of() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Banner function
print_banner() {
    cat << "EOF"
    ____                  __      __  ____
   / ___| __ _ _ __   __| | __ _ \ \/ /\ \
  | |  _ / _` | '_ \ / _` |/ _` | \  /  | |
  | |_| | (_| | | | | (_| | (_| | /  \  | |
   \____|\__,_|_| |_|\__,_|\__,_|/_/\_\ | |
                                         /_/
   Bash Edition - Remote Forensic Acquisition
EOF
    echo "   Version ${VERSION}"
    echo
    local quotes=(
        "You shall pass... your artifacts to the analyst!"
        "The Road goes ever on and on... and ends at the analyst"
        "Even the very wise cannot see all ends: collect everything"
        "Keep it secret, keep it safe... then decrypt it for analysis"
        "All we have to decide is what to do with the evidence given to us"
    )
    local random_quote=${quotes[$RANDOM % ${#quotes[@]}]}
    echo -e "${BLUE}   ${random_quote}${NC}\n"
}

# Usage function
usage() {
    echo "Usage: sudo $0 <Encryption> <Mode> [OPTIONS]"
    echo ""
    echo "Encryption Methods:"
    echo "  Key       - Generate and use encryption key file"
    echo "  Password  - Use password-based encryption"
    echo "  None      - No encryption"
    echo ""
    echo "Acquisition Modes:"
    echo "  Local     - Acquire from local system"
    echo "  Remote    - Acquire from remote hosts via SSH"
    echo ""
    echo "Options:"
    echo "  -o DIR    Output directory (default: /tmp/gandalf/acquisitions)"
    echo "  -m        Acquire memory dump"
    echo "  -a        Collect file access times"
    echo "  -c        Collect specific files from files.list"
    echo "  -l        Live containers: ask Docker and Podman about their running containers"
    echo "            (inspect, processes, filesystem export); opt-in, every command audited"
    echo "  -h HOST   Remote hostname (for Remote mode)"
    echo "  -u USER   Remote username (for Remote mode)"
    echo "  -f FILE   Hosts file (for Remote mode batch)"
    echo "  -p        Show progress: each artefact as it's taken"
    echo "  -n        No questions: accept the defaults (the remote username is yours);"
    echo "            an encryption password is still asked for"
    echo ""
    echo "Examples:"
    echo "  sudo $0 None Local"
    echo "  sudo $0 Password Local -m -o /evidence"
    echo "  sudo $0 Key Remote -h 192.168.1.100 -u analyst"
    echo ""
    exit 1
}

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    local cmds="tar gzip hostname date"
    # Only Remote mode needs an SSH client; Local runs on the target itself.
    [ "$(lower "$ACQUISITION_MODE")" = "remote" ] && cmds="$cmds ssh scp"
    for cmd in $cmds; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
        missing_deps+=("sha256sum")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Missing required dependencies: ${missing_deps[*]}"
        echo "Please install them before running this script"
        exit 1
    fi
}

# Parse arguments
parse_args() {
    if [ $# -lt 2 ]; then
        usage
    fi

    ENCRYPTION_METHOD="$1"
    ACQUISITION_MODE="$2"
    shift 2

    # Validate encryption method
    case "$(lower "$ENCRYPTION_METHOD")" in
        key|password|none)
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid encryption method: $ENCRYPTION_METHOD"
            usage
            ;;
    esac

    # Validate acquisition mode
    case "$(lower "$ACQUISITION_MODE")" in
        local|remote)
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid acquisition mode: $ACQUISITION_MODE"
            usage
            ;;
    esac

    # Parse options
    while getopts "o:machlu:f:pn" opt; do
        case $opt in
            o) OUTPUT_DIR="$OPTARG" ;;
            m) MEMORY_DUMP=true ;;
            a) ACCESS_TIMES=true ;;
            c) COLLECT_FILES=true ;;
            l) LIVE_CONTAINERS=true ;;
            h) REMOTE_HOST="$OPTARG" ;;
            u) REMOTE_USER="$OPTARG" ;;
            f) HOSTS_FILE="$OPTARG" ;;
            p) SHOW_PROGRESS=true ;;
            n) NO_PROMPT=true ;;
            *) usage ;;
        esac
    done
}

# Initialize directories
init_directories() {
    local hostname="$1"
    local acq_dir="${OUTPUT_DIR}/${hostname}"

    mkdir -p "${acq_dir}/artefacts"/{memory,logs,conf,cron,services,browsers,user,tmp}
    is_macos && mkdir -p "${acq_dir}/artefacts"/{plists,logs_library,logs_security,shared}

    echo "$acq_dir"
}

# Initialize audit log
init_audit_log() {
    local log_file="$1"
    echo "datetime,hostname,artefact,collected" > "$log_file"
}

# Initialize metadata log
init_meta_log() {
    local log_file="$1"
    echo "hostname,file_path,sha256_hash" > "$log_file"
}

# Log to audit
log_audit() {
    local log_file="$1"
    local hostname="$2"
    local artefact="$3"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
    case "$timestamp" in *N*) timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z") ;; esac  # BSD date has no %N

    echo "${timestamp},${hostname},${artefact},collected" >> "$log_file"
    [ "$SHOW_PROGRESS" = true ] && echo "   -> ${timestamp} -> ${artefact}" >&2
    return 0
}

# Copy a file into the acquisition directory. Hashing waits for write_manifest, once
# everything is copied, so it doesn't widen the window in which the system changes.
collect_file() {
    local source="$1"
    local dest="$2"
    local hostname="$3"
    local meta_log="$4"

    if [ -e "$source" ]; then
        # Create destination directory
        mkdir -p "$(dirname "$dest")"

        # Copy file preserving timestamps
        cp -p "$source" "$dest" 2>/dev/null || return 1
        return 0
    fi
    return 1
}

# Collect volatile data
collect_volatile() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"

    echo -e "${BLUE}[*]${NC} Collecting volatile data..."

    # Order of volatility (RFC 3227): connections change by the second, then processes
    if is_macos; then
        netstat -anv > "${acq_dir}/artefacts/netstat.info" 2>/dev/null && log_audit "$audit_log" "$hostname" "netstat.info" || true
        lsof -nP -i > "${acq_dir}/artefacts/lsof.info" 2>/dev/null && log_audit "$audit_log" "$hostname" "lsof.info" || true
    else
        if command -v ss &> /dev/null; then
            ss -tunap > "${acq_dir}/artefacts/ss.info" 2>/dev/null || true
            log_audit "$audit_log" "$hostname" "ss.info"
        fi
        if command -v netstat &> /dev/null; then
            netstat -tunap > "${acq_dir}/artefacts/netstat.info" 2>/dev/null || true
            log_audit "$audit_log" "$hostname" "netstat.info"
        fi
    fi

    ps aux > "${acq_dir}/artefacts/process.info" 2>/dev/null || true
    log_audit "$audit_log" "$hostname" "process.info"

    if is_macos; then
        collect_volatile_macos "$acq_dir" "$hostname" "$audit_log"
    else
        lsmod > "${acq_dir}/artefacts/lsmod.info" 2>/dev/null || true
        env > "${acq_dir}/artefacts/env.info" 2>/dev/null || true
    fi

    # First line is what Elrond reads: <host>::<Linux|macOS>
    local platform="Linux"
    is_macos && platform="macOS"
    { echo "${hostname}::${platform}"; uname -a; } > "${acq_dir}/artefacts/host.info" 2>/dev/null || true
    log_audit "$audit_log" "$hostname" "host.info"
}

# A command run on the target, not a file taken from it: audited as "ran"
log_live() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
    case "$timestamp" in *N*) timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z") ;; esac
    echo "${timestamp},$2,$3,ran" >> "$1"
    [ "$SHOW_PROGRESS" = true ] && echo "   -> ${timestamp} -> ran: $3" >&2
    return 0
}

# -l: what Docker and Podman say about their running containers, which the files on disk
# don't hold: the processes running in each, and its filesystem as it is now. Asking the
# runtime touches the live host (its daemon logs the calls; export reads the whole
# filesystem), so it's opt-in and every command is audited. export never pauses or stops
# the container. Each export is cut at GANDALF_CONTAINER_EXPORT_MAX bytes (default 2 GB;
# 0 leaves exports out), and the audit says when it was cut. Rootless Podman keeps each
# user's containers to that user (root's podman doesn't list them), so each user with
# rootless storage is asked as themselves too, and the audit names them.
collect_live_containers() {
    local acq_dir="$1" hostname="$2" audit_log="$3"
    local name _x uid home source
    local sources=()
    command -v docker &> /dev/null && sources+=(docker)
    if command -v podman &> /dev/null; then
        sources+=(podman)
        while IFS=: read -r name _x uid _x _x home _x; do
            [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ] || continue
            [ -d "$home/.local/share/containers/storage" ] && sources+=("podman:$name")
        done < /etc/passwd
    fi
    for source in "${sources[@]}"; do
        live_from "$acq_dir" "$hostname" "$audit_log" "$source"
    done
}

# docker, podman (root's), or podman:<user>, run as that user with their own runtime dir
runtime_cmd() {
    local source="$1"; shift
    case "$source" in
        podman:*)
            local user="${source#podman:}" uid run=""
            uid=$(id -u "$user" 2>/dev/null) || return 1
            [ -d "/run/user/$uid" ] && run="XDG_RUNTIME_DIR=/run/user/$uid "
            if command -v runuser &> /dev/null; then
                runuser -l "$user" -c "${run}podman $*"
            else
                su -l "$user" -s /bin/sh -c "${run}podman $*"
            fi ;;
        *) "$source" "$@" ;;
    esac
}

live_from() {
    local acq_dir="$1" hostname="$2" audit_log="$3" source="$4"
    local max="${GANDALF_CONTAINER_EXPORT_MAX:-2147483648}" runtime="${4%%:*}" label id dir size
    label="$runtime"
    [ "$source" != "$runtime" ] && label="$runtime (rootless, ${source#podman:})"
    for id in $(runtime_cmd "$source" ps -q --no-trunc 2>/dev/null); do
        case "$id" in *[!0-9a-f]*) continue ;; esac
        dir="${acq_dir}/artefacts/live_containers/${runtime}/${id:0:12}"
        mkdir -p "$dir"
        runtime_cmd "$source" inspect "$id" > "$dir/inspect.json" 2>/dev/null && log_live "$audit_log" "$hostname" "$label inspect $id"
        if [ "$runtime" = docker ]; then
            docker top "$id" -eo pid,ppid,user,etime,args > "$dir/top.txt" 2>/dev/null
        else
            runtime_cmd "$source" top "$id" pid ppid user etime args > "$dir/top.txt" 2>/dev/null
        fi && log_live "$audit_log" "$hostname" "$label top $id"
        [ -s "$dir/top.txt" ] || rm -f "$dir/top.txt"
        [ "$max" -gt 0 ] 2>/dev/null || continue
        runtime_cmd "$source" export "$id" 2>/dev/null | head -c "$max" > "$dir/export.tar"
        size=$(wc -c < "$dir/export.tar" | tr -d ' ')
        if [ "$size" -ge "$max" ]; then
            log_live "$audit_log" "$hostname" "$label export $id (cut at $max bytes)"
        else
            log_live "$audit_log" "$hostname" "$label export $id"
        fi
    done
}

# Collect memory dump
collect_memory() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"

    if [ "$MEMORY_DUMP" = false ]; then
        return 0
    fi

    echo -e "${BLUE}[*]${NC} Acquiring memory dump..."

    # Check for AVML
    if command -v avml &> /dev/null; then
        avml "${acq_dir}/artefacts/memory/${hostname}.mem" 2>/dev/null || {
            echo -e "${YELLOW}[!]${NC} Memory acquisition failed"
            return 0
        }
        log_audit "$audit_log" "$hostname" "memory/${hostname}.mem"
        echo -e "${GREEN}[+]${NC} Memory dump acquired"
    else
        echo -e "${YELLOW}[!]${NC} AVML not found, skipping memory acquisition"
    fi
}

# Collect filesystem artifacts
collect_artifacts() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"

    echo -e "${BLUE}[*]${NC} Collecting filesystem artifacts..."

    if is_macos; then
        collect_macos_artifacts "$acq_dir" "$hostname" "$audit_log" "$meta_log"
        return 0
    fi

    # Order of volatility: temp directories (cleaned by tmpfiles and reboots) and the
    # loaded modules, then logs (rotated), then configuration and user files
    collect_linux_volatile_files "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_directory "/var/log" "${acq_dir}/artefacts/logs" "$hostname" "$audit_log" "$meta_log" || true

    # Artefact mappings: source|destination under artefacts/ (a plain list, as
    # bash 3.2 has no associative arrays)
    local mapping source dest_name dest
    while IFS='|' read -r source dest_name; do
        [ -n "$source" ] || continue
        dest="${acq_dir}/artefacts/${dest_name:-$(basename "$source")}"
        if collect_file "$source" "$dest" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "$source"
        fi
    done <<'MAP'
/etc/passwd|etc+passwd
/etc/shadow|etc+shadow
/etc/group|etc+group
/etc/hosts|etc+hosts
/etc/hostname|etc+hostname
/etc/fstab|etc+fstab
/etc/sudoers|conf/etc+sudoers
/etc/ssh/sshd_config|conf/etc+ssh+sshd_config
/etc/crontab|cron/etc+crontab
/etc/timezone|etc+timezone
/etc/os-release|etc+os-release
MAP

    collect_directory "/etc/cron.d" "${acq_dir}/artefacts/cron" "$hostname" "$audit_log" "$meta_log" || true
    # Per-user crontabs (/var/spool/cron/crontabs/<user> or /var/spool/cron/<user>) and at jobs
    collect_directory "/var/spool/cron" "${acq_dir}/artefacts/cron_jobs" "$hostname" "$audit_log" "$meta_log" 3 1M || true
    collect_directory "/var/spool/at" "${acq_dir}/artefacts/at_jobs" "$hostname" "$audit_log" "$meta_log" 2 1M || true
    collect_directory "/etc/systemd" "${acq_dir}/artefacts/conf" "$hostname" "$audit_log" "$meta_log" || true

    collect_linux_extras "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_container_layers "$acq_dir" "$hostname" "$audit_log" "$meta_log"

    # User directories (limited to key files)
    for user_home in /home/* /root; do
        if [ -d "$user_home" ]; then
            local username=$(basename "$user_home")
            collect_user_artifacts "$user_home" "$username" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
        fi
    done
}

# Linux artefacts beyond the core set, into artefacts/linux/ under their path with
# '/' as '+' (etc+pam.d+sshd). Elrond's collect/linux.py and gandalf.py carry the
# same lists. A file reached twice through a symlink (/lib -> /usr/lib) is taken once.
collect_linux_extras() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"
    local linux="${acq_dir}/artefacts/linux"
    local seen=$'\n' source real dest top depth max_size suffix user_home username web=0

    take() {  # source destination [max bytes]
        [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ] || return 0
        if [ -n "${3:-}" ] && [ "$(wc -c < "$1" 2>/dev/null || echo 0)" -gt "$3" ]; then return 0; fi
        real=$(readlink -f "$1" 2>/dev/null || echo "$1")
        case "$seen" in *$'\n'"$real"$'\n'*) return 0 ;; esac
        seen="${seen}${real}"$'\n'
        collect_file "$1" "$2" "$hostname" "$meta_log" && log_audit "$audit_log" "$hostname" "$1"
        return 0
    }
    flat() { printf '%s/%s' "$linux" "$(printf '%s' "${1#/}" | tr '/' '+')"; }

    for source in /etc/ld.so.preload /etc/ld.so.conf /etc/environment /etc/profile /etc/bash.bashrc \
        /etc/bashrc /etc/rc.local /etc/sudoers /run/utmp /var/run/utmp /var/log/wtmp /var/log/btmp \
        /var/log/lastlog /var/log/faillog /var/lib/wtmpdb/wtmp.db /var/lib/lastlog/lastlog2.db \
        /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db \
        /var/lib/containers/storage/overlay-containers/containers.json \
        /var/lib/containers/storage/db.sql /var/lib/containers/storage/db.sql-wal \
        /var/lib/containers/storage/libpod/bolt_state.db; do
        take "$source" "$(flat "$source")" 67108864
    done
    # directory|depth|largest file|file name suffix (empty: any)
    while IFS='|' read -r top depth max_size suffix; do
        [ -d "$top" ] || continue
        while IFS= read -r -d '' source; do
            take "$source" "$(flat "$source")" "$max_size"
        done < <(find "$top" -maxdepth "$depth" -type f ${suffix:+-name "*${suffix}"} -print0 2>/dev/null)
    done <<'DIRS'
/etc/ld.so.conf.d|1|1048576|
/etc/profile.d|1|1048576|
/etc/pam.d|1|1048576|
/etc/sudoers.d|1|1048576|
/etc/udev/rules.d|1|1048576|.rules
/usr/lib/udev/rules.d|1|1048576|.rules
/lib/udev/rules.d|1|1048576|.rules
/etc/systemd/system-generators|1|10485760|
/etc/systemd/user-generators|1|10485760|
/usr/local/lib/systemd/system-generators|1|10485760|
/etc/xdg/autostart|1|1048576|.desktop
/etc/update-motd.d|1|1048576|
/etc/nginx|3|1048576|
/etc/apache2|3|1048576|
/etc/httpd|3|1048576|
/var/lib/docker/containers|2|10485760|config.v2.json
/var/lib/docker/containers|2|10485760|hostconfig.json
/var/lib/docker/containers|2|67108864|-json.log
/var/log/pods|3|67108864|.log
/etc/kubernetes/manifests|1|1048576|.yaml
/etc/kubernetes/manifests|1|1048576|.yml
/var/log/kubernetes|2|268435456|.log
DIRS
    # Web roots: server-side scripts only, at most 5000
    for top in /var/www /srv/www /srv/http /usr/share/nginx/html; do
        [ -d "$top" ] || continue
        while IFS= read -r -d '' source; do
            [ "$web" -lt 5000 ] || break
            take "$source" "$(flat "$source")" 1048576
            web=$((web + 1))
        done < <(find "$top" -maxdepth 6 -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[3457]' \
            -o -iname '*.phar' -o -iname '*.inc' -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.asp' \
            -o -iname '*.aspx' -o -iname '*.ashx' -o -iname '*.asmx' -o -iname '*.cgi' -o -iname '*.pl' \
            -o -iname '*.py' -o -iname '*.sh' -o -iname '*.cfm' \) -print0 2>/dev/null)
    done
    # Per user: extra histories into user/<name>/, autostart and systemd user units into linux/
    for user_home in /root /home/*; do
        [ -d "$user_home" ] || continue
        username=$(basename "$user_home")
        for source in .zsh_history .viminfo .lesshst .python_history .mysql_history .psql_history .wget-hsts \
            .local/share/recently-used.xbel .local/share/containers/storage/db.sql \
            .local/share/containers/storage/db.sql-wal .local/share/containers/storage/libpod/bolt_state.db; do
            take "${user_home}/${source}" "${acq_dir}/artefacts/user/${username}/$(basename "$source")"
        done
        while IFS= read -r -d '' source; do
            take "$source" "$(flat "$source")" 1048576
        done < <(find "${user_home}/.config/autostart" "${user_home}/.config/systemd/user" -maxdepth 1 -type f \
            \( -name '*.desktop' -o -name '*.service' -o -name '*.timer' \) -print0 2>/dev/null)
    done

}

# Listings of what changes fastest: loaded kernel modules and the executables in the
# temp directories, into artefacts/linux/ as Elrond reads them
collect_linux_volatile_files() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"
    local linux="${acq_dir}/artefacts/linux" hash
    mkdir -p "$linux"
    # The temp directories themselves (hidden files included), capped per file
    collect_directory "/tmp" "${acq_dir}/artefacts/tmp" "$hostname" "$audit_log" "$meta_log" 3 10M || true
    collect_directory "/var/tmp" "${acq_dir}/artefacts/var_tmp" "$hostname" "$audit_log" "$meta_log" 3 10M || true
    collect_directory "/dev/shm" "${acq_dir}/artefacts/dev_shm" "$hostname" "$audit_log" "$meta_log" 3 10M || true
    # Loaded kernel modules, the file each came from and its hash ('?': no modinfo)
    if [ -r /proc/modules ]; then
        local name size instances deps state address taint path hash
        {
            echo "Name,Size,Instances,State,Taint,Path,SHA256"
            while read -r name size instances deps state address taint; do
                path="?"; hash=""
                if command -v modinfo &> /dev/null; then path=$(modinfo -n "$name" 2>/dev/null || true); fi
                if [ -n "$path" ] && [ "$path" != "?" ] && [ -f "$path" ]; then hash=$(sha256_of "$path"); fi
                taint="${taint#(}"; taint="${taint%)}"
                echo "${name},${size},${instances},${state},${taint},${path},${hash}"
            done < /proc/modules
        } > "${linux}/gandalf+kernel_modules.csv"
        log_audit "$audit_log" "$hostname" "/proc/modules"
    fi
    # Executables in the temp directories: ELF, scripts, anything with an exec bit
    local listing="${linux}/gandalf+tmp_executables.csv" rows="" kind head mode uid mtime fsize
    while IFS= read -r -d '' source; do
        case "$source" in "$WORK_DIR"/*|*/gandalf_collect.sh) continue ;; esac
        head=$(head -c 4 "$source" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        if [ "$head" = "7f454c46" ]; then kind="elf"
        elif [ "${head:0:4}" = "2321" ]; then kind="script"
        elif [ -x "$source" ]; then kind="executable"
        else continue; fi
        read -r fsize mode uid mtime < <(stat -c '%s %a %u %Y' "$source" 2>/dev/null) || continue
        hash=""
        [ "$fsize" -le 104857600 ] && hash=$(sha256_of "$source")
        rows="${rows}\"${source//\"/\"\"}\",${fsize},0o${mode},${uid},${kind},${hash},${mtime}"$'\n'
    done < <(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -print0 2>/dev/null)
    if [ -n "$rows" ]; then
        printf 'Path,Size,Mode,UID,Kind,SHA256,MTime\n%s' "$rows" > "$listing"
        log_audit "$audit_log" "$hostname" "temp-directory executables"
    fi
    # Each Docker container's writable layer: everything changed since its image, deleted
    # files as overlay whiteouts (character devices 0/0); listed and hashed, not copied
    local docker=/var/lib/docker cid mount_id upper inside count
    listing="${linux}/gandalf+container_changes.csv"; rows=""
    for cid in $(ls "$docker/containers" 2>/dev/null); do
        mount_id=$(cat "$docker/image/overlay2/layerdb/mounts/$cid/mount-id" 2>/dev/null) || continue
        upper="$docker/overlay2/$mount_id/diff"
        [ -d "$upper" ] || continue
        count=0
        while IFS= read -r -d '' source; do
            [ "$count" -lt 5000 ] || break
            count=$((count + 1))
            inside="${source#"$upper"}"
            read -r fsize mode uid mtime < <(stat -c '%s %a %u %Y' "$source" 2>/dev/null) || continue
            kind=""; hash=""
            if [ -c "$source" ]; then kind="deleted"
            elif [ -f "$source" ] && [ ! -L "$source" ]; then
                head=$(head -c 4 "$source" 2>/dev/null | od -An -tx1 | tr -d ' \n')
                if [ "$head" = "7f454c46" ]; then kind="elf"
                elif [ "${head:0:4}" = "2321" ]; then kind="script"
                elif [ -x "$source" ]; then kind="executable"; fi
                [ -n "$kind" ] && [ "$fsize" -le 104857600 ] && hash=$(sha256_of "$source")
            fi
            rows="${rows}${cid:0:12},\"${inside//\"/\"\"}\",${fsize},0o${mode},${kind},${hash},${mtime}"$'\n'
        done < <(find "$upper" -mindepth 1 -maxdepth 12 \( -type f -o -type c \) -print0 2>/dev/null)
    done
    if [ -n "$rows" ]; then
        printf 'Container,Path,Size,Mode,Kind,SHA256,MTime\n%s' "$rows" > "$listing"
        log_audit "$audit_log" "$hostname" "container writable layers"
    fi
}

# The executables and scripts each container gained since its image, into
# container_layer/<id>/ with '/' as '+': at most 500 per container, each up to 64 MB
collect_container_layers() {
    local acq_dir="$1" hostname="$2" audit_log="$3" meta_log="$4"
    local docker=/var/lib/docker cid mount_id upper taken head source inside
    for cid in $(ls "$docker/containers" 2>/dev/null); do
        mount_id=$(cat "$docker/image/overlay2/layerdb/mounts/$cid/mount-id" 2>/dev/null) || continue
        upper="$docker/overlay2/$mount_id/diff"
        [ -d "$upper" ] || continue
        taken=0
        while IFS= read -r -d '' source; do
            [ "$taken" -lt 500 ] || break
            head=$(head -c 4 "$source" 2>/dev/null | od -An -tx1 | tr -d ' \n')
            [ "$head" = "7f454c46" ] || [ "${head:0:4}" = "2321" ] || [ -x "$source" ] || continue
            inside="${source#"$upper"/}"
            if collect_file "$source" "${acq_dir}/artefacts/container_layer/${cid:0:12}/$(printf '%s' "$inside" | tr '/' '+')" \
                "$hostname" "$meta_log"; then
                log_audit "$audit_log" "$hostname" "$source"
                taken=$((taken + 1))
            fi
        done < <(find "$upper" -mindepth 1 -maxdepth 12 -type f -size -65537k -print0 2>/dev/null)
    done
}

# The raw unified-log store (uuidtext first, then tracev3 newest first) up to
# GANDALF_UNIFIED_LOG_STORE_MAX bytes (default 2 GB; 0 turns it off), layout kept under
# unified_log_store/; Spotlight's index stores up to GANDALF_SPOTLIGHT_MAX bytes each
# (default 1 GB; 0 turns it off), into spotlight/
collect_macos_stores() {
    local acq_dir="$1" hostname="$2" audit_log="$3" meta_log="$4"
    local a="${acq_dir}/artefacts" budget="${GANDALF_UNIFIED_LOG_STORE_MAX:-2147483648}"
    local limit="${GANDALF_SPOTLIGHT_MAX:-1073741824}" top label source size top_spot
    for top in /private/var/db/uuidtext /private/var/db/diagnostics; do
        [ "$budget" -gt 0 ] && [ -d "$top" ] || continue
        label=$(basename "$top")
        while IFS= read -r source; do
            size=$(stat -f '%z' "$source" 2>/dev/null || stat -c '%s' "$source" 2>/dev/null || echo 0)
            [ "$size" -le "$budget" ] || continue
            if collect_file "$source" "${a}/unified_log_store/${label}/${source#"$top"/}" "$hostname" "$meta_log"; then
                log_audit "$audit_log" "$hostname" "$source"
                budget=$((budget - size))
            fi
        done < <(find "$top" -maxdepth 4 -type f -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null)
    done
    for top_spot in /System/Volumes/Data/.Spotlight-V100 /.Spotlight-V100; do
        [ "$limit" -gt 0 ] && [ -d "$top_spot" ] || continue
        while IFS= read -r -d '' source; do
            size=$(stat -f '%z' "$source" 2>/dev/null || stat -c '%s' "$source" 2>/dev/null || echo 0)
            [ "$size" -le "$limit" ] || continue
            if collect_file "$source" "${a}/spotlight/$(printf '%s' "${source#"$top_spot"/}" | tr '/' '+')" \
                "$hostname" "$meta_log"; then
                log_audit "$audit_log" "$hostname" "$source"
            fi
        # store.db can't be read without the dbStr maps beside it (properties, categories)
        done < <(find "$top_spot" -maxdepth 3 -type f \( -name store.db -o -name .store.db \
            -o -name 'dbStr-*.map.*' -o -name VolumeConfiguration.plist \) -print0 2>/dev/null)
        break
    done
}

# SHA-256 of every collected file, by its path in the archive, once everything is
# copied (Elrond checks them on arrival)
write_manifest() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"
    local file rel count=0

    echo -e "${BLUE}[*]${NC} Hashing collected files..."
    while IFS= read -r -d '' file; do
        # log.audit is still being written (this pass adds to it), so it isn't hashed
        [ "$file" = "$meta_log" ] || [ "$file" = "$audit_log" ] && continue
        rel="${file#"${acq_dir}"/}"
        printf '%s,"%s",%s\n' "$hostname" "${rel//\"/\"\"}" "$(sha256_of "$file")" >> "$meta_log"
        count=$((count + 1))
    done < <(find "$acq_dir" -type f -print0 2>/dev/null)
    log_audit "$audit_log" "$hostname" "log.meta (${count} files hashed)"
}

# Collect directory with depth limit
collect_directory() {
    local source_dir="$1"
    local dest_dir="$2"
    local hostname="$3"
    local audit_log="$4"
    local meta_log="$5"
    local max_depth="${6:-3}"
    local max_size="${7:-}"  # find -size limit, e.g. 10M; empty = no limit

    if [ ! -d "$source_dir" ]; then
        return 1
    fi

    mkdir -p "$dest_dir"

    # Use find to collect files with depth limit
    while IFS= read -r -d '' file; do
        # Never collect Gandalf's own working files (it runs from /tmp)
        case "$file" in "$WORK_DIR"/*|/private"$WORK_DIR"/*|*/gandalf_collect.sh) continue ;; esac
        # Container and Kubernetes logs are taken into linux/ with the other container artefacts
        case "$file" in /var/log/pods/*|/var/log/containers/*|/var/log/kubernetes/*) continue ;; esac
        local rel_path="${file#$source_dir/}"
        local dest_file="${dest_dir}/$(echo "$rel_path" | tr '/' '+')"

        if collect_file "$file" "$dest_file" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "$file"
        fi
    done < <(find "$source_dir" -maxdepth "$max_depth" -type f ${max_size:+-size -"$max_size"} -print0 2>/dev/null)
}

# Collect user artifacts
collect_user_artifacts() {
    local user_home="$1"
    local username="$2"
    local acq_dir="$3"
    local hostname="$4"
    local audit_log="$5"
    local meta_log="$6"

    local user_dir="${acq_dir}/artefacts/user/${username}"
    mkdir -p "$user_dir"

    # Bash history
    collect_file "${user_home}/.bash_history" "${user_dir}/.bash_history" "$hostname" "$meta_log" || true
    collect_file "${user_home}/.bashrc" "${user_dir}/.bashrc" "$hostname" "$meta_log" || true
    collect_file "${user_home}/.profile" "${user_dir}/.profile" "$hostname" "$meta_log" || true

    # SSH keys and config
    if [ -d "${user_home}/.ssh" ]; then
        collect_directory "${user_home}/.ssh" "${user_dir}/ssh" "$hostname" "$audit_log" "$meta_log" 1 || true
    fi

    # Browser artifacts
    collect_browser_artifacts "$user_home" "$username" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
}

# Collect browser artifacts
collect_browser_artifacts() {
    local user_home="$1"
    local username="$2"
    local acq_dir="$3"
    local hostname="$4"
    local audit_log="$5"
    local meta_log="$6"

    local browser_dir="${acq_dir}/artefacts/browsers"

    # Chrome/Chromium
    local chrome_paths=(
        "${user_home}/.config/google-chrome/Default"
        "${user_home}/.config/chromium/Default"
        "${user_home}/Library/Application Support/Google/Chrome/Default"
        "${user_home}/Library/Application Support/Chromium/Default"
    )

    for chrome_path in "${chrome_paths[@]}"; do
        if [ -d "$chrome_path" ]; then
            local chrome_dest="${browser_dir}/chrome/${username}"
            mkdir -p "$chrome_dest"

            for file in "History" "Bookmarks" "Preferences" "Web Data" "Cookies"; do
                if [ -f "${chrome_path}/${file}" ]; then
                    collect_file "${chrome_path}/${file}" "${chrome_dest}/${username}+${file}" "$hostname" "$meta_log" || true
                    log_audit "$audit_log" "$hostname" "${chrome_path}/${file}"
                fi
            done
        fi
    done

    # Firefox
    local firefox_path="${user_home}/.mozilla/firefox"
    [ -d "$firefox_path" ] || firefox_path="${user_home}/Library/Application Support/Firefox/Profiles"
    if [ -d "$firefox_path" ]; then
        for profile in "${firefox_path}"/*.default*; do
            if [ -d "$profile" ]; then
                local firefox_dest="${browser_dir}/firefox/${username}"
                mkdir -p "$firefox_dest"

                for file in "places.sqlite" "favicons.sqlite" "cookies.sqlite" "prefs.js"; do
                    if [ -f "${profile}/${file}" ]; then
                        collect_file "${profile}/${file}" "${firefox_dest}/${username}+${file}" "$hostname" "$meta_log" || true
                        log_audit "$audit_log" "$hostname" "${profile}/${file}"
                    fi
                done
            fi
        done
    fi
}

# Safari (macOS): History.db holds visits; Downloads/Bookmarks are plists
collect_safari_artifacts() {
    local user_home="$1"
    local username="$2"
    local acq_dir="$3"
    local hostname="$4"
    local audit_log="$5"
    local meta_log="$6"

    local safari_path="${user_home}/Library/Safari"
    [ -d "$safari_path" ] || return 0
    local safari_dest="${acq_dir}/artefacts/browsers/safari/${username}"
    local file
    for file in "History.db" "History.db-wal" "Downloads.plist" "Bookmarks.plist" "TopSites.plist"; do
        if collect_file "${safari_path}/${file}" "${safari_dest}/${username}+${file}" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "${safari_path}/${file}"
        fi
    done
}

# Volatile data on macOS (BSD tools: no ss, lsmod or netstat -p)
collect_volatile_macos() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local out="${acq_dir}/artefacts"

    kmutil showloaded > "${out}/kexts.info" 2>/dev/null || kextstat > "${out}/kexts.info" 2>/dev/null || true
    launchctl list > "${out}/launchctl.info" 2>/dev/null || true
    sw_vers > "${out}/sw_vers.info" 2>/dev/null || true
    who -a > "${out}/who.info" 2>/dev/null || true
    last > "${out}/last.info" 2>/dev/null || true
    csrutil status > "${out}/csrutil.info" 2>/dev/null || true
    env > "${out}/env.info" 2>/dev/null || true
}

# Copy each *.plist in a directory to plists/<prefix><name>, the names Elrond's
# own macOS collection uses (launchagents+x.plist, system+launchdaemons-x.plist)
collect_plists() {
    local source_dir="$1"
    local prefix="$2"
    local acq_dir="$3"
    local hostname="$4"
    local audit_log="$5"
    local meta_log="$6"

    [ -d "$source_dir" ] || return 0
    local plist
    for plist in "$source_dir"/*.plist; do
        [ -f "$plist" ] || continue
        if collect_file "$plist" "${acq_dir}/artefacts/plists/${prefix}$(basename "$plist")" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "$plist"
        fi
    done
}

# macOS filesystem artefacts. Protected locations (TCC.db, Safari, Mail,
# KnowledgeC) are only readable when sshd or the terminal has Full Disk Access;
# anything unreadable is skipped and left out of log.meta.
# macOS artefacts beyond the core set, into artefacts/macos/ under their path with
# '/' as '+'. Elrond's collect/mac.py and gandalf.py carry the same lists. SQLite
# databases come with their -wal so uncheckpointed rows aren't lost.
collect_macos_extras() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"
    local macos="${acq_dir}/artefacts/macos"
    local source top depth max_size suffix user_home biome=0

    mtake() {  # source [max bytes]
        [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ] || return 0
        if [ -n "${2:-}" ] && [ "$(wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0)" -gt "$2" ]; then return 0; fi
        collect_file "$1" "${macos}/$(printf '%s' "${1#/}" | tr '/' '+')" "$hostname" "$meta_log" && log_audit "$audit_log" "$hostname" "$1"
        return 0
    }

    for source in /private/var/db/SystemPolicyConfiguration/ExecPolicy /private/var/db/SystemPolicyConfiguration/KextPolicy \
        /private/var/protected/xprotect/XPdb /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm \
        /private/var/folders/*/*/0/com.apple.notificationcenter/db2/db; do
        mtake "$source" 67108864
        mtake "${source}-wal" 67108864
    done
    mtake /private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL 268435456
    mtake /private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL-wal 268435456
    for source in /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist \
        /private/etc/periodic.conf /private/etc/daily.local /private/etc/weekly.local /private/etc/monthly.local \
        /private/etc/launchd.conf /private/etc/rc.common /Library/Receipts/InstallHistory.plist; do
        mtake "$source" 67108864
    done
    # directory|depth|largest file
    while IFS='|' read -r top depth max_size; do
        [ -d "$top" ] || continue
        while IFS= read -r -d '' source; do
            mtake "$source" "$max_size"
        done < <(find "$top" -maxdepth "$depth" -type f -print0 2>/dev/null)
    done <<'DIRS'
/private/etc/periodic|2|1048576
/private/etc/emond.d|2|1048576
/private/var/db/emondClients|1|1048576
DIRS
    for user_home in /Users/* /var/root; do
        [ -d "$user_home" ] || continue
        [ "$(basename "$user_home")" = "Shared" ] && continue
        mtake "${user_home}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm" 67108864
        mtake "${user_home}/Library/Group Containers/group.com.apple.usernoted/db2/db" 67108864
        mtake "${user_home}/Library/Group Containers/group.com.apple.usernoted/db2/db-wal" 67108864
        while IFS= read -r -d '' source; do
            mtake "$source" 10485760
        done < <(find "${user_home}/Library/Application Support/com.apple.sharedfilelist" -maxdepth 2 -type f \
            \( -name '*.sfl2' -o -name '*.sfl3' \) -print0 2>/dev/null)
    done
    # Biome streams (app focus, notifications, Safari...): at most 2000 files of 10 MB
    while IFS= read -r -d '' source; do
        [ "$biome" -lt 2000 ] || break
        mtake "$source" 10485760
        biome=$((biome + 1))
    done < <(find /private/var/db/biome/streams/restricted /Users/*/Library/Biome/streams/restricted -maxdepth 4 \
        -type f -print0 2>/dev/null)

    # Unified logs (G17): a filtered, time-boxed export rather than the multi-GB store.
    # GANDALF_UNIFIED_LOG_WINDOW sets how far back (default 1d); capped at 500,000 events.
    if command -v log &> /dev/null; then
        mkdir -p "$macos"
        log show --last "${GANDALF_UNIFIED_LOG_WINDOW:-1d}" --style ndjson --predicate \
            'process IN {"sudo","su","sshd","sshd-session","loginwindow","screensharingd","syspolicyd","XprotectService","backgroundtaskmanagementd","authd"} OR subsystem IN {"com.apple.TCC","com.apple.xprotect","com.apple.syspolicy.exec","com.apple.backgroundtaskmanagement"}' \
            2>/dev/null | head -n 500000 > "${macos}/gandalf+unifiedlog.ndjson" || true
        if [ -s "${macos}/gandalf+unifiedlog.ndjson" ]; then
            log_audit "$audit_log" "$hostname" "unified log export"
        fi
    fi
}

collect_macos_artifacts() {
    local acq_dir="$1"
    local hostname="$2"
    local audit_log="$3"
    local meta_log="$4"
    local a="${acq_dir}/artefacts"

    # Order of volatility: temp folders first (cleaned at reboot and by periodic jobs),
    # then logs (rotated), then configuration and persistence
    # Staging locations: world-writable shared and temporary folders (hidden
    # files included), capped per file so large caches don't swamp the archive
    collect_directory "/Users/Shared" "${a}/shared" "$hostname" "$audit_log" "$meta_log" 3 10M || true
    collect_directory "/private/tmp" "${a}/tmp" "$hostname" "$audit_log" "$meta_log" 2 10M || true
    # FSEvents: the file-system change journal, which rolls over; on the Data volume
    # from macOS 10.15, at the root before
    local fsevents
    for fsevents in /System/Volumes/Data/.fseventsd /.fseventsd; do
        if [ -d "$fsevents" ]; then
            collect_directory "$fsevents" "${a}/fseventsd" "$hostname" "$audit_log" "$meta_log" 1 64M || true
            break
        fi
    done

    # Logs: /var/log, /Library/Logs and the BSM audit config
    collect_directory "/private/var/log" "${a}/logs" "$hostname" "$audit_log" "$meta_log" 2 || true
    collect_directory "/Library/Logs" "${a}/logs_library" "$hostname" "$audit_log" "$meta_log" 2 50M || true
    collect_directory "/etc/security" "${a}/logs_security" "$hostname" "$audit_log" "$meta_log" 1 || true

    local source dest_name
    while IFS='|' read -r source dest_name; do
        [ -n "$source" ] || continue
        if collect_file "$source" "${a}/${dest_name}" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "$source"
        fi
    done <<'MAP'
/etc/passwd|etc+passwd
/etc/group|etc+group
/etc/hosts|etc+hosts
/etc/shells|etc+shells
/etc/sudoers|conf/etc+sudoers
/etc/ssh/sshd_config|conf/etc+ssh+sshd_config
/etc/crontab|cron/etc+crontab
/System/Library/CoreServices/SystemVersion.plist|plists/systemversion+SystemVersion.plist
/Library/Preferences/com.apple.loginwindow.plist|plists/preferences+com.apple.loginwindow.plist
/Library/Preferences/com.apple.alf.plist|plists/preferences+com.apple.alf.plist
/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist|plists/preferences+com.apple.smb.server.plist
/Library/Application Support/com.apple.TCC/TCC.db|tcc/system+TCC.db
/private/var/db/CoreDuet/Knowledge/knowledgeC.db|coreduet/system+knowledgeC.db
MAP

    # Persistence: launchd jobs and login items, system-wide and Apple's own
    collect_plists "/Library/LaunchAgents" "launchagents+" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_plists "/Library/LaunchDaemons" "launchdaemons+" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_plists "/Library/StartupItems" "startupitems+" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_plists "/System/Library/LaunchAgents" "system+launchagents-" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_plists "/System/Library/LaunchDaemons" "system+launchdaemons-" "$acq_dir" "$hostname" "$audit_log" "$meta_log"


    # cron/at: per-user crontabs are files named after the user
    local tab
    for tab in /private/var/at/tabs/* /usr/lib/cron/tabs/*; do
        [ -f "$tab" ] || continue
        collect_file "$tab" "${a}/cron/$(basename "$tab")+crontab" "$hostname" "$meta_log" && log_audit "$audit_log" "$hostname" "$tab"
    done


    local user_home username
    for user_home in /Users/* /var/root; do
        [ -d "$user_home" ] || continue
        username=$(basename "$user_home")
        [ "$username" = "Shared" ] && continue
        collect_macos_user_artifacts "$user_home" "$username" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    done

    collect_macos_extras "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_macos_stores "$acq_dir" "$hostname" "$audit_log" "$meta_log"
}

collect_macos_user_artifacts() {
    local user_home="$1"
    local username="$2"
    local acq_dir="$3"
    local hostname="$4"
    local audit_log="$5"
    local meta_log="$6"
    local user_dir="${acq_dir}/artefacts/user/${username}"
    local f

    # Shell history and start-up files (zsh has been the default since 10.15)
    for f in .zsh_history .bash_history .zshrc .zprofile .zshenv .bashrc .bash_profile .profile; do
        if collect_file "${user_home}/${f}" "${user_dir}/${f}" "$hostname" "$meta_log"; then
            log_audit "$audit_log" "$hostname" "${user_home}/${f}"
        fi
    done
    for f in "${user_home}/.zsh_sessions"/*.history "${user_home}/.bash_sessions"/*.history; do
        [ -f "$f" ] || continue
        collect_file "$f" "${user_dir}/sessions/$(basename "$f")" "$hostname" "$meta_log" && log_audit "$audit_log" "$hostname" "$f"
    done

    if [ -d "${user_home}/.ssh" ]; then
        collect_directory "${user_home}/.ssh" "${user_dir}/ssh" "$hostname" "$audit_log" "$meta_log" 1 || true
    fi

    # Per-user persistence and preferences
    collect_plists "${user_home}/Library/LaunchAgents" "${username}+launchagents+" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_plists "${user_home}/Library/Preferences" "${username}+" "$acq_dir" "$hostname" "$audit_log" "$meta_log"

    # Quarantine events (downloads and where they came from), TCC grants
    if collect_file "${user_home}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
        "${user_dir}/QuarantineEventsV2" "$hostname" "$meta_log"; then
        log_audit "$audit_log" "$hostname" "${user_home}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    fi
    if collect_file "${user_home}/Library/Application Support/com.apple.TCC/TCC.db" \
        "${acq_dir}/artefacts/tcc/${username}+TCC.db" "$hostname" "$meta_log"; then
        log_audit "$audit_log" "$hostname" "${user_home}/Library/Application Support/com.apple.TCC/TCC.db"
    fi

    # Trash: names and contents of deleted files, capped per file
    [ -d "${user_home}/.Trash" ] && collect_directory "${user_home}/.Trash" "${user_dir}/trash" "$hostname" "$audit_log" "$meta_log" 2 10M || true

    collect_safari_artifacts "$user_home" "$username" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    collect_browser_artifacts "$user_home" "$username" "$acq_dir" "$hostname" "$audit_log" "$meta_log"
}

# Create archive
create_archive() {
    local acq_dir="$1"
    local hostname="$2"
    local output_file="${OUTPUT_DIR}/${hostname}.tar.gz"

    echo -e "${BLUE}[*]${NC} Creating archive..." >&2

    # COPYFILE_DISABLE: macOS tar would otherwise add an AppleDouble ._ file for each
    # file with extended attributes
    COPYFILE_DISABLE=1 tar -czf "$output_file" -C "${acq_dir}" . 2>/dev/null || {
        echo -e "${RED}[ERROR]${NC} Failed to create archive" >&2
        return 1
    }

    echo -e "${GREEN}[+]${NC} Archive created: $output_file" >&2
    echo "$output_file"
}

# Encrypt archive
encrypt_archive() {
    local archive_file="$1"
    local hostname="$2"

    case "$(lower "$ENCRYPTION_METHOD")" in
        none)
            return 0
            ;;
        key|password)
            echo -e "${YELLOW}[!]${NC} Encryption with openssl (AES-256-CBC)"

            if [ "$(lower "$ENCRYPTION_METHOD")" = "key" ]; then
                # Generate random key
                local key_file="${OUTPUT_DIR}/shadowfax.key"
                openssl rand -base64 32 > "$key_file"
                echo -e "${GREEN}[+]${NC} Encryption key saved: $key_file"

                # Encrypt with key
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "$archive_file" -out "${archive_file}.enc" -pass file:"$key_file"
            elif [ -n "${GANDALF_PASSWORD:-}" ]; then
                # Remote batch: asked once up front; on a descriptor, not argv or the environment
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "$archive_file" -out "${archive_file}.enc" -pass fd:3 3<<<"$GANDALF_PASSWORD"
            else
                # Password-based encryption
                echo -e "${BLUE}[*]${NC} Enter encryption password:"
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "$archive_file" -out "${archive_file}.enc"
            fi

            if [ -f "${archive_file}.enc" ]; then
                rm -f "$archive_file"
                echo -e "${GREEN}[+]${NC} Archive encrypted: ${archive_file}.enc"
            else
                echo -e "${RED}[ERROR]${NC} Encryption failed"
                return 1
            fi
            ;;
    esac
}

# Local acquisition
acquire_local() {
    local hostname=$(hostname)
    local start_time=$(date +%s)

    echo -e "${GREEN}[+]${NC} Starting local acquisition for: $hostname"

    # Initialize
    local acq_dir=$(init_directories "$hostname")
    local audit_log="${acq_dir}/log.audit"
    local meta_log="${acq_dir}/log.meta"

    init_audit_log "$audit_log"
    init_meta_log "$meta_log"

    # Collect
    collect_volatile "$acq_dir" "$hostname" "$audit_log"
    collect_memory "$acq_dir" "$hostname" "$audit_log"
    # After memory: an export reads whole filesystems through the page cache
    [ "$LIVE_CONTAINERS" = true ] && ! is_macos && collect_live_containers "$acq_dir" "$hostname" "$audit_log"
    collect_artifacts "$acq_dir" "$hostname" "$audit_log" "$meta_log"
    write_manifest "$acq_dir" "$hostname" "$audit_log" "$meta_log"

    # Archive
    local archive_file=$(create_archive "$acq_dir" "$hostname")

    # Encrypt
    encrypt_archive "$archive_file" "$hostname"

    # Cleanup work directory
    rm -rf "$acq_dir"

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo -e "${GREEN}[+]${NC} Acquisition complete!"
    echo -e "${BLUE}[*]${NC} Duration: ${duration} seconds"
    echo -e "${BLUE}[*]${NC} Output: ${OUTPUT_DIR}/"
}

# Remote acquisition
acquire_remote() {
    if [ -z "$REMOTE_HOST" ] && [ -z "$HOSTS_FILE" ]; then
        echo -e "${RED}[ERROR]${NC} Remote mode requires -h HOST or -f HOSTS_FILE"
        exit 1
    fi

    if [ -z "$REMOTE_USER" ]; then
        local default_user="${SUDO_USER:-$(id -un)}"
        if [ "$NO_PROMPT" = true ]; then
            REMOTE_USER="$default_user"
        else
            echo -e "${BLUE}[*]${NC} Enter remote username [${default_user}]:"
            read -r REMOTE_USER
            REMOTE_USER="${REMOTE_USER:-$default_user}"
        fi
    fi

    local hosts=()
    if [ -n "$HOSTS_FILE" ]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            hosts+=("$line")
        done < "$HOSTS_FILE"
    else
        hosts=("$REMOTE_HOST")
    fi

    # Password encryption can't prompt over a non-interactive ssh, so the target
    # collects unencrypted (the archive travels over scp) and it's encrypted here
    local remote_encryption="$ENCRYPTION_METHOD"
    if [ "$(lower "$ENCRYPTION_METHOD")" = "password" ]; then
        remote_encryption="None"
        local confirm
        read -rsp "Encryption password: " GANDALF_PASSWORD; echo >&2
        read -rsp "Confirm password: " confirm; echo >&2
        if [ -z "$GANDALF_PASSWORD" ] || [ "$GANDALF_PASSWORD" != "$confirm" ]; then
            echo -e "${RED}[ERROR]${NC} Passwords are empty or don't match"
            exit 1
        fi
        unset confirm
    fi

    local failed=0
    for host in "${hosts[@]}"; do
        echo -e "${GREEN}[+]${NC} Acquiring from remote host: $host"

        # Copy script to remote
        local remote_script="/tmp/gandalf_collect.sh"
        scp "$0" "${REMOTE_USER}@${host}:${remote_script}" || {
            echo -e "${RED}[ERROR]${NC} Failed to copy script to $host"
            failed=$((failed + 1))
            continue
        }

        # Execute remotely
        if ! ssh "${REMOTE_USER}@${host}" "sudo bash ${remote_script} ${remote_encryption} Local -o /tmp/gandalf/acquisitions $([ "$MEMORY_DUMP" = true ] && echo -m) $([ "$LIVE_CONTAINERS" = true ] && echo -l) $([ "$SHOW_PROGRESS" = true ] && echo -p)"; then
            echo -e "${RED}[ERROR]${NC} Remote execution failed on $host"
            ssh "${REMOTE_USER}@${host}" "sudo rm -rf /tmp/gandalf ${remote_script}" || true
            failed=$((failed + 1))
            continue
        fi

        # Retrieve archive (and, with Key encryption, the key: it is generated on the target)
        local remote_file=$(ssh "${REMOTE_USER}@${host}" "ls -1 /tmp/gandalf/acquisitions/*.tar.gz* | head -1")
        if [ -n "$remote_file" ]; then
            if scp "${REMOTE_USER}@${host}:${remote_file}" "${OUTPUT_DIR}/"; then
                if [ "$(lower "$ENCRYPTION_METHOD")" = "key" ]; then
                    scp "${REMOTE_USER}@${host}:/tmp/gandalf/acquisitions/shadowfax.key" "${OUTPUT_DIR}/${host}.shadowfax.key" \
                        && echo -e "${GREEN}[+]${NC} Encryption key saved: ${OUTPUT_DIR}/${host}.shadowfax.key" \
                        || echo -e "${RED}[ERROR]${NC} Failed to retrieve the encryption key from $host"
                fi
                if [ "$remote_encryption" != "$ENCRYPTION_METHOD" ]; then
                    encrypt_archive "${OUTPUT_DIR}/$(basename "$remote_file")" "$host" \
                        || echo -e "${RED}[ERROR]${NC} Failed to encrypt the archive from $host"
                fi
                echo -e "${GREEN}[+]${NC} Successfully acquired from $host"
            else
                echo -e "${RED}[ERROR]${NC} Failed to retrieve archive from $host"
                failed=$((failed + 1))
            fi
        else
            echo -e "${RED}[ERROR]${NC} No archive found on $host"
            failed=$((failed + 1))
        fi

        # Leave nothing of Gandalf's on the target
        ssh "${REMOTE_USER}@${host}" "sudo rm -rf /tmp/gandalf ${remote_script}" || true
    done
    unset GANDALF_PASSWORD
    if [ "$failed" -gt 0 ]; then
        echo -e "${RED}[ERROR]${NC} $failed of ${#hosts[@]} host(s) not acquired"
        return 1
    fi
}

# Main function
main() {
    print_banner
    check_root
    parse_args "$@"
    check_dependencies

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    case "$(lower "$ACQUISITION_MODE")" in
        local)
            acquire_local
            ;;
        remote)
            acquire_remote
            ;;
    esac
}

# Run main
main "$@"
