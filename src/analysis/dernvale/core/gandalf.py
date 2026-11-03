import csv
import getpass
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime
from zipfile import ZipFile

from dernvale.audit import write_audit_log_entry
from dernvale.core import event_dataset
from dernvale.core.identify import identify_gandalf_host
from dernvale.core.identify import identify_memory_image


ARCHIVE_SUFFIXES = (".zip", ".7z", ".tar.gz", ".tgz")
STAGING_DIR = ".gandalf_staging"
# Files Gandalf writes about the live system (not collected from disk); they sit
# beside raw/ as they do for disk images.
VOLATILE_SUFFIXES = (".info", ".csv")


def _inside(root, path):
    root, path = os.path.realpath(root), os.path.realpath(path)
    return path == root or path.startswith(root + os.sep)


class UnsafeArchiveError(Exception):
    """An archive member would land outside the extraction directory."""


def extract_tarball(archive, destination):
    """
    Extract a gandalf.sh archive. Gandalf never writes a member outside the
    archive root, so one that does means tampering: the archive is refused.
    """
    with tarfile.open(archive, "r:gz") as tarball:
        members = tarball.getmembers()
        for member in members:
            if not _inside(destination, os.path.join(destination, member.name)) or (
                (member.issym() or member.islnk())
                and not _inside(destination, os.path.join(destination, os.path.dirname(member.name), member.linkname))
            ):
                raise UnsafeArchiveError("member '{}' points outside the archive".format(member.name))
        if hasattr(tarfile, "data_filter"):
            tarball.extractall(destination, filter="data")
        else:
            tarball.extractall(destination, members=[m for m in members if m.isfile() or m.isdir()])


def extract_zip(archive, destination):
    """Extract a gandalf.py or Invoke-Gandalf zip. Windows zips can use backslash separators."""
    with ZipFile(archive) as zipped:
        for member in zipped.infolist():
            name = member.filename.replace("\\", "/")
            target = os.path.join(destination, name)
            if not _inside(destination, target):
                raise UnsafeArchiveError("member '{}' points outside the archive".format(member.filename))
            if name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zipped.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def _extract7z(archive, destination, iteration="First", pw_7z=""):
    out_7z = str(
        subprocess.Popen(
            ["7z", "x", archive, "-o" + destination, "-p{}".format(pw_7z), "-y"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    )
    if "Wrong password" in out_7z:
        prompt = "    Encrypted archive; please provide password: " if iteration == "First" else "    Incorrect password; please try again: "
        _extract7z(archive, destination, "Again", getpass.getpass(prompt))


def archive_stem(name):
    for suffix in ARCHIVE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _place(src, dest):
    """Move src to dest, never overwriting: a clash gets a numbered suffix."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    candidate, n = dest, 1
    while os.path.exists(candidate):
        candidate = "{}.{}".format(dest, n)
        n += 1
    shutil.move(src, candidate)


def _files_under(directory):
    for root, _, files in os.walk(directory):
        for name in files:
            yield os.path.join(root, name)


def normalise_gandalf_artefacts(anchor, artefacts_dir):
    """
    Lay a host's Gandalf artefacts out the way Elrond's collect phase does, so the
    processing and analysis stages read them like a disk image's.

    anchor is the directory holding host.info. Invoke-Gandalf already writes
    Elrond's layout (anchor/raw/...); gandalf.sh and gandalf.py write their own
    (etc+passwd, logs/, user/<name>/.bash_history, ...), which is mapped here:

      etc+<file>                  -> raw/<file>
      logs/<file>                 -> raw/logs/var+<file>    (journal/ -> raw/journal/)
      logs_<source>/<file>        -> raw/logs/<source>+<file> (macOS /Library/Logs, /etc/security)
      user|home/<name>/[.]<file>  -> raw/user_profiles/<name>+<file>
      browsers/<browser>/[<name>/]<name>+<file>
                                  -> raw/browsers/<name>/<browser>/<file>
      cron/[etc+]crontab          -> raw/crontab, other cron files -> raw/cron/
      *.info, *.csv               -> artefacts/ (volatile data, beside raw/)
      anything else               -> raw/<same path> (plists/, tcc/, shared/, ...)
    """
    raw = os.path.join(artefacts_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    for entry in sorted(os.listdir(anchor)):
        path = os.path.join(anchor, entry)
        if os.path.isfile(path):
            if entry.endswith(VOLATILE_SUFFIXES):
                _place(path, os.path.join(artefacts_dir, entry))
            elif entry.startswith("etc+"):
                _place(path, os.path.join(raw, entry[len("etc+"):]))
            else:
                _place(path, os.path.join(raw, entry))
        elif entry == "raw":  # already Elrond's layout
            for f in list(_files_under(path)):
                _place(f, os.path.join(raw, os.path.relpath(f, path)))
        elif entry == "logs":
            for f in list(_files_under(path)):
                rel = os.path.relpath(f, path)
                if rel.split(os.sep)[0] == "journal":
                    _place(f, os.path.join(raw, rel))
                else:
                    _place(f, os.path.join(raw, "logs", "var+" + rel.replace(os.sep, "+")))
        elif entry.startswith("logs_"):
            source = entry[len("logs_"):]
            for f in list(_files_under(path)):
                rel = os.path.relpath(f, path).replace(os.sep, "+")
                _place(f, os.path.join(raw, "logs", "{}+{}".format(source, rel)))
        elif entry == "browsers":
            for f in list(_files_under(path)):
                parts = os.path.relpath(f, path).split(os.sep)
                browser, name = parts[0], parts[-1]
                user, _, browser_file = name.partition("+")
                if not browser_file:  # not <user>+<file>: keep the path as it is
                    _place(f, os.path.join(raw, "browsers", *parts))
                else:
                    _place(f, os.path.join(raw, "browsers", user, browser, browser_file))
        elif entry == "journal":
            for f in list(_files_under(path)):
                _place(f, os.path.join(raw, "journal", os.path.relpath(f, path)))
        elif entry in ("user", "home"):
            for user in sorted(os.listdir(path)):
                user_dir = os.path.join(path, user)
                if not os.path.isdir(user_dir):
                    continue
                for f in list(_files_under(user_dir)):
                    name = os.path.basename(f).lstrip(".")
                    _place(f, os.path.join(raw, "user_profiles", "{}+{}".format(user, name)))
        elif entry == "cron":
            for f in list(_files_under(path)):
                name = os.path.basename(f)
                if name in ("crontab", "etc+crontab"):
                    _place(f, os.path.join(raw, "crontab"))
                else:
                    _place(f, os.path.join(raw, "cron", os.path.relpath(f, path)))
        else:
            for f in list(_files_under(path)):
                _place(f, os.path.join(raw, entry, os.path.relpath(f, path)))
    return raw


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(staging):
    """
    Check every file Gandalf's log.meta lists against the extracted archive: path in
    the archive (relative to log.meta, either separator), SHA-256. Returns
    (rows, counts) with a status per file (verified, MISMATCH, missing, unhashed), or
    None when there's no manifest, or one from a Gandalf that recorded source paths
    instead of archive paths, which can't be checked.
    """
    manifest = None
    for f in _files_under(staging):
        if os.path.basename(f) == "log.meta":
            manifest = f
            break
    if manifest is None:
        return None
    base = os.path.dirname(manifest)
    rows, counts = [], {"verified": 0, "MISMATCH": 0, "missing": 0, "unhashed": 0}
    with open(manifest, newline="", errors="replace") as f:
        for record in csv.reader(f):
            if len(record) < 3 or record[:3] == ["hostname", "file_path", "sha256_hash"]:
                continue
            relative, expected = ",".join(record[1:-1]), record[-1].strip().lower()
            if os.path.isabs(relative):
                return None
            path = os.path.join(base, *relative.replace("\\", "/").split("/"))
            if not _inside(base, path) or not os.path.isfile(path):
                status, actual = "missing", ""
            elif len(expected) != 64:
                status, actual = "unhashed", ""
            else:
                actual = _sha256(path)
                status = "verified" if actual == expected else "MISMATCH"
            counts[status] += 1
            rows.append({"file_path": relative, "expected_sha256": expected, "actual_sha256": actual, "status": status})
    if rows and counts["verified"] == 0 and counts["missing"] == len(rows):
        return None
    return rows, counts


def _find_host_info(root):
    for dirpath, _, files in os.walk(root):
        if "host.info" in files:
            return os.path.join(dirpath, "host.info")
    return None


def _remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)


def ingest_gandalf_archive(archive, output_directory, verbosity, allimgs):
    """
    Extract one Gandalf archive into <output>/<host>/artefacts/ in Elrond's
    layout and register the host in allimgs as {raw dir: "<host>::<platform>"},
    the same shape as a mounted disk image. Returns the host name, or None.
    """
    name = os.path.basename(archive)
    stem = archive_stem(name)
    staging = os.path.join(output_directory, STAGING_DIR, stem)
    _remove_tree(staging)
    os.makedirs(staging)
    entry, prnt = (
        "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
        " -> {} -> created audit log file for '{}'".format(datetime.now().isoformat().replace("T", " "), stem),
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print("  Extracting artefacts for '{}'...".format(stem))
    try:
        if name.endswith(".zip"):
            extract_zip(archive, staging)
        elif name.endswith(".7z"):
            _extract7z(archive, staging)
        else:
            extract_tarball(archive, staging)
    except UnsafeArchiveError as error:
        print("   Refusing '{}': {} (possible tampering); skipping it\n".format(name, error))
        _remove_tree(staging)
        return None
    except Exception as error:  # corrupt or truncated archive: report it, carry on with the rest
        print("   Couldn't read '{}' ({}); skipping it\n".format(name, error))
        _remove_tree(staging)
        return None
    host_info = _find_host_info(staging)
    if not host_info:
        hosts = None
        if event_dataset.looks_like_event_dataset(staging):
            hosts = ingest_event_dataset(staging, stem, output_directory, verbosity, allimgs)
        else:
            print("   No host.info in '{}'; skipping it\n".format(name))
        _remove_tree(staging)
        return hosts[0] if hosts else None
    gandalf_host, osplatform = identify_gandalf_host(output_directory, verbosity, host_info)
    host_dir = os.path.join(output_directory, gandalf_host)
    artefacts_dir = os.path.join(host_dir, "artefacts")
    if os.path.isdir(os.path.join(artefacts_dir, "raw")):
        print("   '{}' was already extracted to {}; reusing it".format(gandalf_host, artefacts_dir))
    else:
        integrity = verify_manifest(staging)
        if integrity is not None:
            rows, counts = integrity
            os.makedirs(host_dir, exist_ok=True)
            with open(os.path.join(host_dir, "gandalf_integrity.csv"), "w", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=["file_path", "expected_sha256", "actual_sha256", "status"])
                writer.writeheader()
                writer.writerows(rows)
            summary = ", ".join("{} {}".format(n, s) for s, n in counts.items() if n)
            print("   Checked '{}' against Gandalf's hashes: {}".format(gandalf_host, summary))
            entry, prnt = (
                "{},{},gandalf integrity,{}\n".format(datetime.now().isoformat(), gandalf_host, summary.replace(",", ";")),
                " -> {} -> checked '{}' against Gandalf's hashes: {}".format(
                    datetime.now().isoformat().replace("T", " "), gandalf_host, summary),
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        else:
            print("   No archive-path hashes from Gandalf for '{}' (older collector); integrity not checked".format(gandalf_host))
        for audit in ("log.audit", "log.meta"):
            for f in list(_files_under(staging)):
                if os.path.basename(f) == audit:
                    _place(f, os.path.join(host_dir, "gandalf_" + audit))
        normalise_gandalf_artefacts(os.path.dirname(host_info), artefacts_dir)
        print("   Successfully extracted artefacts for '{}'".format(gandalf_host))
    _remove_tree(staging)
    print()
    allimgs[os.path.join(artefacts_dir, "raw")] = "{}::{}".format(gandalf_host, osplatform)
    return gandalf_host


def ingest_event_dataset(staging, stem, output_directory, verbosity, allimgs):
    """
    An archive of Windows events with no host.info (an OTRF/Mordor dataset, or one the lab
    captured or converted from a recording): one Elrond host per computer its events name, its
    events in cooked/evt/ as Artemis would leave a disk image's .evtx, tagged with the ATT&CK
    techniques they show. Returns the hosts, registered in allimgs.
    """
    from dernvale.process.extractions.artemis import enrich_with_mitre

    placed = event_dataset.ingest(staging, stem, output_directory)
    if not placed:
        write_audit_log_entry(
            verbosity, output_directory,
            "{},{},event dataset,no Windows events found\n".format(datetime.now().isoformat(), stem),
            "   No Windows events in '{}'; skipping it\n".format(stem),
        )
        return []
    write_audit_log_entry(
        verbosity, output_directory,
        "{},{},event dataset,{}\n".format(datetime.now().isoformat(), stem, event_dataset.summary(placed)),
        "   '{}' is an event dataset: {}".format(stem, event_dataset.summary(placed)),
    )
    for host, count, evt_files in placed:
        for evt_file in evt_files:
            enrich_with_mitre(evt_file, "eventlogs")
        allimgs[os.path.join(output_directory, host, "artefacts", "raw")] = event_dataset.platform_entry(host)
        write_audit_log_entry(
            verbosity, output_directory,
            "{},{},identified platform,{}\n".format(datetime.now().isoformat(), host, event_dataset.PLATFORM),
            "    {}: {:,} events -> {}{}".format(
                host, count, os.path.dirname(evt_files[0]),
                " ({} parts)".format(len(evt_files)) if len(evt_files) > 1 else ""),
        )
    return [host for host, _, _ in placed]


ENCRYPTED_SUFFIXES = (".tar.gz.enc", ".zip.enc")


def _shadowfax_key(archive):
    """The key Gandalf saved for an encrypted archive: <host>.shadowfax.key beside it (as
    gandalf.sh and gandalf.py save it), or shadowfax.key in the same folder."""
    folder, name = os.path.split(archive)
    host = name[: -len(".tar.gz.enc")] if name.endswith(".tar.gz.enc") else name[: -len(".zip.enc")]
    for candidate in (host + ".shadowfax.key", "shadowfax.key"):
        path = os.path.join(folder, candidate)
        if os.path.isfile(path):
            return path
    return None


def decrypt_archive(archive, staging_root):
    """
    Decrypt a Gandalf archive with the key saved beside it, into staging_root; returns the
    decrypted archive's path, or None after saying what's needed. gandalf.py's .zip.enc is
    Fernet; gandalf.sh's .tar.gz.enc is openssl AES-256-CBC (PBKDF2). A password-encrypted
    archive has no key file: it has to be decrypted by hand first.
    """
    name = os.path.basename(archive)
    plain_name = name[:-4]  # drop .enc
    key = _shadowfax_key(archive)
    if not key:
        if name.endswith(".zip.enc"):
            how = "python3 src/acquisition/python/passkey_decrypt.py (password), or put its <host>.shadowfax.key beside it"
        else:
            how = "openssl enc -d -aes-256-cbc -pbkdf2 -in {} -out {}".format(archive, archive[:-4])
        print("   '{}' is encrypted and there's no shadowfax.key beside it; decrypt it first:\n     {}\n".format(name, how))
        return None
    os.makedirs(staging_root, exist_ok=True)
    out = os.path.join(staging_root, plain_name)
    try:
        if name.endswith(".zip.enc"):
            from cryptography.fernet import Fernet, InvalidToken

            with open(key, "rb") as fh:
                fernet = Fernet(fh.read().strip())
            with open(archive, "rb") as fh:
                data = fernet.decrypt(fh.read())
            with open(out, "wb") as fh:
                fh.write(data)
        else:
            subprocess.run(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", archive, "-out", out, "-pass", "file:" + key],
                check=True, capture_output=True,
            )
    except Exception as error:  # wrong key, corrupt archive, or openssl missing
        print("   Couldn't decrypt '{}' with {} ({}); skipping it\n".format(name, os.path.basename(key), error))
        if os.path.exists(out):
            os.remove(out)
        return None
    print("   Decrypted '{}' with {}".format(name, os.path.basename(key)))
    return out


MEMORY_SUFFIXES = (".mem", ".lime", ".dmp")
MIN_MEMORY_DUMP = 1 << 20  # anything smaller is a failed dump, not memory


def gandalf_memory_dumps(output_directory):
    """
    The memory dumps the collectors left among the hosts' artefacts:
      Invoke-Gandalf (DumpIt)  raw/memory/<host>.raw
      gandalf.sh (AVML)        raw/memory/<host>.mem
      gandalf.py (AVML)        raw/<host>.mem
      gandalf.py (osxpmem)     raw/mem.raw, converted from raw/mem.aff4 (used only without it)
    """
    found = []
    for root, _, files in os.walk(output_directory):
        names = set(files)
        for name in sorted(files):
            lower = name.lower()
            path = os.path.join(root, name)
            if lower.endswith(MEMORY_SUFFIXES):
                pass
            elif lower.endswith(".raw") and (lower == "mem.raw" or "memory" in path.lower()):
                pass
            elif lower.endswith(".aff4") and not any(n.lower() == "mem.raw" for n in names):
                pass
            else:
                continue
            try:
                if os.path.getsize(path) >= MIN_MEMORY_DUMP:
                    found.append(path)
            except OSError:
                continue
    return found


def assess_gandalf(
    auto,
    gandalf,
    vss,
    nsrl,
    volatility,
    metacollected,
    ot,
    d,
    cwd,
    sha256,
    flags,
    output_directory,
    verbosity,
    allimgs,
    imgs,
    volchoice,
    vssmem,
    memtimeline,
):
    """
    Gandalf source node: ingest every acquisition under d (…/acquisitions/)
    and register each host in allimgs (updated in place), ready for the shared
    processing and analysis stages.
    """
    if not d.endswith("/"):
        d = d + "/"
    if not d.endswith("/acquisitions/"):
        print(
            "   Hosts, must be in the 'acquisitions' directory, produced from gandalf's output.\n    For example, '/{}/acquisitions/'\n     Please try again\n\n".format(
                d.strip("/")
            )
        )
        sys.exit()
    staging_root = os.path.join(output_directory, STAGING_DIR)
    for groot, dirs, gfiles in os.walk(d):
        dirs[:] = [x for x in dirs if os.path.join(groot, x) != staging_root.rstrip("/")]
        for gfile in sorted(gfiles):
            if gfile.startswith("._"):  # macOS AppleDouble metadata, not an archive
                continue
            if gfile.endswith(ENCRYPTED_SUFFIXES):
                decrypted = decrypt_archive(os.path.join(groot, gfile), staging_root)
                if decrypted:
                    ingest_gandalf_archive(decrypted, output_directory, verbosity, allimgs)
                continue
            if gfile.endswith(ARCHIVE_SUFFIXES):
                ingest_gandalf_archive(os.path.join(groot, gfile), output_directory, verbosity, allimgs)
    _remove_tree(staging_root)
    if volatility:
        for memory_path in gandalf_memory_dumps(output_directory):
            memory_file = os.path.basename(memory_path)
            memory_path_moved = os.path.join(output_directory, memory_file, memory_file)
            os.makedirs(os.path.dirname(memory_path_moved), exist_ok=True)
            try:
                shutil.move(memory_path, memory_path_moved)
            except OSError as error:
                print("   Couldn't move memory dump '{}' ({}); skipping it".format(memory_path, error))
                continue
            ot = identify_memory_image(
                verbosity,
                output_directory,
                flags,
                auto,
                metacollected,
                cwd,
                sha256,
                nsrl,
                memory_file,
                ot,
                d,
                memory_path_moved,
                volchoice,
                vss,
                vssmem,
                memtimeline,
            )
            allimgs.update(ot)  # in place: the caller's dict
    allimgs.update(ot)
