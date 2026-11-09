# Volatility 3 symbol tables

Linux and macOS memory needs a symbol table (ISF) for the exact kernel the dump came from. These folders, `linux/` and `mac/`, are mounted into the worker (Volatility's own `symbols/linux` and `symbols/mac`) and into the backend (Aragorn's list). Windows tables come from Microsoft's symbol server through Volatility itself, kept in the `volatility_windows` volume.

## Found or fetched for each image

Elrond reads the image's kernel banner and works out the kernel build, the distribution that built it, and the architecture (`src/analysis/rowanholt/memory/symbols/`). It then tries these in order:

1. A table already indexed for that exact banner, in `rowanholt.index`.
2. A table in the folder that serves it, which is indexed then.
3. The prebuilt collection [Abyss-W4tcher/volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols), by exact banner. Each file is a GitHub release asset, checked against the SHA-256 GitHub gives for it. The collection is fetched, never bundled: it declares no licence. It covers Ubuntu, Debian, Kali, Rocky, Alma and macOS 10.x.
4. The distribution's debug package, unpacked for its `vmlinux` and built with dwarf2json:

| Distribution | Package | Hash checked |
|---|---|---|
| Ubuntu | `linux-image-unsigned-<release>-dbgsym` (or the older `linux-image-<release>-dbgsym`) from Launchpad | SHA-256 from Launchpad's `binaryFileUrls` |
| Debian | `linux-image-<release>-dbg` from snapshot.debian.org | SHA-1, the only one the snapshot publishes |
| Rocky, Alma | `kernel-debuginfo` from the point release's vault | SHA-256 from the repository's `primary.xml` |

A file that fails its hash is deleted before anything opens it. Every download and build goes into the case's audit log and into the folder's `rowanholt-symbols.log`.

Some sources aren't fetched:
- Fedora: Koji turns automated clients away and publishes no file hash.
- CentOS Stream.
- RHEL, which needs a subscription.
- macOS 11 and later: Apple's Kernel Debug Kits need an Apple ID.

For those, an image whose table can't be found is skipped, and the audit log says why.

## Downloads off

`ROWANHOLT_SYMBOL_DOWNLOADS=off` in `.env` turns off both fetching tables and Volatility's own PDB downloads (`vol.py` runs `--offline`). `rowanholt server init` writes `off`: a team server's worker doesn't reach out unless an administrator decides it should. A job that then needs a table names the command that fetches it:

```bash
rowanholt symbols fetch --banner 'Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) ...'
```

## When it can't be fetched

The job's audit log names the exact file to get and where it's published, and `rowanholt symbols what <image>` (or `--banner`) says the same before a job. That's the only manual step. One command then turns the file into a table:

| Kernel | What to get | Then |
|---|---|---|
| Ubuntu, Debian, Rocky, Alma (offline, or a build since removed) | The debug package the message names (`.ddeb`, `-dbg` `.deb`, `kernel-debuginfo` `.rpm`) | `rowanholt symbols add --package <file>` |
| Fedora, CentOS Stream, Oracle Linux | `kernel-debuginfo-<version>.rpm`: the message gives the Koji, mirror or oss.oracle.com URL | `rowanholt symbols add --package <file>` |
| RHEL | `dnf download --enablerepo='*debug*' kernel-debuginfo-<version>` on a subscribed host | `rowanholt symbols add --package <file>` |
| macOS | The Kernel Debug Kit for the image's macOS version and build, from developer.apple.com/download/all (Apple ID). The message gives the macOS version, from the Darwin version, and the xnu build | `rowanholt symbols add --kdk <the .dmg> --banner '<banner>'`, on the Mac |
| Anything else | The kernel's `vmlinux` with debug info | `rowanholt symbols add --vmlinux <file> [--system-map <file>]` |

Each runs in the worker. A file the worker can't see is copied under `/tmp/rowanholt` for the run and removed afterwards; the worker sees `/tmp/rowanholt`, and `/Volumes` on a Mac. A KDK `.dmg` or `.pkg` is unpacked on the Mac first (`hdiutil`, `pkgutil --expand-full`), because the worker can't open Apple's package format. `--banner` picks the KDK's kernel that matches: `kernel` for `RELEASE_X86_64`, `kernel.release.t6000` and the like for Apple silicon. `--kernel` names one outright.

```bash
rowanholt symbols what /Volumes/Evidence/host.lime
rowanholt symbols add --package ~/Downloads/kernel-debuginfo-6.5.6-300.fc39.x86_64.rpm
rowanholt symbols add --kdk ~/Downloads/Kernel_Debug_Kit_14.4_build_23E214.dmg --banner 'Darwin Kernel Version 23.4.0: ...'
rowanholt symbols add --table ubuntu-6.8.0-31-generic.json.xz
rowanholt symbols list
```

Aragorn's Settings tab takes the same files as uploads and lists every table with where it came from. The uploads are a debug package, a table, a vmlinux, or a KDK's kernel and its dSYM DWARF file; a `.dmg` needs the CLI on a Mac.

`build-ubuntu-isf.sh` builds an Ubuntu table in a throwaway container, from before the worker could. Its default is the test image's `5.8.0-44-generic`, for which no prebuilt table is published.

The tables, the index and the log aren't committed (`.gitignore`).
