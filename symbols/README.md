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

## By hand

`rowanholt symbols` runs in the worker. Images and files must be at a path the worker mounts: `/Volumes`, `/tmp/rowanholt`, or an evidence folder.

```bash
rowanholt symbols fetch /Volumes/Evidence/host.lime      # the image's kernel (a Windows image: its PDB)
rowanholt symbols add --vmlinux vmlinux-6.8.0-31-generic --system-map System.map-6.8.0-31-generic
rowanholt symbols add --kdk /Volumes/Data/KDK_14.4_23E214.kdk --kernel kernel.release.t6000
rowanholt symbols add --table ubuntu-6.8.0-31-generic.json.xz
rowanholt symbols list
```

For a macOS kernel, install the Kernel Debug Kit for the image's xnu build (developer.apple.com/download/all; the job's message names the build). Pass the KDK folder, choosing the kernel that matches the banner's `RELEASE_` suffix: `kernel` for x86_64, `kernel.release.t6000` and the like for Apple silicon. Aragorn's Settings tab takes the same uploads (a table, a vmlinux, or a KDK's kernel and its dSYM DWARF file) and lists every table with where it came from.

`build-ubuntu-isf.sh` builds an Ubuntu table in a throwaway container, from before the worker could. Its default is the test image's `5.8.0-44-generic`, for which no prebuilt table is published.

The tables, the index and the log aren't committed (`.gitignore`).
