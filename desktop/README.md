# The Rowanholt desktop app

Rowanholt is a Docker stack with a web UI on `http://localhost:5687`. The desktop app is the front door to it: launch it from the Dock, taskbar or application menu and it starts the stack if the UI isn't answering, waits for it, then opens the UI in its own window.

There are two ways to get it. The release downloads are for everyone: no git, terminal or build tools, and the first launch walks through setup. The `rowanholt app install` route is for a checkout you're developing in, and always runs that checkout.

## Release downloads

Each `v*` tag builds the files below (`.github/workflows/desktop-release.yml`, which also builds and smoke-tests every push it's run on) and attaches them to a draft GitHub release. Each package carries the source tree at that tag (as `rowanholt-src.tar.gz`), so setup works offline. The names are the convention Rowanholt shares with Shikari and Ostraka.

| OS | Download | Installing it | First-run setup |
|---|---|---|---|
| macOS 12+ | `Rowanholt-<version>-macos-universal.dmg` (Apple silicon and Intel) | Drag Rowanholt to Applications | In the app's window |
| Windows 10/11 | `Rowanholt-<version>-windows-universal.msi` (x64 and Arm) | Double-click, or `desktop/install.ps1` (no admin needed) | In the app, on first launch |
| Debian, Ubuntu | `rowanholt_<version>-1_all.deb` | Double-click (App Center), or `sudo apt install ./rowanholt_*.deb` | Zenity dialogs on first launch |
| Team servers, any Linux | `rowanholt-<version>-source.tar.gz`: the source tree under one top folder, `rowanholt-<version>/` (`desktop/source-tarball.sh`) | Unpack, then `rowanholt server init` ([docs/SERVER.md](../docs/SERVER.md)) | |
| | `SHA256SUMS`: checksums of all of the above, which `desktop/install.sh` and `desktop/install.ps1` check | | |

One package per platform runs on every architecture: the packages hold the launcher and the source tree, with nothing compiled for a CPU but the Mac app's own universal binary, and Docker builds or pulls images for the machine when the stack first starts. (Shikari splits per architecture because its installers bundle a compiled Python; the rule for both is to split only when the contents differ.) Every package carries `LICENSE`: in the Mac app's `Contents/Resources`, at `/usr/share/doc/rowanholt/copyright` and `/opt/rowanholt/LICENSE` in the `.deb`, and in the Windows install folder (`%LOCALAPPDATA%\Programs\cmdaltr\Rowanholt`); the MSI shows it when double-clicked. The Mac app shows it under Help › Licence, and the web UI's About under Licence.

A pre-release is spelt as its tag in every file name (`Rowanholt-1.4.0-rc1-macos-universal.dmg`, `rowanholt_1.4.0-rc1-1_all.deb`, `rowanholt-1.4.0-rc1-source.tar.gz`). Inside, the `.deb`'s version is `1.4.0-0.rc1`, the pre-release in the Debian revision, so dpkg sorts the release candidate before `1.4.0-1`, and the `.msi`'s is `1.4.0`, the numbers Windows Installer takes (a dev build's `-dev.N` becomes a fourth number).

Setup covers the same three things everywhere.

**The container runtime.** On macOS, if neither OrbStack nor Docker Desktop is there, **Install OrbStack** downloads the DMG for the Mac's architecture and has `spctl` check it is a notarised Developer ID app before copying it into Applications and opening it. OrbStack's own first run then asks to install its helper; approve it, since Andúril mounts `/var/run/docker.sock`. Docker Desktop is a link to its download page. On Windows, setup explains Docker Desktop and offers its download page. On Linux, setup checks for `docker`, the compose plugin and membership of the `docker` group, and says what's missing. Docker itself is never installed silently: every OS needs admin rights and Docker's own setup for it. OrbStack and Docker Desktop are free for personal use; commercial use may need a licence.

**Rowanholt's files.** By default they go into a `Rowanholt` folder in the home directory (`%USERPROFILE%\Rowanholt` on Windows), or another folder you choose. You can point setup at a checkout you already have instead. A copy the app unpacked carries `.rowanholt-version`: when a newer app version launches, it offers to update the files in place (`.env`, evidence mounts and cases stay), and the next `rowanholt start` rebuilds the images once. A git checkout is never overwritten, so keep it current with `git pull`. On its first start, an unpacked copy gets a `.env` with a random `SECRET_KEY`.

Rocky, RHEL and Alma have no desktop package, as Shikari has none: they run Rowanholt as a team server (`rowanholt server init`, [docs/SERVER.md](../docs/SERVER.md#rocky-rhel-and-alma)), and `desktop/install.sh` says so there. A checkout's `rowanholt app install` still works on a Rocky desktop: the launcher there says Docker Engine comes from Docker's own repository, not the distribution's (which ships Podman, unsupported), and SELinux stays enforcing, the containers that mount evidence folders running unlabelled rather than relabelling the evidence.

**Evidence folders** (optional). Setup writes `docker-compose.local.yml`, which the launcher adds to the stack when it exists. The file is gitignored, so pulls never touch it. Each folder is mounted read-only in the backend and read-write in the worker. On macOS and Linux it appears at the same path inside the containers. On Windows, `D:\Cases` appears as `/mnt/d/Cases`. A `docker-compose.local.yml` you wrote by hand is left alone. To change the folders later: **Rowanholt › Set Up Rowanholt…** (macOS), the **Set Up Rowanholt** action on the menu entry (Linux), or the **Set Up Rowanholt** Start menu entry (Windows).

### Signing

Unsigned builds work, but warn. On macOS, a downloaded ad-hoc-signed app won't open until it's allowed in System Settings › Privacy & Security. On Windows, SmartScreen shows "Windows protected your PC" and needs **More info › Run anyway**. Signing is switched on by repository secrets:

| Secret | For |
|---|---|
| `MACOS_CERTIFICATE_P12`, `MACOS_CERTIFICATE_PASSWORD` | A Developer ID Application certificate, base64-encoded `.p12` (Apple Developer Program) |
| `MACOS_SIGN_IDENTITY` | Its name, `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | Notarisation; the password is an app-specific one from account.apple.com |
| `WINDOWS_CERTIFICATE_PFX`, `WINDOWS_CERTIFICATE_PASSWORD` | A code-signing certificate, base64-encoded `.pfx` |

The packages build locally too, from a source tarball:

```bash
desktop/source-tarball.sh /tmp/rowanholt-src.tar.gz
desktop/macos/package.sh --version 1.4.0 --source /tmp/rowanholt-src.tar.gz dist     # on a Mac
desktop/linux/package-deb.sh --version 1.4.0 --source /tmp/rowanholt-src.tar.gz dist # on Debian/Ubuntu
```

```powershell
# On Windows, with the .NET SDK and WiX 5
dotnet tool install --global wix --version 5.0.2
wix extension add --global WixToolset.UI.wixext/5.0.2
desktop\windows\build-msi.ps1 -Version 1.4.0 -Tarball rowanholt-src.tar.gz -OutDir dist
```

## From a checkout

| OS | Command | What it installs |
|---|---|---|
| macOS | `rowanholt app install [--dock]` | `Rowanholt.app` built from source with `swiftc` (Xcode command-line tools), in `/Applications` or `~/Applications`; `--dock` pins it |
| Linux | `rowanholt app install` | A menu entry for the current user, under `~/.local/share` |
| Windows | `powershell -ExecutionPolicy Bypass -File desktop\windows\install.ps1` | Start menu and desktop shortcuts |

The checkout build records the repo's path, so reinstall after moving the checkout. On macOS its bundle ID is `io.github.cmdaltr.rowanholt.local`, so it keeps its settings and web logins apart from a release install. `rowanholt app uninstall` (or `desktop\windows\install.ps1 -Uninstall`) removes it.

## Using it

| OS | Window | Stop the stack |
|---|---|---|
| macOS | A native WebKit window with its own Dock icon | **Rowanholt › Stop Rowanholt**, or **Stop Rowanholt and Quit** (⌥⌘Q) |
| Linux | Chromium, Chrome, Brave or Edge in app mode; the default browser otherwise | The **Stop Rowanholt** action on the menu entry |
| Windows | Edge (or Chrome) in app mode | The **Stop Rowanholt** Start menu shortcut |

Quitting leaves the stack running, since a Celery job may be mid-analysis. `rowanholt stop` works wherever the launcher does.

On macOS, the window shows Gandalf walking from the Shire to Rowanholt while the stack starts, with an ETA taken from this machine's earlier starts (`rowanholt start --progress`; the first start is a guess, and a build paces itself on its steps). The Linux app shows the same journey as a zenity progress bar, and Windows as a console progress bar. If the stack goes away, the window falls back to the start page with a **Try again** button. Downloads go to `~/Downloads`, and Splunk, Kibana, Navigator and other external links open in the default browser. On Linux, progress goes to desktop notifications and `~/.local/state/rowanholt/app.log`. On Windows, it's in the shortcut's console, which starts minimised. The Linux and Windows windows use their own browser profile, so the Rowanholt login stays apart from everyday browsing. On Wayland, Chromium may ignore `--class`, and the dock then shows the browser's icon.

Windows won't let a program pin itself to the taskbar: right-click Rowanholt in the Start menu › **Pin to taskbar**. On GNOME and KDE, right-click the running app's dock icon to pin it.

### Connecting to a server

In setup, **Connect to my team's Rowanholt server** takes a hostname (`https://` is assumed) and nothing else: no Docker, no checkout, and start and stop do nothing. The Mac app opens the server in its own window and needs the server's certificate trusted in the Keychain when it comes from the server's own CA (`rowanholt server ca`); Linux and Windows open it in the app-mode browser window. The address is kept in `RowanholtServer` (macOS defaults), `~/.config/rowanholt/server` (Linux) or `.rowanholt-server` beside the Windows install, and `ROWANHOLT_SERVER` overrides it on Linux and Windows. The Windows installer asks at its first page, and leaves Docker and the source tree out for a client. See `docs/SERVER.md` for the server side.

### Connecting an organisation

IT can set the server, which skips setup's choice and takes away **Set Up Rowanholt** (on the Mac, the menu item is greyed out; on Linux and Windows, setup says the server is set):

| | Setting |
|---|---|
| macOS | A configuration profile from your MDM: a Custom Settings (`com.apple.ManagedClient.preferences`) payload for `io.github.cmdaltr.rowanholt`, key `ServerURL` (string). Only an enforced value counts, as with Shikari |
| Windows | Group Policy or Intune: `HKLM\SOFTWARE\Policies\cmdaltr\Rowanholt`, string value `ServerURL` (`HKCU` works too; `HKLM` wins) |
| Linux | `/etc/rowanholt/client.json`: `{"server_url": "https://rowanholt.example.org"}` |
| Any | The environment variable `ROWANHOLT_SERVER`: a URL, or `local` to run Rowanholt on this computer whatever setup saved. Not locked |

An address IT or `ROWANHOLT_SERVER` sets may be plain `http://`, for a server on a network they trust; one typed into setup must be `https://` unless it's this computer. If IT's address isn't a web address, the app says so and stops, rather than running Rowanholt locally instead.

### Updates

A release install (not a checkout's build) asks GitHub for the latest published release once a day, once its window is open, and says when there's a newer one. Drafts and prereleases never count, and the version is compared by its numbers only (`2.1.0-dev.4` is `2.1.0`). The check sends GitHub nothing but the request; `GH_TOKEN` or `GITHUB_TOKEN` is used if set, only for GitHub's rate limit, since the repository is public. `ROWANHOLT_UPDATE_CHECK=0` turns it off.

| | The notice | From a terminal |
|---|---|---|
| macOS | A sheet: **Update** (closes Rowanholt, runs `Rowanholt.app/Contents/Resources/install.sh --version <tag> --launch`, logged to `~/Library/Logs/Rowanholt/update.log`, and reopens it), **Later** (until the next launch), **Skip This Version** (until a newer one). **Help › Check for Updates…** asks now and has the switch for the daily check | `Rowanholt.app/Contents/MacOS/Rowanholt update`, or `update --check` to only look |
| Linux | A notification and a dialog giving the command, since apt needs a password the menu entry can't ask for: `sh /opt/rowanholt/install.sh --version <tag>`. **Later** or **Skip this version** | `/opt/rowanholt/rowanholt-app.sh --update`, or `--update --check` |
| Windows | A dialog: **Update** (runs `%LOCALAPPDATA%\Programs\cmdaltr\Rowanholt\seed\install.ps1 -Version <tag> -Launch`), **Later**, **Skip this version** | `powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\cmdaltr\Rowanholt\desktop\windows\Rowanholt.ps1" -Update`, or `-Update -Check` |

Quitting for an update leaves the stack running, as quitting always does. This is separate from the files folder: when a newer app launches, it still offers to update the files setup unpacked, as before.

## Layout

| Path | What |
|---|---|
| `macos/Rowanholt.swift`, `macos/Setup.swift`, `macos/setup.html` | The Mac app: window, splash and menus; first-run setup and updates; the setup page |
| `macos/journey.html` | The start-up journey (its map, `journey.png`, is cut from `docs/images/middle_earth.png` at build time) |
| `macos/build.sh`, `macos/package.sh` | Checkout and release builds; the signed, notarised DMG |
| `linux/rowanholt-app.sh` | Launcher and zenity setup, for a checkout or the `.deb` |
| `linux/rowanholt.desktop.in`, `linux/desktop-entry.sh`, `desktop/linux/install.sh`, `linux/package-deb.sh` | Menu entry, checkout install, `.deb` |
| `windows/Rowanholt.ps1`, `desktop/windows/install.ps1`, `windows/rowanholt.wxs`, `windows/build-msi.ps1` | Launcher and first-run setup, checkout shortcuts, the MSI (WiX 5) and its build |
| `../desktop/install.sh`, `../desktop/uninstall.sh`, `../desktop/install.ps1`, `../desktop/uninstall.ps1` | The release installers (`desktop/` at the repository's top level, as Shikari's): install, upgrade or remove a release. The Mac app carries the `.sh` pair in `Contents/Resources`, the `.deb` in `/opt/rowanholt`, the MSI the `.ps1` pair in `seed\` |
| `source-tarball.sh` | The source tree the packages carry (`git archive HEAD`) |
| `icons/` | `rowanholt.icns`, `.ico`, `.png`, committed; `icons/build.sh` regenerates them from the logo on a Mac |
