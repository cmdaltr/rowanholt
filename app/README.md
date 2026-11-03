# The Rivendell desktop app

Rivendell is a Docker stack with a web UI on `http://localhost:5687`. The desktop app is the front door to it: launch it from the Dock, taskbar or application menu and it starts the stack if the UI isn't answering, waits for it, then opens the UI in its own window.

There are two ways to get it. The release downloads are for everyone: no git, terminal or build tools, and the first launch walks through setup. The `rivendell app install` route is for a checkout you're developing in, and always runs that checkout.

## Release downloads

Each `v*` tag builds three packages (`.github/workflows/desktop-release.yml`) and attaches them to a draft GitHub release with a `SHA256SUMS`. Each carries the source tree at that tag, so setup works offline.

| OS | Download | Installing it | First-run setup |
|---|---|---|---|
| macOS 12+ | `Rivendell-<version>.dmg` (universal) | Drag Rivendell to Applications | In the app's window |
| Windows 10/11 | `Rivendell-Setup-<version>.exe` | The installer (no admin needed) | In the installer |
| Debian, Ubuntu | `rivendell_<version>_all.deb` | Double-click (App Center), or `sudo apt install ./rivendell_*.deb` | Zenity dialogs on first launch |

Setup covers the same three things everywhere.

**The container runtime.** On macOS, if neither OrbStack nor Docker Desktop is there, **Install OrbStack** downloads the DMG for the Mac's architecture and has `spctl` check it is a notarised Developer ID app before copying it into Applications and opening it. OrbStack's own first run then asks to install its helper; approve it, since Andúril mounts `/var/run/docker.sock`. Docker Desktop is a link to its download page. On Windows, the installer explains Docker Desktop and offers its download page at the end. On Linux, setup checks for `docker`, the compose plugin and membership of the `docker` group, and says what's missing. Docker itself is never installed silently: every OS needs admin rights and Docker's own setup for it. OrbStack and Docker Desktop are free for personal use; commercial use may need a licence.

**Rivendell's files.** By default they go into a `Rivendell` folder in the home directory (`%USERPROFILE%\Rivendell` on Windows), or another folder you choose. On macOS and Linux you can point setup at a checkout you already have instead. A copy the app unpacked carries `.rivendell-version`: when a newer app version launches, it offers to update the files in place (`.env`, evidence mounts and cases stay), and the next `rivendell start` rebuilds the images once. A git checkout is never overwritten, so keep it current with `git pull`. On its first start, an unpacked copy gets a `.env` with a random `SECRET_KEY`.

An RPM for Rocky Linux 9 / RHEL 9 is a feature request (FR-03 in `docs/FEATURE_REQUESTS.md`).

**Evidence folders** (optional). Setup writes `docker-compose.local.yml`, which the launcher adds to the stack when it exists. The file is gitignored, so pulls never touch it. Each folder is mounted read-only in the backend and read-write in the worker. On macOS and Linux it appears at the same path inside the containers. On Windows, `D:\Cases` appears as `/mnt/d/Cases`. A `docker-compose.local.yml` you wrote by hand is left alone. To change the folders later: **Rivendell › Set Up Rivendell…** (macOS), the **Set Up Rivendell** action on the menu entry (Linux), or run the installer again (Windows).

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
app/source-tarball.sh /tmp/rivendell-src.tar.gz
app/macos/package.sh --version 1.4.0 --source /tmp/rivendell-src.tar.gz dist     # on a Mac
app/linux/package-deb.sh --version 1.4.0 --source /tmp/rivendell-src.tar.gz dist # on Debian/Ubuntu
```

```powershell
# On Windows, with Inno Setup 6 and the tarball unpacked to stage\rivendell
ISCC /DAppVersion=1.4.0 /DSourceDir=$PWD\stage\rivendell /DOutputDir=$PWD\dist app\windows\rivendell.iss
```

## From a checkout

| OS | Command | What it installs |
|---|---|---|
| macOS | `rivendell app install [--dock]` | `Rivendell.app` built from source with `swiftc` (Xcode command-line tools), in `/Applications` or `~/Applications`; `--dock` pins it |
| Linux | `rivendell app install` | A menu entry for the current user, under `~/.local/share` |
| Windows | `powershell -ExecutionPolicy Bypass -File app\windows\install.ps1` | Start menu and desktop shortcuts |

The checkout build records the repo's path, so reinstall after moving the checkout. On macOS its bundle ID is `io.github.cmdaltr.rivendell.local`, so it keeps its settings and web logins apart from a release install. `rivendell app uninstall` (or `install.ps1 -Uninstall`) removes it.

## Using it

| OS | Window | Stop the stack |
|---|---|---|
| macOS | A native WebKit window with its own Dock icon | **Rivendell › Stop Rivendell**, or **Stop Rivendell and Quit** (⌥⌘Q) |
| Linux | Chromium, Chrome, Brave or Edge in app mode; the default browser otherwise | The **Stop Rivendell** action on the menu entry |
| Windows | Edge (or Chrome) in app mode | The **Stop Rivendell** Start menu shortcut |

Quitting leaves the stack running, since a Celery job may be mid-analysis. `rivendell stop` works wherever the launcher does.

On macOS, the window shows Gandalf walking from the Shire to Rivendell while the stack starts, with an ETA taken from this machine's earlier starts (`rivendell start --progress`; the first start is a guess, and a build paces itself on its steps). The Linux app shows the same journey as a zenity progress bar, and Windows as a console progress bar. If the stack goes away, the window falls back to the start page with a **Try again** button. Downloads go to `~/Downloads`, and Splunk, Kibana, Navigator and other external links open in the default browser. On Linux, progress goes to desktop notifications and `~/.local/state/rivendell/app.log`. On Windows, it's in the shortcut's console, which starts minimised. The Linux and Windows windows use their own browser profile, so the Rivendell login stays apart from everyday browsing. On Wayland, Chromium may ignore `--class`, and the dock then shows the browser's icon.

Windows won't let a program pin itself to the taskbar: right-click Rivendell in the Start menu › **Pin to taskbar**. On GNOME and KDE, right-click the running app's dock icon to pin it.

### Connecting to a server

In setup, **Connect to my team's Rivendell server** takes a hostname (`https://` is assumed) and nothing else: no Docker, no checkout, and start and stop do nothing. The Mac app opens the server in its own window and needs the server's certificate trusted in the Keychain when it comes from the server's own CA (`rivendell server ca`); Linux and Windows open it in the app-mode browser window. The address is kept in `RivendellServer` (macOS defaults), `~/.config/rivendell/server` (Linux) or `.rivendell-server` beside the Windows install, and `RIVENDELL_SERVER` overrides it on Linux and Windows. The Windows installer asks at its first page, and leaves Docker and the source tree out for a client. See `docs/SERVER.md` for the server side.

## Layout

| Path | What |
|---|---|
| `macos/Rivendell.swift`, `macos/Setup.swift`, `macos/setup.html` | The Mac app: window, splash and menus; first-run setup and updates; the setup page |
| `macos/journey.html` | The start-up journey (its map, `journey.png`, is cut from `docs/images/middle_earth.png` at build time) |
| `macos/build.sh`, `macos/package.sh` | Checkout and release builds; the signed, notarised DMG |
| `linux/rivendell-app.sh` | Launcher and zenity setup, for a checkout or the `.deb` |
| `linux/rivendell.desktop.in`, `linux/desktop-entry.sh`, `linux/install.sh`, `linux/package-deb.sh` | Menu entry, checkout install, `.deb` |
| `windows/Rivendell.ps1`, `windows/install.ps1`, `windows/rivendell.iss` | Launcher, checkout shortcuts, Inno Setup installer |
| `source-tarball.sh` | The source tree the packages carry (`git archive HEAD`) |
| `icons/` | `rivendell.icns`, `.ico`, `.png`, committed; `icons/build.sh` regenerates them from the logo on a Mac |
