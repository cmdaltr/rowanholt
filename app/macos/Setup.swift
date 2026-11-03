// First run and updates for Rivendell.app: either connect to a team's Rivendell server,
// or run Rivendell here: find or install a container runtime (OrbStack), put Rivendell's
// files somewhere (the copy a release build carries, or a checkout the user already
// has), and mount evidence folders through docker-compose.local.yml.
import AppKit

let localComposeHeader = "# Written by Rivendell.app's setup"

struct SetupError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class SetupState {
    enum Runtime: String { case checking, running, installed, missing }

    var runtime = Runtime.checking
    var runtimeName = "Docker"
    var checkingRuntime = false
    var orbBusy = false
    var orbText: String?
    var orbPct: Double?
    var orbError: String?
    var mode = "bundled"  // bundled, existing, or server
    var serverAddress = ""
    var installParent = URL(fileURLWithPath: NSHomeDirectory())
    var existingPath: String?
    var evidence: [String] = []
    var evidenceLocked = false
    var busy: String?
    var error: String?

    var installTarget: URL { installParent.appendingPathComponent("Rivendell") }
}

/// A server address as typed, as the URL to open: https unless it's this machine,
/// scheme added when missing, nothing after the host and port
func parseServerAddress(_ text: String) -> URL? {
    var text = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if !text.contains("://") { text = "https://\(text)" }
    guard let parts = URLComponents(string: text), let host = parts.host, !host.isEmpty,
          let scheme = parts.scheme?.lowercased() else { return nil }
    let local = ["localhost", "127.0.0.1", "::1"].contains(host)
    guard scheme == "https" || (scheme == "http" && local) else { return nil }
    var clean = URLComponents()
    clean.scheme = scheme
    clean.host = host
    clean.port = parts.port
    return clean.url
}

/// A folder Rivendell can run from: the launcher and the compose file
func isRivendellCopy(_ path: String) -> Bool {
    FileManager.default.isExecutableFile(atPath: "\(path)/rivendell")
        && FileManager.default.fileExists(atPath: "\(path)/docker-compose.yml")
}

/// A copy setup unpacked (and may update), as opposed to a git clone the user manages
func isAppCopy(_ path: String) -> Bool {
    FileManager.default.fileExists(atPath: "\(path)/.rivendell-version")
        && !FileManager.default.fileExists(atPath: "\(path)/.git")
}

/// The environment for child processes: apps launched from the Dock get
/// /usr/bin:/bin:/usr/sbin:/sbin and nothing else, which misses Docker's CLI
func processEnvironment() -> [String: String] {
    var env = ProcessInfo.processInfo.environment
    let home = NSHomeDirectory()
    let extra = ["/opt/homebrew/bin", "/usr/local/bin", "\(home)/.orbstack/bin",
                 "/Applications/Docker.app/Contents/Resources/bin", "\(home)/.docker/bin"]
    env["PATH"] = (extra + [env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"]).joined(separator: ":")
    return env
}

/// Runs a command to completion (call off the main thread); returns its status and output.
@discardableResult
func run(_ executable: String, _ args: [String]) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = args
    process.environment = processEnvironment()
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
    } catch {
        return (-1, error.localizedDescription)
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

extension AppDelegate {
    func showSetup() {
        show(.setup)
        setup.error = nil
        setup.busy = nil
        if bundledSource == nil { setup.mode = "existing" }
        if let server = serverURL {
            setup.mode = "server"
            setup.serverAddress = server.absoluteString
        } else if let current = root {
            if isAppCopy(current) && bundledSource != nil {
                setup.mode = "bundled"
                setup.installParent = URL(fileURLWithPath: current).deletingLastPathComponent()
            } else {
                setup.mode = "existing"
                setup.existingPath = current
            }
        }
        loadEvidence()
        window.title = "Set Up Rivendell"
        let page = Bundle.main.url(forResource: "setup", withExtension: "html")!
        webView.loadFileURL(page, allowingReadAccessTo: Bundle.main.resourceURL!)
        checkRuntime()
        runtimeTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.checkRuntime()
        }
    }

    func setupMessage(_ body: [String: Any]) {
        switch body["action"] as? String {
        case "ready", "recheck":
            renderSetup()
            checkRuntime()
        case "installOrbStack": installOrbStack()
        case "openRuntime": NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/OrbStack.app"))
        case "openURL":
            if let url = (body["url"] as? String).flatMap(URL.init(string:)), url.scheme == "https" {
                NSWorkspace.shared.open(url)
            }
        case "mode":
            let mode = body["mode"] as? String ?? ""
            setup.mode = ["bundled", "existing", "server"].contains(mode) ? mode : "existing"
            setup.error = nil
            loadEvidence()
            renderSetup()
        case "chooseInstall": chooseInstallFolder()
        case "chooseExisting": chooseExistingCopy()
        case "addEvidence": addEvidence()
        case "serverAddress":
            setup.serverAddress = body["address"] as? String ?? ""
            setup.error = nil
            renderSetup()
        case "removeEvidence":
            setup.evidence.removeAll { $0 == body["path"] as? String }
            renderSetup()
        case "finish": finishSetup()
        default: break
        }
    }

    /// The copy the evidence list belongs to, when it exists yet
    var setupRoot: String? {
        let path = setup.mode == "bundled" ? setup.installTarget.path : setup.existingPath
        return path.flatMap { isRivendellCopy($0) ? $0 : nil }
    }

    func installNote() -> String {
        let target = setup.installTarget.path
        guard FileManager.default.fileExists(atPath: target) else { return "" }
        if isAppCopy(target) { return "updates the copy already there" }
        if isRivendellCopy(target) { return "a git checkout is already there: use it with the option below" }
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: target)) ?? []
        return contents.isEmpty ? "" : "that folder already exists and isn't empty: choose another"
    }

    func renderSetup() {
        let orNull = { (value: Any?) -> Any in value ?? NSNull() }
        let state: [String: Any] = [
            "runtime": ["status": setup.runtime.rawValue, "name": setup.runtimeName],
            "orb": ["busy": setup.orbBusy, "text": orNull(setup.orbText),
                    "pct": orNull(setup.orbPct), "error": orNull(setup.orbError)],
            "bundled": bundledSource != nil,
            "version": appVersion,
            "mode": setup.mode,
            "installPath": setup.installTarget.path,
            "installNote": installNote(),
            "existingPath": orNull(setup.existingPath),
            "serverAddress": setup.serverAddress,
            "serverValid": parseServerAddress(setup.serverAddress) != nil,
            "evidence": setup.evidence,
            "evidenceLocked": setup.evidenceLocked,
            "busy": orNull(setup.busy),
            "error": orNull(setup.error),
        ]
        js("render", [state])
    }

    // MARK: Container runtime

    func checkRuntime() {
        guard !setup.checkingRuntime else { return }
        setup.checkingRuntime = true
        DispatchQueue.global().async {
            let fm = FileManager.default
            let installed = { (name: String) in
                ["/Applications", "\(NSHomeDirectory())/Applications"].contains { fm.fileExists(atPath: "\($0)/\(name).app") }
            }
            let running = run("/usr/bin/env", ["docker", "info"]).status == 0
            let cli = run("/usr/bin/env", ["which", "docker"]).status == 0
            let name = installed("OrbStack") ? "OrbStack" : installed("Docker") ? "Docker Desktop" : "Docker"
            let status: SetupState.Runtime = running ? .running
                : (installed("OrbStack") || installed("Docker") || cli) ? .installed : .missing
            DispatchQueue.main.async {
                self.setup.checkingRuntime = false
                guard self.setup.runtime != status || self.setup.runtimeName != name else { return }
                self.setup.runtime = status
                self.setup.runtimeName = name
                self.renderSetup()
            }
        }
    }

    func installOrbStack() {
        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "amd64"
        #endif
        let url = URL(string: "https://orbstack.dev/download/stable/latest/\(arch)")!
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("rivendell-orbstack-\(UUID().uuidString)")
        let dmg = work.appendingPathComponent("OrbStack.dmg")
        try? FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)

        setup.orbBusy = true
        setup.orbError = nil
        setup.orbPct = 0
        setup.orbText = "Downloading OrbStack…"
        renderSetup()

        let task = URLSession.shared.downloadTask(with: url) { tmp, response, error in
            var failure: String?
            if let error = error {
                failure = error.localizedDescription
            } else if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                failure = "the server answered HTTP \(http.statusCode)"
            } else if let tmp = tmp {
                // The temporary file is gone once this handler returns
                do { try FileManager.default.moveItem(at: tmp, to: dmg) } catch { failure = error.localizedDescription }
            }
            if let failure = failure {
                self.orbFailed("Couldn't download OrbStack: \(failure). Get it from orbstack.dev instead.", work: work)
            } else {
                DispatchQueue.global().async { self.installOrbStackImage(dmg, work: work) }
            }
        }
        orbObservation = task.progress.observe(\.fractionCompleted) { progress, _ in
            DispatchQueue.main.async {
                guard self.setup.orbBusy, self.setup.orbPct ?? 0 < 1 else { return }
                self.setup.orbPct = progress.fractionCompleted
                self.setup.orbText = "Downloading OrbStack… \(Int(progress.fractionCompleted * 100))%"
                self.renderSetup()
            }
        }
        task.resume()
    }

    /// Mounts the downloaded image, checks Gatekeeper accepts OrbStack (Developer ID,
    /// notarised) before copying it into Applications, and opens it. Off the main thread.
    func installOrbStackImage(_ dmg: URL, work: URL) {
        let mount = work.appendingPathComponent("mount")
        try? FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true)
        let progress = { (text: String) in
            DispatchQueue.main.async {
                self.setup.orbPct = 1
                self.setup.orbText = text
                self.renderSetup()
            }
        }
        progress("Checking OrbStack's signature…")
        guard run("/usr/bin/hdiutil", ["attach", dmg.path, "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount.path]).status == 0 else {
            orbFailed("Couldn't open the OrbStack disk image.", work: work)
            return
        }
        defer { run("/usr/bin/hdiutil", ["detach", mount.path, "-quiet", "-force"]) }
        let app = mount.appendingPathComponent("OrbStack.app")
        let assessment = run("/usr/sbin/spctl", ["--assess", "--type", "execute", app.path])
        guard assessment.status == 0 else {
            orbFailed("The OrbStack download didn't pass Gatekeeper, so it wasn't installed. \(assessment.output)", work: work)
            return
        }
        let applications = FileManager.default.isWritableFile(atPath: "/Applications")
            ? URL(fileURLWithPath: "/Applications")
            : URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Applications")
        try? FileManager.default.createDirectory(at: applications, withIntermediateDirectories: true)
        let target = applications.appendingPathComponent("OrbStack.app")
        progress("Installing OrbStack into \(applications.path)…")
        let copy = run("/usr/bin/ditto", [app.path, target.path])
        guard copy.status == 0 else {
            orbFailed("Couldn't copy OrbStack into \(applications.path): \(copy.output)", work: work)
            return
        }
        run("/usr/bin/open", [target.path])
        try? FileManager.default.removeItem(at: dmg)
        DispatchQueue.main.async {
            self.setup.orbBusy = false
            self.setup.orbText = "OrbStack is installed and opening. Finish its own setup (approve its helper so /var/run/docker.sock exists), then carry on here."
            self.renderSetup()
            self.checkRuntime()
        }
    }

    func orbFailed(_ message: String, work: URL) {
        DispatchQueue.main.async {
            self.setup.orbBusy = false
            self.setup.orbText = nil
            self.setup.orbError = message
            self.renderSetup()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { try? FileManager.default.removeItem(at: work) }
    }

    // MARK: Rivendell's files

    func chooseInstallFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Install Here"
        panel.message = "Rivendell's files go into a Rivendell folder inside the folder you choose."
        panel.directoryURL = setup.installParent
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, var url = panel.url else { return }
            if url.lastPathComponent == "Rivendell" { url.deleteLastPathComponent() }
            self.setup.installParent = url
            self.setup.mode = "bundled"
            self.setup.error = nil
            self.loadEvidence()
            self.renderSetup()
        }
    }

    func chooseExistingCopy() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Use This Copy"
        panel.message = "Choose the folder with Rivendell's rivendell launcher and docker-compose.yml."
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            if isRivendellCopy(url.path) {
                self.setup.existingPath = url.path
                self.setup.mode = "existing"
                self.setup.error = nil
                self.loadEvidence()
            } else {
                self.setup.error = "\(url.path) doesn't look like Rivendell: there's no rivendell launcher and docker-compose.yml in it."
            }
            self.renderSetup()
        }
    }

    /// Unpacks the source tree this build carries into `target`, over an earlier copy
    /// if there is one (.env, docker-compose.local.yml and other untracked files stay).
    func installBundledCopy(to target: URL) throws {
        guard let source = bundledSource else { throw SetupError(message: "This build of Rivendell.app doesn't carry Rivendell's files.") }
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        let unpack = run("/usr/bin/tar", ["-xzf", source.path, "-C", target.path, "--strip-components", "1"])
        guard unpack.status == 0 else { throw SetupError(message: "Couldn't unpack Rivendell into \(target.path): \(unpack.output)") }
        try appVersion.write(to: target.appendingPathComponent(".rivendell-version"), atomically: true, encoding: .utf8)
    }

    func needsUpdate(_ root: String) -> Bool {
        guard bundledSource != nil, isAppCopy(root),
              let installed = try? String(contentsOfFile: "\(root)/.rivendell-version", encoding: .utf8) else { return false }
        return installed.trimmingCharacters(in: .whitespacesAndNewlines) != appVersion
    }

    func askToUpdate(_ root: String) {
        let alert = NSAlert()
        alert.messageText = "Update Rivendell to \(appVersion)?"
        alert.informativeText = "This replaces Rivendell's files in \(root). Your .env, evidence folders and cases are kept. The images are rebuilt on this start, which takes a while."
        alert.addButton(withTitle: "Update")
        alert.addButton(withTitle: "Not Now")
        alert.beginSheetModal(for: window) { response in
            guard response == .alertFirstButtonReturn else {
                self.startOrShow()
                return
            }
            self.showSplash()
            self.splashStatus("Updating Rivendell's files…")
            DispatchQueue.global().async {
                do {
                    try self.installBundledCopy(to: URL(fileURLWithPath: root))
                    DispatchQueue.main.async { self.startOrShow() }
                } catch {
                    DispatchQueue.main.async { self.splashError(error.localizedDescription) }
                }
            }
        }
    }

    // MARK: Evidence folders

    func addEvidence() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        panel.message = "Choose folders of evidence to make visible inside Rivendell."
        panel.beginSheetModal(for: window) { response in
            guard response == .OK else { return }
            for url in panel.urls where !self.setup.evidence.contains(url.path) {
                self.setup.evidence.append(url.path)
            }
            self.renderSetup()
        }
    }

    /// Picks up the folders an earlier setup mounted in the chosen copy; a hand-written
    /// docker-compose.local.yml locks the list instead
    func loadEvidence() {
        setup.evidenceLocked = false
        guard let root = setupRoot,
              let text = try? String(contentsOfFile: "\(root)/docker-compose.local.yml", encoding: .utf8) else { return }
        guard text.hasPrefix(localComposeHeader) else {
            setup.evidenceLocked = true
            return
        }
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("source: "),
                  let data = trimmed.dropFirst("source: ".count).data(using: .utf8),
                  let path = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String,
                  !setup.evidence.contains(path) else { continue }
            setup.evidence.append(path)
        }
    }

    /// Mounts each folder at its own path in the backend (read-only) and the worker,
    /// in long syntax with JSON-quoted paths so colons and spaces are safe
    func writeEvidenceCompose(root: String, folders: [String]) throws {
        let file = URL(fileURLWithPath: root).appendingPathComponent("docker-compose.local.yml")
        if let existing = try? String(contentsOf: file, encoding: .utf8), !existing.hasPrefix(localComposeHeader) {
            return
        }
        guard !folders.isEmpty else {
            try? FileManager.default.removeItem(at: file)
            return
        }
        func quote(_ s: String) -> String {
            let data = try! JSONSerialization.data(withJSONObject: s, options: [.fragmentsAllowed, .withoutEscapingSlashes])
            return String(data: data, encoding: .utf8)!
        }
        var yaml = "\(localComposeHeader): evidence folders, mounted at the same path inside the containers.\n"
        yaml += "# Change them in Rivendell › Set Up Rivendell…\nservices:\n"
        for (service, readOnly) in [("backend", true), ("celery-worker", false)] {
            yaml += "  \(service):\n    volumes:\n"
            for folder in folders {
                yaml += "      - type: bind\n        source: \(quote(folder))\n        target: \(quote(folder))\n"
                if readOnly { yaml += "        read_only: true\n" }
            }
        }
        try yaml.write(to: file, atomically: true, encoding: .utf8)
    }

    // MARK: Finishing

    func finishSetup() {
        if setup.mode == "server" {
            guard let server = parseServerAddress(setup.serverAddress) else {
                setup.error = "Enter the server's address, e.g. rivendell.example.org (https only)."
                renderSetup()
                return
            }
            UserDefaults.standard.set(server.absoluteString, forKey: "RivendellServer")
            window.title = "Rivendell"
            launch()
            return
        }
        let mode = setup.mode
        let target = setup.installTarget
        let existing = setup.existingPath
        let folders = setup.evidence
        let locked = setup.evidenceLocked
        setup.error = nil
        setup.busy = mode == "bundled" ? "Copying Rivendell into \(target.path)…" : "Saving…"
        renderSetup()

        DispatchQueue.global().async {
            do {
                let root: String
                if mode == "bundled" {
                    let note = self.installNote()
                    if note.hasPrefix("a git checkout") || note.hasPrefix("that folder") {
                        throw SetupError(message: "\(target.path): \(note).")
                    }
                    if !isAppCopy(target.path) || self.needsUpdate(target.path) {
                        try self.installBundledCopy(to: target)
                    }
                    root = target.path
                } else {
                    guard let path = existing, isRivendellCopy(path) else {
                        throw SetupError(message: "Choose the Rivendell folder to use.")
                    }
                    root = path
                }
                if !locked { try self.writeEvidenceCompose(root: root, folders: folders) }
                DispatchQueue.main.async {
                    UserDefaults.standard.set(root, forKey: "RivendellRoot")
                    UserDefaults.standard.removeObject(forKey: "RivendellServer")
                    self.setup.busy = nil
                    self.window.title = "Rivendell"
                    self.launch()
                }
            } catch {
                DispatchQueue.main.async {
                    self.setup.busy = nil
                    self.setup.error = error.localizedDescription
                    self.renderSetup()
                }
            }
        }
    }
}
