// Rowanholt.app: shows Rowanholt's web UI in its own window. Either it runs Rowanholt
// here, starting the Docker stack through the launcher when the UI isn't answering, or
// it connects to a team's Rowanholt server. Setup.swift handles the first run (where
// Rowanholt runs, the container runtime, evidence folders) and updates.
import AppKit
import WebKit

let localURL = URL(string: "http://localhost:5687")!
let startTimeout: TimeInterval = 900

enum Page { case splash, setup, ui }

@main
final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate,
                         WKDownloadDelegate, WKScriptMessageHandler, NSMenuItemValidation {
    var window: NSWindow!
    var webView: WKWebView!
    var page = Page.splash
    var pageReady = false
    var pageQueue: [String] = []
    let setup = SetupState()
    var runtimeTimer: Timer?
    /// When a start began with no progress reports (no python3 for startup_progress.py):
    /// the journey then walks against this Mac's earlier starts, and this one is recorded
    var unreportedStart: Date?
    var orbObservation: NSKeyValueObservation?
    var licenceWindow: NSWindow?
    var updateOffered = false

    static func main() {
        // Rowanholt.app/Contents/MacOS/Rowanholt update [--check], from a terminal
        if CommandLine.arguments.dropFirst().first == "update" {
            exit(Updates.command(check: CommandLine.arguments.contains("--check")))
        }
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }

    var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    /// The source tree a release build carries, unpacked by setup into the user's chosen folder
    var bundledSource: URL? {
        Bundle.main.url(forResource: "rowanholt-src", withExtension: "tar.gz")
    }

    /// The ServerURL IT has enforced with a configuration profile for this app's bundle ID, as text
    var managedServerText: String? {
        let key = "ServerURL" as CFString
        let domain = (Bundle.main.bundleIdentifier ?? "io.github.cmdaltr.rowanholt") as CFString
        guard CFPreferencesAppValueIsForced(key, domain),
              let value = CFPreferencesCopyAppValue(key, domain) as? String else { return nil }
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    /// IT's server: it wins, and setup can't change it
    var managedServer: URL? { managedServerText.flatMap { parseServerAddress($0, allowHTTP: true) } }

    /// The server to open, if any (nothing runs on this Mac then): IT's, then ROWANHOLT_SERVER
    /// (a URL, or "local" to run here whatever setup saved), then the one chosen in setup
    var serverURL: URL? {
        if let managed = managedServer { return managed }
        if let env = ProcessInfo.processInfo.environment["ROWANHOLT_SERVER"]?
            .trimmingCharacters(in: .whitespacesAndNewlines), !env.isEmpty {
            return env == "local" ? nil : parseServerAddress(env, allowHTTP: true)
        }
        return UserDefaults.standard.string(forKey: "RowanholtServer").flatMap(URL.init(string:))
    }

    /// Where the web UI is: the server, or the local stack
    var uiURL: URL { serverURL ?? localURL }

    /// The Rowanholt copy to run: ROWANHOLT_ROOT, then the one chosen in setup, then the
    /// checkout a local build (`rowanholt app install`) was made from
    var root: String? {
        [ProcessInfo.processInfo.environment["ROWANHOLT_ROOT"],
         UserDefaults.standard.string(forKey: "RowanholtRoot"),
         Bundle.main.object(forInfoDictionaryKey: "RowanholtRoot") as? String]
            .compactMap { $0 }
            .first(where: isRowanholtCopy)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "rowanholt")
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1440, height: 900),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Rowanholt"
        window.contentView = webView
        window.center()
        window.setFrameAutosaveName("RowanholtMain")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        launch()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { window.makeKeyAndOrderFront(nil) }
        return true
    }

    // MARK: Starting the stack

    func launch() {
        // A broken IT setting stops here rather than quietly running Rowanholt on this Mac instead
        if let text = managedServerText, managedServer == nil {
            showSplash()
            splashError("The server address your organisation set (\(text)) isn't a web address. Ask IT to correct it.")
            return
        }
        if let server = serverURL {
            connect(to: server)
            return
        }
        guard let root = root else {
            showSetup()
            return
        }
        if needsUpdate(root) {
            askToUpdate(root)
        } else {
            startOrShow()
        }
    }

    func startOrShow() {
        showSplash()
        probe { up in
            if up { self.showUI() } else { self.startStack() }
        }
    }

    func probe(_ done: @escaping (Bool) -> Void) {
        probe(uiURL, timeout: 2) { up, _ in done(up) }
    }

    /// Whether anything answers at `url`, with the error when nothing does
    func probe(_ url: URL, timeout: TimeInterval, _ done: @escaping (Bool, Error?) -> Void) {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "HEAD"
        URLSession.shared.dataTask(with: request) { _, response, error in
            DispatchQueue.main.async { done(response is HTTPURLResponse, error) }
        }.resume()
    }

    func connect(to server: URL) {
        showSplash()
        splashPlain("Connecting to \(server.host ?? server.absoluteString)…")
        probe(server, timeout: 10) { up, error in
            if up {
                self.showUI()
            } else {
                self.splashError(self.connectionProblem(server, error))
            }
        }
    }

    /// What went wrong reaching a server, in terms of what to do about it
    func connectionProblem(_ server: URL, _ error: Error?) -> String {
        let host = server.host ?? server.absoluteString
        let code = (error as NSError?)?.code ?? 0
        let certificate = [NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
                           NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateNotYetValid,
                           NSURLErrorSecureConnectionFailed]
        if certificate.contains(code) {
            return "This Mac doesn't trust \(host)'s certificate. Ask its admin for the root certificate ('rowanholt server ca'), add it to Keychain Access as Always Trust, then try again."
        }
        let detail = error?.localizedDescription ?? "no answer"
        return "Can't reach \(host) (\(detail)). Check the address and your network or VPN; Rowanholt › Set Up Rowanholt… changes the server."
    }

    func startStack() {
        splashStatus("Starting the Docker stack…")
        if let typical = typicalStart() { js("expect", [typical]) }
        unreportedStart = Date()
        runLauncher(["start", "--progress"], output: { line in
            if line.hasPrefix("@@progress ") { self.unreportedStart = nil }
            self.splashLine(line)
        }) { status in
            guard status == 0 else {
                self.splashError("'rowanholt start' exited with status \(status). The output is above.")
                return
            }
            self.splashStatus("Waiting for the web UI on \(localURL.host!):\(localURL.port!)…")
            self.waitForUI(deadline: Date().addingTimeInterval(startTimeout))
        }
    }

    func waitForUI(deadline: Date) {
        probe { up in
            if up {
                if let started = self.unreportedStart {
                    recordStart(seconds: Date().timeIntervalSince(started))
                    self.unreportedStart = nil
                }
                self.showUI()
            } else if Date() > deadline {
                self.splashError("The stack started but nothing answered on \(localURL) after \(Int(startTimeout / 60)) minutes. Try 'rowanholt status'.")
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.waitForUI(deadline: deadline) }
            }
        }
    }

    /// Runs `rowanholt <args>` with a PATH that finds Docker from a GUI launch, passing
    /// each line of output to `output` and the exit status to `completion` (main thread).
    func runLauncher(_ args: [String], output: @escaping (String) -> Void,
                     completion: @escaping (Int32) -> Void) {
        guard let root = root else {
            showSetup()
            return
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["\(root)/rowanholt"] + args
        process.currentDirectoryURL = URL(fileURLWithPath: root)
        process.environment = processEnvironment()

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                text.split(whereSeparator: \.isNewline).forEach { output(String($0)) }
            }
        }
        process.terminationHandler = { p in
            pipe.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async { completion(p.terminationStatus) }
        }
        do {
            try process.run()
        } catch {
            output("Couldn't run \(root)/rowanholt: \(error.localizedDescription)")
            completion(-1)
        }
    }

    // MARK: Pages: splash, setup, the UI

    func show(_ newPage: Page) {
        page = newPage
        pageReady = false
        pageQueue = []
        if newPage != .setup {
            runtimeTimer?.invalidate()
            runtimeTimer = nil
        }
    }

    /// The journey page: Gandalf on the road to Rowanholt while the stack starts
    /// (journey.html), or plain words for stopping and connecting
    func showSplash() {
        show(.splash)
        let page = Bundle.main.url(forResource: "journey", withExtension: "html")!
        webView.loadFileURL(page, allowingReadAccessTo: Bundle.main.resourceURL!)
    }

    /// Calls a function on the splash or setup page, holding calls until the page has loaded.
    func js(_ function: String, _ args: [Any]) {
        guard page != .ui, let data = try? JSONSerialization.data(withJSONObject: args),
              let json = String(data: data, encoding: .utf8) else { return }
        let call = "\(function)(...\(json))"
        if pageReady { webView.evaluateJavaScript(call) } else { pageQueue.append(call) }
    }

    /// A line of launcher output: a progress report for the journey, or one for the log
    func splashLine(_ text: String) {
        let marker = "@@progress "
        if text.hasPrefix(marker), let data = text.dropFirst(marker.count).data(using: .utf8),
           let report = try? JSONSerialization.jsonObject(with: data) {
            js("progress", [report])
        } else {
            js("line", [text])
        }
    }
    func splashPlain(_ text: String) { js("plain", [text]) }
    func splashStatus(_ text: String) { js("status", [text, false]) }
    func splashError(_ text: String) { js("status", [text, true]) }

    func showUI() {
        show(.ui)
        window.title = serverURL.map { "Rowanholt — \($0.host ?? "")" } ?? "Rowanholt"
        webView.load(URLRequest(url: uiURL))
        dailyUpdateCheck()
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.body as? String == "retry" {
            launch()
        } else if page == .setup, let body = message.body as? [String: Any] {
            setupMessage(body)
        }
    }

    // MARK: Menu actions

    // The bundled LICENSE, read-only: works offline and before the stack is up, unlike the web UI's
    @objc func showLicence(_ sender: Any?) {
        if let shown = licenceWindow {
            shown.makeKeyAndOrderFront(nil)
            return
        }
        let text = Bundle.main.url(forResource: "LICENSE", withExtension: nil)
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
            ?? "The licence file is missing from this copy of the app. Rowanholt is under the Elastic License 2.0: https://github.com/cmdaltr/rowanholt/blob/main/LICENSE"
        let commercial = "https://github.com/cmdaltr/rowanholt/blob/main/COMMERCIAL-LICENSE.md"
        let licence = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 600),
                               styleMask: [.titled, .closable, .resizable, .miniaturizable],
                               backing: .buffered, defer: false)
        licence.title = "Rowanholt Licence"
        licence.isReleasedWhenClosed = false

        let note = NSTextField(labelWithAttributedString: {
            let line = NSMutableAttributedString(string: "Rowanholt is under the Elastic License 2.0, below. The Pro and Services editions add the Rowanholt Commercial Licence: ")
            line.append(NSAttributedString(string: "COMMERCIAL-LICENSE.md", attributes: [.link: URL(string: commercial)!]))
            line.append(NSAttributedString(string: "."))
            return line
        }())
        note.allowsEditingTextAttributes = true  // makes the link clickable
        note.isSelectable = true
        note.lineBreakMode = .byWordWrapping
        note.maximumNumberOfLines = 0
        note.translatesAutoresizingMaskIntoConstraints = false

        let scroll = NSTextView.scrollableTextView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        if let body = scroll.documentView as? NSTextView {
            body.isEditable = false
            body.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            body.string = text
            body.textContainerInset = NSSize(width: 8, height: 8)
        }

        let content = NSView()
        content.addSubview(note)
        content.addSubview(scroll)
        NSLayoutConstraint.activate([
            note.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            note.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            note.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            scroll.topAnchor.constraint(equalTo: note.bottomAnchor, constant: 10),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: content.bottomAnchor),
        ])
        licence.contentView = content
        licence.center()
        licence.makeKeyAndOrderFront(nil)
        licenceWindow = licence
    }

    @objc func openInBrowser(_ sender: Any?) {
        NSWorkspace.shared.open(page == .ui ? webView.url ?? uiURL : uiURL)
    }

    @objc func stopStack(_ sender: Any?) {
        stopThen { self.js("status", ["Rowanholt is stopped. Rowanholt › Start Rowanholt (⇧⌘S) brings it back.", false]) }
    }

    @objc func stopAndQuit(_ sender: Any?) {
        stopThen { NSApp.terminate(nil) }
    }

    /// Starting and stopping is for the stack on this Mac; a server's admins do that
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(stopStack(_:)), #selector(stopAndQuit(_:)):
            return serverURL == nil && root != nil
        case #selector(startStackMenu(_:)):
            return serverURL == nil
        case #selector(setupMenu(_:)):
            return managedServer == nil  // IT chose the server
        case #selector(checkForUpdates(_:)):
            return isRelease
        default:
            return true
        }
    }

    @objc func startStackMenu(_ sender: Any?) { launch() }

    @objc func setupMenu(_ sender: Any?) { showSetup() }

    @objc func reload(_ sender: Any?) {
        switch page {
        case .ui: webView.reload()
        case .setup: showSetup()
        case .splash: launch()
        }
    }

    func stopThen(_ next: @escaping () -> Void) {
        guard root != nil else {
            next()
            return
        }
        showSplash()
        splashPlain("Stopping the Docker stack…")
        runLauncher(["stop"], output: splashLine) { _ in next() }
    }

    func buildMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About Rowanholt", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(withTitle: "Set Up Rowanholt…", action: #selector(setupMenu(_:)), keyEquivalent: ",")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Rowanholt", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let others = appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        others.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(.separator())
        let stopQuit = appMenu.addItem(withTitle: "Stop Rowanholt and Quit", action: #selector(stopAndQuit(_:)), keyEquivalent: "q")
        stopQuit.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Quit Rowanholt", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)

        // Without an Edit menu, copy and paste don't reach the web view
        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        main.addItem(editItem)

        let viewItem = NSMenuItem()
        let viewMenu = NSMenu(title: "View")
        viewMenu.addItem(withTitle: "Reload", action: #selector(reload(_:)), keyEquivalent: "r")
        viewMenu.addItem(withTitle: "Back", action: #selector(WKWebView.goBack(_:)), keyEquivalent: "[")
        viewMenu.addItem(withTitle: "Forward", action: #selector(WKWebView.goForward(_:)), keyEquivalent: "]")
        viewMenu.addItem(.separator())
        let fullScreen = viewMenu.addItem(withTitle: "Enter Full Screen", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        fullScreen.keyEquivalentModifierMask = [.command, .control]
        viewItem.submenu = viewMenu
        main.addItem(viewItem)

        let stackItem = NSMenuItem()
        let stackMenu = NSMenu(title: "Rowanholt")
        stackMenu.addItem(withTitle: "Open in Browser", action: #selector(openInBrowser(_:)), keyEquivalent: "o")
        stackMenu.addItem(.separator())
        stackMenu.addItem(withTitle: "Start Rowanholt", action: #selector(startStackMenu(_:)), keyEquivalent: "S")
        stackMenu.addItem(withTitle: "Stop Rowanholt", action: #selector(stopStack(_:)), keyEquivalent: "")
        stackItem.submenu = stackMenu
        main.addItem(stackItem)

        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimise", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowItem.submenu = windowMenu
        main.addItem(windowItem)
        NSApp.windowsMenu = windowMenu

        let helpItem = NSMenuItem()
        let helpMenu = NSMenu(title: "Help")
        helpMenu.addItem(withTitle: "Check for Updates…", action: #selector(checkForUpdates(_:)), keyEquivalent: "")
        helpMenu.addItem(withTitle: "Licence", action: #selector(showLicence(_:)), keyEquivalent: "")
        helpItem.submenu = helpMenu
        main.addItem(helpItem)
        NSApp.helpMenu = helpMenu

        NSApp.mainMenu = main
    }

    // MARK: Updates

    /// A release build (it carries the source tree): a checkout's build updates with git
    var isRelease: Bool { bundledSource != nil }

    /// Once a day, once the UI is up: a newer release offered as a sheet, never while setting up
    func dailyUpdateCheck() {
        guard isRelease, !updateOffered, Updates.checksEnabled else { return }
        updateOffered = true
        DispatchQueue.global(qos: .utility).async {
            let latest = Updates.daily(current: self.appVersion)
            DispatchQueue.main.async {
                if let latest = latest, self.page == .ui { self.offerUpdate(latest) }
            }
        }
    }

    func offerUpdate(_ latest: Updates.Release) {
        let alert = NSAlert()
        alert.messageText = "Rowanholt \(latest.version) is available"
        alert.informativeText = "You have \(appVersion). Update downloads it, checks it against the release's SHA256SUMS, closes Rowanholt, installs it and reopens it. The stack keeps running."
        alert.addButton(withTitle: "Update")
        alert.addButton(withTitle: "Later")
        alert.addButton(withTitle: "Skip This Version")
        alert.beginSheetModal(for: window) { answer in
            switch answer {
            case .alertFirstButtonReturn: self.installUpdate(latest)
            case .alertThirdButtonReturn: Updates.skip(latest.version)
            default: break  // Later: until the next launch
            }
        }
    }

    /// The install script the app carries, run once this app has quit (it replaces the app)
    func installUpdate(_ latest: Updates.Release) {
        guard let script = Bundle.main.url(forResource: "install", withExtension: "sh") else {
            splashError("This copy of Rowanholt doesn't carry its installer: download the new version from GitHub.")
            return
        }
        let logs = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Rowanholt")
        try? FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        let log = logs.appendingPathComponent("update.log").path
        let pid = ProcessInfo.processInfo.processIdentifier
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "while kill -0 \(pid) 2>/dev/null; do sleep 1; done; "
                             + "sh \"$0\" --version \"$1\" --launch > \"$2\" 2>&1",
                             script.path, latest.tag, log]
        do {
            try process.run()
            NSApp.terminate(nil)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    @objc func checkForUpdates(_ sender: Any?) {
        let alert = NSAlert()
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = "Check for updates once a day"
        alert.suppressionButton?.state = Updates.checksEnabled ? .on : .off
        var latest: Updates.Release?
        switch Updates.latest() {
        case .success(let release) where Updates.isNewer(release.version, than: appVersion):
            latest = release
            alert.messageText = "Rowanholt \(release.version) is available"
            alert.informativeText = "You have \(appVersion)."
            alert.addButton(withTitle: "Update")
            alert.addButton(withTitle: "Later")
        case .success:
            alert.messageText = "Rowanholt \(appVersion) is the latest"
            alert.addButton(withTitle: "OK")
        case .failure(let error):
            alert.messageText = "Couldn't check for updates"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "OK")
        }
        let answer = alert.runModal()
        Updates.setChecks(alert.suppressionButton?.state == .on)
        if let latest = latest, answer == .alertFirstButtonReturn { installUpdate(latest) }
    }

    // MARK: Navigation, downloads, pop-ups

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.shouldPerformDownload {
            decisionHandler(.download)
            return
        }
        // Links off the frontend (Splunk, Kibana, ATT&CK, GitHub) go to the default browser
        if let url = action.request.url, action.navigationType == .linkActivated,
           url.host != uiURL.host || url.port != uiURL.port {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        let disposition = (response.response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Disposition") ?? ""
        decisionHandler(!response.canShowMIMEType || disposition.lowercased().hasPrefix("attachment") ? .download : .allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let base = (suggestedFilename as NSString).deletingPathExtension
        let ext = (suggestedFilename as NSString).pathExtension
        var target = downloads.appendingPathComponent(suggestedFilename)
        var n = 1
        while FileManager.default.fileExists(atPath: target.path) {
            target = downloads.appendingPathComponent(ext.isEmpty ? "\(base) (\(n))" : "\(base) (\(n)).\(ext)")
            n += 1
        }
        completionHandler(target)
    }

    func downloadDidFinish(_ download: WKDownload) {
        NSApp.requestUserAttention(.informationalRequest)
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        // target="_blank": the frontend's own pages stay in the window, anything else opens in the browser
        if let url = action.request.url {
            if url.host == uiURL.host && url.port == uiURL.port {
                webView.load(action.request)
            } else {
                NSWorkspace.shared.open(url)
            }
        }
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn) }
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        let alert = NSAlert()
        alert.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        field.stringValue = defaultText ?? ""
        alert.accessoryView = field
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn ? field.stringValue : nil) }
    }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.beginSheetModal(for: window) { completionHandler($0 == .OK ? panel.urls : nil) }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard page != .ui else { return }
        pageReady = true
        pageQueue.forEach { webView.evaluateJavaScript($0) }
        pageQueue = []
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        lostUI(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        lostUI(error)
    }

    func lostUI(_ error: Error) {
        // The stack went away under us (stopped elsewhere, Docker quit): back to the splash
        guard page == .ui, (error as NSError).domain == NSURLErrorDomain else { return }
        showSplash()
        if let server = serverURL {
            splashError(connectionProblem(server, error))
        } else {
            splashError("Lost the web UI: \(error.localizedDescription)")
        }
    }
}

// MARK: Start-up history (startup_progress.py keeps the same file)

let startHistory: URL = {
    let env = ProcessInfo.processInfo.environment
    let base = env["XDG_STATE_HOME"].map { URL(fileURLWithPath: $0) }
        ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/state")
    return base.appendingPathComponent("rowanholt/start-history.jsonl")
}()

/// The median of this Mac's last 20 local starts, in seconds: startup_progress.py's
/// (warm, cold) and the app's own when it had no progress reports (app)
func typicalStart() -> Double? {
    guard let text = try? String(contentsOf: startHistory, encoding: .utf8) else { return nil }
    let totals = text.split(whereSeparator: \.isNewline).compactMap { line -> Double? in
        guard let data = line.data(using: .utf8),
              let record = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let kind = record["kind"] as? String, ["warm", "cold", "app"].contains(kind) else { return nil }
        return (record["total"] as? NSNumber)?.doubleValue
    }.suffix(20).sorted()
    guard !totals.isEmpty else { return nil }
    let mid = totals.count / 2
    return totals.count % 2 == 1 ? totals[mid] : (totals[mid - 1] + totals[mid]) / 2
}

/// Appends a start the app timed itself; startup_progress.py ignores kind "app"
func recordStart(seconds: Double) {
    let record: [String: Any] = ["kind": "app", "at": Int(Date().timeIntervalSince1970),
                                 "total": (seconds * 10).rounded() / 10]
    guard let data = try? JSONSerialization.data(withJSONObject: record),
          let line = String(data: data, encoding: .utf8).map({ $0 + "\n" }) else { return }
    try? FileManager.default.createDirectory(at: startHistory.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    if let handle = try? FileHandle(forWritingTo: startHistory) {
        handle.seekToEndOfFile()
        handle.write(Data(line.utf8))
        handle.closeFile()
    } else {
        try? line.write(to: startHistory, atomically: true, encoding: .utf8)
    }
}

/// GitHub's latest published release of Rowanholt, asked at most once a day (drafts and
/// prereleases are never "latest"). Nothing but the request is sent; the repository is public,
/// so a token (GH_TOKEN, GITHUB_TOKEN) only lifts the rate limit. Off with
/// ROWANHOLT_UPDATE_CHECK=0 or Help > Check for Updates' switch
enum Updates {
    struct Release { let tag: String; let version: String; let url: String }

    static let repo = "cmdaltr/rowanholt"
    static let defaults = UserDefaults.standard

    /// "v2.1.0" as [2, 1, 0]; anything after the numbers (-dev.4, -rc1) is ignored, as Shikari does
    static func parts(_ text: String) -> [Int] {
        var t = Substring(text.trimmingCharacters(in: .whitespaces))
        if t.hasPrefix("v") { t = t.dropFirst() }
        let numeric = t.prefix { $0.isNumber || $0 == "." }
        return numeric.split(separator: ".").compactMap { Int($0) }
    }

    static func isNewer(_ latest: String, than current: String) -> Bool {
        let a = parts(latest), b = parts(current)
        guard !a.isEmpty else { return false }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    static var checksEnabled: Bool {
        let env = ProcessInfo.processInfo.environment["ROWANHOLT_UPDATE_CHECK"]?.lowercased() ?? ""
        if ["0", "false", "no", "off"].contains(env) { return false }
        return defaults.object(forKey: "RowanholtUpdateCheck") as? Bool ?? true
    }

    static func setChecks(_ on: Bool) { defaults.set(on, forKey: "RowanholtUpdateCheck") }

    static func skip(_ version: String) { defaults.set(version, forKey: "RowanholtUpdateSkipped") }

    static func latest(timeout: TimeInterval = 10) -> Result<Release, Error> {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/\(repo)/releases/latest")!,
                                 timeoutInterval: timeout)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("rowanholt-update", forHTTPHeaderField: "User-Agent")
        let env = ProcessInfo.processInfo.environment
        if let token = env["GH_TOKEN"] ?? env["GITHUB_TOKEN"], !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        var result: Result<Release, Error> = .failure(SetupError(message: "GitHub didn't answer"))
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { done.signal() }
            if let error = error { result = .failure(error); return }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard status == 200, let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tag = json["tag_name"] as? String else {
                result = .failure(SetupError(message: status == 404 ? "No release of \(repo) is published yet."
                                                                   : "GitHub answered HTTP \(status)."))
                return
            }
            result = .success(Release(tag: tag, version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag,
                                      url: json["html_url"] as? String ?? ""))
        }.resume()
        done.wait()
        return result
    }

    /// The newer release, or nil; asks GitHub at most once a day, and a failed check is just nil
    static func daily(current: String, now: Date = Date()) -> Release? {
        let checked = defaults.double(forKey: "RowanholtUpdateCheckedAt")
        if checked == 0 || now.timeIntervalSince1970 - checked >= 86_400 {
            if case .success(let release) = latest() {
                defaults.set(["tag": release.tag, "version": release.version, "url": release.url],
                             forKey: "RowanholtUpdateLatest")
            } else {
                defaults.removeObject(forKey: "RowanholtUpdateLatest")
            }
            defaults.set(now.timeIntervalSince1970, forKey: "RowanholtUpdateCheckedAt")
        }
        guard let saved = defaults.dictionary(forKey: "RowanholtUpdateLatest") as? [String: String],
              let tag = saved["tag"], let version = saved["version"],
              isNewer(version, than: current),
              version != defaults.string(forKey: "RowanholtUpdateSkipped") else { return nil }
        return Release(tag: tag, version: version, url: saved["url"] ?? "")
    }

    /// `update` from a terminal: say whether there's a newer release, and install it unless --check
    static func command(check: Bool) -> Int32 {
        let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        switch latest() {
        case .failure(let error):
            FileHandle.standardError.write("Couldn't check for updates: \(error.localizedDescription)\n".data(using: .utf8)!)
            return 1
        case .success(let release) where !isNewer(release.version, than: current):
            print("Rowanholt \(current) is the latest.")
            return 0
        case .success(let release):
            print("Rowanholt \(release.version) is available (you have \(current)): \(release.url)")
            if check { return 0 }
            guard let script = Bundle.main.path(forResource: "install", ofType: "sh") else {
                FileHandle.standardError.write("This copy doesn't carry desktop/install.sh.\n".data(using: .utf8)!)
                return 1
            }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = [script, "--version", release.tag]
            do { try process.run() } catch { return 1 }
            process.waitUntilExit()
            return process.terminationStatus
        }
    }
}
