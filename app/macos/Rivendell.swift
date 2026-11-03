// Rivendell.app: shows Rivendell's web UI in its own window. Either it runs Rivendell
// here, starting the Docker stack through the launcher when the UI isn't answering, or
// it connects to a team's Rivendell server. Setup.swift handles the first run (where
// Rivendell runs, the container runtime, evidence folders) and updates.
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

    static func main() {
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
        Bundle.main.url(forResource: "rivendell-src", withExtension: "tar.gz")
    }

    /// The team server chosen in setup; when set, nothing runs on this Mac
    var serverURL: URL? {
        UserDefaults.standard.string(forKey: "RivendellServer").flatMap(URL.init(string:))
    }

    /// Where the web UI is: the server, or the local stack
    var uiURL: URL { serverURL ?? localURL }

    /// The Rivendell copy to run: RIVENDELL_ROOT, then the one chosen in setup, then the
    /// checkout a local build (`rivendell app install`) was made from
    var root: String? {
        [ProcessInfo.processInfo.environment["RIVENDELL_ROOT"],
         UserDefaults.standard.string(forKey: "RivendellRoot"),
         Bundle.main.object(forInfoDictionaryKey: "RivendellRoot") as? String]
            .compactMap { $0 }
            .first(where: isRivendellCopy)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "rivendell")
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1440, height: 900),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Rivendell"
        window.contentView = webView
        window.center()
        window.setFrameAutosaveName("RivendellMain")
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
            return "This Mac doesn't trust \(host)'s certificate. Ask its admin for the root certificate ('rivendell server ca'), add it to Keychain Access as Always Trust, then try again."
        }
        let detail = error?.localizedDescription ?? "no answer"
        return "Can't reach \(host) (\(detail)). Check the address and your network or VPN; Rivendell › Set Up Rivendell… changes the server."
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
                self.splashError("'rivendell start' exited with status \(status). The output is above.")
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
                self.splashError("The stack started but nothing answered on \(localURL) after \(Int(startTimeout / 60)) minutes. Try 'rivendell status'.")
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.waitForUI(deadline: deadline) }
            }
        }
    }

    /// Runs `rivendell <args>` with a PATH that finds Docker from a GUI launch, passing
    /// each line of output to `output` and the exit status to `completion` (main thread).
    func runLauncher(_ args: [String], output: @escaping (String) -> Void,
                     completion: @escaping (Int32) -> Void) {
        guard let root = root else {
            showSetup()
            return
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["\(root)/rivendell"] + args
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
            output("Couldn't run \(root)/rivendell: \(error.localizedDescription)")
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

    /// The journey page: Gandalf on the road to Rivendell while the stack starts
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
        window.title = serverURL.map { "Rivendell — \($0.host ?? "")" } ?? "Rivendell"
        webView.load(URLRequest(url: uiURL))
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.body as? String == "retry" {
            launch()
        } else if page == .setup, let body = message.body as? [String: Any] {
            setupMessage(body)
        }
    }

    // MARK: Menu actions

    @objc func openInBrowser(_ sender: Any?) {
        NSWorkspace.shared.open(page == .ui ? webView.url ?? uiURL : uiURL)
    }

    @objc func stopStack(_ sender: Any?) {
        stopThen { self.js("status", ["Rivendell is stopped. Rivendell › Start Rivendell (⇧⌘S) brings it back.", false]) }
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
        appMenu.addItem(withTitle: "About Rivendell", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(withTitle: "Set Up Rivendell…", action: #selector(setupMenu(_:)), keyEquivalent: ",")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Rivendell", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let others = appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        others.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(.separator())
        let stopQuit = appMenu.addItem(withTitle: "Stop Rivendell and Quit", action: #selector(stopAndQuit(_:)), keyEquivalent: "q")
        stopQuit.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Quit Rivendell", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
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
        let stackMenu = NSMenu(title: "Rivendell")
        stackMenu.addItem(withTitle: "Open in Browser", action: #selector(openInBrowser(_:)), keyEquivalent: "o")
        stackMenu.addItem(.separator())
        stackMenu.addItem(withTitle: "Start Rivendell", action: #selector(startStackMenu(_:)), keyEquivalent: "S")
        stackMenu.addItem(withTitle: "Stop Rivendell", action: #selector(stopStack(_:)), keyEquivalent: "")
        stackItem.submenu = stackMenu
        main.addItem(stackItem)

        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimise", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowItem.submenu = windowMenu
        main.addItem(windowItem)
        NSApp.windowsMenu = windowMenu

        NSApp.mainMenu = main
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
    return base.appendingPathComponent("rivendell/start-history.jsonl")
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
