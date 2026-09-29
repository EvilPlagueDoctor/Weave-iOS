import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        case account
        case starting
        case ready
        case failed(String)
    }

    enum Section: Hashable {
        case home, search, people, me, groups, curator
    }

    @Published var phase: Phase = .account
    @Published var startupStatus = "Preparing VeilKnit…"
    @Published var profile = ProfileDocument.starter()
    @Published var selectedSection: Section = .home
    @Published var diagnostics: [String] = []
    @Published var profileDirty = false
    @Published var saveState = "Unpublished"
    @Published var advancedEditor = UserDefaults.standard.bool(forKey: "weave.profile.advancedEditor") {
        didSet { UserDefaults.standard.set(advancedEditor, forKey: "weave.profile.advancedEditor") }
    }
    @Published var widgetsEnabled = UserDefaults.standard.object(forKey: "weave.widgets.enabled") as? Bool ?? true {
        didSet { UserDefaults.standard.set(widgetsEnabled, forKey: "weave.widgets.enabled") }
    }
    @Published var imageFilteringEnabled = UserDefaults.standard.object(forKey: "weave.filter.images") as? Bool ?? true {
        didSet { UserDefaults.standard.set(imageFilteringEnabled, forKey: "weave.filter.images") }
    }
    @Published var externalLinkWarnings = UserDefaults.standard.object(forKey: "weave.links.warn") as? Bool ?? true {
        didSet { UserDefaults.standard.set(externalLinkWarnings, forKey: "weave.links.warn") }
    }

    let localizer = Localizer()
    let daemonClient = DaemonClient()
    private(set) var vault: PrivateVault?

    private let profileNamespace = "profiles"
    private let profileName = "active.txt"
    private var logTask: Task<Void, Never>?


    func start(signup: Bool, username: String, password: String) {
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty, !password.isEmpty else {
            phase = .failed("Enter your VeilKnit username and password.")
            return
        }
        do {
            let dataDirectory = try daemonDirectory()
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
            startupStatus = signup ? "Creating your VeilKnit account…" : "Signing in to VeilKnit…"
            phase = .starting
            diagnostics.removeAll(keepingCapacity: true)
            guard NativeDaemonBridge.start(dataDirectory: dataDirectory, signup: signup, username: user, password: password) else {
                phase = .failed("The embedded VeilKnit core could not be started.")
                return
            }
            beginLogPump()
            Task {
                do {
                    try await daemonClient.connect { [weak self] text in
                        Task { @MainActor in self?.startupStatus = text }
                    }
                    let newVault = PrivateVault(client: daemonClient)
                    vault = newVault
                    try await loadProfile(from: newVault)
                    startupStatus = "Weave is ready."
                    phase = .ready
                } catch {
                    phase = .failed(error.localizedDescription)
                }
            }
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    func retryAccountScreen() {
        Task { await daemonClient.disconnect() }
        NativeDaemonBridge.requestStop()
        phase = .account
    }

    func stopSafely() {
        saveProfile()
        NativeDaemonBridge.requestStop()
        Task { await daemonClient.disconnect() }
        vault = nil
        phase = .account
    }

    func saveProfile() {
        guard let vault else { return }
        let snapshot = profile
        Task {
            do {
                let text = try ProfileCodec.encodeText(snapshot)
                try await vault.putNamedBlob(
                    namespace: profileNamespace,
                    name: profileName,
                    contentType: "application/x-weave-vspf-text;version=4",
                    data: Data(text.utf8)
                )
                await MainActor.run {
                    self.profileDirty = false
                    self.diagnostics.append("Saved local VSPF v4 profile to VeilKnit private storage.")
                }
            } catch {
                await MainActor.run { self.diagnostics.append("Profile save failed: \(error.localizedDescription)") }
            }
        }
    }

    func updateProfile(_ transform: (inout ProfileDocument) -> Void) {
        transform(&profile)
        profileDirty = true
    }

    func publishProfile() {
        // The wire-level publishing controller is intentionally isolated behind one call-site.
        // Local VSPF persistence is complete; the Android SocialNetworkController record writer is
        // the remaining Groups/Profile network-runtime parity item documented in PORT_STATUS.md.
        saveProfile()
        saveState = "Publish pending"
        diagnostics.append("Publish requested. VSPF saved; network profile-record writer still needs its iOS parity pass.")
    }

    func unpublishProfile() {
        saveState = "Unpublished"
        diagnostics.append("Profile marked unpublished locally.")
    }

    func exportProfile(to url: URL) throws {
        try ProfileCodec.save(profile, to: url)
    }

    func importProfile(from url: URL) throws {
        let imported = try ProfileCodec.load(from: url)
        let validation = ProfileCodec.validate(imported)
        guard validation.ok else { throw ImportError.invalid(validation.message) }
        profile = imported
        profileDirty = true
        saveProfile()
    }

    func restoreAccountBackup(from backup: URL, passphrase: String) throws -> String {
        let directory = try daemonDirectory()
        return NativeDaemonBridge.restoreBackup(dataDirectory: directory, backup: backup, passphrase: passphrase)
    }

    private func loadProfile(from vault: PrivateVault) async throws {
        if let bytes = try await vault.getNamedBlob(namespace: profileNamespace, name: profileName, maxBytes: 8 * 1024 * 1024),
           let text = String(data: bytes, encoding: .utf8) {
            let decoded = try ProfileCodec.decodeText(text)
            await MainActor.run {
                self.profile = decoded
                self.profileDirty = false
            }
        } else {
            let starter = ProfileDocument.starter()
            let text = try ProfileCodec.encodeText(starter)
            try await vault.putNamedBlob(
                namespace: profileNamespace,
                name: profileName,
                contentType: "application/x-weave-vspf-text;version=4",
                data: Data(text.utf8)
            )
            await MainActor.run {
                self.profile = starter
                self.profileDirty = false
            }
        }
    }

    private func beginLogPump() {
        logTask?.cancel()
        logTask = Task { [weak self] in
            while !Task.isCancelled {
                let lines = NativeDaemonBridge.drainLogs()
                if !lines.isEmpty {
                    self?.diagnostics.append(contentsOf: lines)
                    if let latest = lines.last, self?.phase == .starting {
                        self?.startupStatus = DaemonClient.friendlyStatus(from: latest)
                    }
                    if let self, self.diagnostics.count > 1200 {
                        self.diagnostics.removeFirst(self.diagnostics.count - 1200)
                    }
                }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
    }

    private func daemonDirectory() throws -> URL {
        let root = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return root.appendingPathComponent("VeilKnit", isDirectory: true)
    }

    enum ImportError: LocalizedError {
        case invalid(String)
        var errorDescription: String? {
            switch self { case .invalid(let reason): return "Invalid VSPF profile: \(reason)" }
        }
    }
}
