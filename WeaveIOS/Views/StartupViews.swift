import SwiftUI
import UniformTypeIdentifiers
import Combine

struct VeilKnitAccountView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var strings: Localizer
    @State private var username = ""
    @State private var password = ""
    @State private var createAccount = false
    @State private var showingRestore = false
    @State private var restorePassphrase = ""
    @State private var restoreResult = ""
    @State private var selectedBackup: URL?
    @State private var pickingBackup = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    Image("WeaveLogo")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 112, height: 112)
                        .clipShape(RoundedRectangle(cornerRadius: 24))
                        .shadow(radius: 5)

                    VStack(spacing: 6) {
                        Text("Weave")
                            .font(.system(size: 38, weight: .bold, design: .rounded))
                        Text(createAccount ? "Create a VeilKnit account to start Weave." : "Sign in to the VeilKnit account used by Weave.")
                            .multilineTextAlignment(.center)
                            .foregroundStyle(.secondary)
                    }

                    Picker("Account action", selection: $createAccount) {
                        Text("Sign in").tag(false)
                        Text("Create account").tag(true)
                    }
                    .pickerStyle(.segmented)

                    VStack(spacing: 12) {
                        TextField("Username", text: $username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .textContentType(.username)
                            .weaveField()
                        SecureField("Password", text: $password)
                            .textContentType(createAccount ? .newPassword : .password)
                            .weaveField()
                    }

                    Button(createAccount ? "Create account and start Weave" : "Sign in and start Weave") {
                        model.start(signup: createAccount, username: username, password: password)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(username.trimmingCharacters(in: .whitespaces).isEmpty || password.isEmpty)

                    Divider()

                    DisclosureGroup("Restore an account backup", isExpanded: $showingRestore) {
                        VStack(alignment: .leading, spacing: 12) {
                            Button(selectedBackup?.lastPathComponent ?? "Choose backup file…") { pickingBackup = true }
                                .buttonStyle(.bordered)
                            SecureField("Backup passphrase", text: $restorePassphrase)
                                .weaveField()
                            Button("Restore backup") {
                                guard let selectedBackup else { return }
                                do { restoreResult = try model.restoreAccountBackup(from: selectedBackup, passphrase: restorePassphrase) }
                                catch { restoreResult = error.localizedDescription }
                            }
                            .disabled(selectedBackup == nil || restorePassphrase.isEmpty)
                            if !restoreResult.isEmpty {
                                Text(restoreResult).font(.caption).textSelection(.enabled)
                            }
                        }
                        .padding(.top, 12)
                    }
                }
                .padding(28)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .navigationTitle("Set up your profile")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        ForEach(AppLanguage.allCases) { language in
                            Button(language.label) { strings.language = language }
                        }
                    } label: {
                        Label(strings.language.label, systemImage: "globe")
                    }
                }
            }
            .fileImporter(isPresented: $pickingBackup, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                guard let source = try? result.get().first else { return }
                let access = source.startAccessingSecurityScopedResource()
                defer { if access { source.stopAccessingSecurityScopedResource() } }
                let local = FileManager.default.temporaryDirectory.appendingPathComponent("veilknit-restore-\(UUID().uuidString).backup")
                do {
                    try? FileManager.default.removeItem(at: local)
                    try FileManager.default.copyItem(at: source, to: local)
                    selectedBackup = local
                } catch { restoreResult = error.localizedDescription }
            }
        }
    }
}

struct StartupLoadingView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tipIndex = StartupTips.next(excluding: nil)
    private let timer = Timer.publish(every: 4, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 26) {
            ProgressView()
                .controlSize(.large)
                .tint(.red)
            Text("Weave")
                .font(.largeTitle.bold())
            Text(StartupTips.all[tipIndex])
                .font(.title3)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
                .transition(.opacity)
                .id(tipIndex)
            Text(model.startupStatus)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
        }
        .padding(32)
        .onReceive(timer) { _ in
            withAnimation(.easeInOut(duration: 0.25)) {
                tipIndex = StartupTips.next(excluding: tipIndex)
            }
        }
    }
}

private extension View {
    func weaveField() -> some View {
        self
            .padding(12)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
    }
}
