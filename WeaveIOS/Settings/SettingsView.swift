import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var strings: Localizer
    @State private var showDiagnostics = false

    var body: some View {
        Form {
            Section("Profile") {
                Toggle("Advanced editor", isOn: $model.advancedEditor)
                LabeledContent("Publishing", value: model.saveState)
                Button("Unpublish") { model.unpublishProfile() }
            }
            Section("Widgets") {
                Toggle("Allow widgets to load", isOn: $model.widgetsEnabled)
                Text("Widgets remain click-to-load. The Kotlin widget VM and full Chess template are retained as Android reference sources; the iOS VM execution pass is still pending.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Local content safety") {
                Toggle("Filter images locally", isOn: $model.imageFilteringEnabled)
                Text("This toggle is wired into the iOS UI/settings. The Android ONNX classifier still needs a Core ML or ONNX Runtime iOS adapter before filtering has Android parity.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Warn before external links", isOn: $model.externalLinkWarnings)
            }
            Section("Language") {
                Picker("Interface language", selection: $strings.language) {
                    ForEach(AppLanguage.allCases) { language in Text(language.label).tag(language) }
                }
            }
            Section("This identity") {
                Button("Save local profile now") { model.saveProfile() }
                Button("Stop safely", role: .destructive) { model.stopSafely() }
                Text("iOS may suspend or terminate an app in the background, so the embedded VeilKnit core runs with Weave while the process is active rather than pretending to be an Android-style permanent foreground service.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Diagnostics") {
                NavigationLink("VeilKnit log") { DiagnosticsView() }
                LabeledContent("Protocol", value: "v\(DaemonClient.protocolVersion)")
                LabeledContent("Profile format", value: "VSPF v\(VSPFLimits.formatVersion)")
            }
        }
        .navigationTitle("Settings")
    }
}

struct DiagnosticsView: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        ScrollView {
            Text(model.diagnostics.joined(separator: "\n"))
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .navigationTitle("VeilKnit log")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                ShareLink(item: model.diagnostics.joined(separator: "\n")) { Image(systemName: "square.and.arrow.up") }
            }
        }
    }
}
