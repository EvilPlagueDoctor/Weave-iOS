import SwiftUI
import UniformTypeIdentifiers

struct MeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showEditor = false
    @State private var importing = false
    @State private var exportDocument: VSPFFileDocument?
    @State private var exporting = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(model.profile.profileName).font(.title2.bold())
                            Text(model.saveState).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(model.advancedEditor ? "Advanced" : "Basic") {
                            model.advancedEditor.toggle()
                        }.buttonStyle(.bordered)
                    }
                    if let page = model.profile.pages.first {
                        ProfileRendererView(page: page)
                            .frame(height: 480)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .overlay(RoundedRectangle(cornerRadius: 18).stroke(.red.opacity(0.25)))
                    }
                    HStack {
                        Button("Edit profile") { showEditor = true }.buttonStyle(.borderedProminent)
                        Button("Publish") { model.publishProfile() }.buttonStyle(.bordered)
                        Menu {
                            Button("Import VSPF…") { importing = true }
                            Button("Export VSPF…") {
                                if let text = try? ProfileCodec.encodeText(model.profile) {
                                    exportDocument = VSPFFileDocument(text: text)
                                    exporting = true
                                }
                            }
                        } label: { Image(systemName: "ellipsis.circle") }
                    }
                }.padding()
            }
            .navigationTitle("Me")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { NavigationLink(destination: SettingsView()) { Image(systemName: "gearshape") } }
            }
            .sheet(isPresented: $showEditor) {
                if model.advancedEditor { AdvancedProfileEditorView() } else { BasicProfileEditorView() }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .data], allowsMultipleSelection: false) { result in
                guard let url = try? result.get().first else { return }
                let access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                do { try model.importProfile(from: url) }
                catch { model.diagnostics.append("Profile import failed: \(error.localizedDescription)") }
            }
            .fileExporter(isPresented: $exporting, document: exportDocument, contentType: .plainText, defaultFilename: "weave-profile.vspf") { _ in }
        }
    }
}

struct VSPFFileDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText, .data] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
