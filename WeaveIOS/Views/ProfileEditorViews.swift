import SwiftUI

struct BasicProfileEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Profile") {
                    TextField("Name", text: Binding(
                        get: { model.profile.profileName },
                        set: { value in model.updateProfile { $0.profileName = value } }
                    ))
                }
                Section("Home page") {
                    if let pageIndex = model.profile.pages.indices.first,
                       let titleIndex = model.profile.pages[pageIndex].root.children.firstIndex(where: { $0.type == .text }) {
                        TextField("Heading", text: elementTextBinding(pageIndex: pageIndex, elementIndex: titleIndex), axis: .vertical)
                    }
                    Button("Switch to Advanced editor") { model.advancedEditor = true; dismiss() }
                }
                Section {
                    Text("Basic editing intentionally exposes only the safest common fields. Advanced mode edits pages, freeform layers, position, size and appearance.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Edit profile")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Save") { model.saveProfile(); dismiss() } }
            }
        }
    }

    private func elementTextBinding(pageIndex: Int, elementIndex: Int) -> Binding<String> {
        Binding(
            get: { model.profile.pages[pageIndex].root.children[elementIndex].text },
            set: { value in
                model.updateProfile { doc in doc.pages[pageIndex].root.children[elementIndex].text = value }
            }
        )
    }
}

struct AdvancedProfileEditorView: View {
    enum EditingLayer: String, CaseIterable { case background = "Background", foreground = "Foreground" }

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var pageIndex = 0
    @State private var editingLayer: EditingLayer = .foreground
    @State private var selectedElementID: String?
    @State private var sidebarOpen = UserDefaults.standard.object(forKey: "weave.editor.sidebar.open") as? Bool ?? false
    @State private var undo: [ProfileDocument] = []
    @State private var addExpanded = true
    @State private var moveExpanded = true
    @State private var appearanceExpanded = false
    @State private var contentExpanded = true
    @State private var showingCreatePage = false

    var body: some View {
        NavigationStack {
            GeometryReader { proxy in
                HStack(spacing: 0) {
                    if sidebarOpen {
                        editorSidebar
                            .frame(width: min(285, proxy.size.width * 0.38))
                            .transition(.move(edge: .leading))
                        Divider()
                    }
                    VStack(spacing: 0) {
                        ZStack(alignment: .topLeading) {
                            Color(uiColor: .secondarySystemBackground)
                            if let page = currentPage {
                                ProfileRendererView(page: page)
                                    .overlay(selectionOverlay(page: page))
                                    .padding(16)
                            }
                            Button {
                                withAnimation { sidebarOpen.toggle() }
                                UserDefaults.standard.set(sidebarOpen, forKey: "weave.editor.sidebar.open")
                            } label: {
                                Image(systemName: sidebarOpen ? "sidebar.left" : "sidebar.right")
                                    .padding(10).background(.ultraThinMaterial, in: Capsule())
                            }
                            .padding(10)
                        }
                        editorBottomBar
                    }
                }
            }
            .navigationTitle(currentPage?.name ?? "Profile Editor")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close") { model.saveProfile(); dismiss() }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button { undoLast() } label: { Image(systemName: "arrow.uturn.backward.circle") }
                        .disabled(undo.isEmpty)
                    Button("Basic") { model.advancedEditor = false; dismiss() }
                    Button("Save") { model.saveProfile() }
                }
            }
            .sheet(isPresented: $showingCreatePage) { createPageSheet }
            .onAppear { normalizePageIndex() }
        }
    }

    private var currentPage: ProfilePage? {
        guard model.profile.pages.indices.contains(pageIndex) else { return nil }
        return model.profile.pages[pageIndex]
    }

    private var selectedElement: ProfileElement? {
        guard let id = selectedElementID, let page = currentPage else { return nil }
        return page.root.children.first(where: { $0.id == id })
    }

    private var editorSidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Pages & Layers").font(.headline)
                pageList
                Divider()
                if editingLayer == .foreground {
                    layerList
                    inspector
                } else {
                    backgroundInspector
                }
            }.padding(12)
        }
        .background(.background)
    }

    private var pageList: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(model.profile.pages.enumerated()), id: \.element.id) { index, page in
                HStack {
                    Image(systemName: index == pageIndex ? "doc.fill" : "doc")
                    Text(page.name).lineLimit(1)
                    Spacer()
                }
                .contentShape(Rectangle())
                .padding(.vertical, 6)
                .padding(.horizontal, 7)
                .background(index == pageIndex ? Color.red.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 8))
                .onTapGesture { pageIndex = index; selectedElementID = nil }
                .contextMenu {
                    Button("Move earlier") { movePage(index, delta: -1) }.disabled(index == 0)
                    Button("Move later") { movePage(index, delta: 1) }.disabled(index == model.profile.pages.count - 1)
                    if model.profile.pages.count > 1 { Button("Delete", role: .destructive) { deletePage(index) } }
                }
            }
            Button { showingCreatePage = true } label: { Label("Add page", systemImage: "plus") }
                .buttonStyle(.bordered)
        }
    }

    private var layerList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Foreground layers").font(.subheadline.bold())
            if let page = currentPage {
                ForEach(page.root.children.sorted { $0.rect.zIndex > $1.rect.zIndex }) { item in
                    HStack(spacing: 7) {
                        Image(systemName: symbol(for: item.type))
                        Text(item.name).lineLimit(1)
                        Spacer()
                        Image(systemName: item.rect.visible ? "eye" : "eye.slash")
                            .foregroundStyle(.secondary)
                    }
                    .padding(7)
                    .background(selectedElementID == item.id ? Color.red.opacity(0.14) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    .contentShape(Rectangle())
                    .onTapGesture { selectedElementID = item.id }
                    .contextMenu {
                        Button("Bring forward") { shiftZ(item.id, by: 1) }
                        Button("Send backward") { shiftZ(item.id, by: -1) }
                        Button(item.rect.visible ? "Hide" : "Show") { toggleVisibility(item.id) }
                        Button("Delete", role: .destructive) { deleteElement(item.id) }
                    }
                }
            }
            Text("Long-press a layer for ordering controls. Reordering updates z-order without changing its content.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var inspector: some View {
        if let element = selectedElement {
            Divider()
            DisclosureGroup("Add", isExpanded: $addExpanded) { addControls.padding(.top, 6) }
            DisclosureGroup("Move / Size", isExpanded: $moveExpanded) { moveSizeControls(element).padding(.top, 6) }
            DisclosureGroup("Appearance", isExpanded: $appearanceExpanded) { appearanceControls(element).padding(.top, 6) }
            DisclosureGroup("Content", isExpanded: $contentExpanded) { contentControls(element).padding(.top, 6) }
        } else {
            Divider()
            DisclosureGroup("Add", isExpanded: $addExpanded) { addControls.padding(.top, 6) }
            Text("Choose a foreground layer to edit it.").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var addControls: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 80))], spacing: 8) {
            addButton("Text", .text, "textformat")
            addButton("Image", .media, "photo")
            addButton("Audio", .media, "waveform", mediaKind: .audio)
            addButton("Widget", .widget, "square.stack.3d.up")
            addButton("Link", .link, "link")
            addButton("Button", .button, "capsule")
            addButton("Stamp", .stamp, "star")
            addButton("Box", .block, "square")
        }
    }

    private func moveSizeControls(_ element: ProfileElement) -> some View {
        VStack(spacing: 8) {
            scalar("X", value: element.rect.x, range: 0...max(0, 1 - element.rect.width)) { updateRect(element.id, key: \.x, value: $0) }
            scalar("Y", value: element.rect.y, range: 0...max(0, 1 - element.rect.height)) { updateRect(element.id, key: \.y, value: $0) }
            scalar("Width", value: element.rect.width, range: 0.03...1) { updateRect(element.id, key: \.width, value: $0) }
            scalar("Height", value: element.rect.height, range: 0.03...1) { updateRect(element.id, key: \.height, value: $0) }
        }
    }

    private func appearanceControls(_ element: ProfileElement) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Visible", isOn: boolBinding(element.id, keyPath: \.rect.visible))
            if element.type == .text || element.type == .link || element.type == .button {
                Toggle("Bold", isOn: boolBinding(element.id, keyPath: \.bold))
                scalar("Font", value: element.fontSize, range: 8...64) { newValue in updateElement(element.id) { $0.fontSize = newValue } }
            }
            if element.type == .stamp {
                scalar("Rotation", value: element.rotationDegrees, range: -180...180) { newValue in updateElement(element.id) { $0.rotationDegrees = newValue } }
                scalar("Opacity", value: element.opacity, range: 0...1) { newValue in updateElement(element.id) { $0.opacity = newValue } }
            }
        }
    }

    private func contentControls(_ element: ProfileElement) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Layer name", text: stringBinding(element.id, keyPath: \.name))
                .textFieldStyle(.roundedBorder)
            switch element.type {
            case .text:
                TextField("Text", text: stringBinding(element.id, keyPath: \.text), axis: .vertical)
                    .textFieldStyle(.roundedBorder)
            case .link, .button:
                TextField("Label", text: stringBinding(element.id, keyPath: \.label)).textFieldStyle(.roundedBorder)
                TextField("Target", text: stringBinding(element.id, keyPath: \.target)).textFieldStyle(.roundedBorder)
            case .media:
                TextField("Title", text: stringBinding(element.id, keyPath: \.mediaTitle)).textFieldStyle(.roundedBorder)
                Text("Media picker/storage hooks are kept separate so iOS can use PhotosPicker without putting device paths into VSPF.")
                    .font(.caption2).foregroundStyle(.secondary)
            case .widget:
                TextField("Widget label", text: stringBinding(element.id, keyPath: \.widgetLabel)).textFieldStyle(.roundedBorder)
                Toggle("Online", isOn: boolBinding(element.id, keyPath: \.widgetOnline))
            default:
                EmptyView()
            }
        }
    }

    private var backgroundInspector: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Background").font(.headline)
            if let page = currentPage {
                Picker("Fill", selection: Binding(
                    get: { page.root.background.kind },
                    set: { newValue in mutate { doc in doc.pages[pageIndex].root.background.kind = newValue } }
                )) {
                    Text("Solid").tag(BackgroundKind.solid)
                    Text("Gradient").tag(BackgroundKind.linearGradient)
                }
                .pickerStyle(.segmented)
                Text("VSPF keeps ARGB colors and gradient geometry platform-neutral. The compact iOS color inspector can be expanded without changing the file format.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var editorBottomBar: some View {
        HStack(spacing: 8) {
            Button { previousPage() } label: { Label("Previous", systemImage: "chevron.left") }
                .disabled(pageIndex <= 0)
            Spacer(minLength: 4)
            ForEach(EditingLayer.allCases, id: \.self) { layer in
                Button(layer.rawValue) { editingLayer = layer }
                    .buttonStyle(.borderedProminent)
                    .tint(editingLayer == layer ? .red : .gray)
            }
            Spacer(minLength: 4)
            Button { nextPage() } label: { Label("Next", systemImage: "chevron.right") }
        }
        .padding(10)
        .background(.bar)
    }

    private var createPageSheet: some View {
        NavigationStack {
            VStack(spacing: 18) {
                Text("Create another profile page?").font(.title2.bold())
                Text("The new page is placed immediately after the current one and becomes the next page in Previous/Next order.")
                    .multilineTextAlignment(.center).foregroundStyle(.secondary)
                Button("Create page") { createPage(); showingCreatePage = false }.buttonStyle(.borderedProminent)
                Button("Cancel") { showingCreatePage = false }
            }.padding(28)
        }.presentationDetents([.medium])
    }

    private func selectionOverlay(page: ProfilePage) -> some View {
        GeometryReader { proxy in
            if let selectedElement, editingLayer == .foreground {
                let rect = selectedElement.rect
                RoundedRectangle(cornerRadius: 4)
                    .stroke(Color.red, style: StrokeStyle(lineWidth: 2, dash: [6, 3]))
                    .frame(width: proxy.size.width * CGFloat(rect.width), height: proxy.size.height * CGFloat(rect.height))
                    .position(
                        x: proxy.size.width * (CGFloat(rect.x) + CGFloat(rect.width) / 2),
                        y: proxy.size.height * (CGFloat(rect.y) + CGFloat(rect.height) / 2)
                    )
                    .allowsHitTesting(false)
            }
        }
        .padding(16)
    }

    private func addButton(_ label: String, _ type: ElementType, _ symbol: String, mediaKind: MediaKind = .image) -> some View {
        Button {
            snapshotUndo()
            var item = ProfileElement(type: type, name: label, rect: .init(x: 0.12, y: 0.15, width: 0.36, height: 0.14, zIndex: nextZ()))
            switch type {
            case .text: item.text = "New text"
            case .link: item.label = "Link"; item.targetType = .external
            case .button: item.label = "Button"
            case .media: item.mediaKind = mediaKind; item.mediaTitle = mediaKind == .audio ? "Audio" : "Image"
            case .widget: item.widgetLabel = "Widget"
            case .stamp: item.stampDecoration = .init(builtinName: "Star1", basedOnBuiltin: "Star1")
            default: break
            }
            model.updateProfile { $0.pages[pageIndex].root.children.append(item) }
            selectedElementID = item.id
        } label: {
            VStack(spacing: 4) { Image(systemName: symbol); Text(label).font(.caption) }
                .frame(maxWidth: .infinity).padding(.vertical, 7)
        }
        .buttonStyle(.bordered)
        .tint(.red)
    }

    private func scalar(_ name: String, value: Float, range: ClosedRange<Float>, set: @escaping (Float) -> Void) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack { Text(name).font(.caption); Spacer(); Text(String(format: "%.2f", value)).font(.caption.monospacedDigit()) }
            Slider(value: Binding(get: { Double(value) }, set: { set(Float($0)) }), in: Double(range.lowerBound)...Double(range.upperBound))
        }
    }

    private func stringBinding(_ id: String, keyPath: WritableKeyPath<ProfileElement, String>) -> Binding<String> {
        Binding(get: { selectedElementValue(id, keyPath) ?? "" }, set: { value in updateElement(id) { $0[keyPath: keyPath] = value } })
    }

    private func boolBinding(_ id: String, keyPath: WritableKeyPath<ProfileElement, Bool>) -> Binding<Bool> {
        Binding(get: { selectedElementValue(id, keyPath) ?? false }, set: { value in updateElement(id) { $0[keyPath: keyPath] = value } })
    }

    private func selectedElementValue<T>(_ id: String, _ keyPath: KeyPath<ProfileElement, T>) -> T? {
        guard let item = currentPage?.root.children.first(where: { $0.id == id }) else { return nil }
        return item[keyPath: keyPath]
    }

    private func updateRect(_ id: String, key: WritableKeyPath<RectSpec, Float>, value: Float) {
        updateElement(id) { $0.rect[keyPath: key] = value }
    }

    private func updateElement(_ id: String, change: (inout ProfileElement) -> Void) {
        model.updateProfile { doc in
            guard doc.pages.indices.contains(pageIndex), let i = doc.pages[pageIndex].root.children.firstIndex(where: { $0.id == id }) else { return }
            change(&doc.pages[pageIndex].root.children[i])
        }
    }

    private func mutate(_ change: (inout ProfileDocument) -> Void) { snapshotUndo(); model.updateProfile(change) }
    private func snapshotUndo() { undo.append(model.profile); if undo.count > 60 { undo.removeFirst(undo.count - 60) } }
    private func undoLast() { guard let previous = undo.popLast() else { return }; model.profile = previous; model.profileDirty = true; normalizePageIndex() }
    private func normalizePageIndex() { pageIndex = min(max(0, pageIndex), max(0, model.profile.pages.count - 1)) }
    private func nextZ() -> Int32 { (currentPage?.root.children.map(\.rect.zIndex).max() ?? -1) + 1 }

    private func movePage(_ index: Int, delta: Int) {
        let target = index + delta
        guard model.profile.pages.indices.contains(index), model.profile.pages.indices.contains(target) else { return }
        snapshotUndo(); model.updateProfile { $0.pages.swapAt(index, target) }; pageIndex = target
    }
    private func deletePage(_ index: Int) {
        guard model.profile.pages.count > 1 else { return }
        snapshotUndo(); model.updateProfile { doc in
            let removed = doc.pages.remove(at: index)
            if doc.defaultPageID == removed.id { doc.defaultPageID = doc.pages[0].id }
        }; normalizePageIndex(); selectedElementID = nil
    }
    private func createPage() {
        snapshotUndo()
        var page = ProfilePage(id: makeID("page"), name: "Page \(model.profile.pages.count + 1)", aspectRatio: 0.60)
        page.root.id = makeID("root"); page.root.name = page.name
        let insert = min(model.profile.pages.count, pageIndex + 1)
        model.updateProfile { $0.pages.insert(page, at: insert) }
        pageIndex = insert; editingLayer = .foreground; selectedElementID = nil
    }
    private func previousPage() { if pageIndex > 0 { pageIndex -= 1; selectedElementID = nil } }
    private func nextPage() {
        if pageIndex + 1 < model.profile.pages.count { pageIndex += 1; selectedElementID = nil }
        else { showingCreatePage = true }
    }
    private func deleteElement(_ id: String) {
        snapshotUndo(); model.updateProfile { $0.pages[pageIndex].root.children.removeAll { $0.id == id } }; selectedElementID = nil
    }
    private func shiftZ(_ id: String, by delta: Int32) { snapshotUndo(); updateElement(id) { $0.rect.zIndex += delta } }
    private func toggleVisibility(_ id: String) { snapshotUndo(); updateElement(id) { $0.rect.visible.toggle() } }

    private func symbol(for type: ElementType) -> String {
        switch type {
        case .block: return "square"
        case .text: return "textformat"
        case .link: return "link"
        case .button: return "capsule"
        case .stamp: return "star"
        case .media: return "photo"
        case .widget: return "square.stack.3d.up"
        }
    }
}
