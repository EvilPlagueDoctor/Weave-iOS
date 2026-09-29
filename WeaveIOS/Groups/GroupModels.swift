import Foundation

struct WeaveGroup: Codable, Identifiable, Equatable {
    enum BranchKind: String, Codable { case original = "Original", claim = "Claim" }
    var id: String = makeID("group")
    var title: String = "New Group"
    var details: String = ""
    var branch: BranchKind = .original
    var isPublic = true
    var joined = true
    var memberCount = 1
    var posts: [GroupPost] = []
}

struct GroupPost: Codable, Identifiable, Equatable {
    var id: String = makeID("post")
    var author = "You"
    var text = ""
    var createdAt = Date()
    var mediaKind: MediaKind?
    var comments: [GroupComment] = []
    var moderationState = "kept"
}

struct GroupComment: Codable, Identifiable, Equatable {
    var id: String = makeID("comment")
    var author = "You"
    var text = ""
    var createdAt = Date()
}

@MainActor
final class GroupStore: ObservableObject {
    @Published var groups: [WeaveGroup] = []
    @Published var loaded = false
    private weak var model: AppModel?
    private let namespace = "groups-ios"
    private let filename = "index-v1.json"

    func load(using model: AppModel) async {
        guard !loaded else { return }
        self.model = model
        guard let vault = model.vault else { loaded = true; return }
        do {
            if let data = try await vault.getNamedBlob(namespace: namespace, name: filename),
               let decoded = try? JSONDecoder().decode([WeaveGroup].self, from: data) {
                groups = decoded
            }
        } catch {
            model.diagnostics.append("Group cache load failed: \(error.localizedDescription)")
        }
        loaded = true
    }

    func save() {
        guard let vault = model?.vault else { return }
        let snapshot = groups
        Task {
            do {
                let data = try JSONEncoder().encode(snapshot)
                try await vault.putNamedBlob(namespace: namespace, name: filename, contentType: "application/json", data: data)
            } catch {
                await MainActor.run { self.model?.diagnostics.append("Group cache save failed: \(error.localizedDescription)") }
            }
        }
    }

    func create(title: String, details: String) {
        groups.insert(.init(title: title, details: details), at: 0)
        save()
    }
}
