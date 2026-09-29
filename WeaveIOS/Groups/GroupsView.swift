import SwiftUI

struct GroupsView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var store = GroupStore()
    @State private var createGroup = false
    @State private var title = ""
    @State private var details = ""

    var body: some View {
        NavigationStack {
            Group {
                if store.groups.isEmpty {
                    ContentUnavailableView("No groups cached yet", systemImage: "person.3", description: Text("Create a local group draft, or discover groups once the Groups-v2 network runtime is connected on iOS."))
                } else {
                    List {
                        ForEach($store.groups) { $group in
                            NavigationLink { GroupDetailView(group: $group, save: { store.save() }) } label: {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(group.title).font(.headline)
                                    Text("\(group.memberCount) members  •  \(group.isPublic ? "Public" : "Private")  •  \(group.branch.rawValue)")
                                        .font(.caption).foregroundStyle(.secondary)
                                    if !group.details.isEmpty { Text(group.details).lineLimit(2).font(.subheadline) }
                                }.padding(.vertical, 4)
                            }
                        }
                        .onDelete { offsets in store.groups.remove(atOffsets: offsets); store.save() }
                    }
                }
            }
            .navigationTitle("Groups")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { NavigationLink(destination: SettingsView()) { Image(systemName: "gearshape") } }
                ToolbarItem(placement: .topBarTrailing) { Button { createGroup = true } label: { Image(systemName: "plus") } }
            }
            .tint(.blue)
            .task { await store.load(using: model) }
            .sheet(isPresented: $createGroup) {
                NavigationStack {
                    Form {
                        TextField("Group title", text: $title)
                        TextField("Description", text: $details, axis: .vertical)
                    }
                    .navigationTitle("Create group")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { Button("Cancel") { createGroup = false } }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Create") { store.create(title: title.isEmpty ? "New Group" : title, details: details); title = ""; details = ""; createGroup = false }
                        }
                    }
                }
            }
        }
    }
}

private struct GroupDetailView: View {
    @Binding var group: WeaveGroup
    let save: () -> Void
    @State private var newPost = ""
    @State private var selectedPost: GroupPost?

    var body: some View {
        List {
            Section {
                HStack {
                    VStack(alignment: .leading) {
                        Text("\(group.memberCount) members • \(group.isPublic ? "Public" : "Private")")
                        Menu {
                            Button("Original") { group.branch = .original; save() }
                            Button("Claim") { group.branch = .claim; save() }
                        } label: { Label(group.branch.rawValue, systemImage: "arrow.triangle.branch") }
                    }
                    Spacer()
                    Button(group.joined ? "Leave" : "Join") { group.joined.toggle(); save() }
                    ShareLink(item: "weave://group/\(group.id)") { Image(systemName: "link") }
                }
                if !group.details.isEmpty { Text(group.details) }
            }
            Section("Create a post") {
                TextField("What do you want to post?", text: $newPost, axis: .vertical)
                Button("Post") {
                    let trimmed = newPost.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty else { return }
                    group.posts.insert(.init(text: trimmed), at: 0); newPost = ""; save()
                }
            }
            Section("Posts") {
                if group.posts.isEmpty { Text("No posts yet.").foregroundStyle(.secondary) }
                ForEach($group.posts) { $post in
                    NavigationLink {
                        GroupPostView(post: $post, save: save)
                    } label: {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(post.text).lineLimit(4)
                            HStack { Text(post.author); Text(post.createdAt, style: .relative); Text("\(post.comments.count) comments") }
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .onDelete { group.posts.remove(atOffsets: $0); save() }
            }
        }
        .navigationTitle(group.title)
        .tint(.blue)
    }
}

private struct GroupPostView: View {
    @Binding var post: GroupPost
    let save: () -> Void
    @State private var comment = ""

    var body: some View {
        List {
            Section { Text(post.text); Text(post.createdAt, style: .date).font(.caption).foregroundStyle(.secondary) }
            Section("Comments") {
                ForEach(post.comments) { item in
                    VStack(alignment: .leading) { Text(item.text); Text(item.author).font(.caption).foregroundStyle(.secondary) }
                }
                HStack {
                    TextField("Leave a comment", text: $comment)
                    Button("Send") {
                        let value = comment.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !value.isEmpty else { return }
                        post.comments.append(.init(text: value)); comment = ""; save()
                    }
                }
            }
        }
        .navigationTitle("Post")
        .tint(.blue)
    }
}

struct CuratorView: View {
    var body: some View {
        NavigationStack {
            ContentUnavailableView("Curator queue", systemImage: "checklist", description: Text("The iOS shell is ready for the current Groups-v2 witness/private-mailbox moderation events. Network event parity is listed in PORT_STATUS.md."))
                .navigationTitle("Curator")
                .tint(.blue)
        }
    }
}
