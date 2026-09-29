import SwiftUI

struct MainShellView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView(selection: $model.selectedSection) {
            HomeView()
                .tabItem { Label("Home", systemImage: "house") }
                .tag(AppModel.Section.home)
            SearchView()
                .tabItem { Label("Search", systemImage: "magnifyingglass") }
                .tag(AppModel.Section.search)
            PeopleView()
                .tabItem { Label("People", systemImage: "person.2") }
                .tag(AppModel.Section.people)
            MeView()
                .tabItem { Label("Me", systemImage: "person.crop.circle") }
                .tag(AppModel.Section.me)
            GroupsView()
                .tabItem { Label("Groups", systemImage: "person.3") }
                .tag(AppModel.Section.groups)
            CuratorView()
                .tabItem { Label("Curator", systemImage: "checklist") }
                .tag(AppModel.Section.curator)
        }
    }
}

struct HomeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Your corner of Weave")
                        .font(.title2.bold())
                    ProfileCard(document: model.profile)
                    Group {
                        Label("Discovery uses the same People + Groups sources as Search.", systemImage: "sparkles")
                        Label("Your local profile is stored as compatible VSPF v4 data.", systemImage: "doc.badge.gearshape")
                        Label("VeilKnit runs inside the app process on iOS.", systemImage: "network")
                    }
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("Home")
            .toolbar { settingsToolbar }
        }
    }

    @ToolbarContentBuilder private var settingsToolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarTrailing) {
            NavigationLink(destination: SettingsView()) { Image(systemName: "gearshape") }
        }
    }
}

struct ProfileCard: View {
    let document: ProfileDocument
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(document.profileName).font(.headline)
            if let page = document.pages.first {
                ProfileRendererView(page: page, interactiveWidgets: false)
                    .frame(height: 330)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(.quaternary))
            }
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 20))
    }
}
