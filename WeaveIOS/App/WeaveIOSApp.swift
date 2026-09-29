import SwiftUI

@main
struct WeaveIOSApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            AppRootView()
                .environmentObject(model)
                .environmentObject(model.localizer)
                .tint(model.selectedSection == .groups || model.selectedSection == .curator ? .blue : .red)
                .onOpenURL { url in
                    DeepLinkRouter.route(url, model: model)
                }
        }
    }
}

enum DeepLinkRouter {
    @MainActor
    static func route(_ url: URL, model: AppModel) {
        guard url.scheme?.lowercased() == "weave" else { return }
        switch url.host?.lowercased() {
        case "group", "groups": model.selectedSection = .groups
        case "profile", "people": model.selectedSection = .people
        default: model.selectedSection = .search
        }
        model.diagnostics.append("Opened Weave link: \(url.absoluteString)")
    }
}
