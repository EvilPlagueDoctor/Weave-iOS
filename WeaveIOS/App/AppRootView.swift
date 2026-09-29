import SwiftUI

struct AppRootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            switch model.phase {
            case .account:
                VeilKnitAccountView()
            case .starting:
                StartupLoadingView()
            case .ready:
                MainShellView()
            case .failed(let message):
                ContentUnavailableView {
                    Label("Weave couldn't start", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(message)
                } actions: {
                    Button("Back to sign in") { model.retryAccountScreen() }
                }
                .padding()
            }
        }
    }
}
