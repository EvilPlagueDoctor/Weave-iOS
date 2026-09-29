import SwiftUI

struct WidgetHostPlaceholder: View {
    let element: ProfileElement
    var interactive: Bool
    @EnvironmentObject private var model: AppModel
    @State private var opened = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            RoundedRectangle(cornerRadius: 10)
                .fill(.black.opacity(0.06))
            if opened && model.widgetsEnabled {
                VStack(spacing: 5) {
                    Image(systemName: "square.stack.3d.up.fill")
                    Text(element.widgetLabel).font(.caption.bold())
                    Text("Widget package ready for the iOS VM parity layer")
                        .font(.caption2).multilineTextAlignment(.center).foregroundStyle(.secondary)
                }
                .padding(8)
            } else {
                Button {
                    if interactive && model.widgetsEnabled { opened = true }
                } label: {
                    VStack(spacing: 5) {
                        Image(systemName: model.widgetsEnabled ? "play.rectangle" : "nosign")
                        Text(model.widgetsEnabled ? "Open \(element.widgetLabel)" : "Widgets disabled")
                            .font(.caption.bold())
                    }.padding(8)
                }
                .buttonStyle(.plain)
                .disabled(!interactive || !model.widgetsEnabled)
            }
            if opened {
                Button { opened = false } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).padding(5)
            }
        }
    }
}
