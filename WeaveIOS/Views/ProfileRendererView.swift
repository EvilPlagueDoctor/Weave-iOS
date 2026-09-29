import SwiftUI

struct ProfileRendererView: View {
    let page: ProfilePage
    var interactiveWidgets: Bool = true

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .topLeading) {
                BackgroundView(spec: page.root.background)
                ForEach(page.root.children.filter(\.rect.visible).sorted { $0.rect.zIndex < $1.rect.zIndex }) { element in
                    RenderedElement(element: element, interactiveWidgets: interactiveWidgets)
                        .frame(
                            width: max(1, proxy.size.width * CGFloat(element.rect.width)),
                            height: max(1, proxy.size.height * CGFloat(element.rect.height))
                        )
                        .position(
                            x: proxy.size.width * (CGFloat(element.rect.x) + CGFloat(element.rect.width) / 2),
                            y: proxy.size.height * (CGFloat(element.rect.y) + CGFloat(element.rect.height) / 2)
                        )
                }
            }
            .clipped()
        }
        .aspectRatio(CGFloat(page.aspectRatio), contentMode: .fit)
    }
}

private struct BackgroundView: View {
    let spec: BackgroundSpec
    var body: some View {
        Group {
            switch spec.kind {
            case .solid:
                spec.solidARGB.swiftUIColor
            case .linearGradient:
                LinearGradient(
                    stops: spec.stops.map { .init(color: $0.argb.swiftUIColor, location: CGFloat($0.position)) },
                    startPoint: UnitPoint(x: CGFloat(spec.startX), y: CGFloat(spec.startY)),
                    endPoint: UnitPoint(x: CGFloat(spec.endX), y: CGFloat(spec.endY))
                )
            }
        }
    }
}

private struct RenderedElement: View {
    let element: ProfileElement
    let interactiveWidgets: Bool

    var body: some View {
        Group {
            switch element.type {
            case .block:
                ZStack {
                    BackgroundView(spec: element.background)
                    GeometryReader { proxy in
                        ZStack(alignment: .topLeading) {
                            ForEach(element.children.filter(\.rect.visible).sorted { $0.rect.zIndex < $1.rect.zIndex }) { child in
                                RenderedElement(element: child, interactiveWidgets: interactiveWidgets)
                                    .frame(
                                        width: proxy.size.width * CGFloat(child.rect.width),
                                        height: proxy.size.height * CGFloat(child.rect.height)
                                    )
                                    .position(
                                        x: proxy.size.width * (CGFloat(child.rect.x) + CGFloat(child.rect.width) / 2),
                                        y: proxy.size.height * (CGFloat(child.rect.y) + CGFloat(child.rect.height) / 2)
                                    )
                            }
                        }
                    }
                }
                .overlay(RoundedRectangle(cornerRadius: 3).stroke(.black.opacity(0.10), lineWidth: CGFloat(max(0, element.borderThickness))))
            case .text:
                Text(element.text)
                    .font(.system(size: CGFloat(max(8, element.fontSize)), weight: element.bold ? .bold : .regular))
                    .italic(element.italic)
                    .underline(element.underline)
                    .foregroundStyle(element.textARGB.swiftUIColor)
                    .multilineTextAlignment(alignment(element.textAlign))
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: frameAlignment(element.textAlign))
            case .link:
                Label(element.label.isEmpty ? "Link" : element.label, systemImage: "link")
                    .font(.system(size: CGFloat(max(10, element.fontSize))))
                    .foregroundStyle(.blue)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .button:
                Text(element.label.isEmpty ? "Button" : element.label)
                    .font(.system(size: CGFloat(max(10, element.fontSize)), weight: .semibold))
                    .padding(.horizontal, 8)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.thinMaterial, in: Capsule())
            case .stamp:
                Image(systemName: stampSymbol(element.stampDecoration.builtinName))
                    .resizable().scaledToFit()
                    .padding(2)
                    .rotationEffect(.degrees(Double(element.rotationDegrees)))
                    .opacity(Double(element.opacity))
                    .scaleEffect(x: element.flipX ? -1 : 1, y: element.flipY ? -1 : 1)
            case .media:
                ZStack {
                    RoundedRectangle(cornerRadius: 9).fill(.black.opacity(0.08))
                    VStack(spacing: 4) {
                        Image(systemName: element.mediaKind == .audio ? "waveform" : element.mediaKind == .video ? "video" : "photo")
                        Text(element.mediaTitle).font(.caption).lineLimit(2)
                    }.foregroundStyle(.secondary)
                }
            case .widget:
                WidgetHostPlaceholder(element: element, interactive: interactiveWidgets)
            }
        }
        .accessibilityLabel(element.name)
    }

    private func alignment(_ value: TextAlignMode) -> TextAlignment {
        switch value { case .left: return .leading; case .center: return .center; case .right: return .trailing }
    }
    private func frameAlignment(_ value: TextAlignMode) -> Alignment {
        switch value { case .left: return .leading; case .center: return .center; case .right: return .trailing }
    }
    private func stampSymbol(_ name: String) -> String {
        let value = name.lowercased()
        if value.contains("heart") { return "heart.fill" }
        if value.contains("yarn") { return "circle.hexagongrid.fill" }
        return "star.fill"
    }
}
