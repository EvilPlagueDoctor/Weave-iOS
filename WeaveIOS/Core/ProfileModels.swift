import Foundation
import SwiftUI

enum VSPFLimits {
    static let formatVersion: UInt16 = 4
    static let maxPages = 64
    static let maxDepth = 16
    static let maxElementsPerPage = 2048
    static let maxStringBytes = 16 * 1024
    static let maxGradientStops = 8
}

enum BackgroundKind: Int, Codable, CaseIterable { case solid, linearGradient }
enum DecorationKind: Int, Codable, CaseIterable { case builtin, decorationPack }
enum ElementType: Int, Codable, CaseIterable { case block, text, link, button, stamp, media, widget }
enum LayoutMode: Int, Codable, CaseIterable { case freeform, column, row }
enum StickyMode: Int, Codable, CaseIterable { case normal, stickyParent, floatViewport }
enum LinkTargetType: Int, Codable, CaseIterable { case page, profile, post, community, dht, external }
enum MediaKind: Int, Codable, CaseIterable { case image, audio, video }
enum TextAlignMode: Int, Codable, CaseIterable { case left, center, right }

struct GradientStop: Codable, Equatable, Identifiable {
    var position: Float = 0
    var argb: UInt32 = 0xFF000000
    var id: String { "\(position)-\(argb)" }
}

struct BackgroundSpec: Codable, Equatable {
    var kind: BackgroundKind = .solid
    var solidARGB: UInt32 = 0xFFF7F7F7
    var startX: Float = 0
    var startY: Float = 0
    var endX: Float = 1
    var endY: Float = 1
    var stops: [GradientStop] = [
        .init(position: 0, argb: 0xFFF7F7F7),
        .init(position: 1, argb: 0xFFE5E7EB)
    ]
}

struct DecorationRef: Codable, Equatable {
    var kind: DecorationKind = .builtin
    var builtinName: String = "Thin1"
    var packRecordKey: String = ""
    var itemID: UInt32 = 0
    var contentHash: String = ""
    var basedOnBuiltin: String = "Thin1"
}

struct RectSpec: Codable, Equatable {
    var x: Float = 0.05
    var y: Float = 0.05
    var width: Float = 0.30
    var height: Float = 0.12
    var zIndex: Int32 = 0
    var visible: Bool = true
}

struct ProfileElement: Codable, Equatable, Identifiable {
    var type: ElementType = .block
    var id: String = makeID("item")
    var name: String = "Item"
    var rect: RectSpec = .init()

    var layout: LayoutMode = .freeform
    var background: BackgroundSpec = .init()
    var border: DecorationRef = .init()
    var borderThickness: Float = 1
    var clipChildren: Bool = true
    var scrollChildren: Bool = false
    var sticky: StickyMode = .normal
    var children: [ProfileElement] = []

    var text: String = "Text"
    var fontID: String = "Default1"
    var fontSize: Float = 18
    var textARGB: UInt32 = 0xFF111827
    var textAlign: TextAlignMode = .left
    var bold: Bool = false
    var italic: Bool = false
    var underline: Bool = false

    var label: String = "Link"
    var targetType: LinkTargetType = .page
    var target: String = ""
    var buttonDecoration: DecorationRef = .init()

    var stampDecoration: DecorationRef = .init(builtinName: "Star1", basedOnBuiltin: "Star1")
    var rotationDegrees: Float = 0
    var opacity: Float = 1
    var flipX: Bool = false
    var flipY: Bool = false

    var mediaKind: MediaKind = .image
    var mediaRecordKey: String = ""
    var mediaContentHash: String = ""
    var intrinsicWidth: UInt32 = 640
    var intrinsicHeight: UInt32 = 480
    var mediaTitle: String = "Image"
    var mediaDescription: String = "Media placeholder"

    var widgetLabel: String = "Widget"
    var widgetRecordKey: String = ""
    var widgetItemID: UInt32 = 0
    var widgetSourceHash: String = ""
    var widgetDefaultWidth: UInt32 = 320
    var widgetDefaultHeight: UInt32 = 180
    var widgetWarnOnResize: Bool = true
    var widgetDataDHT: String = ""
    var widgetOnline: Bool = false
}

struct ProfilePage: Codable, Equatable, Identifiable {
    var id: String = makeID("page")
    var name: String = "Page"
    var aspectRatio: Float = 0.60
    var root: ProfileElement = .init(type: .block, name: "Page", rect: .init(x: 0, y: 0, width: 1, height: 1))
}

struct ProfileDocument: Codable, Equatable, Identifiable {
    var profileID: String = makeID("profile")
    var profileName: String = "My Profile"
    var defaultPageID: String = "home"
    var pages: [ProfilePage] = []
    var id: String { profileID }
}

func makeID(_ prefix: String) -> String {
    "\(prefix)_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).lowercased())"
}

extension ProfileDocument {
    static func starter() -> ProfileDocument {
        var root = ProfileElement(
            type: .block,
            id: makeID("root"),
            name: "Home Page",
            rect: .init(x: 0, y: 0, width: 1, height: 1),
            background: .init(
                kind: .linearGradient,
                solidARGB: 0xFFF7F7F7,
                startX: 0, startY: 0, endX: 1, endY: 1,
                stops: [
                    .init(position: 0, argb: 0xFFF7F4FF),
                    .init(position: 0.55, argb: 0xFFEAF4FF),
                    .init(position: 1, argb: 0xFFFDF2F8)
                ]
            )
        )
        root.children.append(.init(
            type: .stamp,
            id: makeID("stamp"),
            name: "Star",
            rect: .init(x: 0.05, y: 0.05, width: 0.08, height: 0.08, zIndex: 0),
            stampDecoration: .init(builtinName: "Star1", basedOnBuiltin: "Star1"),
            rotationDegrees: -12,
            opacity: 0.75
        ))
        root.children.append(.init(
            type: .stamp,
            id: makeID("stamp"),
            name: "Star 2",
            rect: .init(x: 0.84, y: 0.13, width: 0.055, height: 0.055, zIndex: 1),
            stampDecoration: .init(builtinName: "Star1", basedOnBuiltin: "Star1"),
            rotationDegrees: 23,
            opacity: 0.75
        ))
        root.children.append(.init(
            type: .text,
            id: makeID("text"),
            name: "Profile Title",
            rect: .init(x: 0.09, y: 0.07, width: 0.82, height: 0.10, zIndex: 2),
            text: "My Weave Page",
            fontSize: 30,
            textAlign: .center,
            bold: true
        ))
        root.children.append(.init(
            type: .text,
            id: makeID("text"),
            name: "Welcome Text",
            rect: .init(x: 0.15, y: 0.27, width: 0.70, height: 0.20, zIndex: 3),
            text: "Drag, resize and decorate this page. The profile document stays non-executable; compiled widgets run only inside their own sandboxed rectangles.",
            fontSize: 17
        ))
        root.children.append(.init(
            type: .widget,
            id: makeID("widget"),
            name: "Widget Placeholder",
            rect: .init(x: 0.24, y: 0.54, width: 0.52, height: 0.20, zIndex: 4),
            widgetLabel: "Future Widget"
        ))
        return .init(profileName: "My Profile", defaultPageID: "home", pages: [
            .init(id: "home", name: "Home", aspectRatio: 0.60, root: root)
        ])
    }
}

extension UInt32 {
    var swiftUIColor: Color {
        let a = Double((self >> 24) & 0xFF) / 255
        let r = Double((self >> 16) & 0xFF) / 255
        let g = Double((self >> 8) & 0xFF) / 255
        let b = Double(self & 0xFF) / 255
        return Color(.sRGB, red: r, green: g, blue: b, opacity: a)
    }
}
