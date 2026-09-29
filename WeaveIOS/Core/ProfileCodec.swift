import Foundation

enum ProfileCodec {
    private static let envelope = "VEILYSOCIAL_PROFILE_V2"
    private static let legacyEnvelope = "VEILYSOCIAL_PROFILE_V1"

    struct Validation { let ok: Bool; let message: String }

    static func validate(_ doc: ProfileDocument) -> Validation {
        if doc.pages.isEmpty { return .init(ok: false, message: "profile has no pages") }
        if doc.pages.count > VSPFLimits.maxPages { return .init(ok: false, message: "too many pages") }
        if !doc.pages.contains(where: { $0.id == doc.defaultPageID }) { return .init(ok: false, message: "default page id does not exist") }
        for page in doc.pages {
            if !(0.20...1.20).contains(page.aspectRatio) { return .init(ok: false, message: "page aspect ratio outside 0.20..1.20") }
            var count = 0
            func walk(_ element: ProfileElement, depth: Int) -> String? {
                if depth > VSPFLimits.maxDepth { return "nesting exceeds limit" }
                count += 1
                if count > VSPFLimits.maxElementsPerPage { return "page element limit exceeded" }
                let q = element.rect
                if !(0...1).contains(q.x) || !(0...1).contains(q.y) || !(0.0001...1).contains(q.width) || !(0.0001...1).contains(q.height) {
                    return "element rectangle outside normalized range"
                }
                if element.background.stops.count > VSPFLimits.maxGradientStops { return "too many gradient stops" }
                if element.background.kind == .linearGradient && element.background.stops.count < 2 { return "gradient needs at least two stops" }
                if element.background.stops.contains(where: { !(0...1).contains($0.position) }) { return "gradient stop outside 0..1" }
                if !(0...1).contains(element.opacity) { return "stamp opacity outside 0..1" }
                for child in element.children {
                    if let error = walk(child, depth: depth + 1) { return error }
                }
                return nil
            }
            if let error = walk(page.root, depth: 0) { return .init(ok: false, message: error) }
        }
        return .init(ok: true, message: "")
    }

    static func encodeBinary(_ doc: ProfileDocument) throws -> Data {
        let validation = validate(doc)
        guard validation.ok else { throw CodecError.invalid(validation.message) }
        var w = Writer()
        for byte in Data("VSPF".utf8) { w.u8(byte) }
        w.u16(VSPFLimits.formatVersion)
        try w.string(doc.profileID)
        try w.string(doc.profileName)
        try w.string(doc.defaultPageID)
        w.u16(UInt16(doc.pages.count))
        for page in doc.pages {
            try w.string(page.id)
            try w.string(page.name)
            w.f32(page.aspectRatio)
            try writeElement(page.root, to: &w, depth: 0)
        }
        return w.data
    }

    static func decodeBinary(_ data: Data) throws -> ProfileDocument {
        var r = Reader(data)
        guard try r.u8() == UInt8(ascii: "V"), try r.u8() == UInt8(ascii: "S"),
              try r.u8() == UInt8(ascii: "P"), try r.u8() == UInt8(ascii: "F") else {
            throw CodecError.invalid("not a VSPF profile")
        }
        let version = try r.u16()
        guard version >= 1 && version <= VSPFLimits.formatVersion else { throw CodecError.invalid("unsupported VSPF version") }
        var doc = ProfileDocument(profileID: try r.string(), profileName: try r.string(), defaultPageID: try r.string(), pages: [])
        let count = Int(try r.u16())
        guard count >= 1 && count <= VSPFLimits.maxPages else { throw CodecError.invalid("invalid page count") }
        for _ in 0..<count {
            let id = try r.string()
            let name = try r.string()
            let aspect = try r.f32()
            guard (0.20...1.20).contains(aspect) else { throw CodecError.invalid("invalid page aspect ratio") }
            var elementCount = 0
            let root = try readElement(from: &r, depth: 0, count: &elementCount, version: version)
            doc.pages.append(.init(id: id, name: name, aspectRatio: aspect, root: root))
        }
        guard r.isDone else { throw CodecError.invalid("trailing data in VSPF payload") }
        let validation = validate(doc)
        guard validation.ok else { throw CodecError.invalid(validation.message) }
        return doc
    }

    static func encodeText(_ doc: ProfileDocument) throws -> String {
        "\(envelope)\n\(try encodeBinary(doc).base64EncodedString())\n"
    }

    static func decodeText(_ text: String) throws -> ProfileDocument {
        guard let newline = text.firstIndex(of: "\n") else { throw CodecError.invalid("empty profile file") }
        let first = String(text[..<newline])
        guard first == envelope || first == legacyEnvelope else { throw CodecError.invalid("invalid profile text envelope") }
        let b64 = text[text.index(after: newline)...].filter { !$0.isWhitespace }
        guard let data = Data(base64Encoded: String(b64)) else { throw CodecError.invalid("invalid base64 profile") }
        return try decodeBinary(data)
    }

    static func save(_ doc: ProfileDocument, to url: URL) throws {
        try encodeText(doc).write(to: url, atomically: true, encoding: .utf8)
    }

    static func load(from url: URL) throws -> ProfileDocument {
        try decodeText(String(contentsOf: url, encoding: .utf8))
    }

    enum CodecError: LocalizedError {
        case invalid(String)
        var errorDescription: String? { if case .invalid(let message) = self { return message }; return nil }
    }

    private struct Writer {
        var data = Data()
        mutating func u8(_ v: UInt8) { data.append(v) }
        mutating func bool(_ v: Bool) { u8(v ? 1 : 0) }
        mutating func u16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { data.append(contentsOf: $0) } }
        mutating func u32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { data.append(contentsOf: $0) } }
        mutating func i32(_ v: Int32) { u32(UInt32(bitPattern: v)) }
        mutating func f32(_ v: Float) { u32(v.bitPattern) }
        mutating func string(_ value: String) throws {
            let bytes = Data(value.utf8)
            guard bytes.count <= VSPFLimits.maxStringBytes else { throw CodecError.invalid("string exceeds VSPF limit") }
            u32(UInt32(bytes.count)); data.append(bytes)
        }
    }

    private struct Reader {
        let data: Data
        var pos = 0
        init(_ data: Data) { self.data = data }
        var isDone: Bool { pos == data.count }
        mutating func need(_ n: Int) throws { guard pos + n <= data.count else { throw CodecError.invalid("truncated VSPF payload") } }
        mutating func u8() throws -> UInt8 { try need(1); defer { pos += 1 }; return data[pos] }
        mutating func bool() throws -> Bool { let v = try u8(); guard v <= 1 else { throw CodecError.invalid("invalid bool") }; return v != 0 }
        mutating func u16() throws -> UInt16 { UInt16(try u8()) | (UInt16(try u8()) << 8) }
        mutating func u32() throws -> UInt32 {
            var v: UInt32 = 0
            for shift in stride(from: 0, through: 24, by: 8) { v |= UInt32(try u8()) << UInt32(shift) }
            return v
        }
        mutating func i32() throws -> Int32 { Int32(bitPattern: try u32()) }
        mutating func f32() throws -> Float { Float(bitPattern: try u32()) }
        mutating func string() throws -> String {
            let n = Int(try u32())
            guard n <= VSPFLimits.maxStringBytes else { throw CodecError.invalid("string exceeds VSPF limit") }
            try need(n)
            let slice = data[pos..<(pos + n)]; pos += n
            guard let value = String(data: slice, encoding: .utf8) else { throw CodecError.invalid("invalid UTF-8") }
            return value
        }
    }

    private static func writeDecoration(_ d: DecorationRef, to w: inout Writer) throws {
        w.u8(UInt8(d.kind.rawValue)); try w.string(d.builtinName); try w.string(d.packRecordKey); w.u32(d.itemID); try w.string(d.contentHash); try w.string(d.basedOnBuiltin)
    }
    private static func readDecoration(from r: inout Reader) throws -> DecorationRef {
        guard let kind = DecorationKind(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid decoration kind") }
        return .init(kind: kind, builtinName: try r.string(), packRecordKey: try r.string(), itemID: try r.u32(), contentHash: try r.string(), basedOnBuiltin: try r.string())
    }
    private static func writeBackground(_ b: BackgroundSpec, to w: inout Writer) throws {
        w.u8(UInt8(b.kind.rawValue)); w.u32(b.solidARGB); w.f32(b.startX); w.f32(b.startY); w.f32(b.endX); w.f32(b.endY)
        guard b.stops.count <= VSPFLimits.maxGradientStops else { throw CodecError.invalid("too many gradient stops") }
        w.u8(UInt8(b.stops.count)); for stop in b.stops { w.f32(stop.position); w.u32(stop.argb) }
    }
    private static func readBackground(from r: inout Reader) throws -> BackgroundSpec {
        guard let kind = BackgroundKind(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid background kind") }
        var b = BackgroundSpec(kind: kind, solidARGB: try r.u32(), startX: try r.f32(), startY: try r.f32(), endX: try r.f32(), endY: try r.f32(), stops: [])
        let n = Int(try r.u8()); guard n <= VSPFLimits.maxGradientStops else { throw CodecError.invalid("too many gradient stops") }
        for _ in 0..<n { b.stops.append(.init(position: try r.f32(), argb: try r.u32())) }
        return b
    }
    private static func writeRect(_ q: RectSpec, to w: inout Writer) { w.f32(q.x); w.f32(q.y); w.f32(q.width); w.f32(q.height); w.i32(q.zIndex); w.bool(q.visible) }
    private static func readRect(from r: inout Reader) throws -> RectSpec { .init(x: try r.f32(), y: try r.f32(), width: try r.f32(), height: try r.f32(), zIndex: try r.i32(), visible: try r.bool()) }

    private static func writeElement(_ e: ProfileElement, to w: inout Writer, depth: Int) throws {
        guard depth <= VSPFLimits.maxDepth else { throw CodecError.invalid("element nesting too deep") }
        w.u8(UInt8(e.type.rawValue + 1)); try w.string(e.id); try w.string(e.name); writeRect(e.rect, to: &w)
        switch e.type {
        case .block:
            w.u8(UInt8(e.layout.rawValue)); try writeBackground(e.background, to: &w); try writeDecoration(e.border, to: &w); w.f32(e.borderThickness); w.bool(e.clipChildren); w.bool(e.scrollChildren); w.u8(UInt8(e.sticky.rawValue))
            guard e.children.count <= 65535 else { throw CodecError.invalid("too many children") }
            w.u16(UInt16(e.children.count)); for child in e.children { try writeElement(child, to: &w, depth: depth + 1) }
        case .text:
            try w.string(e.text); try w.string(e.fontID); w.f32(e.fontSize); w.u32(e.textARGB); w.u8(UInt8(e.textAlign.rawValue)); w.bool(e.bold); w.bool(e.italic); w.bool(e.underline)
        case .link:
            try w.string(e.label); w.u8(UInt8(e.targetType.rawValue)); try w.string(e.target)
        case .button:
            try w.string(e.label); try writeDecoration(e.buttonDecoration, to: &w); try writeBackground(e.background, to: &w); try w.string(e.fontID); w.f32(e.fontSize); w.u32(e.textARGB); w.u8(UInt8(e.textAlign.rawValue)); w.bool(e.bold); w.bool(e.italic); w.bool(e.underline); w.u8(UInt8(e.targetType.rawValue)); try w.string(e.target)
        case .stamp:
            try writeDecoration(e.stampDecoration, to: &w); w.f32(e.rotationDegrees); w.f32(e.opacity); w.bool(e.flipX); w.bool(e.flipY)
        case .media:
            w.u8(UInt8(e.mediaKind.rawValue)); try w.string(e.mediaRecordKey); try w.string(e.mediaContentHash); w.u32(e.intrinsicWidth); w.u32(e.intrinsicHeight); try w.string(e.mediaTitle); try w.string(e.mediaDescription)
        case .widget:
            try w.string(e.widgetLabel); try w.string(e.widgetRecordKey); w.u32(e.widgetItemID); try w.string(e.widgetSourceHash); w.u32(e.widgetDefaultWidth); w.u32(e.widgetDefaultHeight); w.bool(e.widgetWarnOnResize); try w.string(e.widgetDataDHT); w.bool(e.widgetOnline)
        }
    }

    private static func readElement(from r: inout Reader, depth: Int, count: inout Int, version: UInt16) throws -> ProfileElement {
        guard depth <= VSPFLimits.maxDepth else { throw CodecError.invalid("element nesting too deep") }
        count += 1; guard count <= VSPFLimits.maxElementsPerPage else { throw CodecError.invalid("too many elements") }
        let tag = Int(try r.u8()); guard let type = ElementType(rawValue: tag - 1) else { throw CodecError.invalid("unknown VSPF element type") }
        var e = ProfileElement(type: type, id: try r.string(), name: try r.string(), rect: try readRect(from: &r))
        switch type {
        case .block:
            guard let layout = LayoutMode(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid layout") }
            e.layout = layout; e.background = try readBackground(from: &r); e.border = try readDecoration(from: &r); e.borderThickness = try r.f32(); e.clipChildren = try r.bool(); e.scrollChildren = try r.bool()
            guard let sticky = StickyMode(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid sticky mode") }; e.sticky = sticky
            let n = Int(try r.u16()); e.children = []; for _ in 0..<n { e.children.append(try readElement(from: &r, depth: depth + 1, count: &count, version: version)) }
        case .text:
            e.text = try r.string(); if version >= 2 { e.fontID = try r.string() }; e.fontSize = try r.f32(); e.textARGB = try r.u32(); guard let align = TextAlignMode(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid alignment") }; e.textAlign = align; e.bold = try r.bool(); e.italic = try r.bool(); if version >= 2 { e.underline = try r.bool() }
        case .link:
            e.label = try r.string(); guard let target = LinkTargetType(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid link target") }; e.targetType = target; e.target = try r.string()
        case .button:
            e.label = try r.string(); e.buttonDecoration = try readDecoration(from: &r)
            if version >= 2 { e.background = try readBackground(from: &r); e.fontID = try r.string(); e.fontSize = try r.f32(); e.textARGB = try r.u32(); guard let align = TextAlignMode(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid alignment") }; e.textAlign = align; e.bold = try r.bool(); e.italic = try r.bool(); e.underline = try r.bool() }
            guard let target = LinkTargetType(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid link target") }; e.targetType = target; e.target = try r.string()
        case .stamp:
            e.stampDecoration = try readDecoration(from: &r); e.rotationDegrees = try r.f32(); e.opacity = try r.f32(); e.flipX = try r.bool(); e.flipY = try r.bool()
        case .media:
            guard let kind = MediaKind(rawValue: Int(try r.u8())) else { throw CodecError.invalid("invalid media kind") }; e.mediaKind = kind; e.mediaRecordKey = try r.string(); e.mediaContentHash = try r.string(); e.intrinsicWidth = try r.u32(); e.intrinsicHeight = try r.u32(); e.mediaTitle = try r.string(); e.mediaDescription = try r.string()
        case .widget:
            e.widgetLabel = try r.string(); e.widgetRecordKey = try r.string(); e.widgetItemID = try r.u32()
            if version >= 3 { e.widgetSourceHash = try r.string(); e.widgetDefaultWidth = try r.u32(); e.widgetDefaultHeight = try r.u32(); e.widgetWarnOnResize = try r.bool() }
            if version >= 4 { e.widgetDataDHT = try r.string(); e.widgetOnline = try r.bool() }
        }
        return e
    }
}
