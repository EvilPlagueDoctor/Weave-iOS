import Foundation
import SwiftUI

enum AppLanguage: String, CaseIterable, Identifiable, Codable {
    case en, fr, es, ru, zhHans = "zh-Hans"

    var id: String { rawValue }
    var label: String {
        switch self {
        case .en: return "English"
        case .fr: return "Français"
        case .es: return "Español"
        case .ru: return "Русский"
        case .zhHans: return "简体中文"
        }
    }
}

@MainActor
final class Localizer: ObservableObject {
    @Published var language: AppLanguage {
        didSet { UserDefaults.standard.set(language.rawValue, forKey: "weave.language") }
    }

    private var map: [String: [String: String]] = [:]

    init() {
        let saved = UserDefaults.standard.string(forKey: "weave.language")
        language = saved.flatMap(AppLanguage.init(rawValue:)) ?? .en
        if let url = Bundle.main.url(forResource: "AppLanguageMap", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([String: [String: String]].self, from: data) {
            map = decoded
        }
    }

    func tr(_ english: String) -> String {
        guard language != .en else { return english }
        return map[english]?[language.rawValue] ?? english
    }
}

enum StartupTips {
    static let all = [
        "Don't forget to publish your profile!",
        "Your profile stays unpublished until you choose to publish it.",
        "You can switch between Basic and Advanced profile editing at any time.",
        "Advanced profiles can use multiple pages.",
        "Use Pages & Layers to change which elements appear in front.",
        "Long-press a page or layer to move it.",
        "Your profile can include images, audio, widgets, links, and more.",
        "Widgets only load when you choose to open them.",
        "You can disable widget loading in Settings.",
        "External links show a warning before opening your browser.",
        "Images are filtered locally on your device according to your settings.",
        "Content filtering does not require uploading your images to a moderation server.",
        "You can adjust content-filter sensitivity in Settings.",
        "Group moderation is branch-based — you can choose which moderation branch you follow.",
        "If a group's original moderator disappears, another user can claim a moderation branch.",
        "Tap a group's Original/Claim label to switch moderation branches.",
        "Posts can contain images and audio.",
        "Full-size media is only fetched when you open it.",
        "Comments on your profile can take a little while to arrive.",
        "Weave has no private-message system — conversations are meant to stay visible.",
        "Search can discover people, groups, and related content.",
        "Your device helps carry public network information for other users.",
        "Custody helps keep group submissions alive while moderators are offline.",
        "Your account can be backed up from Settings → This identity.",
        "Make an account backup before moving to a new device.",
        "Your Weave identity is tied to your VeilKnit account.",
        "You can copy group links and share them directly.",
        "A group can have several moderation branches without changing the original group.",
        "Profile comments can be kept or rejected by the profile owner.",
        "You can unpublish your profile later from Settings.",
        "The Advanced editor remembers whether you left its sidebar open or closed.",
        "Use Undo if you move or resize something by accident.",
        "Profile pages are ordered — Previous and Next follow the order shown in Pages & Layers.",
        "Not everything has to be serious. Make your profile weird.",
        "Old-school profile customization is encouraged.",
        "Your profile does not have to look like everyone else's.",
        "Try making more than one profile page.",
        "A quiet network is still a network — discovery improves as more peers come online.",
        "Yes, you can make your profile ugly on purpose.",
        "Please do not teach the widgets to become sentient.",
        "Moderation branches: because apparently one argument wasn't enough."
    ]

    static func next(excluding current: Int?) -> Int {
        guard all.count > 1 else { return 0 }
        if let current {
            let candidate = Int.random(in: 0..<(all.count - 1))
            return candidate >= current ? candidate + 1 : candidate
        }
        return Int.random(in: 0..<all.count)
    }
}
