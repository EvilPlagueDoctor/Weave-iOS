import Foundation

enum NativeDaemonBridge {
    private static func stringAndFree(_ pointer: UnsafeMutablePointer<CChar>?) -> String {
        guard let pointer else { return "" }
        defer { weave_veilknit_string_free(pointer) }
        return String(cString: pointer)
    }

    static func start(dataDirectory: URL, signup: Bool, username: String, password: String) -> Bool {
        dataDirectory.path.withCString { data in
            username.withCString { user in
                password.withCString { pass in
                    weave_veilknit_start(data, signup, user, pass)
                }
            }
        }
    }

    static func sendCommand(_ command: String) -> Bool {
        command.withCString { weave_veilknit_send_command($0) }
    }

    static func requestStop() -> Bool { weave_veilknit_request_stop() }
    static var isRunning: Bool { weave_veilknit_is_running() }

    static func drainLogs() -> [String] {
        let text = stringAndFree(weave_veilknit_drain_logs())
        guard let data = text.data(using: .utf8),
              let lines = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return lines
    }

    static func transact(_ request: String) -> String {
        request.withCString { stringAndFree(weave_veilknit_transact($0)) }
    }

    static func recoverEmbeddedAppCredential(_ appID: String) -> String {
        appID.withCString { stringAndFree(weave_veilknit_recover_app_credential($0)) }
    }

    static func subscribe(_ request: String) -> UInt64 {
        request.withCString { weave_veilknit_subscribe($0) }
    }

    static func drainSubscription(_ id: UInt64) -> [String] {
        let text = stringAndFree(weave_veilknit_drain_subscription(id))
        guard let data = text.data(using: .utf8),
              let lines = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return lines
    }

    static func subscriptionActive(_ id: UInt64) -> Bool {
        weave_veilknit_subscription_active(id)
    }

    static func profileID() -> String {
        stringAndFree(weave_veilknit_profile_id())
    }

    @discardableResult
    static func unsubscribe(_ id: UInt64) -> Bool {
        weave_veilknit_unsubscribe(id)
    }

    static func restoreBackup(dataDirectory: URL, backup: URL, passphrase: String) -> String {
        dataDirectory.path.withCString { data in
            backup.path.withCString { file in
                passphrase.withCString { pass in
                    stringAndFree(weave_veilknit_restore_backup(data, file, pass))
                }
            }
        }
    }
}
