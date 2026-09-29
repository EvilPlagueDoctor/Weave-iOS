import Foundation
import CryptoKit
import Security


/// JSON object returned by the embedded daemon.
///
/// The dictionary is produced from JSONSerialization and is never mutated after
/// leaving DaemonClient. Wrapping it lets Swift 6 safely move the response across
/// actor boundaries without weakening isolation for DaemonClient itself.
struct DaemonResult: @unchecked Sendable, CustomStringConvertible {
    fileprivate let storage: [String: Any]

    subscript(_ key: String) -> Any? { storage[key] }
    var description: String { String(describing: storage) }
}

actor DaemonClient {
    static let protocolVersion = 3
    static let appID = "weave.v1"
    static let appName = "Weave"
    static let capabilities = [
        "SendMessages", "ReceiveMessages", "ManageOwnStorage", "ReadOwnStorage",
        "ReadPublicProfiles", "SubscribeNetworkStatus", "SignAppData"
    ]
    private static let proofDomain = Data("veilknit/app-auth/v2".utf8)

    private var requestID: Int64 = 1
    private var sessionToken: String?
    private(set) var profileID: String?

    enum ClientError: LocalizedError {
        case malformedResponse(String)
        case daemon(String, String)
        case timeout(String)
        case missingCredential
        case generationChanged

        var errorDescription: String? {
            switch self {
            case .malformedResponse(let value): return "Malformed daemon response: \(value.prefix(300))"
            case .daemon(let code, let message): return "\(code): \(message)"
            case .timeout(let message): return message
            case .missingCredential: return "Missing Weave application credential"
            case .generationChanged: return "Credential generation changed; authorize Weave again"
            }
        }
    }

    func connect(status: @escaping @Sendable (String) -> Void) async throws {
        sessionToken = nil
        profileID = nil
        let deadline = Date().addingTimeInterval(90)
        var activeProfile = ""
        while Date() < deadline {
            if !NativeDaemonBridge.isRunning {
                throw ClientError.timeout("VeilKnit stopped before its application API became ready.")
            }
            activeProfile = NativeDaemonBridge.profileID().trimmingCharacters(in: .whitespacesAndNewlines)
            if !activeProfile.isEmpty { break }
            let logs = NativeDaemonBridge.drainLogs()
            if let latest = logs.last { status(Self.friendlyStatus(from: latest)) }
            try await Task.sleep(for: .milliseconds(500))
        }
        guard !activeProfile.isEmpty else {
            throw ClientError.timeout("VeilKnit did not become ready after 90 seconds.")
        }
        profileID = activeProfile
        try await ensureCredential(profileID: activeProfile, status: status)
        do {
            try authenticate(profileID: activeProfile)
        } catch ClientError.generationChanged {
            KeychainCredentialStore.clear(profileID: activeProfile)
            try await ensureCredential(profileID: activeProfile, status: status)
            try authenticate(profileID: activeProfile)
        }
    }

    func disconnect() {
        sessionToken = nil
        profileID = nil
    }

    func request(_ action: String, body: [String: Any] = [:]) throws -> DaemonResult {
        DaemonResult(storage: try rawRequest(action, authenticated: true, body: body))
    }

    func identity() throws -> DaemonResult { try request("get_identity") }
    func listAppPeers() throws -> DaemonResult { try request("list_app_peers", body: ["limit": 1000, "start_search": true]) }
    func getAppRoot(peerMainDHT: String) throws -> DaemonResult {
        try request("get_app_root", body: ["peer_main_dht": peerMainDHT, "start_lookup": true])
    }
    func registerAppRoot(_ rootDHT: String) throws -> DaemonResult {
        try request("register_app_root", body: ["root_dht": rootDHT])
    }
    func triggerMessageRetrieval() throws -> DaemonResult { try request("trigger_message_retrieval") }
    func mailboxStatus() throws -> DaemonResult { try request("get_mailbox_status") }

    private func ensureCredential(profileID: String, status: @escaping @Sendable (String) -> Void) async throws {
        if KeychainCredentialStore.read(profileID: profileID) != nil { return }

        let token = Self.randomBytes(count: 32).hex
        let registration: [String: Any]
        do {
            registration = try rawRequest("request_app_registration", authenticated: false, body: [
                "app_id": Self.appID,
                "display_name": Self.appName,
                "requested_capabilities": Self.capabilities,
                "request_token_hex": token
            ])
        } catch ClientError.daemon(let code, _) where code == "app_already_registered" {
            status("Recovering Weave authorization for this VeilKnit account…")
            let text = NativeDaemonBridge.recoverEmbeddedAppCredential(Self.appID)
            guard let data = text.data(using: .utf8),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  root["ok"] as? Bool == true,
                  let secret = root["secret_hex"] as? String,
                  let generation = Self.int64(root["credential_generation"]) else {
                throw ClientError.malformedResponse(text)
            }
            try KeychainCredentialStore.write(profileID: profileID, credential: .init(secretHex: secret, generation: generation))
            return
        }

        guard let registrationID = Self.int64(registration["request_id"]) else {
            throw ClientError.malformedResponse("registration request id missing")
        }
        guard NativeDaemonBridge.sendCommand("app-approve \(registrationID)") else {
            throw ClientError.daemon("embedded_approval_failed", "VeilKnit did not accept the bundled Weave approval command")
        }

        status("Authorizing Weave with the embedded VeilKnit core…")
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            try await Task.sleep(for: .milliseconds(900))
            let result = try rawRequest("get_app_registration_status", authenticated: false, body: [
                "registration_request_id": registrationID,
                "request_token_hex": token
            ])
            switch result["type"] as? String ?? "" {
            case "app_registration_still_pending": continue
            case "app_registration_approved":
                guard let secret = result["secret_hex"] as? String,
                      let generation = Self.int64(result["credential_generation"]) else {
                    throw ClientError.malformedResponse("approved credential missing")
                }
                try KeychainCredentialStore.write(profileID: profileID, credential: .init(secretHex: secret, generation: generation))
                return
            case "app_registration_rejected":
                throw ClientError.daemon("registration_rejected", result["reason"] as? String ?? "Application registration rejected")
            case "app_registration_expired":
                throw ClientError.daemon("registration_expired", "Application registration expired")
            default:
                throw ClientError.malformedResponse(String(describing: result))
            }
        }
        throw ClientError.timeout("Timed out authorizing Weave with VeilKnit.")
    }

    private func authenticate(profileID: String) throws {
        let begin = try rawRequest("begin_authentication", authenticated: false, body: [
            "app_id": Self.appID,
            "requested_capabilities": Self.capabilities
        ])
        guard let challengeID = Self.int64(begin["challenge_id"]),
              let nonceHex = begin["nonce_hex"] as? String,
              let nonce = Data(hex: nonceHex),
              let issuedAt = Self.int64(begin["issued_at"]),
              let expiresAt = Self.int64(begin["expires_at"]),
              let generation = Self.int64(begin["credential_generation"]),
              let capabilities = begin["requested_capabilities"] as? [String],
              let credential = KeychainCredentialStore.read(profileID: profileID),
              let secret = Data(hex: credential.secretHex) else {
            throw ClientError.missingCredential
        }
        guard credential.generation == generation else {
            KeychainCredentialStore.clear(profileID: profileID)
            throw ClientError.generationChanged
        }
        let proof = Self.computeProof(
            secret: secret,
            appID: Self.appID,
            challengeID: challengeID,
            nonce: nonce,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            generation: generation,
            capabilities: capabilities
        )
        let finish = try rawRequest("finish_authentication", authenticated: false, body: [
            "app_id": Self.appID,
            "challenge_id": challengeID,
            "proof_hex": proof.hex
        ])
        guard let token = finish["session_token_hex"] as? String else {
            throw ClientError.malformedResponse("authentication session token missing")
        }
        sessionToken = token
    }

    private func rawRequest(_ action: String, authenticated: Bool, body: [String: Any]) throws -> [String: Any] {
        let id = requestID
        requestID += 1
        var object = body
        object["protocol_version"] = Self.protocolVersion
        object["request_id"] = id
        object["action"] = action
        if authenticated {
            guard let sessionToken else { throw ClientError.daemon("not_authenticated", "Weave is not authenticated") }
            object["session_token"] = sessionToken
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [])
        let text = String(decoding: data, as: UTF8.self)
        let responseText = NativeDaemonBridge.transact(text)
        guard let responseData = responseText.data(using: .utf8),
              let envelope = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw ClientError.malformedResponse(responseText)
        }
        guard envelope["ok"] as? Bool == true else {
            let error = envelope["error"] as? [String: Any]
            throw ClientError.daemon(
                error?["code"] as? String ?? "daemon_error",
                error?["message"] as? String ?? "Unknown daemon error"
            )
        }
        return envelope["result"] as? [String: Any] ?? [:]
    }

    private static func computeProof(
        secret: Data,
        appID: String,
        challengeID: Int64,
        nonce: Data,
        issuedAt: Int64,
        expiresAt: Int64,
        generation: Int64,
        capabilities: [String]
    ) -> Data {
        var input = Data()
        input.append(proofDomain)
        let appData = Data(appID.utf8)
        input.appendLE(UInt32(appData.count))
        input.append(appData)
        input.appendLE(UInt64(challengeID))
        input.append(nonce)
        input.appendLE(UInt64(issuedAt))
        input.appendLE(UInt64(expiresAt))
        input.appendLE(UInt64(generation))
        input.appendLE(UInt32(capabilities.count))
        for capability in capabilities {
            input.append(Data(capability.utf8))
            input.append(0)
        }
        let key = SymmetricKey(data: secret)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
    }

    static func friendlyStatus(from line: String) -> String {
        let lower = line.lowercased()
        if lower.contains("attaching") { return "Attaching to Veilid…" }
        if lower.contains("main dht") && lower.contains("ready") { return "Main DHT ready…" }
        if lower.contains("mailbox") { return "Preparing mailbox…" }
        if lower.contains("application") && lower.contains("service") { return "Preparing application services…" }
        if lower.contains("restor") { return "Restoring saved network data…" }
        return line.replacingOccurrences(of: #"^\[[^]]+\]\s*"#, with: "", options: .regularExpression)
    }

    private static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    private static func int64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let i = value as? Int64 { return i }
        if let i = value as? Int { return Int64(i) }
        return nil
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }

    mutating func appendLE(_ value: UInt32) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    mutating func appendLE(_ value: UInt64) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }
}
