import Foundation
import Security
import CryptoKit

struct AppCredential: Codable, Equatable {
    let secretHex: String
    let generation: Int64
}

enum KeychainCredentialStore {
    private static let service = "weave.bootstrap-credential.v1"

    private static func account(for profileID: String) -> String {
        let digest = SHA256.hash(data: Data(profileID.utf8))
        return digest.map { String(format: "%02x", $0) }.joined().prefix(32).description
    }

    static func read(profileID: String) -> AppCredential? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: profileID),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(AppCredential.self, from: data)
    }

    static func write(profileID: String, credential: AppCredential) throws {
        let data = try JSONEncoder().encode(credential)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: profileID)
        ]
        let updateStatus = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess else { throw KeychainError(status) }
        } else if updateStatus != errSecSuccess {
            throw KeychainError(updateStatus)
        }
    }

    static func clear(profileID: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: profileID)
        ]
        SecItemDelete(query as CFDictionary)
    }

    struct KeychainError: LocalizedError {
        let status: OSStatus
        init(_ status: OSStatus) { self.status = status }
        var errorDescription: String? {
            SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        }
    }
}
