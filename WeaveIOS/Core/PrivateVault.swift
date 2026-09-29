import Foundation

actor PrivateVault {
    enum Retention: String { case persistent, cache, temporary, deleteOnShutdown = "delete_on_shutdown" }

    private let client: DaemonClient
    private static let chunkBytes = 256 * 1024

    init(client: DaemonClient) { self.client = client }

    func putValue(key: String, data: Data, retention: Retention = .persistent, ttlSeconds: Int64? = nil) async throws {
        var body: [String: Any] = [
            "key": key,
            "value_base64": data.base64EncodedString(),
            "retention": retention.rawValue
        ]
        if let ttlSeconds { body["ttl_seconds"] = ttlSeconds }
        _ = try await client.request("put_private_value", body: body)
    }

    func getValue(key: String) async throws -> Data? {
        let result = try await client.request("get_private_value", body: ["key": key])
        switch result["type"] as? String ?? "" {
        case "private_value_missing": return nil
        case "private_value_read":
            guard let b64 = result["value_base64"] as? String else { return nil }
            return Data(base64Encoded: b64)
        default: throw VaultError.unexpected(String(describing: result))
        }
    }

    func putText(key: String, value: String, retention: Retention = .persistent) async throws {
        try await putValue(key: key, data: Data(value.utf8), retention: retention)
    }

    func getText(key: String) async throws -> String? {
        guard let data = try await getValue(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func deleteValue(key: String) async throws -> Bool {
        let result = try await client.request("delete_private_value", body: ["key": key])
        return result["deleted"] as? Bool ?? false
    }

    func putBlob(contentType: String, data: Data, retention: Retention = .persistent) async throws -> String {
        let started = try await client.request("begin_private_blob", body: [
            "content_type": contentType,
            "retention": retention.rawValue
        ])
        guard let blob = started["blob"] as? [String: Any], let blobID = blob["blob_id"] as? String else {
            throw VaultError.unexpected("begin_private_blob returned no blob id")
        }
        do {
            var offset = 0
            while offset < data.count {
                let end = min(data.count, offset + Self.chunkBytes)
                _ = try await client.request("append_private_blob", body: [
                    "blob_id": blobID,
                    "data_base64": Data(data[offset..<end]).base64EncodedString()
                ])
                offset = end
            }
            let finished = try await client.request("finish_private_blob", body: ["blob_id": blobID])
            let resultBlob = finished["blob"] as? [String: Any]
            return resultBlob?["blob_id"] as? String ?? blobID
        } catch {
            _ = try? await client.request("abort_private_blob", body: ["blob_id": blobID])
            throw error
        }
    }

    func getBlob(blobID: String, maxBytes: Int = 32 * 1024 * 1024) async throws -> Data {
        let metadataResult = try await client.request("read_private_blob_range", body: ["blob_id": blobID, "offset": 0, "length": 0])
        guard let blob = metadataResult["blob"] as? [String: Any], let totalNumber = blob["total_bytes"] as? NSNumber else {
            throw VaultError.unexpected("private blob metadata missing")
        }
        let total = totalNumber.intValue
        guard total >= 0 && total <= maxBytes else { throw VaultError.tooLarge(total) }
        var output = Data(capacity: total)
        var offset = 0
        while offset < total {
            let length = min(Self.chunkBytes, total - offset)
            let range = try await client.request("read_private_blob_range", body: [
                "blob_id": blobID,
                "offset": offset,
                "length": length
            ])
            guard let b64 = range["data_base64"] as? String, let chunk = Data(base64Encoded: b64), !chunk.isEmpty else {
                throw VaultError.unexpected("empty private blob chunk")
            }
            output.append(chunk)
            offset += chunk.count
        }
        guard output.count == total else { throw VaultError.unexpected("private blob length mismatch") }
        return output
    }

    func deleteBlob(blobID: String) async throws {
        _ = try await client.request("delete_private_blob", body: ["blob_id": blobID])
    }

    func putNamedBlob(namespace: String, name: String, contentType: String, data: Data, retention: Retention = .persistent) async throws {
        let indexKey = "\(namespace)/index"
        var index: [String: String] = [:]
        if let text = try await getText(key: indexKey), let bytes = text.data(using: .utf8),
           let decoded = try? JSONDecoder().decode([String: String].self, from: bytes) { index = decoded }
        let previous = index[name]
        let next = try await putBlob(contentType: contentType, data: data, retention: retention)
        do {
            index[name] = next
            let encoded = try JSONEncoder().encode(index)
            try await putValue(key: indexKey, data: encoded)
        } catch {
            try? await deleteBlob(blobID: next)
            throw error
        }
        if let previous, previous != next { try? await deleteBlob(blobID: previous) }
    }

    func getNamedBlob(namespace: String, name: String, maxBytes: Int = 32 * 1024 * 1024) async throws -> Data? {
        let indexKey = "\(namespace)/index"
        guard let text = try await getText(key: indexKey), let bytes = text.data(using: .utf8),
              let index = try? JSONDecoder().decode([String: String].self, from: bytes),
              let blobID = index[name] else { return nil }
        return try await getBlob(blobID: blobID, maxBytes: maxBytes)
    }

    func listNamedBlobs(namespace: String) async throws -> [String] {
        guard let text = try await getText(key: "\(namespace)/index"), let bytes = text.data(using: .utf8),
              let index = try? JSONDecoder().decode([String: String].self, from: bytes) else { return [] }
        return index.keys.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    enum VaultError: LocalizedError {
        case unexpected(String)
        case tooLarge(Int)
        var errorDescription: String? {
            switch self {
            case .unexpected(let message): return message
            case .tooLarge(let size): return "Private blob is too large for this operation: \(size) bytes"
            }
        }
    }
}
