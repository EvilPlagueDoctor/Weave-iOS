import SwiftUI

struct NetworkPeer: Identifiable {
    let id: String
    let name: String
    let mainDHT: String
}

@MainActor
final class DiscoveryModel: ObservableObject {
    @Published var peers: [NetworkPeer] = []
    @Published var status = ""

    func refresh(client: DaemonClient) async {
        status = "Searching…"
        do {
            let result = try await client.listAppPeers()
            let raw = (result["peers"] as? [[String: Any]]) ?? (result["items"] as? [[String: Any]]) ?? []
            peers = raw.compactMap { item in
                let dht = (item["main_dht"] as? String) ?? (item["mainDht"] as? String) ?? (item["peer_main_dht"] as? String) ?? ""
                guard !dht.isEmpty else { return nil }
                let name = (item["display_name"] as? String) ?? (item["name"] as? String) ?? String(dht.prefix(12))
                return NetworkPeer(id: dht, name: name, mainDHT: dht)
            }
            status = peers.isEmpty ? "No application peers found yet." : "Found \(peers.count) peers."
        } catch { status = error.localizedDescription }
    }
}

struct SearchView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var discovery = DiscoveryModel()
    @State private var query = ""

    var filtered: [NetworkPeer] {
        guard !query.isEmpty else { return discovery.peers }
        return discovery.peers.filter { $0.name.localizedCaseInsensitiveContains(query) || $0.mainDHT.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        NavigationStack {
            List {
                if !discovery.status.isEmpty { Text(discovery.status).font(.caption).foregroundStyle(.secondary) }
                ForEach(filtered) { peer in
                    VStack(alignment: .leading, spacing: 4) { Text(peer.name).font(.headline); Text(peer.mainDHT).font(.caption.monospaced()).lineLimit(1) }
                }
            }
            .searchable(text: $query, prompt: "People, groups, DHT keys")
            .navigationTitle("Search")
            .refreshable { await discovery.refresh(client: model.daemonClient) }
            .task { await discovery.refresh(client: model.daemonClient) }
        }
    }
}

struct PeopleView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var discovery = DiscoveryModel()

    var body: some View {
        NavigationStack {
            List {
                ForEach(discovery.peers) { peer in
                    VStack(alignment: .leading, spacing: 4) { Text(peer.name).font(.headline); Text(peer.mainDHT).font(.caption.monospaced()).lineLimit(1) }
                }
                if discovery.peers.isEmpty { Text(discovery.status.isEmpty ? "No people discovered yet." : discovery.status).foregroundStyle(.secondary) }
            }
            .navigationTitle("People")
            .refreshable { await discovery.refresh(client: model.daemonClient) }
            .task { await discovery.refresh(client: model.daemonClient) }
        }
    }
}
