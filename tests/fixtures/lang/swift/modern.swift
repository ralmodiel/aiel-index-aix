import Foundation

protocol Store { func load(id: Int) async throws -> String }
actor Cache { var n = 0; func bump() { n += 1 } }
struct Item: Identifiable { let id: Int }
enum Mode { case on, off }

final class Service: Store {
    let cache = Cache()
    func load(id: Int) async throws -> String { await cache.bump(); return helper(id: id) }
    private func helper(id: Int) -> String { "\(id)" }
}
