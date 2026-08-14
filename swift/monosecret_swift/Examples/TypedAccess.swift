import Foundation
import Monosecret

private struct AppSecrets: Decodable {
    let databaseURL: String

    private enum CodingKeys: String, CodingKey {
        case databaseURL = "DATABASE_URL"
    }
}

func typedAccess(resolved: Resolved) throws {
    let typed = try JSONDecoder().decode(
        AppSecrets.self,
        from: resolved.fieldsJSON()
    )
    print(typed.databaseURL)
}
