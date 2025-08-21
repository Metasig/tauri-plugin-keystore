
import XCTest
@testable import KeystorePlugin

final class KeystorePluginTests: XCTestCase {
    func testHexRoundtrip() throws {
        let bytes = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let hex = dataToHex(bytes)
        let back = hexToData(hex)
        XCTAssertEqual(bytes, back)
    }

    func testPlainStoreRetrieve() throws {
        let core = KeystoreCore.shared
        _ = core.store_unencrypted("hello", value: "world")
        let res = core.retrieve_unencrypted("hello")
        XCTAssertTrue(res.ok)
        XCTAssertEqual(res.result, "world")
    }
}
