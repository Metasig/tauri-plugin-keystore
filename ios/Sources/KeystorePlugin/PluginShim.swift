
import Foundation
#if canImport(Tauri)
import Tauri
import SwiftRs
#endif

class ContainsKey: Decodable {
    let key: String
}

class ContainsUnencryptedKey: Decodable {
    let key: String
}

class StoreUnencrypted: Decodable {
    let key: String
    let value: String
}

class RetrieveUnencrypted: Decodable {
    let key: String
}

class Store: Decodable {
    let key: String
    let plaintext: String
}

class Retrieve: Decodable {
    let key: String
}

class Remove: Decodable {
    let key: String
}

class HmacSha256: Decodable {
    let message: String
}

class SharedSecret: Decodable {
    let withP256PubKeys: [String]
}

#if canImport(Tauri)

class KeystorePlugin: Plugin {
    private let core = KeystoreCore.shared

    /// contains_key(key: String) -> Bool
    @objc public func contains_key(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(ContainsKey.self)
        invoke.resolve(core.contains_key(args.key))
    }

    /// contains_unencrypted_key(key: String) -> Bool
    @objc public func contains_unencrypted_key(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(ContainsUnencryptedKey.self)
        invoke.resolve(core.contains_unencrypted_key(args.key))
    }

    /// store_unencrypted(key: String, value: String) -> Bool
    @objc public func store_unencrypted(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(StoreUnencrypted.self)
        invoke.resolve(core.store_unencrypted(args.key, value: args.value))
    }

    /// retrieve_unencrypted(key: String) -> String?
    @objc public func retrieve_unencrypted(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(RetrieveUnencrypted.self)
        invoke.resolve(core.retrieve_unencrypted(args.key))
    }

    /// store(key: String, plaintext: String) -> Bool
    @objc public func store(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(Store.self)
        invoke.resolve(core.store(args.key, plaintext: args.plaintext))
    }

    /// retrieve(key: String) -> String?
    @objc public func retrieve(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(Retrieve.self)
        invoke.resolve(core.retrieve(args.key))
    }

    /// remove(key: String) -> Bool
    @objc public func remove(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(Remove.self)
        invoke.resolve(core.remove(args.key))
    }

    /// hmac_sha256(message: String) -> hex String
    @objc public func hmac_sha256(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(HmacSha256.self)
        invoke.resolve(core.hmac_sha256(args.message))
    }

    /// shared_secret_pub_key() -> hex String (no args)
    @objc public func shared_secret_pub_key(_ invoke: Invoke) throws {
        // No args are expected; do not call parseArgs() here.
        invoke.resolve(core.shared_secret_pub_key())
    }

    /// shared_secret(withP256PubKeys: [String]) -> [hex String]
    @objc public func shared_secret(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SharedSecret.self)
        invoke.resolve(core.shared_secret(args.withP256PubKeys))
    }
}

@_cdecl("init_plugin_keystore")
public func initPluginKeystore() -> UnsafeMutableRawPointer? {
    let plugin = KeystorePlugin()
    let unmanaged = Unmanaged.passRetained(plugin)
    return UnsafeMutableRawPointer(unmanaged.toOpaque())
}
#endif
