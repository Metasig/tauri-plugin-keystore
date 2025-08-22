
import Foundation

#if canImport(Tauri)
import Tauri
import SwiftRs

@objc(KeystorePlugin)
public class KeystorePlugin: Plugin {
    private let core = KeystoreCore.shared

    // MARK: - Helpers

    /// Tries to parse args to the requested Decodable type.
    /// If parsing fails, rejects the invoke and returns nil.
    private func parseOrReject<T: Decodable>(_ type: T.Type, _ invoke: Invoke) -> T? {
        do {
            return try invoke.parseArgs(T.self)
        } catch {
            invoke.reject("invalid_args: \(error)")
            return nil
        }
    }

    // MARK: - Commands (argument handling aligned with Android plugin)

    /// contains_key(key: String) -> Bool
    @objc public func contains_key(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.contains_key(args.key))
    }

    /// contains_unencrypted_key(key: String) -> Bool
    @objc public func contains_unencrypted_key(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.contains_unencrypted_key(args.key))
    }

    /// store_unencrypted(key: String, value: String) -> Bool
    @objc public func store_unencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String; let value: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.store_unencrypted(args.key, value: args.value))
    }

    /// retrieve_unencrypted(key: String) -> String?
    @objc public func retrieve_unencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.retrieve_unencrypted(args.key))
    }

    /// store(key: String, plaintext: String) -> Bool
    @objc public func store(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String; let plaintext: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.store(args.key, plaintext: args.plaintext))
    }

    /// retrieve(key: String) -> String?
    @objc public func retrieve(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.retrieve(args.key))
    }

    /// remove(key: String) -> Bool
    @objc public func remove(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.remove(args.key))
    }

    /// hmac_sha256(message: String) -> hex String
    @objc public func hmac_sha256(_ invoke: Invoke) throws {
        struct Args: Decodable { let message: String }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.hmac_sha256(args.message))
    }

    /// shared_secret_pub_key() -> hex String (no args)
    @objc public func shared_secret_pub_key(_ invoke: Invoke) throws {
        // No args are expected; do not call parseArgs() here.
        invoke.resolve(core.shared_secret_pub_key())
    }

    /// shared_secret(withP256PubKeys: [String]) -> [hex String]
    @objc public func shared_secret(_ invoke: Invoke) throws {
        struct Args: Decodable { let withP256PubKeys: [String] }
        guard let args: Args = parseOrReject(Args.self, invoke) else { return }
        invoke.resolve(core.shared_secret(args.withP256PubKeys))
    }
}

@_cdecl("init_plugin_keystore")
public func initPluginKeystore() -> UnsafeMutableRawPointer? {
    let plugin = KeystorePlugin()
    let unmanaged = Unmanaged.passRetained(plugin)
    return UnsafeMutableRawPointer(unmanaged.toOpaque())
}
#else
@_cdecl("init_plugin_keystore")
public func initPluginKeystore() -> UnsafeMutableRawPointer? {
    return nil
}
#endif
