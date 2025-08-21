
import Foundation

#if canImport(Tauri)
import Tauri
import SwiftRs

@objc(KeystorePlugin)
public class KeystorePlugin: Plugin {
    private let core = KeystoreCore.shared

    @objc public func contains_key(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.contains_key(args.key))
    }

    @objc public func contains_unencrypted_key(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.contains_unencrypted_key(args.key))
    }

    @objc public func store_unencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String; let value: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.store_unencrypted(args.key, value: args.value))
    }

    @objc public func retrieve_unencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.retrieve_unencrypted(args.key))
    }

    @objc public func store(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String; let plaintext: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.store(args.key, plaintext: args.plaintext))
    }

    @objc public func retrieve(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.retrieve(args.key))
    }

    @objc public func remove(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.remove(args.key))
    }

    @objc public func hmac_sha256(_ invoke: Invoke) throws {
        struct Args: Decodable { let message: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.hmac_sha256(args.message))
    }

    @objc public func shared_secret_pub_key(_ invoke: Invoke) throws {
        invoke.resolve(core.shared_secret_pub_key())
    }

    @objc public func shared_secret(_ invoke: Invoke) throws {
        struct Args: Decodable { let withP256PubKeys: [String] }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.shared_secret(args.withP256PubKeys))
    }
}

@_cdecl("init_plugin_keystore")
func initPlugin() -> Plugin {
  return KeystorePlugin()
}

#else
@_cdecl("init_plugin_keystore")
public func initPluginKeystore() -> UnsafeMutableRawPointer? {
    return nil
}
#endif
