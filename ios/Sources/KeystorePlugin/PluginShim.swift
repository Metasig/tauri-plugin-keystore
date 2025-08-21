
import Foundation

#if canImport(Tauri)
import Tauri

@objc(KeystorePlugin)
public class KeystorePlugin: Plugin {
    private let core = KeystoreCore.shared

    @objc public func containsKey(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.contains_key(args.key))
    }

    @objc public func containsUnencryptedKey(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.contains_unencrypted_key(args.key))
    }

    @objc public func storeUnencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String; let value: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.store_unencrypted(args.key, value: args.value))
    }

    @objc public func retrieveUnencrypted(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.retrieve_unencrypted(args.key))
    }

    @objc public func remove(_ invoke: Invoke) throws {
        struct Args: Decodable { let key: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.remove(args.key))
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

    @objc public func hmacSha256(_ invoke: Invoke) throws {
        struct Args: Decodable { let message: String }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.hmac_sha256(args.message))
    }

    @objc public func sharedSecretPubKey(_ invoke: Invoke) throws {
        invoke.resolve(core.shared_secret_pub_key())
    }

    @objc public func sharedSecret(_ invoke: Invoke) throws {
        struct Args: Decodable { let pubKeys: [String] }
        let args: Args = try invoke.parseArgs()
        invoke.resolve(core.shared_secret(args.pubKeys))
    }
}
#endif
